"""Domain-separated model selection and one-time held-out evaluation."""

from __future__ import annotations

import json
from pathlib import Path

import joblib
import numpy as np
from sklearn.dummy import DummyClassifier
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    average_precision_score,
    confusion_matrix,
    precision_recall_curve,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import GroupShuffleSplit
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler

from .data import load_url_labels
from .features import FEATURE_NAMES, HOST_FEATURE_NAMES, feature_frame, host_feature_frame, is_https_root


def group_partitions(groups: np.ndarray, seed: int = 42) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    indices = np.arange(len(groups))
    train_val, test = next(
        GroupShuffleSplit(n_splits=1, test_size=0.2, random_state=seed).split(indices, groups=groups)
    )
    train_rel, valid_rel = next(
        GroupShuffleSplit(n_splits=1, test_size=0.25, random_state=seed + 1).split(
            train_val, groups=groups[train_val]
        )
    )
    train, valid = train_val[train_rel], train_val[valid_rel]
    sets = [set(groups[part]) for part in (train, valid, test)]
    if any(sets[a] & sets[b] for a, b in ((0, 1), (0, 2), (1, 2))):
        raise AssertionError("A hostname appears in more than one partition")
    return train, valid, test


def precision_floor_threshold(
    truth: np.ndarray, scores: np.ndarray, *, target: float = 0.90, minimum_alerts: int = 50
) -> tuple[float, bool]:
    """Pick the largest validation recall meeting a precision target."""
    precision, recall, thresholds = precision_recall_curve(truth, scores)
    ordered_scores = np.sort(scores)
    predicted_positive = len(scores) - np.searchsorted(ordered_scores, thresholds, side="left")
    feasible = np.flatnonzero((precision[:-1] >= target) & (predicted_positive >= minimum_alerts))
    if len(feasible):
        best = feasible[np.argmax(recall[feasible])]
        return float(thresholds[best]), True
    # A failed precision target is explicit in the report. F1 gives a defined fallback.
    f1 = 2 * precision[:-1] * recall[:-1] / np.maximum(precision[:-1] + recall[:-1], 1e-12)
    return float(thresholds[np.argmax(f1)]), False


def score_metrics(truth: np.ndarray, scores: np.ndarray, threshold: float) -> dict:
    predicted = scores >= threshold
    tn, fp, fn, tp = confusion_matrix(truth, predicted, labels=[0, 1]).ravel()
    return {
        "rows": int(len(truth)),
        "phishing_prevalence": float(truth.mean()),
        "average_precision": float(average_precision_score(truth, scores)),
        "roc_auc": float(roc_auc_score(truth, scores)),
        "precision": float(precision_score(truth, predicted, zero_division=0)),
        "recall": float(recall_score(truth, predicted, zero_division=0)),
        "tn": int(tn),
        "fp": int(fp),
        "fn": int(fn),
        "tp": int(tp),
    }


def train_and_evaluate(csv_path: Path, output: Path, *, seed: int = 42, cohort: str = "matched-root") -> dict:
    rows, hygiene = load_url_labels(csv_path)
    cohort_counts = {
        "all_legitimate": int((rows["phishing"] == 0).sum()),
        "all_phishing": int((rows["phishing"] == 1).sum()),
    }
    root = rows["URL"].map(is_https_root)
    cohort_counts["https_root_legitimate"] = int(((rows["phishing"] == 0) & root).sum())
    cohort_counts["https_root_phishing"] = int(((rows["phishing"] == 1) & root).sum())
    if cohort == "matched-root":
        rows = rows.loc[root].reset_index(drop=True)
        features = host_feature_frame(rows["URL"])
        feature_names = HOST_FEATURE_NAMES
    elif cohort == "all":
        features = feature_frame(rows["URL"])
        feature_names = FEATURE_NAMES
    else:
        raise ValueError(f"Unknown cohort: {cohort}")
    groups = rows["host"].to_numpy()
    train, valid, test = group_partitions(groups, seed)
    labels = rows["phishing"].to_numpy()
    if any(len(np.unique(labels[part])) != 2 for part in (train, valid, test)):
        raise ValueError("Each partition must contain both classes")
    x_train, y_train = features.iloc[train], labels[train]
    x_valid, y_valid = features.iloc[valid], labels[valid]
    x_test, y_test = features.iloc[test], labels[test]

    candidates = {
        "logistic_regression": make_pipeline(StandardScaler(), LogisticRegression(max_iter=1000, random_state=seed)),
        "histogram_gradient_boosting": HistGradientBoostingClassifier(
            max_iter=150, max_leaf_nodes=15, learning_rate=0.08, random_state=seed
        ),
    }
    validation_ap = {}
    for name, model in candidates.items():
        model.fit(x_train, y_train)
        validation_ap[name] = float(average_precision_score(y_valid, model.predict_proba(x_valid)[:, 1]))
    winner = max(validation_ap, key=validation_ap.get)
    model = candidates[winner]
    valid_scores = model.predict_proba(x_valid)[:, 1]
    threshold, floor_met = precision_floor_threshold(y_valid, valid_scores)
    test_scores = model.predict_proba(x_test)[:, 1]
    baseline = DummyClassifier(strategy="prior").fit(x_train, y_train)
    baseline_ap = float(average_precision_score(y_test, baseline.predict_proba(x_test)[:, 1]))

    output.mkdir(parents=True, exist_ok=True)
    report = {
        "source": "UCI PhiUSIIL Phishing URL (Website), dataset 967; URL and label columns only",
        "cohort": cohort,
        "cohort_counts": cohort_counts,
        "seed": seed,
        "hygiene": hygiene,
        "split": {
            "method": "exact hostname grouped; no hostname shared across train, validation, test",
            "train_rows": len(train),
            "validation_rows": len(valid),
            "test_rows": len(test),
            "train_hosts": len(set(groups[train])),
            "validation_hosts": len(set(groups[valid])),
            "test_hosts": len(set(groups[test])),
        },
        "model": winner,
        "validation_average_precision_by_model": validation_ap,
        "validation_precision_target": 0.90,
        "validation_precision_target_met": floor_met,
        "threshold_selected_on_validation": threshold,
        "validation": score_metrics(y_valid, valid_scores, threshold),
        "test": score_metrics(y_test, test_scores, threshold),
        "test_prior_baseline_average_precision": baseline_ap,
        "limitations": [
            "The dataset has a collection artifact: all legitimate URLs are HTTPS site roots, while many phishing URLs are not.",
            "Even the matched cohort may contain source or campaign artifacts; it is not a live-traffic sample.",
            "Exact-host grouping does not prevent related subdomains or campaigns crossing partitions.",
            "No collection dates are supplied, so temporal generalization is not measured.",
            "Scores are model outputs, not calibrated real-world fraud probabilities.",
            "This is a URL-only triage experiment, not a browser safety or blocking service.",
        ],
    }
    (output / "evaluation.json").write_text(json.dumps(report, indent=2) + "\n")
    joblib.dump({"model": model, "features": feature_names, "threshold": threshold, "cohort": cohort}, output / "model.joblib")
    return report
