"""Command-line interface for the reproducible URL risk experiment."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import joblib

from .download import CSV_NAME, download_dataset
from .evaluate import train_and_evaluate
from .features import feature_frame, host_feature_frame, is_https_root


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate URL-only phishing risk signals")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("download", help="Download the attributed public UCI dataset into ignored data/")
    train = sub.add_parser("train", help="Train, select, and evaluate with a held-out test set")
    train.add_argument("--csv", type=Path, default=Path("data") / CSV_NAME)
    train.add_argument("--cohort", choices=["matched-root", "all"], default="matched-root")
    train.add_argument("--output", type=Path)
    score = sub.add_parser("score", help="Score a URL without visiting it")
    score.add_argument("url")
    score.add_argument("--model", type=Path, default=Path("reports/matched-root/model.joblib"))
    args = parser.parse_args()
    if args.command == "download":
        print(download_dataset(Path("data")))
    elif args.command == "train":
        output = args.output or Path("reports") / args.cohort
        print(json.dumps(train_and_evaluate(args.csv, output, cohort=args.cohort), indent=2))
    else:
        saved = joblib.load(args.model)
        if saved["cohort"] == "matched-root" and not is_https_root(args.url):
            parser.error("The matched-root experiment accepts only HTTPS site-root URLs")
        features = host_feature_frame([args.url]) if saved["cohort"] == "matched-root" else feature_frame([args.url])
        risk_score = float(saved["model"].predict_proba(features)[0, 1])
        print(json.dumps({"experimental_score": risk_score, "flagged_at_study_threshold": risk_score >= saved["threshold"], "not_a_safety_verdict": True}, indent=2))


if __name__ == "__main__":
    main()
