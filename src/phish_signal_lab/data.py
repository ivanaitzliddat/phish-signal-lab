"""Load the independently licensed public dataset and enforce label hygiene."""

from __future__ import annotations

from pathlib import Path

import pandas as pd

from .features import hostname


def load_url_labels(csv_path: Path) -> tuple[pd.DataFrame, dict[str, int]]:
    frame = pd.read_csv(csv_path, usecols=["URL", "label"], encoding="utf-8-sig")
    raw_rows = len(frame)
    frame = frame.dropna(subset=["URL", "label"]).copy()
    frame["URL"] = frame["URL"].astype(str).str.strip()
    frame = frame[frame["URL"] != ""]
    labels = set(frame["label"].unique().tolist())
    if not labels.issubset({0, 1}):
        raise ValueError(f"Unexpected labels: {labels}")
    # UCI labels 0=phishing, 1=legitimate. This project uses 1=phishing.
    conflicting = frame.groupby("URL")["label"].transform("nunique") > 1
    conflicting_rows = int(conflicting.sum())
    frame = frame.loc[~conflicting].drop_duplicates("URL").reset_index(drop=True)
    frame["phishing"] = (frame["label"] == 0).astype("int8")
    frame["host"] = frame["URL"].map(hostname)
    if frame["phishing"].nunique() != 2:
        raise ValueError("Both classes must be present")
    return frame[["URL", "phishing", "host"]], {
        "raw_rows": raw_rows,
        "conflicting_label_rows_removed": conflicting_rows,
        "unique_urls": len(frame),
    }
