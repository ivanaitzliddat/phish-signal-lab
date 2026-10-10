"""Fetch the UCI source archive without checking dataset rows into Git."""

from __future__ import annotations

import hashlib
import io
import urllib.request
import zipfile
from pathlib import Path


DATASET_URL = "https://archive.ics.uci.edu/static/public/967/phiusiil%2Bphishing%2Burl%2Bdataset.zip"
ARCHIVE_SHA256 = "0a639fd03aea6308c5b1c10c92aa23c2ce1505447a9137271865cd0badc9a59a"
CSV_NAME = "PhiUSIIL_Phishing_URL_Dataset.csv"


def download_dataset(destination: Path) -> Path:
    destination.mkdir(parents=True, exist_ok=True)
    csv_path = destination / CSV_NAME
    with urllib.request.urlopen(DATASET_URL, timeout=90) as response:
        archive = response.read()
    digest = hashlib.sha256(archive).hexdigest()
    if digest != ARCHIVE_SHA256:
        raise ValueError(f"Dataset archive SHA-256 changed: {digest}")
    with zipfile.ZipFile(io.BytesIO(archive)) as zipped:
        with zipped.open(CSV_NAME) as source, csv_path.open("wb") as target:
            while chunk := source.read(1024 * 1024):
                target.write(chunk)
    return csv_path
