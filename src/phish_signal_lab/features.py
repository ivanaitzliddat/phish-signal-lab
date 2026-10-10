"""Features available from the URL string before visiting a website."""

from __future__ import annotations

import ipaddress
import math
from collections import Counter
from urllib.parse import urlsplit

import pandas as pd


FEATURE_NAMES = (
    "url_length",
    "host_length",
    "path_length",
    "query_length",
    "host_dots",
    "host_hyphens",
    "path_slashes",
    "query_markers",
    "at_signs",
    "percent_signs",
    "digit_fraction",
    "url_entropy",
    "is_https",
    "is_ip_host",
    "has_punycode",
    "has_port",
)

HOST_FEATURE_NAMES = (
    "host_length",
    "host_dots",
    "host_hyphens",
    "host_digit_fraction",
    "host_entropy",
    "is_ip_host",
    "has_punycode",
)


def parsed_url(raw: str):
    """Parse without fetching; tolerate scheme-free and malformed inputs."""
    value = raw.strip()
    if "://" not in value:
        value = "http://" + value
    try:
        return urlsplit(value)
    except ValueError:
        return urlsplit("http://invalid.local/")


def hostname(raw: str) -> str:
    host = (parsed_url(raw).hostname or "").lower().rstrip(".")
    if host.startswith("www."):
        host = host[4:]
    return host or raw.strip().lower()


def is_https_root(raw: str) -> bool:
    parts = parsed_url(raw)
    return parts.scheme.lower() == "https" and parts.path in ("", "/") and not parts.query


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    return -sum((count / len(value)) * math.log2(count / len(value)) for count in counts.values())


def extract_features(raw: str) -> dict[str, float]:
    parts = parsed_url(raw)
    host = (parts.hostname or "").lower()
    value = raw.strip().lower()
    try:
        ipaddress.ip_address(host)
        is_ip = 1
    except ValueError:
        is_ip = 0
    try:
        has_port = int(parts.port is not None)
    except ValueError:
        has_port = 0
    return {
        "url_length": float(len(value)),
        "host_length": float(len(host)),
        "path_length": float(len(parts.path)),
        "query_length": float(len(parts.query)),
        "host_dots": float(host.count(".")),
        "host_hyphens": float(host.count("-")),
        "path_slashes": float(parts.path.count("/")),
        "query_markers": float(parts.query.count("&") + bool(parts.query)),
        "at_signs": float(value.count("@")),
        "percent_signs": float(value.count("%")),
        "digit_fraction": sum(c.isdigit() for c in value) / max(len(value), 1),
        "url_entropy": _entropy(value),
        "is_https": float(parts.scheme.lower() == "https"),
        "is_ip_host": float(is_ip),
        "has_punycode": float("xn--" in host),
        "has_port": float(has_port),
    }


def feature_frame(urls: list[str] | pd.Series) -> pd.DataFrame:
    return pd.DataFrame.from_records((extract_features(url) for url in urls), columns=FEATURE_NAMES)


def host_feature_frame(urls: list[str] | pd.Series) -> pd.DataFrame:
    def one(raw: str) -> dict[str, float]:
        host = hostname(raw)
        try:
            ipaddress.ip_address(host)
            is_ip = 1.0
        except ValueError:
            is_ip = 0.0
        return {
            "host_length": float(len(host)),
            "host_dots": float(host.count(".")),
            "host_hyphens": float(host.count("-")),
            "host_digit_fraction": sum(c.isdigit() for c in host) / max(len(host), 1),
            "host_entropy": _entropy(host),
            "is_ip_host": is_ip,
            "has_punycode": float("xn--" in host),
        }

    return pd.DataFrame.from_records((one(url) for url in urls), columns=HOST_FEATURE_NAMES)
