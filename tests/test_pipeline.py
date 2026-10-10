from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

import numpy as np

from phish_signal_lab.data import load_url_labels
from phish_signal_lab.evaluate import group_partitions, precision_floor_threshold
from phish_signal_lab.features import FEATURE_NAMES, HOST_FEATURE_NAMES, feature_frame, host_feature_frame, is_https_root


class PipelineTests(unittest.TestCase):
    def test_public_dataset_label_mapping_and_conflicts(self):
        with tempfile.TemporaryDirectory() as folder:
            csv = Path(folder) / "rows.csv"
            csv.write_text(
                "URL,label\n"
                "https://safe.test,1\n"
                "http://phish.test/login,0\n"
                "http://phish.test/login,0\n"
                "https://conflict.test,0\n"
                "https://conflict.test,1\n"
            )
            rows, hygiene = load_url_labels(csv)
        self.assertEqual(hygiene["conflicting_label_rows_removed"], 2)
        self.assertEqual(hygiene["unique_urls"], 2)
        self.assertEqual(rows.set_index("URL").loc["https://safe.test", "phishing"], 0)
        self.assertEqual(rows.set_index("URL").loc["http://phish.test/login", "phishing"], 1)

    def test_host_groups_never_cross_partitions(self):
        groups = np.array([f"host-{i // 3}.test" for i in range(300)])
        train, validation, test = group_partitions(groups)
        partitions = [set(groups[part]) for part in (train, validation, test)]
        self.assertFalse(partitions[0] & partitions[1])
        self.assertFalse(partitions[0] & partitions[2])
        self.assertFalse(partitions[1] & partitions[2])
        self.assertEqual(sorted(np.concatenate([train, validation, test])), list(range(300)))

    def test_cohort_and_feature_scopes(self):
        self.assertTrue(is_https_root("https://www.example.org/"))
        self.assertFalse(is_https_root("http://example.org/"))
        self.assertFalse(is_https_root("https://example.org/login"))
        self.assertEqual(tuple(feature_frame(["https://example.org/"]).columns), FEATURE_NAMES)
        self.assertEqual(tuple(host_feature_frame(["https://example.org/"]).columns), HOST_FEATURE_NAMES)
        self.assertEqual(
            host_feature_frame(["https://example.org/", "https://example.org/login"]).iloc[0].to_dict(),
            host_feature_frame(["https://example.org/", "https://example.org/login"]).iloc[1].to_dict(),
        )

    def test_validation_threshold_has_explicit_fallback(self):
        labels = np.array([1, 1, 0, 0])
        scores = np.array([0.9, 0.8, 0.7, 0.1])
        threshold, met = precision_floor_threshold(labels, scores, target=0.9, minimum_alerts=2)
        self.assertTrue(met)
        self.assertEqual(threshold, 0.8)
        _, met = precision_floor_threshold(labels, scores, target=0.9, minimum_alerts=5)
        self.assertFalse(met)


if __name__ == "__main__":
    unittest.main()
