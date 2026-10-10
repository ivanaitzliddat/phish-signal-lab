# Phish Signal Lab

A reproducible study of phishing risk signals available from a URL **before visiting the site**. It compares a simple logistic regression with histogram gradient boosting, selects a model and alert threshold on validation data, and evaluates once on a held-out test set. URLs are split by hostname so the same host never appears in more than one partition.

The project also demonstrates why a striking benchmark number needs a dataset audit. In this dataset, every legitimate URL is an HTTPS site root, while many phishing URLs use HTTP, paths, or query strings. A model can learn how the two classes were collected. The default experiment therefore restricts both classes to HTTPS site-root URLs and uses hostname features only. This reduces an obvious artifact; it does **not** make the sample representative of live traffic.

## Data and attribution

The experiment uses the [PhiUSIIL Phishing URL (Website) dataset](https://archive.ics.uci.edu/dataset/967/phiusil-phishing-url-dataset) by Arvind Prasad and Shalini Chandra, supplied by the UCI Machine Learning Repository under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). The dataset's label `0` means phishing and `1` means legitimate; the code maps phishing to the positive class. Only the `URL` and `label` columns are read. Website content and the source dataset's derived features are not used. The dataset is downloaded locally into ignored `data/`; no URL samples are included in this repository. The download script checks the source archive's SHA-256 before extracting it.

## Reproduce

Use Python 3.11 or newer and [uv](https://docs.astral.sh/uv/):

```sh
uv sync
uv run phish-signal download
uv run phish-signal train
uv run phish-signal train --cohort all
uv run python -m unittest discover -s tests -v
```

The default run writes `reports/matched-root/evaluation.json` and a local model artifact. The `all` run writes to `reports/all/`. Both directories are ignored by Git. The CLI can score an HTTPS site-root URL with `uv run phish-signal score https://example.org/`; it never visits the site. That output is an experimental model score, **not** a safety verdict.

## Evaluation design

1. Remove exact duplicate URLs and URLs with conflicting labels.
2. For the default cohort, keep only HTTPS URLs with no path beyond `/` and no query string. Compute hostname-only length, punctuation, digit, entropy, IP, and punycode features.
3. Split by exact hostname into training, validation, and test partitions. A related subdomain or campaign can still cross partitions.
4. Fit logistic regression and histogram gradient boosting on training rows. Select the model by validation average precision.
5. On validation rows, choose the lowest score threshold that reaches 90% precision with at least 50 flagged examples, maximizing recall. If none exists, use the F1 maximum and report that the target was unmet.
6. Apply the chosen model and threshold to the test set once. Report average precision, ROC AUC, precision, recall, prevalence, and confusion counts. A constant-prior classifier supplies a prevalence baseline.

## Observed results

These are reproducible results for this dataset and seed (`42`), not estimates of performance on real-world phishing traffic.

| Cohort | Test rows | Phishing prevalence | Average precision | Prior baseline AP | Precision | Recall |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| All URLs, all structural features | 46,878 | 42.3% | 0.998 | 0.423 | 0.908 | 0.995 |
| Matched HTTPS roots, hostname features | 32,668 | 17.1% | 0.935 | 0.171 | 0.894 | 0.861 |

The apparent drop is not a like-for-like estimate of the same population: the cohort, class prevalence, and feature set all change. Its value is as an artifact check. In the matched test set, the selected threshold delivered **89.4% precision**, below the 90% target observed on validation. The threshold is therefore a study operating point, not a guaranteed service level.

## Limits

- The source has no collection timestamps, so this experiment cannot test future campaigns or concept drift.
- Hostname grouping blocks exact host overlap, but related domains and collection artifacts may remain.
- The source has far more phishing URLs than normal traffic is likely to have. Precision will change when prevalence changes.
- Model scores are not calibrated probabilities of a site being malicious.
- Do not use this experiment to decide whether a URL is safe to open.
