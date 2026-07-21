# CodeRiskTools Observatory

CodeRiskTools Observatory is an OSS-only, local-first system for producing reproducible, review-gated risk reports about public GitHub repositories. It is evidence, not certification.

## What Observatory is

A reproducible pipeline that binds a report to an exact commit SHA, records tools and ruleset identities, separates detection from publication policy, redacts sensitive evidence, and publishes only through a reviewed pull request.

## What Observatory is not

It is not a security certificate, a guarantee that a repository is secure, an autonomous vulnerability-disclosure channel, a paid service, or a replacement for maintainer review.

## OSS-only boundary

The required pipeline uses Python, Git, the CodeRiskTools Secret Scanner OSS component, local scripts, open formats, and standard GitHub repository mechanisms. It does not require paid APIs, SaaS subscriptions, proprietary SDKs, closed AI models, paid storage, or paid CI/CD.

## Repository split

- `coderisktools-observatory`: code, schemas, policies, tests, local runner, adapters, report builders and publication validation.
- `coderisktools-observatory-reports`: immutable public reports, manifests, feeds, badges, status and correction/retraction records.

## Evidence, not certification

Every report states its target SHA, scope, tools, ruleset digest, completeness, limitations, publication decision, manifest and checksums. A clean result is not a certification. Partial or failed scans are never presented as clean.

## Development status

Bootstrap stage. The project is not production-ready and no real report is published by this repository. Follow `Obserwator.md` and `Obserwator_todo.md` in the workspace for the governing plan.

## Benchmark

Run the deterministic local scanner/policy corpus with the installed OSS scanner:

```bash
PYTHONPATH=src python3 -m observatory benchmark \
  --manifest benchmark/manifest.json \
  --ruleset-digest sha256:<64 lowercase hex characters> \
  --json
```

Exit codes are `0` when every case matches, `2` when a case mismatches, and `3` for an invalid manifest or runtime error. The positive fixture is assembled only in a temporary directory from split parts; raw secret material is not stored in the repository. The benchmark output contains statuses, counts, decisions and reason codes, never raw evidence.

The manifest also records binary `ground_truth` labels and minimum quality thresholds. The JSON result includes `TP`, `TN`, `FP`, `FN`, precision, recall and F1; a threshold failure makes the benchmark exit `2`.

The performance baseline records materialized fixture sizes, a canonical `result_digest`, and `max_total_duration_ms`. Runtime is measured separately from the digest, so timing variance does not create false content regressions; exceeding the baseline fails with exit `2`.

## Self-scan

Scan the Observatory checkout at its exact Git `HEAD` without printing raw findings:

```bash
PYTHONPATH=src python3 -m observatory self-scan \
  --path . \
  --ruleset-digest sha256:<64 lowercase hex characters> \
  --json
```

A clean self-scan returns exit `0`. Findings or scan errors return `2`; missing Git provenance, invalid configuration or scanner runtime errors return `3`. The output contains only provenance, status, counts, decisions, reason codes, errors and warnings.

## CI scanner provenance

CI checks out the scanner source at an exact commit, installs that pinned checkout, derives a canonical SHA-256 digest from the scanner's built-in declarative rules, and runs both the real benchmark and self-scan with that digest. The ruleset digest is therefore distinct from the scanner source/artifact SHA and is not a placeholder.

## Static status page

A privacy-safe status artifact can be generated without reading private operator data:

```bash
PYTHONPATH=src python3 -m observatory status \
  --output-dir public/status \
  --generated-at 2026-07-21T08:00:00Z \
  --build-sha <full-commit-sha> \
  --reports 0 \
  --digests 0 \
  --retractions 0 \
  --partial-scans 0 \
  --feed-status healthy \
  --self-scan-decision PUBLISH \
  --self-scan-findings 0 \
  --benchmark-passed
```

For a checked-out reports repository, use `--reports-repo <path>` instead of the four manual counters. The loader reads only canonical `public/reports/github/**` and `public/weekly/*/report.json` artifacts and emits `publication_scope` as `empty`, `synthetic`, `real` or `mixed`. It never reads `operator/`.

The command writes only aggregate `status.json` and static `index.html`; it does not publish findings, operator identity, raw scanner output or repository-private data.

## Local development

```bash
python3 -m unittest discover -s tests -v
python3 -m py_compile src/observatory/*.py
```