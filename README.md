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

## Local development

```bash
python3 -m unittest discover -s tests -v
python3 -m py_compile src/observatory/*.py
```