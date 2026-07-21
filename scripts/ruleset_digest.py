#!/usr/bin/env python3
"""Print the canonical digest of the installed scanner built-in ruleset."""

import hashlib
import json

from src.patterns import DEFAULT_DETECTION_RULES

_FIELDS = (
    "name", "regex", "severity", "description", "rule_id",
    "category", "confidence", "remediation", "kind", "file_globs",
)


def main():
    rules = [{field: getattr(rule, field) for field in _FIELDS} for rule in DEFAULT_DETECTION_RULES]
    payload = json.dumps(rules, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    print("sha256:" + hashlib.sha256(payload).hexdigest())


if __name__ == "__main__":
    main()
