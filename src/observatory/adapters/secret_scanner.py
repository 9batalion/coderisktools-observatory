"""Adapter for the local OSS CodeRiskTools Secret Scanner CLI."""

import json
import re
import subprocess
from pathlib import Path

from observatory.contracts import ScanResult


class AdapterError(RuntimeError):
    """Raised when the scanner cannot produce a bounded structured result."""


class SecretScannerAdapter:
    scanner_id = "coderisktools-secret-scanner"

    def __init__(self, command=None, ruleset_digest=None, timeout_seconds=120, max_output_bytes=5 * 1024 * 1024):
        self.command = list(command or ["secret-scanner"])
        self.ruleset_digest = ruleset_digest
        self.timeout_seconds = timeout_seconds
        self.max_output_bytes = max_output_bytes
        if not isinstance(ruleset_digest, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", ruleset_digest):
            raise AdapterError("a ruleset digest is required; adapter will not invent provenance")

    def is_available(self):
        try:
            self.version()
            return True
        except AdapterError:
            return False

    def version(self):
        try:
            completed = subprocess.run(
                [*self.command, "--version"],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=self.timeout_seconds,
                shell=False,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise AdapterError("secret scanner version query failed") from exc
        value = completed.stdout.strip()
        if not value or len(value.splitlines()) != 1 or any(ord(char) < 32 or ord(char) == 127 for char in value) or len(value.encode()) > 1024:
            raise AdapterError("secret scanner returned an invalid version")
        return value

    def capabilities(self):
        return {"directory": True, "offline": True, "json": True, "target_execution": False}

    @staticmethod
    def _relative_finding_paths(findings, target_path):
        root = Path(target_path)
        normalized = []
        for finding in findings:
            if not isinstance(finding, dict) or not isinstance(finding.get("file"), str):
                normalized.append(finding)
                continue
            candidate = Path(finding["file"])
            if candidate.is_absolute():
                try:
                    finding = dict(finding)
                    finding["file"] = candidate.relative_to(root).as_posix()
                except ValueError:
                    pass
            normalized.append(finding)
        return normalized
    def scan(self, target_path, target_sha):
        scanner_version: str = self.version()
        command = [
            *self.command,
            "scan", "--dir", str(target_path), "--recursive", "--format", "json",
            "--profile", "secrets-only", "--no-config-check",
        ]
        try:
            completed = subprocess.run(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=self.timeout_seconds,
                shell=False,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise AdapterError("secret scanner execution failed") from exc
        stdout_bytes = completed.stdout.encode("utf-8", "replace")
        stderr_bytes = completed.stderr.encode("utf-8", "replace")
        if len(stdout_bytes) > self.max_output_bytes or len(stderr_bytes) > self.max_output_bytes:
            raise AdapterError("secret scanner output limit exceeded")
        try:
            payload = json.loads(completed.stdout)
        except (TypeError, ValueError) as exc:
            raise AdapterError("secret scanner returned invalid JSON") from exc
        if not isinstance(payload, dict) or not isinstance(payload.get("findings"), list):
            raise AdapterError("secret scanner JSON has no findings array")
        if completed.returncode not in (0, 1):
            return ScanResult(
                self.scanner_id, scanner_version, self.ruleset_digest, target_sha,
                "failed", [], [f"scanner_exit_{completed.returncode}"], [],
            )
        warnings = []
        summary = payload.get("summary")
        if isinstance(summary, dict) and summary.get("baseline_stale"):
            warnings.append("scanner_baseline_stale")
        return ScanResult(
            self.scanner_id,
            scanner_version,
            self.ruleset_digest,
            target_sha,
            "complete",
            self._relative_finding_paths(payload["findings"], target_path),
            [],
            warnings,
        )
