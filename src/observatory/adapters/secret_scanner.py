"""Adapter for the local OSS CodeRiskTools Secret Scanner CLI."""

from dataclasses import dataclass
import json
import re
import subprocess
from pathlib import Path

from observatory.contracts import ScanResult


class AdapterError(RuntimeError):
    """Raised when the scanner cannot produce a bounded structured result."""


@dataclass(frozen=True)
class ScanProfile:
    """Resource limits for a repository-size class."""

    name: str
    timeout_seconds: float
    max_output_bytes: int
    max_files: int
    max_bytes: int


_PROFILES = {
    "small": ScanProfile("small", 120.0, 5 * 1024 * 1024, 10_000, 250 * 1024 * 1024),
    "medium": ScanProfile("medium", 600.0, 20 * 1024 * 1024, 100_000, 2 * 1024 * 1024 * 1024),
    "large": ScanProfile("large", 1_800.0, 50 * 1024 * 1024, 500_000, 10 * 1024 * 1024 * 1024),
    "huge": ScanProfile("huge", 3_600.0, 100 * 1024 * 1024, 2_000_000, 50 * 1024 * 1024 * 1024),
}


class SecretScannerAdapter:
    scanner_id = "coderisktools-secret-scanner"

    def __init__(self, command=None, ruleset_digest=None, timeout_seconds=None, max_output_bytes=None, profile="auto"):
        self.command = list(command or ["secret-scanner"])
        self.ruleset_digest = ruleset_digest
        self.profile_name = profile
        self._timeout_override = timeout_seconds
        self._output_override = max_output_bytes
        self.active_profile = "small"
        self.timeout_seconds = float(timeout_seconds) if timeout_seconds is not None else _PROFILES["small"].timeout_seconds
        self.max_output_bytes = int(max_output_bytes) if max_output_bytes is not None else _PROFILES["small"].max_output_bytes
        if profile != "auto" and profile not in _PROFILES:
            raise AdapterError(f"unknown scan profile: {profile}")
        if not isinstance(ruleset_digest, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", ruleset_digest):
            raise AdapterError("a ruleset digest is required; adapter will not invent provenance")

    @staticmethod
    def profile(name):
        if name == "auto":
            raise AdapterError("auto profile requires a target directory")
        try:
            return _PROFILES[name]
        except KeyError as exc:
            raise AdapterError(f"unknown scan profile: {name}") from exc

    @staticmethod
    def profile_for_target(target_path):
        root = Path(target_path)
        file_count = 0
        total_bytes = 0
        for path in root.rglob("*"):
            if path.is_file():
                file_count += 1
                total_bytes += path.stat().st_size
        if file_count <= _PROFILES["small"].max_files and total_bytes <= _PROFILES["small"].max_bytes:
            return _PROFILES["small"]
        if file_count <= _PROFILES["medium"].max_files and total_bytes <= _PROFILES["medium"].max_bytes:
            return _PROFILES["medium"]
        if file_count <= _PROFILES["large"].max_files and total_bytes <= _PROFILES["large"].max_bytes:
            return _PROFILES["large"]
        return _PROFILES["huge"]

    def _apply_profile(self, target_path):
        selected = self.profile(self.profile_name) if self.profile_name != "auto" else self.profile_for_target(target_path)
        self.active_profile = selected.name
        self.timeout_seconds = float(self._timeout_override if self._timeout_override is not None else selected.timeout_seconds)
        self.max_output_bytes = int(self._output_override if self._output_override is not None else selected.max_output_bytes)
        return selected

    def is_available(self):
        try:
            self.version()
            return True
        except AdapterError:
            return False

    def version(self):
        try:
            completed = subprocess.run(
                [*self.command, "--version"], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, timeout=self.timeout_seconds, shell=False,
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
        self._apply_profile(target_path)
        scanner_version: str = self.version()
        command = [*self.command, "scan", "--dir", str(target_path), "--recursive", "--format", "json", "--profile", "secrets-only", "--no-config-check"]
        try:
            completed = subprocess.run(
                command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                timeout=self.timeout_seconds, shell=False,
            )
        except subprocess.TimeoutExpired:
            return ScanResult(self.scanner_id, scanner_version, self.ruleset_digest, target_sha, "failed", [], ["scanner_timeout"], [])
        except (OSError, subprocess.SubprocessError) as exc:
            raise AdapterError("secret scanner execution failed") from exc
        stdout_bytes = completed.stdout.encode("utf-8", "replace")
        stderr_bytes = completed.stderr.encode("utf-8", "replace")
        if len(stdout_bytes) > self.max_output_bytes or len(stderr_bytes) > self.max_output_bytes:
            return ScanResult(self.scanner_id, scanner_version, self.ruleset_digest, target_sha, "failed", [], ["scanner_output_limit"], [])
        try:
            payload = json.loads(completed.stdout)
        except (TypeError, ValueError) as exc:
            raise AdapterError("secret scanner returned invalid JSON") from exc
        if not isinstance(payload, dict) or not isinstance(payload.get("findings"), list):
            raise AdapterError("secret scanner JSON has no findings array")
        if completed.returncode not in (0, 1):
            return ScanResult(self.scanner_id, scanner_version, self.ruleset_digest, target_sha, "failed", [], [f"scanner_exit_{completed.returncode}"], [])
        warnings = []
        summary = payload.get("summary")
        if isinstance(summary, dict) and summary.get("baseline_stale"):
            warnings.append("scanner_baseline_stale")
        return ScanResult(self.scanner_id, scanner_version, self.ruleset_digest, target_sha, "complete", self._relative_finding_paths(payload["findings"], target_path), [], warnings)
