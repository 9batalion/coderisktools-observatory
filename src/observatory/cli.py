"""Command-line interface for the local Observatory runner."""

import argparse
from dataclasses import asdict
import json
from pathlib import Path
import shlex
import sys
import tempfile

from observatory.adapters.secret_scanner import SecretScannerAdapter
from observatory.acquisition.clone import acquire_repository
from observatory.contracts import NormalizedFinding, ScanResult, Target
from observatory.normalization.findings import normalize_scanner_findings
from observatory.policy.engine import evaluate_publication
from observatory.reporting.runner import run_pipeline
from observatory.target_registry import add_target
from observatory.verification.bundle import verify_bundle


def build_parser():
    parser = argparse.ArgumentParser(prog="observatory", description="OSS-only local repository risk observatory")
    parser.add_argument("--offline", action="store_true", help="Reject network repository URLs")
    parser.add_argument("--verbose", action="store_true", help="Include diagnostic errors on stderr")
    subparsers = parser.add_subparsers(dest="command", required=True)
    acquire = subparsers.add_parser("acquire", help="Acquire a repository at an exact SHA")
    acquire.add_argument("--source", required=True)
    acquire.add_argument("--sha", required=True)
    acquire.add_argument("--workspace", type=Path, required=True)
    acquire.add_argument("--json", action="store_true")
    normalize = subparsers.add_parser("normalize", help="Normalize a redacted scanner JSON result")
    normalize.add_argument("--input", type=Path, required=True)
    normalize.add_argument("--sha", required=True)
    normalize.add_argument("--scanner-id", required=True)
    normalize.add_argument("--output", type=Path, required=True)
    decide = subparsers.add_parser("decide", help="Evaluate fail-closed publication policy")
    decide.add_argument("--scan", type=Path, required=True)
    decide.add_argument("--findings", type=Path, required=True)
    decide.add_argument("--license-status", choices=["recognized", "unknown", "restricted"], required=True)
    decide.add_argument("--output", type=Path, required=True)
    target = subparsers.add_parser("target", help="Manage the append-only target registry")
    target_commands = target.add_subparsers(dest="target_command", required=True)
    target_add = target_commands.add_parser("add", help="Record an exact-SHA target")
    target_add.add_argument("--repository-url", required=True)
    target_add.add_argument("--ref", required=True)
    target_add.add_argument("--sha", required=True)
    target_add.add_argument("--registry", type=Path, required=True)
    target_add.add_argument("--license-status", choices=["recognized", "unknown", "restricted"], default="unknown")
    target_add.add_argument("--publication-mode", choices=["public-summary", "maintainer-only", "embargoed", "redacted"], default="public-summary")
    target_add.add_argument("--json", action="store_true")
    scan = subparsers.add_parser("scan", help="Acquire an exact SHA, scan it and build a report bundle")
    scan.add_argument("--source", required=True, help="Local repository path or HTTPS GitHub URL")
    scan.add_argument("--sha", required=True, help="Full 40-character lowercase commit SHA")
    scan.add_argument("--repository-url", required=True, help="Canonical public GitHub repository URL")
    scan.add_argument("--license-status", choices=["recognized", "unknown", "restricted"], default="unknown")
    scan.add_argument("--output", required=True, type=Path, help="Report output directory")
    scan.add_argument("--workspace", type=Path, help="Temporary acquisition workspace")
    scan.add_argument("--ruleset-digest", required=True, help="SHA-256 digest of the scanner ruleset")
    scan.add_argument("--scanner-command", default="secret-scanner", help="Scanner executable and fixed arguments")
    scan.add_argument("--json", action="store_true", help="Print machine-readable result summary")
    verify = subparsers.add_parser("verify", help="Verify report manifest, hashes and bundle paths")
    verify.add_argument("bundle", type=Path, help="Report bundle directory")
    verify.add_argument("--json", action="store_true", help="Print machine-readable verification result")
    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "decide":
        temporary = args.output.with_name(args.output.name + ".tmp")
        try:
            if args.scan.stat().st_size > 5 * 1024 * 1024 or args.findings.stat().st_size > 5 * 1024 * 1024:
                raise ValueError("decision input limit exceeded")
            scan = ScanResult.from_dict(json.loads(args.scan.read_text(encoding="utf-8")))
            raw_findings = json.loads(args.findings.read_text(encoding="utf-8"))
            if not isinstance(raw_findings, list):
                raise ValueError("findings JSON must be an array")
            findings = [NormalizedFinding.from_dict(item) for item in raw_findings]
            if any(finding.location["commit"] != scan.target_sha for finding in findings):
                raise ValueError("finding SHA does not match scan target SHA")
            decision = evaluate_publication(scan.status, args.license_status, findings, scan.errors)
            temporary.parent.mkdir(parents=True, exist_ok=True)
            temporary.write_text(json.dumps(asdict(decision), ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
            temporary.replace(args.output)
        except Exception as exc:
            temporary.unlink(missing_ok=True)
            if args.verbose:
                print(f"observatory: decision failed: {type(exc).__name__}", file=sys.stderr)
            return 3
        return 0
    if args.command == "normalize":
        temporary = args.output.with_name(args.output.name + ".tmp")
        try:
            if args.input.stat().st_size > 5 * 1024 * 1024:
                raise ValueError("scanner JSON input limit exceeded")
            payload = json.loads(args.input.read_text(encoding="utf-8"))
            if not isinstance(payload, dict) or not isinstance(payload.get("findings"), list):
                raise ValueError("scanner JSON must contain a findings array")
            findings = normalize_scanner_findings(payload["findings"], args.sha, args.scanner_id)
            temporary.parent.mkdir(parents=True, exist_ok=True)
            temporary.write_text(json.dumps([asdict(item) for item in findings], ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
            temporary.replace(args.output)
        except Exception as exc:
            temporary.unlink(missing_ok=True)
            if args.verbose:
                print(f"observatory: normalization failed: {type(exc).__name__}", file=sys.stderr)
            return 3
        return 0
    if args.command == "acquire":
        try:
            result = acquire_repository(args.source, args.sha, args.workspace)
        except Exception as exc:
            if args.verbose:
                print(f"observatory: {exc}", file=sys.stderr)
            return 3
        payload = {
            "path": str(result.path),
            "resolved_sha": result.resolved_sha,
            "file_count": result.file_count,
            "total_bytes": result.total_bytes,
        }
        print(json.dumps(payload, sort_keys=True) if args.json else f"ACQUIRED: {payload['resolved_sha']} -> {payload['path']}")
        return 0
    if args.command == "target":
        if args.target_command != "add":
            parser.error("unsupported target command")
        try:
            canonical_url = args.repository_url.rstrip("/")
            target = Target.from_dict({
                "target_id": canonical_url.removeprefix("https://github.com/").replace("/", "-"),
                "repository_url": canonical_url,
                "requested_ref": args.ref,
                "resolved_sha": args.sha,
                "source": "operator",
                "selection_reason": "explicit exact SHA supplied by operator",
                "license_status": args.license_status,
                "execution_allowed": False,
                "publication_mode": args.publication_mode,
                "status": "candidate",
            })
            add_target(args.registry, target)
        except Exception as exc:
            if args.verbose:
                print(f"observatory: {exc}", file=sys.stderr)
            return 3
        payload = asdict(target)
        print(json.dumps(payload, sort_keys=True) if args.json else f"ADDED: {target.target_id}@{target.resolved_sha}")
        return 0
    if args.command == "verify":
        result = verify_bundle(args.bundle)
        payload = {"valid": result.valid, "errors": result.errors, "checked_files": result.checked_files}
        print(json.dumps(payload, sort_keys=True) if args.json else ("VALID" if result.valid else "INVALID"))
        return 0 if result.valid else 2
    if args.command != "scan":
        parser.error("unsupported command")
    source = str(args.source)
    if args.offline and (source.startswith("http://") or source.startswith("https://")):
        parser.error("--offline accepts only a local source path")
    workspace_context = tempfile.TemporaryDirectory() if args.workspace is None else None
    workspace = args.workspace or Path(workspace_context.name)
    try:
        adapter = SecretScannerAdapter(shlex.split(args.scanner_command), args.ruleset_digest)
        result = run_pipeline(source, args.sha, workspace, args.output, args.repository_url, args.license_status, adapter)
    except Exception as exc:
        if args.verbose:
            print(f"observatory: {exc}", file=sys.stderr)
        return 3
    finally:
        if workspace_context is not None:
            workspace_context.cleanup()
    summary = {
        "target_sha": result.target.resolved_sha,
        "scan_status": result.scan.status,
        "finding_count": len(result.findings),
        "decision": result.decision.decision,
        "output": str(args.output),
    }
    print(json.dumps(summary, sort_keys=True) if args.json else f"{summary['decision']}: {summary['output']}")
    return 0 if result.decision.decision == "PUBLISH" else 2
