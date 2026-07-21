"""Command-line interface for the local Observatory runner."""

import argparse
import json
from pathlib import Path
import shlex
import sys
import tempfile

from observatory.adapters.secret_scanner import SecretScannerAdapter
from observatory.reporting.runner import run_pipeline
from observatory.verification.bundle import verify_bundle


def build_parser():
    parser = argparse.ArgumentParser(prog="observatory", description="OSS-only local repository risk observatory")
    parser.add_argument("--offline", action="store_true", help="Reject network repository URLs")
    parser.add_argument("--verbose", action="store_true", help="Include diagnostic errors on stderr")
    subparsers = parser.add_subparsers(dest="command", required=True)
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
