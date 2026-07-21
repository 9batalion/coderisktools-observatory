"""Command-line interface for the local Observatory runner."""

import argparse
from dataclasses import asdict
import json
from pathlib import Path
import shlex
import sys
import tempfile
import time

from observatory.adapters.secret_scanner import SecretScannerAdapter
from observatory.benchmark import benchmark_result_digest, calculate_metrics, calculate_performance, load_manifest, run_benchmark
from observatory.acquisition.clone import acquire_repository
from observatory.contracts import NormalizedFinding, PublicationDecision, ScanResult, Target
from observatory.normalization.findings import normalize_scanner_findings
from observatory.policy.engine import evaluate_publication
from observatory.reporting.builder import ReportModel, build_report_bundle
from observatory.reporting.runner import run_pipeline
from observatory.self_scan import run_self_scan
from observatory.publishing.immutability import verify_immutability
from observatory.publishing.pr import create_publication_pr, prepare_publication
from observatory.publishing.retract import create_retraction_pr, prepare_retraction
from observatory.target_registry import add_target
from observatory.verification.bundle import verify_bundle
from observatory.verification.schema import validate_json_file


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
    report = subparsers.add_parser("report", help="Build a deterministic report bundle")
    report.add_argument("--target", type=Path, required=True)
    report.add_argument("--scan", type=Path, required=True)
    report.add_argument("--findings", type=Path, required=True)
    report.add_argument("--decision", type=Path, required=True)
    report.add_argument("--repository-name", required=True)
    report.add_argument("--output-dir", type=Path, required=True)
    report.add_argument("--limitation", action="append", default=[])
    publish = subparsers.add_parser("publish-pr", help="Stage a verified PUBLISH bundle for a reports PR")
    publish.add_argument("--bundle", type=Path, required=True)
    publish.add_argument("--reports-repo", type=Path, required=True)
    publish.add_argument("--revision", type=int, default=1)
    publish.add_argument("--create-pr", action="store_true", help="Push a branch and create the GitHub PR")
    publish.add_argument("--branch", help="Explicit publication branch")
    publish.add_argument("--title", help="PR title and commit message")
    publish.add_argument("--body", help="PR body")
    publish.add_argument("--remote-repo", help="GitHub owner/repository override")
    retract = subparsers.add_parser("retract", help="Create a fail-closed report retraction record")
    retract.add_argument("--reports-repo", type=Path, required=True)
    retract.add_argument("--repository-url", required=True)
    retract.add_argument("--sha", required=True)
    retract.add_argument("--revision", type=int, default=1)
    retract.add_argument("--reason", required=True)
    retract.add_argument("--timestamp")
    retract.add_argument("--create-pr", action="store_true")
    retract.add_argument("--branch")
    retract.add_argument("--title")
    retract.add_argument("--body")
    retract.add_argument("--remote-repo")
    immutability = subparsers.add_parser("verify-immutability", help="Verify report-tree immutability")
    immutability.add_argument("--base", type=Path, required=True)
    immutability.add_argument("--candidate", type=Path, required=True)
    immutability.add_argument("--paths", type=Path, required=True, help="Newline-separated changed report paths")
    immutability.add_argument("--json", action="store_true")
    schema = subparsers.add_parser("validate-json", help="Validate JSON against a local schema")
    schema.add_argument("--input", type=Path, required=True)
    schema.add_argument("--schema", type=Path, required=True)
    schema.add_argument("--json", action="store_true")
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
    benchmark = subparsers.add_parser("benchmark", help="Run deterministic local scanner/policy benchmark")
    benchmark.add_argument("--manifest", type=Path, default=Path("benchmark/manifest.json"))
    benchmark.add_argument("--ruleset-digest", required=True)
    benchmark.add_argument("--license-status", choices=["recognized", "unknown", "restricted"], default="recognized")
    benchmark.add_argument("--scanner-command", default="secret-scanner")
    benchmark.add_argument("--json", action="store_true")
    self_scan = subparsers.add_parser("self-scan", help="Scan the Observatory source tree without raw evidence output")
    self_scan.add_argument("--path", type=Path, default=Path("."))
    self_scan.add_argument("--ruleset-digest", required=True)
    self_scan.add_argument("--scanner-command", default="secret-scanner")
    self_scan.add_argument("--json", action="store_true")
    verify = subparsers.add_parser("verify", help="Verify report manifest, hashes and bundle paths")
    verify.add_argument("bundle", type=Path, help="Report bundle directory")
    verify.add_argument("--json", action="store_true", help="Print machine-readable verification result")
    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "validate-json":
        try:
            validate_json_file(args.input, args.schema)
        except Exception as exc:
            payload = {"valid": False, "error": str(exc)}
            print(json.dumps(payload, sort_keys=True) if args.json else "INVALID")
            return 2
        payload = {"valid": True, "input": str(args.input), "schema": str(args.schema)}
        print(json.dumps(payload, sort_keys=True) if args.json else "VALID")
        return 0
    if args.command == "verify-immutability":
        try:
            raw_paths = args.paths.read_text(encoding="utf-8").splitlines()
            result = verify_immutability(args.base, args.candidate, raw_paths)
        except Exception as exc:
            result = type("Result", (), {"valid": False, "errors": [str(exc)], "checked_paths": 0})()
        payload = {"valid": result.valid, "errors": result.errors, "checked_paths": result.checked_paths}
        print(json.dumps(payload, sort_keys=True) if args.json else ("VALID" if result.valid else "INVALID"))
        return 0 if result.valid else 2
    if args.command == "retract":
        try:
            if args.create_pr:
                result = create_retraction_pr(
                    args.reports_repo, args.repository_url, args.sha, args.revision,
                    args.reason, args.timestamp, args.branch, args.title, args.body, args.remote_repo,
                )
                print(json.dumps({
                    "created": True, "url": result.url, "branch": result.branch,
                    "commit": result.commit, "path": str(result.plan.path),
                    "target_sha": result.plan.target_sha, "revision": result.plan.revision,
                    "retracted_at": result.plan.retracted_at,
                }, sort_keys=True))
                return 0
            plan = prepare_retraction(
                args.reports_repo, args.repository_url, args.sha, args.revision,
                args.reason, args.timestamp,
            )
        except Exception as exc:
            if args.verbose:
                print(f"observatory: retraction failed: {type(exc).__name__}", file=sys.stderr)
            return 3
        print(json.dumps({
            "staged": True, "path": str(plan.path), "target_sha": plan.target_sha,
            "repository_url": plan.repository_url, "revision": plan.revision,
            "retracted_at": plan.retracted_at,
        }, sort_keys=True))
        return 0
    if args.command == "publish-pr":
        try:
            if args.create_pr:
                result = create_publication_pr(
                    args.reports_repo, args.bundle, args.revision, args.branch,
                    args.title, args.body, args.remote_repo,
                )
                print(json.dumps({
                    "created": True, "url": result.url, "branch": result.branch,
                    "commit": result.commit, "destination": str(result.plan.destination),
                    "target_sha": result.plan.target_sha, "revision": result.plan.revision,
                }, sort_keys=True))
                return 0
            plan = prepare_publication(args.reports_repo, args.bundle, args.revision)
        except Exception as exc:
            if args.verbose:
                print(f"observatory: publication staging failed: {type(exc).__name__}", file=sys.stderr)
            return 3
        print(json.dumps({
            "staged": True,
            "destination": str(plan.destination),
            "target_sha": plan.target_sha,
            "repository_url": plan.repository_url,
            "revision": plan.revision,
            "artifacts": [path.name for path in plan.artifacts],
            "next_step": "create a pull request from the reports repository branch",
        }, sort_keys=True))
        return 0
    if args.command == "report":
        try:
            inputs = (args.target, args.scan, args.findings, args.decision)
            if any(path.stat().st_size > 5 * 1024 * 1024 for path in inputs):
                raise ValueError("report input limit exceeded")
            target = Target.from_dict(json.loads(args.target.read_text(encoding="utf-8")))
            scan = ScanResult.from_dict(json.loads(args.scan.read_text(encoding="utf-8")))
            raw_findings = json.loads(args.findings.read_text(encoding="utf-8"))
            if not isinstance(raw_findings, list):
                raise ValueError("findings JSON must be an array")
            findings = [NormalizedFinding.from_dict(item) for item in raw_findings]
            decision = PublicationDecision.from_dict(json.loads(args.decision.read_text(encoding="utf-8")))
            if target.resolved_sha != scan.target_sha:
                raise ValueError("target SHA does not match scan SHA")
            if any(item.location["commit"] != target.resolved_sha for item in findings):
                raise ValueError("finding SHA does not match target SHA")
            limitations = args.limitation or [
                "The report pipeline does not execute analyzed repository code.",
                "A clean result is evidence, not certification.",
            ]
            model = ReportModel(target, scan, findings, decision, limitations)
            artifacts = build_report_bundle(model, args.output_dir, args.repository_name)
        except Exception as exc:
            if args.verbose:
                print(f"observatory: report failed: {type(exc).__name__}", file=sys.stderr)
            return 3
        print(json.dumps({"output_dir": str(args.output_dir), "artifacts": [path.name for path in artifacts]}, sort_keys=True))
        return 0
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
    if args.command == "self-scan":
        try:
            adapter = SecretScannerAdapter(shlex.split(args.scanner_command), args.ruleset_digest)
            payload = run_self_scan(args.path, adapter, args.ruleset_digest)
        except Exception as exc:
            if args.verbose:
                print(f"observatory: self-scan failed: {type(exc).__name__}", file=sys.stderr)
            return 3
        print(json.dumps(payload, ensure_ascii=False, sort_keys=True) if args.json else f"{payload['decision']}: {payload['finding_count']} findings")
        return 0 if payload["decision"] == "PUBLISH" else 2
    if args.command == "benchmark":
        try:
            manifest = load_manifest(args.manifest)
            started = time.perf_counter()
            adapter = SecretScannerAdapter(shlex.split(args.scanner_command), args.ruleset_digest)
            results = run_benchmark(args.manifest, adapter, args.ruleset_digest, args.license_status)
            elapsed_ms = (time.perf_counter() - started) * 1000
            metrics = calculate_metrics(results, manifest.get("quality"))
            performance = calculate_performance(elapsed_ms, manifest.get("performance"))
        except Exception as exc:
            if args.verbose:
                print(f"observatory: benchmark failed: {type(exc).__name__}", file=sys.stderr)
            return 3
        payload = {"passed": all(item["passed"] for item in results) and metrics["quality_passed"] and performance["performance_passed"], "case_count": len(results), "cases": results, "metrics": metrics, "performance": performance, "result_digest": benchmark_result_digest(results)}
        print(json.dumps(payload, ensure_ascii=False, sort_keys=True) if args.json else ("BENCHMARK PASS" if payload["passed"] else "BENCHMARK FAIL"))
        return 0 if payload["passed"] else 2
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
