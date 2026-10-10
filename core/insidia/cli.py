"""Command line for local scans."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import webbrowser
from pathlib import Path

from insidia.config import init_config, load_project
from insidia.doctor import diagnose
from insidia.engines import install, list_engines
from insidia.errors import CliError
from insidia.mcp import serve
from insidia.policy import POLICIES, get_policy
from insidia.runstore import latest_run, verdict_text
from insidia.scan import execute
from insidia.ui import InstallView, ScanView, Terminal


def main(argv: list[str] | None = None) -> int:
    shared = argparse.ArgumentParser(add_help=False)
    shared.add_argument("--json", action="store_true")
    shared.add_argument("--yes", action="store_true")
    shared.add_argument("--config", default="insidia.yaml")
    shared.add_argument("--quiet", "-q", action="store_true", help="print only the result")
    shared.add_argument("--no-color", action="store_true", help="plain text, no color")

    parser = argparse.ArgumentParser(prog="insidia")
    subcommands = parser.add_subparsers(dest="command", required=True)
    subcommands.add_parser("init", parents=[shared])
    subcommands.add_parser("doctor", parents=[shared])

    engines = subcommands.add_parser("engines", parents=[shared])
    engine_commands = engines.add_subparsers(dest="engine_command", required=True)
    engine_commands.add_parser("list")
    install_parser = engine_commands.add_parser("install")
    install_parser.add_argument("names", nargs="*", metavar="ENGINE")
    install_parser.add_argument("--docker", action="store_true")

    policy = subcommands.add_parser("policy", parents=[shared])
    policy_commands = policy.add_subparsers(dest="policy_command", required=True)
    policy_commands.add_parser("list")
    show = policy_commands.add_parser("show")
    show.add_argument("name")
    policy_commands.add_parser("validate")

    scan = subcommands.add_parser("scan", parents=[shared])
    scan.add_argument("--policy", choices=sorted(POLICIES))
    scan.add_argument("--coverage", choices=("standard", "thorough"))

    report = subcommands.add_parser("report", parents=[shared])
    report.add_argument("run_id", nargs="?")
    report.add_argument("--open", action="store_true")
    rerun = subcommands.add_parser("rerun", parents=[shared])
    rerun.add_argument("run_id", nargs="?")
    subcommands.add_parser("mcp", parents=[shared])

    args = parser.parse_args(argv)
    try:
        return _run(args)
    except CliError as exc:
        _emit(args.json, {"error": str(exc)}, str(exc))
        return exc.code


def _run(args: argparse.Namespace) -> int:
    if args.command == "init":
        _progress(args, "Writing insidia.yaml in this directory.")
        path = init_config(Path.cwd())
        _emit(args.json, {"wrote": path.name}, f"Wrote {path.name}.")
        return 0
    if args.command == "doctor":
        _progress(args, "Checking Python, the config file, and installed engines.")
        checks, code = diagnose(Path(args.config))
        lines = [f"{check['name']}: {check['detail']}" for check in checks]
        _emit(args.json, {"checks": checks}, "\n".join(lines))
        return code
    if args.command == "engines" and args.engine_command == "list":
        engines = list_engines()
        lines = []
        for item in engines:
            state = "installed" if item["installed"] else "not installed"
            lines.append(f"{item['name']} {item['license']} {state}")
        _emit(args.json, {"engines": engines}, "\n".join(lines))
        return 0
    if args.command == "engines" and args.engine_command == "install":
        terminal = _terminal(args)
        message = install(tuple(args.names), docker=args.docker, progress=InstallView(terminal))
        _emit(args.json, {"message": message}, message)
        return 0
    if args.command == "policy" and args.policy_command == "list":
        names = list(POLICIES)
        _emit(args.json, {"policies": names}, "\n".join(names))
        return 0
    if args.command == "policy" and args.policy_command == "show":
        policy = get_policy(args.name)
        controls = [control.family for control in policy.controls]
        _emit(
            args.json,
            {"name": policy.name, "summary": policy.summary, "controls": controls},
            f"{policy.name}: {policy.summary}",
        )
        return 0
    if args.command == "policy" and args.policy_command == "validate":
        project = load_project(Path(args.config))
        get_policy(project.policy)
        _emit(args.json, {"policy": project.policy, "valid": True}, f"{project.policy} is valid")
        return 0
    if args.command == "scan":
        config = Path(args.config)
        project = load_project(config)
        terminal = _terminal(args)
        view = ScanView(terminal)
        outcome = execute(
            project,
            config.resolve().parent,
            policy_name=args.policy,
            coverage=args.coverage,
            assume_yes=args.yes,
            progress=view,
        )
        terminal.line(terminal.dim(view.totals()))
        report_path = outcome.run_dir / "report.html"
        policy_name = args.policy if args.policy is not None else project.policy
        opened = False
        if not args.json:
            try:
                opened = bool(webbrowser.open(report_path.resolve().as_uri()))
            except OSError:
                opened = False
        text = scan_message(
            policy_name,
            outcome.passed,
            len(outcome.findings),
            str(report_path),
            opened,
            execution_status=outcome.execution_status,
            policy_verdict=outcome.policy_verdict or None,
        )
        document = {
            "schema_version": "2.0",
            "run_id": outcome.run_id,
            "passed": outcome.passed,
            "execution_status": outcome.execution_status,
            "policy_verdict": outcome.policy_verdict or ("pass" if outcome.passed else "fail"),
            "findings": [finding.as_json() for finding in outcome.findings],
            "skips": outcome.skips,
            "run_dir": str(outcome.run_dir),
            "report": str(report_path),
            "summary": scan_message(
                policy_name,
                outcome.passed,
                len(outcome.findings),
                str(report_path),
                False,
                execution_status=outcome.execution_status,
                policy_verdict=outcome.policy_verdict or None,
            ),
        }
        _emit(args.json, document, text)
        return outcome.exit_code()
    if args.command == "rerun":
        return _rerun(args)
    if args.command == "report":
        directory = _run_dir(args.run_id, args.config)
        report_path = directory / "report.html"
        if not report_path.is_file():
            raise CliError(f"run {directory.name} has no report")
        if args.open:
            webbrowser.open(report_path.resolve().as_uri())
        _emit(args.json, {"report": str(report_path)}, str(report_path))
        return 0
    if args.command == "mcp":
        return serve(sys.stdin.buffer, sys.stdout.buffer)
    raise CliError(f"unknown command {args.command}")


def _rerun(args: argparse.Namespace) -> int:
    directory = _run_dir(args.run_id, args.config)
    manifest_path = directory / "manifest.json"
    if not manifest_path.is_file():
        raise CliError(f"run {directory.name} has no manifest, so it cannot be rerun")
    manifest = json.loads(manifest_path.read_text())
    if not isinstance(manifest, dict):
        raise CliError(f"run {directory.name} has an unreadable manifest")
    project = load_project(Path(args.config))
    digest = hashlib.sha256(project.path.read_bytes()).hexdigest()
    recorded = manifest.get("config_digest")
    if not isinstance(recorded, str) or not recorded:
        raise CliError(f"run {directory.name} does not record its configuration")
    if recorded != digest and not args.yes:
        raise CliError("configuration changed since that run; pass --yes to scan the current file")
    policy = manifest.get("policy")
    if policy != "L1":
        raise CliError(f"run used policy {policy}, which is not available. Use L1.")
    coverage = manifest.get("coverage")
    if coverage not in {"standard", "thorough"}:
        raise CliError(f"run {directory.name} does not record its coverage")
    args.policy = "L1"
    args.coverage = coverage
    args.command = "scan"
    return _run(args)


def _run_dir(run_id: str | None, config: str) -> Path:
    root = Path(config).resolve().parent
    if run_id:
        directory = root / ".insidia" / "runs" / run_id
        if not directory.is_dir():
            raise CliError(f"no run {run_id}")
        return directory
    latest = latest_run(root)
    if latest is None:
        raise CliError("no runs yet")
    return latest


def scan_message(
    policy: str,
    passed: bool,
    findings: int,
    report: str,
    opened: bool,
    *,
    execution_status: str = "complete",
    policy_verdict: str | None = None,
) -> str:
    head = verdict_text(
        policy,
        passed,
        findings,
        execution_status=execution_status,
        policy_verdict=policy_verdict,
    )
    if opened:
        return f"{head} Opened {report}."
    return f"{head} Report: {report}."


def _terminal(args: argparse.Namespace) -> Terminal:
    return Terminal(
        quiet=args.quiet,
        animate=False if args.json else None,
        no_color=args.no_color,
    )


def _progress(args: argparse.Namespace, message: str) -> None:
    _terminal(args).line(message)


def _emit(as_json: bool, document: dict[str, object], text: str) -> None:
    if as_json:
        print(json.dumps(document))
        return
    print(text, file=sys.stdout)
