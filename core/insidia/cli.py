"""Command line for local scans."""

from __future__ import annotations

import argparse
import json
import sys
import webbrowser
from pathlib import Path

from insidia.config import init_config, load_project
from insidia.doctor import diagnose
from insidia.engines import install, list_engines
from insidia.errors import CliError
from insidia.policy import POLICIES, get_policy
from insidia.runstore import latest_run
from insidia.scan import execute


def main(argv: list[str] | None = None) -> int:
    shared = argparse.ArgumentParser(add_help=False)
    shared.add_argument("--json", action="store_true")
    shared.add_argument("--yes", action="store_true")
    shared.add_argument("--config", default="insidia.yaml")

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

    args = parser.parse_args(argv)
    try:
        return _run(args)
    except CliError as exc:
        _emit(args.json, {"error": str(exc)}, str(exc))
        return exc.code


def _run(args: argparse.Namespace) -> int:
    if args.command == "init":
        path = init_config(Path.cwd())
        _emit(args.json, {"wrote": path.name}, f"wrote {path.name}")
        return 0
    if args.command == "doctor":
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
        message = install(tuple(args.names), docker=args.docker)
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
        outcome = execute(
            project,
            config.resolve().parent,
            policy_name=args.policy,
            coverage=args.coverage,
            assume_yes=args.yes,
        )
        document = {
            "run_id": outcome.run_id,
            "passed": outcome.passed,
            "findings": [finding.as_json() for finding in outcome.findings],
            "skips": outcome.skips,
            "run_dir": str(outcome.run_dir),
        }
        text = f"{outcome.run_id}: {'passed' if outcome.passed else 'failed'}"
        _emit(args.json, document, text)
        return 0 if outcome.passed else 1
    if args.command == "report":
        directory = _run_dir(args.run_id, args.config)
        report_path = directory / "report.html"
        if args.open:
            webbrowser.open(report_path.resolve().as_uri())
        _emit(args.json, {"report": str(report_path)}, str(report_path))
        return 0
    raise CliError(f"unknown command {args.command}")


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


def _emit(as_json: bool, document: dict[str, object], text: str) -> None:
    if as_json:
        print(json.dumps(document))
        return
    print(text, file=sys.stdout)
