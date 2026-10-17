"""Command line for local scans."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import webbrowser
from pathlib import Path

from insidia import version_text
from insidia.config import (
    init_config,
    init_destination,
    load_project,
    prepare_init_kind,
    prepare_init_url,
)
from insidia.doctor import diagnose
from insidia.engines import install, list_engines
from insidia.errors import CliError, ConfigError
from insidia.mcp import serve
from insidia.policy import POLICIES, get_policy
from insidia.runstore import latest_run, read_manifest, verdict_text
from insidia.scan import execute
from insidia.ui import InstallView, ScanView, Terminal

_HELP = """\
global options, before or after the command:
  --config PATH   file to read (default: insidia.yaml)
  --json          print a JSON object instead of text
  --yes           do not ask before scanning a host other than localhost, 127.0.0.1, or ::1
  --quiet, -q     print only the result
  --no-color      plain text, no color
"""


def _global_options(parser: argparse.ArgumentParser, after_command: bool) -> None:
    # After the command the defaults are suppressed, so a value given before it survives.
    def default(value: object) -> object:
        return argparse.SUPPRESS if after_command else value

    parser.add_argument(
        "--json",
        action="store_true",
        default=default(False),
        help="print a JSON object instead of text",
    )
    parser.add_argument(
        "--yes",
        action="store_true",
        default=default(False),
        help="do not ask before scanning a host other than localhost, 127.0.0.1, or ::1",
    )
    parser.add_argument(
        "--config",
        default=default("insidia.yaml"),
        help="file to read (default: insidia.yaml)",
    )
    parser.add_argument(
        "--quiet",
        "-q",
        action="store_true",
        default=default(False),
        help="print only the result",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        default=default(False),
        help="plain text, no color",
    )


class _Version(argparse.Action):
    def __call__(
        self,
        parser: argparse.ArgumentParser,
        namespace: argparse.Namespace,
        values: object,
        option_string: str | None = None,
    ) -> None:
        print(version_text())
        parser.exit()


def main(argv: list[str] | None = None) -> int:
    shared = argparse.ArgumentParser(add_help=False)
    _global_options(shared, after_command=True)

    parser = argparse.ArgumentParser(
        prog="insidia",
        description="Test an AI app and the API around it. Settings live in insidia.yaml.",
        epilog=_HELP,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    _global_options(parser, after_command=False)
    parser.add_argument(
        "--version", action=_Version, nargs=0, help="print the version and build commit"
    )
    subcommands = parser.add_subparsers(
        dest="command",
        required=True,
        title="commands",
        metavar="COMMAND",
    )
    init = subcommands.add_parser(
        "init",
        parents=[shared],
        help="write insidia.yaml in this directory",
        description=(
            "Write insidia.yaml in this directory. "
            "Pass --url to set targets.app.url. Refuses to overwrite an existing file."
        ),
    )
    init.add_argument("--url", help="app URL to write as targets.app.url (local hosts only)")
    init.add_argument(
        "--kind",
        help="target kind (default: chat when the URL path ends with /chat)",
    )
    subcommands.add_parser(
        "doctor",
        parents=[shared],
        help="check Python, the config file, and installed engines",
        description="Check Python, the config file, and installed engines.",
    )

    engines = subcommands.add_parser(
        "engines",
        parents=[shared],
        help="list engines or install the ones you name",
        description="List engines or install the ones you name.",
    )
    engine_commands = engines.add_subparsers(dest="engine_command", title="commands")
    engine_commands.add_parser(
        "list",
        parents=[shared],
        help="show each engine, its license, and whether it is installed",
    )
    install_parser = engine_commands.add_parser(
        "install",
        parents=[shared],
        help="install the named engines",
        description="Install the named engines. With no names, built-in probes stay as they are.",
    )
    install_parser.add_argument("names", nargs="*", metavar="ENGINE", help="engine to install")
    install_parser.add_argument(
        "--docker",
        action="store_true",
        help="check that Docker is installed; engine images are not in this release",
    )
    install_parser.add_argument(
        "--allow-unverified",
        action="store_true",
        help="install a downloaded binary that has no pinned SHA-256 for this platform",
    )

    policy = subcommands.add_parser(
        "policy",
        parents=[shared],
        help="list, show, or validate a scan policy",
        description="List, show, or validate a scan policy. L1 is the policy a scan can run.",
    )
    policy_commands = policy.add_subparsers(dest="policy_command", required=True, title="commands")
    policy_commands.add_parser(
        "list",
        parents=[shared],
        help="show which policy names exist and which can run",
    )
    show = policy_commands.add_parser(
        "show",
        parents=[shared],
        help="print one policy and the checks it names",
    )
    show.add_argument("name", help="policy name, such as L1")
    policy_commands.add_parser(
        "validate",
        parents=[shared],
        help="check the policy named in the config file",
    )

    scan = subcommands.add_parser(
        "scan",
        parents=[shared],
        help="run the checks in the config file and write a report",
        description="Run the checks in the config file and write a report.",
    )
    scan.add_argument(
        "--policy",
        choices=sorted(POLICIES),
        help="policy to run (default: the policy in the config file). Only L1 runs.",
    )
    scan.add_argument(
        "--coverage",
        choices=("standard", "thorough"),
        help="how many engines run per check (default: the coverage in the config file)",
    )
    scan.add_argument(
        "--open",
        action="store_true",
        help="open the report in a browser when the scan finishes (default: print its path)",
    )

    report = subcommands.add_parser(
        "report",
        parents=[shared],
        help="print or open the HTML report from a run",
        description="Print or open the HTML report from a run.",
    )
    report.add_argument("run_id", nargs="?", help="run to open (default: the latest run)")
    report.add_argument("--open", action="store_true", help="open the report in a browser")
    rerun = subcommands.add_parser(
        "rerun",
        parents=[shared],
        help="scan again with the policy and config recorded for a run",
        description="Scan again with the policy and config recorded for a run.",
    )
    rerun.add_argument("run_id", nargs="?", help="run to repeat (default: the latest run)")
    mcp = subcommands.add_parser(
        "mcp",
        parents=[shared],
        help="serve local MCP tools on stdin and stdout",
        description=(
            "Serve local MCP tools on stdin and stdout. "
            "The tools read insidia.yaml and do not take a URL. "
            "A non-local scope runs only with --allow-remote or INSIDIA_MCP_ALLOW_REMOTE=1."
        ),
    )
    mcp.add_argument(
        "--allow-remote",
        action="store_true",
        help="allow a scan whose scope names a host other than localhost",
    )

    args = parser.parse_args(argv)
    try:
        return _run(args)
    except CliError as exc:
        _emit(args.json, {"error": str(exc)}, str(exc))
        return exc.code
    except KeyboardInterrupt:
        _emit(args.json, {"error": "cancelled"}, "Cancelled.")
        return 130


def _run(args: argparse.Namespace) -> int:
    if args.command == "init":
        url = args.url
        kind = args.kind
        destination = init_destination(Path(args.config))
        if destination.exists():
            raise ConfigError(f"{destination} already exists")
        if url is not None:
            prepare_init_url(url)
        if kind is not None:
            prepare_init_kind(url or "http://127.0.0.1:8080/chat", kind)
        _progress(args, f"Writing {destination}.")
        path = init_config(Path(args.config), url=url, kind=kind)
        written = url or "http://127.0.0.1:8080/chat"
        document: dict[str, object] = {"wrote": path.name, "url": written}
        text = f"Wrote {path.name} with targets.app.url {written}."
        if url is None:
            document["next"] = "Set targets.app.url to your app before you scan."
            text += (
                " Set targets.app.url to your app before you scan. "
                "Example: insidia init --url http://127.0.0.1:PORT/path"
            )
        _emit(args.json, document, text)
        return 0
    if args.command == "doctor":
        _progress(args, "Checking Python, the config file, and installed engines.")
        checks, code = diagnose(Path(args.config))
        lines = [_doctor_line(check) for check in checks]
        _emit(args.json, {"checks": checks}, "\n".join(lines))
        return code
    if args.command == "engines" and args.engine_command in {None, "list"}:
        engines = list_engines()
        lines = []
        for item in engines:
            state = "installed" if item["installed"] else "not installed"
            if "note" in item:
                state = f"downloaded, {item['note']}"
            lines.append(f"{item['name']} {item['license']} {state}")
        _emit(args.json, {"engines": engines}, "\n".join(lines))
        return 0
    if args.command == "engines" and args.engine_command == "install":
        terminal = _terminal(args)
        message = install(
            tuple(args.names),
            docker=args.docker,
            progress=InstallView(terminal),
            allow_unverified=args.allow_unverified,
        )
        _emit(args.json, {"message": message}, message)
        return 0
    if args.command == "policy" and args.policy_command == "list":
        rows = [{"name": name, "available": name == "L1"} for name in POLICIES]
        lines = [
            f"{row['name']} {'available' if row['available'] else 'unavailable'}" for row in rows
        ]
        _emit(args.json, {"policies": rows}, "\n".join(lines))
        return 0
    if args.command == "policy" and args.policy_command == "show":
        policy = get_policy(args.name)
        controls = [control.family for control in policy.controls]
        available = policy.name == "L1"
        summary = policy.summary if available else f"{policy.summary} Not available yet."
        _emit(
            args.json,
            {
                "name": policy.name,
                "summary": summary,
                "available": available,
                "controls": controls,
            },
            f"{policy.name}: {summary}",
        )
        return 0
    if args.command == "policy" and args.policy_command == "validate":
        project = load_project(Path(args.config))
        get_policy(project.policy)
        if project.policy != "L1":
            raise CliError(f"policy {project.policy} is not available. Use L1.")
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
        opened = bool(getattr(args, "open", False)) and not args.json and _open(report_path)
        text = scan_message(
            policy_name,
            outcome.passed,
            len(outcome.findings),
            str(report_path),
            opened,
            execution_status=outcome.execution_status,
            policy_verdict=outcome.policy_verdict or None,
            untested=outcome.untested,
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
                untested=outcome.untested,
            ),
        }
        if outcome.notes:
            document["notes"] = list(outcome.notes)
            text = text + "\n" + "\n".join(outcome.notes)
        _emit(args.json, document, text)
        return outcome.exit_code()
    if args.command == "rerun":
        return _rerun(args)
    if args.command == "report":
        directory = _run_dir(args.run_id, args.config)
        read_manifest(directory)
        report_path = directory / "report.html"
        if not report_path.is_file():
            raise CliError(f"run {directory.name} has no report")
        if not args.open:
            _emit(args.json, {"report": str(report_path)}, str(report_path))
            return 0
        opened = _open(report_path)
        text = (
            f"Opened {report_path}."
            if opened
            else f"No browser could be opened here. The report is at {report_path}."
        )
        _emit(args.json, {"report": str(report_path), "opened": opened}, text)
        return 0
    if args.command == "mcp":
        return serve(sys.stdin.buffer, sys.stdout.buffer, allow_remote=args.allow_remote)
    raise CliError(f"unknown command {args.command}")


def _rerun(args: argparse.Namespace) -> int:
    directory = _run_dir(args.run_id, args.config)
    manifest = read_manifest(directory)
    if manifest is None:
        raise CliError(f"run {directory.name} has no manifest, so it cannot be rerun")
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
    execution_status: str = "complete",
    policy_verdict: str | None = None,
    untested: int = 0,
) -> str:
    head = verdict_text(
        policy,
        passed,
        findings,
        execution_status=execution_status,
        policy_verdict=policy_verdict,
        untested=untested,
    )
    if opened:
        return f"{head} Opened {report}."
    return f"{head} Report: {report}."


def _open(report: Path) -> bool:
    try:
        return bool(webbrowser.open(report.resolve().as_uri()))
    except (OSError, webbrowser.Error):
        return False


def _terminal(args: argparse.Namespace) -> Terminal:
    return Terminal(
        quiet=args.quiet,
        animate=False if args.json else None,
        no_color=args.no_color,
    )


def _progress(args: argparse.Namespace, message: str) -> None:
    _terminal(args).line(message)


def _doctor_line(check: dict[str, object]) -> str:
    mark = ""
    if check.get("required") is not False:
        mark = "✔ " if check["ok"] else "✘ "
    return f"{mark}{check['name']}: {check['detail']}"


def _emit(as_json: bool, document: dict[str, object], text: str) -> None:
    if as_json:
        print(json.dumps(document))
        return
    print(text, file=sys.stdout)
