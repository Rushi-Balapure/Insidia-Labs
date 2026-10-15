"""Built-in repository checks: secrets, dangerous calls, and pinned vulnerable packages."""

from __future__ import annotations

import json
import re
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

from insidia.mask import find_secret

_SKIP_DIRS = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        ".insidia",
        ".venv",
        "venv",
        ".tox",
        "node_modules",
        "__pycache__",
        ".mypy_cache",
        ".ruff_cache",
        ".pytest_cache",
        "site-packages",
        "dist",
        "build",
    }
)
_MAX_BYTES = 1_000_000
_MAX_FILES = 20_000
_MAX_HITS = 20


@dataclass(frozen=True)
class RepoHit:
    rule: str
    line: str
    evidence: str
    location: str


@dataclass(frozen=True)
class RepoResult:
    hits: tuple[RepoHit, ...]
    untested: str


def _files(root: Path) -> Iterator[Path]:
    seen = 0
    stack = [root]
    while stack:
        folder = stack.pop()
        try:
            entries = sorted(folder.iterdir())
        except OSError:
            continue
        for entry in entries:
            if entry.is_symlink():
                continue
            if entry.is_dir():
                if entry.name not in _SKIP_DIRS:
                    stack.append(entry)
                continue
            if not entry.is_file():
                continue
            seen += 1
            if seen > _MAX_FILES:
                return
            yield entry


def _text(path: Path) -> str | None:
    try:
        if path.stat().st_size > _MAX_BYTES:
            return None
        raw = path.read_bytes()
    except OSError:
        return None
    if b"\x00" in raw[:1024]:
        return None
    return raw.decode("utf-8", "replace")


def _where(root: Path, path: Path, number: int) -> str:
    return f"{path.relative_to(root).as_posix()}:{number}"


def secrets(root: Path) -> RepoResult:
    hits: list[RepoHit] = []
    scanned = 0
    for path in _files(root):
        text = _text(path)
        if text is None:
            continue
        scanned += 1
        for number, line in enumerate(text.splitlines(), 1):
            found = find_secret(line)
            if found is not None:
                kind, value = found
                hits.append(RepoHit(kind.lower(), line.strip(), value, _where(root, path, number)))
                if len(hits) >= _MAX_HITS:
                    return RepoResult(tuple(hits), "")
    return RepoResult(tuple(hits), "" if scanned else "the repository has no text files")


_NOT_A_METHOD = r"(?<![.\w])"
_SINKS: dict[str, tuple[tuple[str, re.Pattern[str]], ...]] = {
    ".py": (
        ("python-eval", re.compile(_NOT_A_METHOD + r"eval\(")),
        ("python-exec", re.compile(_NOT_A_METHOD + r"exec\(")),
        ("os-system", re.compile(r"\bos\.(?:system|popen)\(")),
        ("subprocess-shell", re.compile(r"\bsubprocess\.\w+\(.*shell\s*=\s*True")),
        ("pickle-load", re.compile(r"\b(?:pickle|cPickle|marshal)\.loads?\(")),
        ("yaml-load", re.compile(r"\byaml\.load\((?!.*Loader\s*=\s*(?:yaml\.)?(?:C?SafeLoader))")),
    ),
    ".js": (
        ("js-eval", re.compile(_NOT_A_METHOD + r"eval\(")),
        ("js-function", re.compile(r"\bnew Function\(")),
        ("child-process-exec", re.compile(r"\bchild_process\.exec(?:Sync)?\(|\bexecSync\(")),
        ("inner-html", re.compile(r"\.innerHTML\s*=|dangerouslySetInnerHTML")),
    ),
    ".php": (
        ("php-exec", re.compile(_NOT_A_METHOD + r"(?:eval|system|shell_exec|passthru|exec)\(")),
    ),
}
for _alias in (".jsx", ".ts", ".tsx", ".mjs", ".cjs"):
    _SINKS[_alias] = _SINKS[".js"]
_COMMENT = ("#", "//", "/*", "*")


def sinks(root: Path) -> RepoResult:
    hits: list[RepoHit] = []
    scanned = 0
    for path in _files(root):
        rules = _SINKS.get(path.suffix.lower())
        if rules is None:
            continue
        text = _text(path)
        if text is None:
            continue
        scanned += 1
        for number, line in enumerate(text.splitlines(), 1):
            code = line.strip()
            if code.startswith(_COMMENT):
                continue
            for rule, pattern in rules:
                found = pattern.search(code)
                if found is not None:
                    hits.append(RepoHit(rule, code, found.group(0), _where(root, path, number)))
                    break
            if len(hits) >= _MAX_HITS:
                return RepoResult(tuple(hits), "")
    if not scanned:
        return RepoResult((), "no Python, JavaScript, TypeScript or PHP source in the repository")
    return RepoResult(tuple(hits), "")


# Package, first fixed version, advisory. A short list; osv-scanner checks every advisory.
_VULNERABLE: dict[str, tuple[tuple[str, tuple[int, ...], str], ...]] = {
    "pypi": (
        ("pyyaml", (5, 4), "CVE-2020-14343"),
        ("jinja2", (2, 11, 3), "CVE-2020-28493"),
        ("django", (2, 2, 28), "CVE-2022-28346"),
        ("flask", (2, 2, 5), "CVE-2023-30861"),
        ("requests", (2, 31, 0), "CVE-2023-32681"),
        ("urllib3", (1, 26, 18), "CVE-2023-45803"),
        ("werkzeug", (2, 2, 3), "CVE-2023-25577"),
        ("pillow", (9, 0, 1), "CVE-2022-22817"),
    ),
    "npm": (
        ("lodash", (4, 17, 21), "CVE-2021-23337"),
        ("minimist", (1, 2, 6), "CVE-2021-44906"),
        ("axios", (0, 21, 1), "CVE-2020-28168"),
        ("express", (4, 19, 2), "CVE-2024-29041"),
        ("jsonwebtoken", (9, 0, 0), "CVE-2022-23529"),
        ("node-fetch", (2, 6, 7), "CVE-2022-0235"),
    ),
}
_PIN = re.compile(
    r"""^\s*["']?([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*==\s*([0-9][^\s;,"'#]*)"""
)
_NPM_VERSION = re.compile(r"^[=v]?(\d+(?:\.\d+)*)$")


def _version(text: str) -> tuple[int, ...]:
    return tuple(int(part) for part in re.findall(r"\d+", text)[:4])


def _python_pins(text: str) -> Iterator[tuple[int, str, str]]:
    for number, line in enumerate(text.splitlines(), 1):
        found = _PIN.match(line)
        if found is not None:
            yield number, found.group(1), found.group(2)


def _npm_pins(path: Path, text: str) -> Iterator[tuple[int, str, str]]:
    try:
        loaded = json.loads(text)
    except json.JSONDecodeError:
        return
    if not isinstance(loaded, dict):
        return
    entries: dict[str, str] = {}
    if path.name == "package-lock.json":
        packages = loaded.get("packages")
        if isinstance(packages, dict):
            for key, value in packages.items():
                if key and isinstance(value, dict) and isinstance(value.get("version"), str):
                    entries[key.rsplit("node_modules/", 1)[-1]] = value["version"]
    else:
        for section in ("dependencies", "devDependencies"):
            declared = loaded.get(section)
            if isinstance(declared, dict):
                for name, spec in declared.items():
                    found = _NPM_VERSION.match(spec) if isinstance(spec, str) else None
                    if found is not None:
                        entries[name] = found.group(1)
    lines = text.splitlines()
    for name, version in entries.items():
        quoted = f'"{name}"'
        number = next((i for i, line in enumerate(lines, 1) if quoted in line), 1)
        yield number, name, version


def _ecosystem(path: Path) -> str | None:
    name = path.name.lower()
    if (name.startswith("requirements") and name.endswith(".txt")) or name in {
        "pyproject.toml",
        "constraints.txt",
    }:
        return "pypi"
    if name in {"package.json", "package-lock.json"}:
        return "npm"
    return None


def dependencies(root: Path) -> RepoResult:
    hits: list[RepoHit] = []
    manifests = 0
    pins = 0
    for path in _files(root):
        ecosystem = _ecosystem(path)
        if ecosystem is None:
            continue
        text = _text(path)
        if text is None:
            continue
        manifests += 1
        found = _python_pins(text) if ecosystem == "pypi" else _npm_pins(path, text)
        advisories = {name: (fixed, cve) for name, fixed, cve in _VULNERABLE[ecosystem]}
        for number, name, version in found:
            pins += 1
            advisory = advisories.get(name.lower().replace("_", "-"))
            if advisory is None or _version(version) >= advisory[0]:
                continue
            fixed, cve = advisory
            evidence = f"{name}=={version} is below {'.'.join(map(str, fixed))} ({cve})"
            hits.append(RepoHit(cve, f"{name}=={version}", evidence, _where(root, path, number)))
    if hits:
        return RepoResult(tuple(hits), "")
    if not manifests:
        return RepoResult((), "no requirements.txt, pyproject.toml or package.json found")
    if not pins:
        return RepoResult((), "no exact version pins to compare")
    return RepoResult(
        (),
        f"{pins} pinned packages checked against a short built-in list; "
        "install osv-scanner for every advisory",
    )
