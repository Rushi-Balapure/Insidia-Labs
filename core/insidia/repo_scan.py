"""Built-in repository checks: secrets, dangerous calls, and pinned vulnerable packages."""

from __future__ import annotations

import json
import re
import tomllib
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import NamedTuple

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


class _Ver(NamedTuple):
    """PEP 440 sort key. A final release sorts after a/b/rc/dev of the same numbers."""

    release: tuple[int, ...]
    pre: tuple[int, int, int]
    post: tuple[int, int]
    dev: tuple[int, int]


_PRE_KIND = {
    "a": 0,
    "alpha": 0,
    "b": 1,
    "beta": 1,
    "c": 2,
    "rc": 2,
    "pre": 2,
    "preview": 2,
}
_VERSION_RE = re.compile(
    r"^v?"
    r"(?P<release>\d+(?:\.\d+)*)"
    r"(?:[._-]?(?P<pre_tag>alpha|beta|preview|pre|rc|a|b|c)[._-]?(?P<pre_num>\d*))?"
    r"(?:(?:[._-]?(?P<post_tag>post|rev|r)[._-]?(?P<post_num>\d*))|(?:-(?P<post_implicit>\d+)))?"
    r"(?:[._-]?dev[._-]?(?P<dev>\d*))?"
    r"(?:\+[0-9A-Za-z.]+)?"
    r"$",
    re.IGNORECASE,
)


def _parse_version(text: str) -> _Ver | None:
    """Parse a pinned version. Epochs are left unparsed; pre-releases sort before the final."""
    found = _VERSION_RE.fullmatch(text.strip())
    if found is None:
        return None
    release_text = found.group("release")
    if release_text is None:
        return None
    release = tuple(int(part) for part in release_text.split("."))
    while len(release) > 1 and release[-1] == 0:
        release = release[:-1]
    pre_tag = found.group("pre_tag")
    dev_text = found.group("dev")
    post_implicit = found.group("post_implicit")
    post_tag = found.group("post_tag")
    has_post = post_tag is not None or post_implicit is not None
    has_dev = dev_text is not None
    if pre_tag is None and not has_post and has_dev:
        pre = (-1, 0, 0)
    elif pre_tag is None:
        pre = (1, 0, 0)
    else:
        pre = (0, _PRE_KIND[pre_tag.lower()], int(found.group("pre_num") or 0))
    if post_implicit is not None:
        post = (0, int(post_implicit))
    elif post_tag is not None:
        post = (0, int(found.group("post_num") or 0))
    else:
        post = (-1, 0)
    dev = (0, int(dev_text or 0)) if has_dev else (1, 0)
    return _Ver(release, pre, post, dev)


def _require_version(text: str) -> _Ver:
    parsed = _parse_version(text)
    if parsed is None:
        raise ValueError(text)
    return parsed


def _normalize_name(name: str) -> str:
    """PEP 503: case-insensitive, and ``.``, ``_``, ``-`` runs collapse to one dash."""
    return re.sub(r"[-_.]+", "-", name).lower()


@dataclass(frozen=True)
class _Span:
    introduced: _Ver | None
    fixed: _Ver
    fixed_text: str


@dataclass(frozen=True)
class _Advisory:
    cve: str
    spans: tuple[_Span, ...]


_SpanSpec = tuple[str | None, str]
# Package, CVE, (introduced inclusive or None, fixed exclusive). One package can have
# several ranges on different branches. A short list; osv-scanner checks every advisory.
_ADVISORY_ROWS: dict[str, tuple[tuple[str, str, tuple[_SpanSpec, ...]], ...]] = {
    "pypi": (
        ("pyyaml", "CVE-2020-14343", ((None, "5.4"),)),
        ("jinja2", "CVE-2020-28493", ((None, "2.11.3"),)),
        (
            "django",
            "CVE-2022-28346",
            ((None, "2.2.28"), ("2.2", "2.2.28"), ("3.2", "3.2.13"), ("4.0", "4.0.4")),
        ),
        (
            "django",
            "CVE-2024-27351",
            (("3.2", "3.2.25"), ("4.2", "4.2.11"), ("5.0", "5.0.3")),
        ),
        ("flask", "CVE-2023-30861", ((None, "2.2.5"), ("2.3.0", "2.3.2"))),
        ("requests", "CVE-2023-32681", ((None, "2.31.0"),)),
        ("urllib3", "CVE-2023-45803", ((None, "1.26.18"), ("2.0.0", "2.0.7"))),
        ("werkzeug", "CVE-2023-25577", ((None, "2.2.3"),)),
        ("pillow", "CVE-2022-22817", ((None, "9.0.1"),)),
    ),
    "npm": (
        ("lodash", "CVE-2021-23337", ((None, "4.17.21"),)),
        ("minimist", "CVE-2021-44906", ((None, "1.2.6"),)),
        ("axios", "CVE-2020-28168", ((None, "0.21.1"),)),
        ("express", "CVE-2024-29041", ((None, "4.19.2"),)),
        ("jsonwebtoken", "CVE-2022-23529", ((None, "9.0.0"),)),
        ("node-fetch", "CVE-2022-0235", ((None, "2.6.7"),)),
    ),
}


def _index_advisories() -> dict[str, dict[str, tuple[_Advisory, ...]]]:
    indexed: dict[str, dict[str, tuple[_Advisory, ...]]] = {}
    for ecosystem, rows in _ADVISORY_ROWS.items():
        grouped: dict[str, list[_Advisory]] = {}
        for package, cve, spans in rows:
            parsed = tuple(
                _Span(
                    None if introduced is None else _require_version(introduced),
                    _require_version(fixed),
                    fixed,
                )
                for introduced, fixed in spans
            )
            grouped.setdefault(_normalize_name(package), []).append(_Advisory(cve, parsed))
        indexed[ecosystem] = {name: tuple(items) for name, items in grouped.items()}
    return indexed


_ADVISORIES = _index_advisories()

_REQ_PIN = re.compile(
    r"(?<![\w.-])"
    r"(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)"
    r"(?:\[[^\]]*\])?"
    r"\s*={2,3}\s*v?"
    r"(?P<version>[0-9][^\s;,\"'#]*)",
    re.IGNORECASE,
)
_ASSIGNED_PIN = re.compile(
    r"^\s*(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)\s*=\s*[\"']"
    r"(?:={2,3}\s*)?v?(?P<version>[0-9][^\s\"'#,;]*)[\"']",
    re.IGNORECASE,
)
_BRACE_PIN = re.compile(
    r"^\s*(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)\s*=\s*\{"
    r"[^}\n]*?\bversion\s*=\s*[\"']"
    r"(?:={2,3}\s*)?v?(?P<version>[0-9][^\"']*)",
    re.IGNORECASE,
)
_NO_MANIFEST = (
    "no requirements.txt, pyproject.toml, Pipfile, Pipfile.lock, poetry.lock, "
    "uv.lock, setup.cfg, setup.py or package.json found"
)


def _affected_span(advisory: _Advisory, version: _Ver) -> _Span | None:
    for span in advisory.spans:
        if span.introduced is not None and version < span.introduced:
            continue
        if version < span.fixed:
            return span
    return None


def _bare_version(text: str) -> str | None:
    value = text.strip()
    pinned = re.fullmatch(r"={2,3}\s*(.+)", value)
    if pinned is not None:
        value = pinned.group(1).strip()
    if len(value) > 1 and value[0] in "vV" and value[1].isdigit():
        value = value[1:]
    if _parse_version(value) is None:
        return None
    return value


def _requirement_pins(number: int, line: str) -> Iterator[tuple[int, str, str]]:
    code = line.split("#", 1)[0]
    for found in _REQ_PIN.finditer(code):
        yield number, found.group("name"), found.group("version")


def _assignment_pins(number: int, line: str) -> Iterator[tuple[int, str, str]]:
    found = _ASSIGNED_PIN.match(line) or _BRACE_PIN.match(line)
    if found is None:
        return
    name = found.group("name")
    if _normalize_name(name) == "python":
        return
    yield number, name, found.group("version")


def _poetry_dependencies_table(header: str) -> bool:
    name = header.strip("[]").strip().strip("'\"").lower()
    if name in {"tool.poetry.dependencies", "tool.poetry.dev-dependencies"}:
        return True
    parts = name.split(".")
    return (
        len(parts) == 5
        and parts[:3] == ["tool", "poetry", "group"]
        and parts[4] == "dependencies"
    )


def _pyproject_pins(text: str) -> Iterator[tuple[int, str, str]]:
    poetry = False
    for number, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            poetry = _poetry_dependencies_table(stripped)
            continue
        yield from _requirement_pins(number, line)
        if poetry:
            yield from _assignment_pins(number, line)


def _requirement_lines(text: str) -> Iterator[tuple[int, str, str]]:
    for number, line in enumerate(text.splitlines(), 1):
        yield from _requirement_pins(number, line)


def _locate(lines: list[str], name: str, version: str) -> int:
    """Line of a package pin. Quoted names cover JSON and TOML strings; bare keys cover Pipfiles."""
    escaped = re.escape(name)
    name_re = re.compile(
        rf"""["'](?:node_modules/)?{escaped}["']|^[ \t]*{escaped}[ \t]*=""",
        re.IGNORECASE,
    )
    version_re = re.compile(rf"""["'](?:=*|v)?{re.escape(version)}["']""", re.IGNORECASE)
    for index, line in enumerate(lines):
        if name_re.search(line) is None:
            continue
        window = lines[index : index + 8]
        if any(version_re.search(later) for later in window):
            return index + 1
    return 1


def _spec_version(spec: object) -> str | None:
    if isinstance(spec, str):
        return _bare_version(spec)
    if isinstance(spec, dict):
        declared = spec.get("version")
        if isinstance(declared, str):
            return _bare_version(declared)
    return None


def _pipfile_pins(text: str) -> Iterator[tuple[int, str, str]]:
    try:
        loaded = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return
    lines = text.splitlines()
    for section in ("packages", "dev-packages"):
        declared = loaded.get(section)
        if not isinstance(declared, dict):
            continue
        for name, spec in declared.items():
            if not isinstance(name, str):
                continue
            version = _spec_version(spec)
            if version is None:
                continue
            yield _locate(lines, name, version), name, version


def _pipfile_lock_pins(text: str) -> Iterator[tuple[int, str, str]]:
    try:
        loaded = json.loads(text)
    except json.JSONDecodeError:
        return
    if not isinstance(loaded, dict):
        return
    lines = text.splitlines()
    for section in ("default", "develop"):
        declared = loaded.get(section)
        if not isinstance(declared, dict):
            continue
        for name, meta in declared.items():
            if not isinstance(name, str) or not isinstance(meta, dict):
                continue
            raw = meta.get("version")
            if not isinstance(raw, str):
                continue
            version = _bare_version(raw)
            if version is None:
                continue
            yield _locate(lines, name, version), name, version


def _toml_lock_pins(text: str) -> Iterator[tuple[int, str, str]]:
    try:
        loaded = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return
    packages = loaded.get("package")
    if not isinstance(packages, list):
        return
    lines = text.splitlines()
    for package in packages:
        if not isinstance(package, dict):
            continue
        source = package.get("source")
        if isinstance(source, dict) and "virtual" in source:
            continue
        name = package.get("name")
        raw = package.get("version")
        if not isinstance(name, str) or not isinstance(raw, str):
            continue
        version = _bare_version(raw)
        if version is None:
            continue
        yield _locate(lines, name, version), name, version


def _setup_cfg_pins(text: str) -> Iterator[tuple[int, str, str]]:
    in_options = False
    in_requires = False
    for number, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", ";")):
            continue
        if stripped.startswith("[") and stripped.endswith("]"):
            in_options = stripped.lower() == "[options]"
            in_requires = False
            continue
        if not in_options:
            continue
        if line[:1] not in " \t":
            key, separator, value = stripped.partition("=")
            in_requires = separator == "=" and key.strip().lower() == "install_requires"
            if in_requires and value.strip():
                yield from _requirement_pins(number, value)
            continue
        if in_requires:
            yield from _requirement_pins(number, stripped)


def _setup_py_pins(text: str) -> Iterator[tuple[int, str, str]]:
    lines = text.splitlines()
    start = next(
        (
            index
            for index, line in enumerate(lines)
            if "install_requires" in line and not line.lstrip().startswith("#")
        ),
        None,
    )
    if start is None or ("[" not in lines[start] and "(" not in lines[start]):
        return
    depth = 0
    for index in range(start, len(lines)):
        line = lines[index]
        depth += line.count("(") + line.count("[") + line.count("{")
        depth -= line.count(")") + line.count("]") + line.count("}")
        yield from _requirement_pins(index + 1, line)
        if depth <= 0:
            return


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
                if not key or not isinstance(key, str) or not isinstance(value, dict):
                    continue
                raw = value.get("version")
                if not isinstance(raw, str):
                    continue
                version = _bare_version(raw)
                if version is None:
                    continue
                entries[key.rsplit("node_modules/", 1)[-1]] = version
    else:
        for section in ("dependencies", "devDependencies"):
            declared = loaded.get(section)
            if not isinstance(declared, dict):
                continue
            for name, spec in declared.items():
                if not isinstance(name, str) or not isinstance(spec, str):
                    continue
                version = _bare_version(spec)
                if version is not None:
                    entries[name] = version
    lines = text.splitlines()
    for name, version in entries.items():
        yield _locate(lines, name, version), name, version


def _ecosystem(path: Path) -> str | None:
    name = path.name.lower()
    if (name.startswith("requirements") and name.endswith(".txt")) or name in {
        "pyproject.toml",
        "constraints.txt",
        "pipfile",
        "pipfile.lock",
        "poetry.lock",
        "uv.lock",
        "setup.cfg",
        "setup.py",
    }:
        return "pypi"
    if name in {"package.json", "package-lock.json"}:
        return "npm"
    return None


def _manifest_pins(path: Path, text: str) -> Iterator[tuple[int, str, str]]:
    name = path.name.lower()
    if name == "pipfile.lock":
        yield from _pipfile_lock_pins(text)
    elif name == "pipfile":
        yield from _pipfile_pins(text)
    elif name in {"poetry.lock", "uv.lock"}:
        yield from _toml_lock_pins(text)
    elif name == "setup.cfg":
        yield from _setup_cfg_pins(text)
    elif name == "setup.py":
        yield from _setup_py_pins(text)
    elif name == "pyproject.toml":
        yield from _pyproject_pins(text)
    elif name in {"package.json", "package-lock.json"}:
        yield from _npm_pins(path, text)
    else:
        yield from _requirement_lines(text)


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
        advisories = _ADVISORIES[ecosystem]
        for number, name, version in _manifest_pins(path, text):
            parsed = _parse_version(version)
            if parsed is None:
                continue
            pins += 1
            label = f"{name}=={version}"
            for advisory in advisories.get(_normalize_name(name), ()):
                span = _affected_span(advisory, parsed)
                if span is None:
                    continue
                evidence = f"{label} is below {span.fixed_text} ({advisory.cve})"
                hits.append(RepoHit(advisory.cve, label, evidence, _where(root, path, number)))
    if hits:
        return RepoResult(tuple(hits), "")
    if not manifests:
        return RepoResult((), _NO_MANIFEST)
    if not pins:
        return RepoResult((), "no exact version pins to compare")
    return RepoResult(
        (),
        f"{pins} pinned packages checked against a short built-in list; "
        "install osv-scanner for every advisory",
    )
