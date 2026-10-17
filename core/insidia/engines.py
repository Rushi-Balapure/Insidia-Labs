"""Install pinned engines into a toolchain directory and read the receipt."""

from __future__ import annotations

import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
import tarfile
import urllib.request
import zipfile
from collections.abc import Callable
from pathlib import Path
from typing import cast

from insidia.catalog import SPECS, EngineSpec
from insidia.errors import CliError
from insidia.process import child_env

_CPU_TORCH = "https://download.pytorch.org/whl/cpu"

# SHA-256 of the file `_github()` downloads, keyed by that exact URL.
# A platform with no entry is refused unless `engines install --allow-unverified`
# is passed. A pin that does not match the bytes always fails, before extract.
PINNED_SHA256: dict[str, str] = {
    (
        "https://github.com/aquasecurity/trivy/releases/download/"
        "v0.75.0/trivy_0.75.0_Linux-64bit.tar.gz"
    ): "c6e65abddb348e25f10549df887045629cf28cc72453cd1c63acb717316b3f3f",
    (
        "https://github.com/aquasecurity/trivy/releases/download/"
        "v0.75.0/trivy_0.75.0_Linux-ARM64.tar.gz"
    ): "a1ee9f6ffb7d112b64ff726a2a0717c21175c1114361391f4a132956751a13b3",
    (
        "https://github.com/gitleaks/gitleaks/releases/download/"
        "v8.30.1/gitleaks_8.30.1_linux_arm64.tar.gz"
    ): "e4a487ee7ccd7d3a7f7ec08657610aa3606637dab924210b3aee62570fb4b080",
    (
        "https://github.com/gitleaks/gitleaks/releases/download/"
        "v8.30.1/gitleaks_8.30.1_linux_x64.tar.gz"
    ): "551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb",
    (
        "https://github.com/google/osv-scanner/releases/download/v2.6.0/osv-scanner_linux_amd64"
    ): "ca69b3d3cd08f889a49dc0a383122f71cc528b83803671df5fd874d97485b108",
    (
        "https://github.com/google/osv-scanner/releases/download/v2.6.0/osv-scanner_linux_arm64"
    ): "2c71403eb443d05891c4f268c3ad771cf4f16e5443463fd7851ef8f454d3c7e4",
    (
        "https://github.com/hahwul/dalfox/releases/download/"
        "v3.2.3/dalfox-v3.2.3-linux-aarch64.tar.gz"
    ): "a7074d1001bb66664c1ed2db35d4b892a8f11da4d07f4deede1da8bfe7992d2b",
    (
        "https://github.com/hahwul/dalfox/releases/download/"
        "v3.2.3/dalfox-v3.2.3-linux-x86_64.tar.gz"
    ): "3b059b6bb55e686b5f240852ea6a6750aa5e35a3b404e4027ffe505e2b60a470",
    (
        "https://github.com/projectdiscovery/httpx/releases/download/"
        "v1.12.0/httpx_1.12.0_linux_amd64.zip"
    ): "9d8439e8b6c9aa7d1e2314817a392e00d5178da3af5652f7475f88868f418f76",
    (
        "https://github.com/projectdiscovery/httpx/releases/download/"
        "v1.12.0/httpx_1.12.0_linux_arm64.zip"
    ): "fd7b123c1dfbc3d69f19f524e4eebcd6ec06b9a6cbd56813c76f11645197331e",
    (
        "https://github.com/projectdiscovery/katana/releases/download/"
        "v1.8.0/katana_1.8.0_linux_amd64.zip"
    ): "cb027ae99d0757061b70c07a15c7a80f62c5a535ab52c4a329f80c4b0a7309d2",
    (
        "https://github.com/projectdiscovery/katana/releases/download/"
        "v1.8.0/katana_1.8.0_linux_arm64.zip"
    ): "80e269210727a855511ffac8dfb01297b2344742acec71a35e8ba4a67a90f0f2",
    (
        "https://github.com/projectdiscovery/nuclei/releases/download/"
        "v3.11.1/nuclei_3.11.1_linux_amd64.zip"
    ): "ea63d4ae232808cd7c6bc00d0142428e231fab59dae01042246097d195835ab6",
    (
        "https://github.com/projectdiscovery/nuclei/releases/download/"
        "v3.11.1/nuclei_3.11.1_linux_arm64.zip"
    ): "8044e3d9768ba0a744b2872c1a87e813006f013da97ca9f50f7661a4203bec07",
    (
        "https://github.com/projectdiscovery/nuclei/releases/download/"
        "v3.11.1/nuclei_3.11.1_macOS_amd64.zip"
    ): "75c47ce11e9dbd4288a1c895ed85e3c4df9f4acb8237d6d178da6dccd1628f2a",
    (
        "https://github.com/projectdiscovery/nuclei/releases/download/"
        "v3.11.1/nuclei_3.11.1_macOS_arm64.zip"
    ): "7d7e291addd1fc29a9bf8d089afe878a9799b20229cbea2fb1693fc40fd4c5f0",
    (
        "https://github.com/projectdiscovery/nuclei/releases/download/"
        "v3.11.1/nuclei_3.11.1_windows_amd64.zip"
    ): "bb6cb9ff8939b753f6fcab06fd30a15f5bc61d8382a597871334c007a85ff9d2",
    (
        "https://github.com/securego/gosec/releases/download/"
        "v2.29.0/gosec_2.29.0_linux_amd64.tar.gz"
    ): "6431b119741c1f4a50fdfcf94e782e16b9e642afc8c7fa9b5d39d48bf3003095",
    (
        "https://github.com/securego/gosec/releases/download/"
        "v2.29.0/gosec_2.29.0_linux_arm64.tar.gz"
    ): "c71244ec8d37488fd479d0d26990968fee03ece48b305d8224ac0c1ebd66e87c",
    (
        "https://github.com/zaproxy/zaproxy/releases/download/v2.17.0/ZAP_2.17.0_Linux.tar.gz"
    ): "efe799aaa3627db683b43f00c9c210aea0b75c00cc8f0a0f0434d12bb3ddde5a",
}


def _venv_python(stage: Path) -> Path:
    folder = "Scripts" if os.name == "nt" else "bin"
    name = "python.exe" if os.name == "nt" else "python"
    return stage / "venv" / folder / name


def _venv_script(name: str) -> str:
    if os.name == "nt":
        return f"venv/Scripts/{name}.exe"
    return f"venv/bin/{name}"


def _npm_script(name: str) -> str:
    if os.name == "nt":
        return f"node_modules/.bin/{name}.cmd"
    return f"node_modules/.bin/{name}"


def _release_os() -> str:
    if sys.platform == "darwin":
        return "macOS"
    if sys.platform == "win32":
        return "windows"
    return "linux"


def toolchain_root() -> Path:
    import os

    override = os.environ.get("INSIDIA_TOOLCHAIN")
    if override:
        return Path(override)
    return Path.home() / ".local" / "share" / "insidia" / "engines"


def list_engines() -> list[dict[str, object]]:
    from insidia.registry import KNOWN_ENGINES

    installed = installed_engines()
    rows: list[dict[str, object]] = []
    for name, license_name in KNOWN_ENGINES:
        receipt = _read_receipt(toolchain_root() / name)
        version = receipt.get("version") if receipt else None
        row: dict[str, object] = {
            "name": name,
            "license": license_name,
            "installed": name == "insidia" or name in installed,
            "version": version,
        }
        missing = missing_runtime(name)
        if receipt is not None and missing:
            row["note"] = f"needs {missing}"
        rows.append(row)
    return rows


# Engines whose program runs on a runtime the toolchain does not ship.
_RUNTIMES = {"zap": ("java", "Java 17 or later on PATH")}


def missing_runtime(name: str) -> str:
    """The runtime an engine needs that this machine lacks, or ""."""
    needed = _RUNTIMES.get(name)
    if needed is None or shutil.which(needed[0]) is not None:
        return ""
    return needed[1]


def unusable_engines() -> dict[str, str]:
    """Engines in the toolchain that cannot run here, with what they need."""
    return {name: missing_runtime(name) for name in _downloaded() if missing_runtime(name)}


def installed_engines() -> frozenset[str]:
    return frozenset(name for name in _downloaded() if not missing_runtime(name))


def _downloaded() -> frozenset[str]:
    root = toolchain_root()
    if not root.is_dir():
        return frozenset()
    found: list[str] = []
    for child in root.iterdir():
        if child.name.startswith("."):
            continue
        receipt = _read_receipt(child)
        if receipt is None or receipt.get("name") != child.name:
            continue
        program = child / str(receipt.get("program", ""))
        if program.is_file():
            found.append(child.name)
    return frozenset(found)


def program_for(name: str) -> str:
    final = toolchain_root() / name
    receipt = _read_receipt(final)
    if receipt is None:
        return str(final / "missing")
    # abspath, not resolve: a venv python is a symlink, and following it
    # drops the venv's site-packages.
    return os.path.abspath(final / str(receipt["program"]))


def install(
    names: tuple[str, ...] = (),
    docker: bool = False,
    progress: Callable[[str], None] | None = None,
    allow_unverified: bool = False,
) -> str:
    if docker:
        if shutil.which("docker") is None:
            raise CliError("docker is not installed")
        if names:
            raise CliError("docker images for named engines are not in this release")
        return "docker is available; engine images arrive with the engine adapters"
    if not names:
        return "built-in probes are already available; name an engine to install it"
    unknown = [name for name in names if name not in {spec.name for spec in SPECS}]
    if unknown:
        raise CliError(f"unknown engine {unknown[0]}")
    lines: list[str] = []
    specs = {spec.name: spec for spec in SPECS}
    for name in names:
        spec = specs[name]
        if progress is not None:
            progress(f"Installing {name} {spec.version}.")
        line = _install_one(name, allow_unverified=allow_unverified)
        needed = missing_runtime(name)
        if needed:
            line = f"{line}; warning: needs {needed} before it can run"
        lines.append(line)
        if progress is not None:
            progress(line)
    return "; ".join(lines)


def _install_one(name: str, allow_unverified: bool = False) -> str:
    spec = next(item for item in SPECS if item.name == name)
    root = toolchain_root()
    final = root / name
    receipt = _read_receipt(final)
    if (
        receipt
        and receipt.get("version") == spec.version
        and (final / str(receipt.get("program", ""))).is_file()
    ):
        _rewrite_shebangs(final)
        return f"{name} {spec.version} is already installed"
    root.mkdir(parents=True, exist_ok=True)
    stage = root / f".{name}.staging"
    if stage.exists():
        shutil.rmtree(stage)
    stage.mkdir()
    try:
        program = _stage(spec, stage, allow_unverified=allow_unverified)
        _publish(
            stage,
            final,
            {"name": name, "version": spec.version, "program": program},
        )
    except Exception:
        if stage.exists():
            shutil.rmtree(stage, ignore_errors=True)
        raise
    return f"installed {name} {spec.version}"


def _publish(stage: Path, final: Path, receipt: dict[str, str]) -> None:
    (stage / "receipt.json").write_text(json.dumps(receipt) + "\n")
    if final.exists():
        backup = final.with_name(f".{final.name}.previous")
        if backup.exists():
            shutil.rmtree(backup)
        final.rename(backup)
        try:
            stage.rename(final)
        except Exception:
            backup.rename(final)
            raise
        shutil.rmtree(backup)
        _rewrite_shebangs(final)
        return
    stage.rename(final)
    _rewrite_shebangs(final)


def _rewrite_shebangs(root: Path) -> None:
    """Point venv scripts at the published interpreter.

    uv writes absolute shebangs. Staging then renaming the tree leaves them
    aimed at a directory that no longer exists.
    """
    python = root / "venv" / "bin" / "python"
    if not python.is_file():
        return
    line = f"#!{python}"
    for script in python.parent.iterdir():
        if script.is_symlink() or not script.is_file():
            continue
        try:
            text = script.read_text()
        except (OSError, UnicodeError):
            continue
        first, sep, rest = text.partition("\n")
        if not first.startswith("#!") or "python" not in first or first == line:
            continue
        script.write_text(line + sep + rest)


def _stage(spec: EngineSpec, stage: Path, allow_unverified: bool = False) -> str:
    if spec.name == "garak":
        # CPU torch first. The second install pins that build so PyPI cannot
        # replace it with a CUDA wheel, and looks at every index so tqdm can
        # come from PyPI. The CPU index only publishes an older tqdm.
        _venv(stage, ["torch"], index=_CPU_TORCH)
        pinned = _installed_version(stage, "torch")
        _venv(
            stage,
            [spec.package, f"torch=={pinned}"],
            extra_index=_CPU_TORCH,
            strategy="unsafe-best-match",
        )
        return _require(stage, _venv_script("garak"))
    if spec.name == "deepteam":
        # 1.0.9 imports sentry_sdk without declaring it. The scan turns its telemetry off.
        _venv(stage, [spec.package, "sentry-sdk==2.71.0"])
        return _require(stage, _venv_script("python"))
    if spec.name in {"pyrit", "bandit"}:
        _venv(stage, [spec.package])
        if spec.name == "bandit":
            return _require(stage, _venv_script("bandit"))
        return _require(stage, _venv_script("python"))
    if spec.name == "mcp-scanner":
        _venv(stage, [spec.package])
        return _require(stage, _venv_script("mcp-scanner"))
    if spec.name == "skillspector":
        _venv(stage, [spec.package])
        return _require(stage, _venv_script("skillspector"))
    if spec.name == "nuguard":
        # 0.9.15 imports cryptography without declaring it.
        _venv(stage, [spec.package, "cryptography==50.0.2"])
        _require(stage, _venv_script("nuguard"))
        return _require(stage, _venv_script("python"))
    if spec.name == "promptfoo":
        _npm(stage, spec.package)
        return _require(stage, _npm_script("promptfoo"))
    if spec.name == "zap":
        return _fetch_zap(spec, stage, allow_unverified=allow_unverified)
    if spec.name == "osv-scanner":
        return _fetch_binary(spec, stage, raw=True, allow_unverified=allow_unverified)
    return _fetch_binary(spec, stage, raw=False, allow_unverified=allow_unverified)


def _require(stage: Path, relative: str) -> str:
    if not (stage / relative).is_file():
        raise CliError(f"{relative} was not installed")
    return relative


def _installed_version(stage: Path, package: str) -> str:
    python = _venv_python(stage)
    try:
        result = subprocess.run(
            [
                str(python),
                "-c",
                "import importlib.metadata as meta, sys; "
                "sys.stdout.write(meta.version(sys.argv[1]))",
                package,
            ],
            check=True,
            capture_output=True,
            text=True,
            env=child_env({}),
            shell=False,
        )
    except subprocess.CalledProcessError as exc:
        raise CliError(f"{package} was not installed") from exc
    return result.stdout.strip()


def _venv(
    stage: Path,
    packages: list[str],
    index: str | None = None,
    extra_index: str | None = None,
    strategy: str | None = None,
) -> None:
    uv = shutil.which("uv")
    if uv is None:
        raise CliError("uv is not installed")
    venv = stage / "venv"
    python = _venv_python(stage)
    env = child_env({})
    if not python.is_file():
        _checked([uv, "venv", "--python", "3.12", str(venv)], env)
    command = [uv, "pip", "install", "--python", str(python)]
    if index:
        command.extend(["--index-url", index])
    if extra_index:
        command.extend(["--extra-index-url", extra_index])
    if strategy:
        command.extend(["--index-strategy", strategy])
    command.extend(packages)
    _checked(command, env)


def _npm(stage: Path, package: str) -> None:
    npm = shutil.which("npm")
    if npm is None:
        raise CliError("npm is not installed")
    _checked(
        [npm, "install", "--prefix", str(stage), "--no-fund", "--no-audit", package],
        child_env({}),
    )


def _checked(command: list[str], env: dict[str, str]) -> None:
    # The tool's own chatter would scroll past the progress line. A failure
    # keeps the last lines so the reason is not lost.
    try:
        subprocess.run(
            command,
            check=True,
            env=env,
            shell=False,
            capture_output=True,
            text=True,
            errors="replace",
        )
    except subprocess.CalledProcessError as exc:
        tail = [line for line in (exc.stderr or exc.stdout or "").splitlines() if line.strip()]
        detail = f": {' | '.join(line.strip() for line in tail[-3:])}" if tail else ""
        raise CliError(f"{Path(command[0]).name} exited {exc.returncode}{detail}") from exc


def _fetch_binary(spec: EngineSpec, stage: Path, raw: bool, allow_unverified: bool = False) -> str:
    url = _github(spec)
    archive = stage / "download"
    _download(url, archive)
    _verify_download(spec, url, archive, allow_unverified)
    binary = f"{spec.package}.exe" if sys.platform == "win32" else spec.package
    if raw:
        destination = stage / "bin" / binary
        destination.parent.mkdir()
        shutil.copy(archive, destination)
        destination.chmod(0o755)
        return f"bin/{binary}"
    unpack = stage / "unpack"
    _extract(archive, unpack)
    matches = [path for path in unpack.rglob(binary) if path.is_file()]
    if not matches:
        raise CliError(f"{binary} was not in the archive")
    destination = stage / "bin" / binary
    destination.parent.mkdir()
    shutil.copy(matches[0], destination)
    destination.chmod(0o755)
    return f"bin/{binary}"


def _fetch_zap(spec: EngineSpec, stage: Path, allow_unverified: bool = False) -> str:
    url = _github(spec)
    archive = stage / "download"
    _download(url, archive)
    _verify_download(spec, url, archive, allow_unverified)
    unpack = stage / "unpack"
    _extract(archive, unpack)
    matches = [path for path in unpack.rglob("zap.sh") if path.is_file()]
    if not matches:
        raise CliError("zap.sh was not in the archive")
    chosen = matches[0]
    relative = chosen.relative_to(unpack).as_posix()
    target = stage / relative
    shutil.copytree(chosen.parent, target.parent)
    zap = stage / relative
    zap.chmod(0o755)
    return relative


def _extract(archive: Path, unpack: Path) -> None:
    unpack.mkdir()
    if zipfile.is_zipfile(archive):
        with zipfile.ZipFile(archive) as bundle:
            bundle.extractall(unpack)
        return
    with tarfile.open(archive, "r:gz") as bundle:
        bundle.extractall(unpack, filter="data")


def _verify_download(spec: EngineSpec, url: str, archive: Path, allow_unverified: bool) -> None:
    """Check the downloaded bytes before they are extracted or made executable."""
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    pinned = PINNED_SHA256.get(url)
    if pinned is None:
        if allow_unverified:
            return
        raise CliError(
            f"no SHA-256 pin for {spec.name} {spec.version} on this platform; "
            "pass --allow-unverified to install it anyway"
        )
    if digest != pinned.lower():
        raise CliError(f"{spec.name} {spec.version} failed SHA-256 verification")


def _download(url: str, destination: Path) -> None:
    request = urllib.request.Request(url, headers={"User-Agent": "insidia"})
    opener = urllib.request.build_opener(urllib.request.HTTPSHandler())
    try:
        with opener.open(request, timeout=120) as response:
            destination.write_bytes(response.read())
    except OSError as exc:
        raise CliError(f"download failed for {url}") from exc


def _github(spec: EngineSpec) -> str:
    machine = platform.machine().lower()
    if machine in {"x86_64", "amd64"}:
        arch, x64, gnu = "amd64", "x64", "x86_64"
        trivy = "64bit"
    elif machine in {"aarch64", "arm64"}:
        arch, x64, gnu = "arm64", "arm64", "aarch64"
        trivy = "ARM64"
    else:
        raise CliError(f"no {spec.name} build for {machine}")
    version = spec.version
    urls = {
        "nuclei": (
            "https://github.com/projectdiscovery/nuclei/releases/download/"
            f"v{version}/nuclei_{version}_{_release_os()}_{arch}.zip"
        ),
        "dalfox": (
            "https://github.com/hahwul/dalfox/releases/download/"
            f"v{version}/dalfox-v{version}-linux-{gnu}.tar.gz"
        ),
        "katana": (
            "https://github.com/projectdiscovery/katana/releases/download/"
            f"v{version}/katana_{version}_linux_{arch}.zip"
        ),
        "httpx": (
            "https://github.com/projectdiscovery/httpx/releases/download/"
            f"v{version}/httpx_{version}_linux_{arch}.zip"
        ),
        "trivy": (
            "https://github.com/aquasecurity/trivy/releases/download/"
            f"v{version}/trivy_{version}_Linux-{trivy}.tar.gz"
        ),
        "osv-scanner": (
            "https://github.com/google/osv-scanner/releases/download/"
            f"v{version}/osv-scanner_linux_{arch}"
        ),
        "gitleaks": (
            "https://github.com/gitleaks/gitleaks/releases/download/"
            f"v{version}/gitleaks_{version}_linux_{x64}.tar.gz"
        ),
        "gosec": (
            "https://github.com/securego/gosec/releases/download/"
            f"v{version}/gosec_{version}_linux_{arch}.tar.gz"
        ),
        "zap": (
            "https://github.com/zaproxy/zaproxy/releases/download/"
            f"v{version}/ZAP_{version}_Linux.tar.gz"
        ),
    }
    url = urls.get(spec.name)
    if url is None:
        raise CliError(f"{spec.name} has no archive")
    return url


def _read_receipt(directory: Path) -> dict[str, object] | None:
    path = directory / "receipt.json"
    if not path.is_file():
        return None
    try:
        loaded = json.loads(path.read_text())
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None
    if not isinstance(loaded, dict):
        return None
    return cast(dict[str, object], loaded)
