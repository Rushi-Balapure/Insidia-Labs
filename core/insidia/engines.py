"""Install pinned engines into a toolchain directory and read the receipt."""

from __future__ import annotations

import json
import os
import platform
import shutil
import subprocess
import sys
import tarfile
import urllib.request
import zipfile
from pathlib import Path
from typing import cast

from insidia.catalog import SPECS, EngineSpec
from insidia.errors import CliError
from insidia.process import child_env

_CPU_TORCH = "https://download.pytorch.org/whl/cpu"


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
        rows.append(
            {
                "name": name,
                "license": license_name,
                "installed": name == "insidia" or name in installed,
                "version": version,
            }
        )
    return rows


def installed_engines() -> frozenset[str]:
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
    return str((final / str(receipt["program"])).resolve())


def install(names: tuple[str, ...] = (), *, docker: bool = False) -> str:
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
    return "; ".join(_install_one(name) for name in names)


def _install_one(name: str) -> str:
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
        program = _stage(spec, stage)
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


def _stage(spec: EngineSpec, stage: Path) -> str:
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
    if spec.name in {"pyrit", "deepteam", "bandit"}:
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
    if spec.name == "promptfoo":
        _npm(stage, spec.package)
        return _require(stage, _npm_script("promptfoo"))
    if spec.name == "zap":
        return _fetch_zap(spec, stage)
    if spec.name == "osv-scanner":
        return _fetch_binary(spec, stage, raw=True)
    return _fetch_binary(spec, stage, raw=False)


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
    *,
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
    try:
        subprocess.run(command, check=True, env=env, shell=False)
    except subprocess.CalledProcessError as exc:
        raise CliError(f"{Path(command[0]).name} exited {exc.returncode}") from exc


def _fetch_binary(spec: EngineSpec, stage: Path, *, raw: bool) -> str:
    url = _github(spec)
    archive = stage / "download"
    _download(url, archive)
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


def _fetch_zap(spec: EngineSpec, stage: Path) -> str:
    archive = stage / "download"
    _download(_github(spec), archive)
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


