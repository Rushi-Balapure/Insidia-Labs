"""Read the internal-only compose file and refuse a sandbox that can egress."""

from __future__ import annotations

import shutil
from pathlib import Path

import yaml

COMPOSE_PATH = Path(__file__).resolve().parents[1] / "targets" / "compose.yml"
SANDBOX_NETWORK = "sandbox"


class SandboxOpen(Exception):
    pass


def load_compose(path: Path = COMPOSE_PATH) -> dict[str, object]:
    loaded = yaml.safe_load(path.read_text())
    if not isinstance(loaded, dict):
        raise SandboxOpen("compose file is empty")
    return loaded


def assert_closed(document: dict[str, object]) -> None:
    networks = document.get("networks")
    network = {}
    if isinstance(networks, dict):
        candidate = networks.get(SANDBOX_NETWORK, {})
        if isinstance(candidate, dict):
            network = candidate
    if network.get("internal") is not True:
        raise SandboxOpen("sandbox network is not internal")
    services = document.get("services")
    if not isinstance(services, dict) or not services:
        raise SandboxOpen("compose has no services")
    for name, service in services.items():
        if not isinstance(service, dict):
            raise SandboxOpen(f"{name} is not a service")
        if service.get("network_mode") == "host":
            raise SandboxOpen(f"{name} uses the host network")
        if "ports" in service:
            raise SandboxOpen(f"{name} publishes a host port")
        if service.get("networks") != [SANDBOX_NETWORK]:
            raise SandboxOpen(f"{name} is not only on the sandbox network")
        for volume in service.get("volumes") or []:
            if isinstance(volume, str) and volume.startswith(("/", ".")):
                raise SandboxOpen(f"{name} bind-mounts the host")
        _assert_pinned(name, service)


def _assert_pinned(name: str, service: dict[str, object]) -> None:
    image = service.get("image")
    if isinstance(image, str) and "@sha256:" in image:
        return
    build = service.get("build")
    if isinstance(build, dict):
        context = COMPOSE_PATH.parent / str(build.get("context", "."))
        dockerfile = context / str(build.get("dockerfile", "Dockerfile"))
        text = dockerfile.read_text()
        if "FROM " in text and "@sha256:" in text.split("FROM ", 1)[1].splitlines()[0]:
            return
    raise SandboxOpen(f"{name} is not pinned by image digest")


def docker_available() -> bool:
    return shutil.which("docker") is not None
