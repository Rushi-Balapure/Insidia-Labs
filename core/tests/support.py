import os
import subprocess
import sys
from pathlib import Path

from insidia.config import RateLimit, Target

REPO = Path(__file__).resolve().parents[2]


def target(
    *,
    kind: str = "chat",
    url: str | None = "http://127.0.0.1/chat",
    path: str | None = None,
    method: str = "POST",
) -> Target:
    return Target(
        "app",
        kind,
        url,
        path,
        method,
        None,
        None,
        {},
        {},
        None,
        RateLimit(100, 1),
        "http",
        None,
        (),
    )


def start_fixture(port: int) -> subprocess.Popen[bytes]:
    return subprocess.Popen(
        [sys.executable, "-m", "benchmark.targets.insidia.serve"],
        cwd=REPO,
        env={
            **os.environ,
            "PYTHONPATH": str(REPO),
            "INSIDIA_FIXTURE_HOST": "127.0.0.1",
            "INSIDIA_FIXTURE_PORT": str(port),
        },
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )


def stop_fixture(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is None:
        process.terminate()
    try:
        process.communicate(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.communicate()
