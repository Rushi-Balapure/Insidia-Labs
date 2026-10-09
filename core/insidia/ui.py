"""Terminal output for progress. Everything here writes to stderr.

Animation and color appear only on an interactive terminal. A pipe, a CI log,
NO_COLOR, or --quiet gets plain lines that read the same without them.
"""

from __future__ import annotations

import os
import sys
import threading
import time
from dataclasses import dataclass
from typing import TextIO

_FRAMES = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
_ORANGE = "38;5;208"
_CLEAR = "\r\x1b[K"


@dataclass(frozen=True)
class Event:
    """One step of a scan. The scan emits these. The terminal view draws them."""

    kind: str  # start | begin | end | note | write
    target: str = ""
    family: str = ""
    engines: tuple[str, ...] = ()
    result: str = ""  # pass | fail | skipped
    detail: str = ""
    seconds: float = 0.0


def wants_color(stream: TextIO, *, no_color: bool = False) -> bool:
    if no_color or os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    return stream.isatty() and os.environ.get("TERM", "") != "dumb"


def short(message: str, limit: int = 90) -> str:
    """First useful line of an engine error, without usage dumps or tracebacks."""
    for raw in message.splitlines():
        line = raw.strip()
        if not line or line.lower().startswith(("usage:", "for more information", "traceback")):
            continue
        line = line.removeprefix("error:").strip()
        if len(line) > limit:
            line = line[: limit - 1].rstrip() + "…"
        return line
    return "no detail"


def seconds_text(value: float) -> str:
    if value < 10:
        return f"{value:.1f}s"
    if value < 60:
        return f"{value:.0f}s"
    return f"{int(value // 60)}m{int(value % 60):02d}s"


class Terminal:
    """Styled lines plus one live line that shows what is running now."""

    def __init__(
        self,
        stream: TextIO | None = None,
        *,
        quiet: bool = False,
        animate: bool | None = None,
        no_color: bool = False,
    ) -> None:
        self.stream = stream if stream is not None else sys.stderr
        self.quiet = quiet
        self.color = wants_color(self.stream, no_color=no_color)
        interactive = self.stream.isatty() and os.environ.get("TERM", "") != "dumb"
        self.animate = interactive if animate is None else animate
        self.unicode = "utf" in (getattr(self.stream, "encoding", "") or "").lower()
        self._lock = threading.Lock()
        self._label = ""
        self._started = 0.0
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()

    # styling

    def paint(self, text: str, code: str) -> str:
        return f"\x1b[{code}m{text}\x1b[0m" if self.color else text

    def bold(self, text: str) -> str:
        return self.paint(text, "1")

    def dim(self, text: str) -> str:
        return self.paint(text, "2")

    def brand(self, text: str) -> str:
        return self.paint(text, f"1;{_ORANGE}")

    def symbol(self, result: str) -> str:
        glyphs = (
            {"pass": "✔", "fail": "✘", "skipped": "–", "note": "!", "ok": "✔"}
            if self.unicode
            else {"pass": "+", "fail": "x", "skipped": "-", "note": "!", "ok": "+"}
        )
        colors = {"pass": "32", "ok": "32", "fail": "31", "skipped": "33", "note": "33"}
        return self.paint(glyphs[result], colors[result])

    # output

    def line(self, text: str = "") -> None:
        if self.quiet:
            return
        with self._lock:
            self._erase()
            print(text, file=self.stream, flush=True)
            self._redraw()

    def start(self, label: str) -> None:
        """Begin the live line. Without a terminal this prints nothing yet."""
        if self.quiet:
            return
        self.stop_live()
        self._label = label
        self._started = time.monotonic()
        if not self.animate:
            # A log has no live line, so say what is running before it finishes.
            mark = "…" if self.unicode else "..."
            print(f"  {mark} {label}", file=self.stream, flush=True)
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._spin, daemon=True)
        self._thread.start()

    def stop_live(self) -> float:
        elapsed = time.monotonic() - self._started if self._started else 0.0
        thread = self._thread
        if thread is not None:
            self._stop.set()
            thread.join(timeout=1)
            self._thread = None
        with self._lock:
            self._erase()
            self._label = ""
        self._started = 0.0
        return elapsed

    # internals

    def _spin(self) -> None:
        index = 0
        while not self._stop.is_set():
            with self._lock:
                self._draw(index)
            index += 1
            self._stop.wait(0.1)

    def _draw(self, index: int) -> None:
        if not self._label:
            return
        frames = _FRAMES if self.unicode else "|/-\\"
        frame = self.paint(frames[index % len(frames)], _ORANGE)
        spent = seconds_text(time.monotonic() - self._started)
        self.stream.write(f"{_CLEAR}  {frame} {self._label} {self.dim(spent)}")
        self.stream.flush()

    def _erase(self) -> None:
        if self._thread is not None:
            self.stream.write(_CLEAR)

    def _redraw(self) -> None:
        if self._thread is not None:
            self._draw(0)


class ScanView:
    """Draws scan events: a header, one row per control, then totals."""

    def __init__(self, terminal: Terminal) -> None:
        self.terminal = terminal
        self._target = ""
        self.counts = {"pass": 0, "fail": 0, "skipped": 0}

    def __call__(self, event: Event) -> None:
        term = self.terminal
        if event.kind == "start":
            term.line(f"{term.brand('insidia')} {term.dim('· ' + event.detail)}")
        elif event.kind == "begin":
            if event.target != self._target:
                self._target = event.target
                term.line()
                term.line(term.bold(event.target))
            term.start(f"{event.family}  {term.dim(', '.join(event.engines))}")
        elif event.kind == "note":
            term.line(f"    {term.symbol('note')} {event.detail}")
        elif event.kind == "end":
            term.stop_live()
            self._row(event)
        elif event.kind == "write":
            term.stop_live()
            term.line()
            term.line(f"{term.dim(event.detail)}")

    def _row(self, event: Event) -> None:
        term = self.terminal
        self.counts[event.result] += 1
        label = {"pass": "pass", "fail": "FAIL", "skipped": "skipped"}[event.result]
        tint = {"pass": "32", "fail": "1;31", "skipped": "33"}[event.result]
        right = event.detail or ", ".join(event.engines)
        timing = seconds_text(event.seconds) if event.seconds else ""
        term.line(
            f"  {term.symbol(event.result)} {event.family:<30} "
            f"{term.paint(f'{label:<8}', tint)} {term.dim(right)} {term.dim(timing)}".rstrip()
        )

    def totals(self) -> str:
        c = self.counts
        parts = [f"{c['pass']} passed", f"{c['fail']} failed", f"{c['skipped']} skipped"]
        return " · ".join(parts)


class InstallView:
    """Turns the installer's messages into a spinner and a check line per engine."""

    def __init__(self, terminal: Terminal) -> None:
        self.terminal = terminal

    def __call__(self, message: str) -> None:
        term = self.terminal
        if message.startswith("Installing "):
            term.start(message.removesuffix("."))
            return
        elapsed = term.stop_live()
        timing = f" {term.dim(seconds_text(elapsed))}" if elapsed else ""
        term.line(f"  {term.symbol('ok')} {message}{timing}")
