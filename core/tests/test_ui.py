import io

import pytest
from insidia.adapters import has_standalone
from insidia.ui import Event, InstallView, ScanView, Terminal, short


class _Stream(io.StringIO):
    encoding = "utf-8"


def _terminal(stream: io.StringIO) -> Terminal:
    return Terminal(stream, animate=False, no_color=True)


def test_short_keeps_one_useful_line_of_an_engine_error() -> None:
    raw = (
        "dalfox exited 2: error: the following required arguments were not provided:\n"
        "  --url <URL>\n\nUsage: dalfox url --url <URL> --format <FORMAT>\n"
    )
    assert (
        short(raw) == "dalfox exited 2: error: the following required arguments were not provided:"
    )
    assert short("") == "no detail"
    assert len(short("x" * 500)) == 90


def test_plain_output_has_no_escape_codes() -> None:
    stream = _Stream()
    view = ScanView(_terminal(stream))
    view(Event("start", detail="scan · policy L1 · coverage standard · 1 target"))
    view(Event("begin", "shop", "web.ssti", ("zap", "nuclei")))
    view(Event("note", "shop", "web.ssti", detail="dalfox: could not scan"))
    view(Event("end", "shop", "web.ssti", ("zap", "nuclei"), "fail", "", 9.4))
    view(Event("end", "shop", "web.ssrf", result="skipped", detail="no engine installed"))
    text = stream.getvalue()
    assert "\x1b" not in text
    assert "web.ssti" in text and "FAIL" in text and "9.4s" in text
    assert "dalfox: could not scan" in text
    assert view.totals() == "0 passed · 1 failed · 1 skipped"


def test_quiet_prints_nothing() -> None:
    stream = _Stream()
    terminal = Terminal(stream, quiet=True, animate=False, no_color=True)
    ScanView(terminal)(Event("start", detail="scan"))
    InstallView(terminal)("Installing bandit 1.9.4.")
    assert stream.getvalue() == ""


def test_install_view_prints_one_check_per_engine() -> None:
    stream = _Stream()
    view = InstallView(_terminal(stream))
    view("Installing bandit 1.9.4.")
    view("installed bandit 1.9.4")
    assert "installed bandit 1.9.4" in stream.getvalue()


def test_no_color_env_wins_over_force_color(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NO_COLOR", "1")
    monkeypatch.setenv("FORCE_COLOR", "1")
    assert Terminal(_Stream()).color is False


def test_arithmetic_product_must_be_its_own_token() -> None:
    assert has_standalone("49", "result: 49")
    assert not has_standalone("49", "width:-1.2549019608%")
    assert not has_standalone("49", "at 12:49")
    assert not has_standalone("49", "49%")
