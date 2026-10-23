"""Accessible presentation helpers for offline scan reports."""

from html import escape


def status_badge(result: str, *, uppercase: bool = False) -> str:
    """Keep an explicit label alongside each status color and symbol."""
    css = {
        "pass": "pass",
        "pass (low assurance)": "low",
        "fail": "fail",
        "info": "info",
        "not tested": "nt",
    }.get(result, "nt")
    label = result.upper() if uppercase else result
    if result == "pass (low assurance)" and uppercase:
        label = "PASS (low assurance)"
    return f'<span class="res res-{css}">{escape(label or "not tested")}</span>'
