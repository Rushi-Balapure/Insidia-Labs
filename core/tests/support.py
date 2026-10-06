from insidia.config import RateLimit, Target


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
