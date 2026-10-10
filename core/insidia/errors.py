"""Failures the CLI can explain without a stack trace."""


class CliError(Exception):
    def __init__(self, message: str, code: int = 2) -> None:
        super().__init__(message)
        self.code = code


class ConfigError(CliError):
    pass


class ScopeError(CliError):
    pass


class EngineFailed(CliError):
    """An upstream engine is missing or did not produce a report."""


class ProbeError(CliError):
    """This check did not receive a usable response from the target."""
