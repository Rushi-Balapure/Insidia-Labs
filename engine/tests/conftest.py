import os

# Dev mode is the default for unit tests. Individual tests override it.
os.environ.setdefault("INSIDIA_DEV_MODE", "true")
