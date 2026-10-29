# Changelog

Each `## ` heading is one release of the `insidia` CLI. The release workflow publishes the section whose version matches the pushed `v*` tag as the GitHub release notes.

## 1.0.0

The first versioned release of the Insidia CLI.

### Added

- `insidia --version` prints the release and the commit it was built from, such as `insidia 1.0.0 (v1.0.0)`.
- `insidia upgrade` checks GitHub for the latest release and reinstalls it with uv, pipx, or pip, whichever installed your copy. `insidia upgrade --check` only reports whether a newer release exists. Installed engines are kept.
- Each release attaches a Sigstore-signed wheel with `SHA256SUMS` and publishes a signed container image to `ghcr.io/rushi-balapure/insidia`.

### Install

```bash
uv tool install "git+https://github.com/Rushi-Balapure/Insidia-Labs-Argus@v1.0.0#subdirectory=core"
```

`pipx install` accepts the same URL. A copy installed before 1.0.0 has no `upgrade` command; run the install command above with `--force` once, then use `insidia upgrade` from then on.
