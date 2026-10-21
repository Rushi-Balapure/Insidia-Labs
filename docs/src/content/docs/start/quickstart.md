---
title: Your first scan
description: Run your first Insidia security scan on localhost. Configure your app URL, check setup with doctor, run the L1 baseline, and review the HTML report.
---

You need [the CLI installed](/docs/start/install/) and your app running on localhost. This guide uses L1, the policy available in the current release. A model is optional for L1.

## 1. Set your app URL

Open a terminal in the project you want to test and point Insidia at the app that is already running:

```bash
insidia init --url http://127.0.0.1:PORT/path
```

Replace `PORT` and `path` with your app, for example `insidia init --url http://127.0.0.1:8081/chat`. A path that ends in `/chat` is written as a chat target. Pass `--kind` (`web`, `api`, `agent`, `rag`, or `mcp`) when it is something else. Init adds the host to `scope` only when it is localhost, `127.0.0.1`, or `::1`. A non-local host is refused until you edit the file and set `authorized: true` yourself.

Without `--url`, init still writes a sample `http://127.0.0.1:8080/chat` and tells you to set `targets.app.url` before you scan. If you already have `insidia.yaml`, keep it and review its targets.

## 2. Match the request

Open `insidia.yaml` before you scan when the defaults do not match your app. Match `kind`, `request_template`, and `response_selector` to the request and response your app actually uses.

A web target is sent as a `POST` with the payload in the body unless you set `method`. For a page that reads a query parameter, such as `/hello?name=...`, use `GET`:

```yaml
targets:
  - name: hello
    kind: web
    url: http://127.0.0.1:5000/hello
    method: GET
    query:
      name: "{{payload}}"
```

Insidia replaces `{{payload}}` with each attack string. Chat targets use `{{prompt}}` or `{{prompt_json}}` in `request_template` instead; see [Placeholders](/docs/start/config/#placeholders).

Keep `scope` on localhost for this first run. See [Configuration](/docs/start/config/) for target types and examples, and [Scope](/docs/start/scope/) before adding a host.

## 3. Check the setup

```bash
insidia doctor
```

Doctor checks Python, the config, configured model endpoints, and installed engines. It does not check that your target app responds correctly. Review its output and confirm your app is running.

## 4. Run L1

```bash
insidia scan --policy L1
```

| Exit code | Meaning | Next step |
| --- | --- | --- |
| `0` | The run completed and the policy passed. | Review the report's coverage and findings. |
| `1` | A check found a problem, so the policy failed. This holds even if another check did not finish. | Review the findings and fix the issues. |
| `2` | The run was incomplete with no finding, or an error stopped it. | Read the error or skipped checks; resolve setup problems before treating the result as a pass. |
| `130` | The run was cancelled. | Run it again when ready. |

For a local scope, `--yes` is unnecessary. A non-local host needs both your authorization in the config and `--yes` at scan time.

## 5. Review and repeat

```bash
insidia report --open
```

The run is saved in `.insidia/runs/<run-id>/`. [Read the report](/docs/concepts/report/) to check execution status, inspect the evidence, and choose fixes. After changing your app, run `insidia scan --policy L1` again to check it.

Built-in probes work without installing extra engines. See [Install engines](/docs/concepts/engines/) when you want to add tools or compare coverage.

If the run stops or is incomplete, use [Troubleshooting](/docs/guides/troubleshooting/). Once it works locally, [run it in CI](/docs/guides/ci/).
