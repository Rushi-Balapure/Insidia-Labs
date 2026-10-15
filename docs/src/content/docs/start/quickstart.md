---
title: Your first scan
description: Write a config, scan localhost, and open the report.
---

You need [the CLI installed](/docs/start/install/) and your app running on localhost. This guide uses L1, the policy available in the current release. A model is optional for L1.

## 1. Create the configuration

Open a terminal in the project you want to test:

```bash
insidia init
```

This writes `insidia.yaml`. If you already have that file, keep it and review its targets.

## 2. Point it at your app

Open `insidia.yaml` **before you scan**. The generated target is a sample chat endpoint at `http://127.0.0.1:8080/chat`; replace it with your app's endpoint. Match `kind`, `request_template`, and `response_selector` to the request and response your app actually uses.

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
