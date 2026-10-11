---
title: insidia.yaml
description: Every field insidia init writes, and what you change before a real scan.
---

`insidia init` writes `insidia.yaml` in the current directory. A scan reads that file and nothing else. There is no URL argument on `insidia scan`.

This is the file it writes:

```yaml
version: 1
policy: L1
coverage: standard
scope:
  - host: localhost
  - host: 127.0.0.1
  - host: "::1"
targets:
  app:
    kind: chat
    url: http://127.0.0.1:8080/chat
    request_template: '{"messages": {{conversation_json}}}'
    response_selector: "$.choices[0].message.content"
    rate_limit:
      rps: 5
      concurrency: 1
# A model host must also be listed in scope.
models: {}
```

Change `targets` so `url` is your app before you treat a result as meaningful. Unknown fields are rejected.

## Top of the file

| Field | What to put |
| --- | --- |
| `version` | `1`. Any other number is an error. |
| `policy` | `L1`. That is the policy a scan runs. `L2` and `L3` are names only; a scan does not run them. |
| `coverage` | `standard` or `thorough`. `standard` picks one engine per check. `thorough` runs every installed engine that covers that check. |
| `scope` | The hosts Insidia is allowed to contact. At least one. |
| `targets` | The apps, APIs, or repositories to test. At least one. The key (`app` above) is the name that shows up in the report. |
| `models` | Optional. `attacker` and `judge` are the only keys. `{}` means no model. |

## scope

Each entry is one host.

| Field | What to put |
| --- | --- |
| `host` | Hostname only, such as `localhost` or `staging.example.com`. No scheme and no path. |
| `authorized` | `true` or `false`. Defaults to `false`. Anything other than localhost, `127.0.0.1`, or `::1` needs `true`, set by you. A scan of that host also needs `insidia scan --yes`. |

```yaml
scope:
  - host: 127.0.0.1
  - host: staging.example.com
    authorized: true
```

A host listed twice is an error. A model endpoint is a host too: if `models.attacker.base_url` points at another machine, that host has to be in `scope`. See [Scope](/docs/start/scope/).

## targets

The key under `targets` is the target name. These are the fields inside it.

| Field | Required | What to put |
| --- | --- | --- |
| `kind` | yes | `chat`, `agent`, `rag`, `mcp`, `web`, `api`, or `repo`. |
| `url` | for every kind except `repo` | Where to send the check, such as `http://127.0.0.1:8080/chat`. |
| `path` | for `repo` | Directory to scan, such as `.` or `services/api`. |
| `command` | instead of `url` on a non-repo target | A list of strings. Insidia runs that command instead of calling a URL. |
| `method` | no | HTTP method. Default `POST`. |
| `request_template` | no | Body template. `{{conversation_json}}` is replaced with the messages for that check. |
| `response_selector` | no | JSONPath into the response. The sample uses `$.choices[0].message.content`. |
| `query` | no | Query string as a map of strings. |
| `headers` | no | Extra request headers as a map of strings. |
| `auth` | no | How to send a credential. The secret stays in the environment. |
| `rate_limit` | no | `rps` (default `5`) and `concurrency` (default `1`). Both must be positive. |
| `api` | no | Request shape. Default `http`. Also `openai`, `anthropic`, `graphql`, or `grpc`. |
| `canary` | no | A string you plant so a leak can be recognized in the reply. |

`auth` looks like this. `scheme` defaults to `Bearer`. `secret_ref` is `env:` plus the variable name. The value is not written into the file.

```yaml
targets:
  app:
    kind: chat
    url: http://127.0.0.1:8080/chat
    auth:
      header: Authorization
      secret_ref: env:APP_TOKEN
      scheme: Bearer
```

A repository target has no URL:

```yaml
targets:
  repo:
    kind: repo
    path: .
```

## models

Leave this as `{}` when the checks do not need a model. L1 does not require one.

`attacker` and `judge` are the only roles. Each role has:

| Field | What to put |
| --- | --- |
| `provider` | Required. `openai-compatible`, `anthropic`, or `gemini`. For Ollama or OpenAI, use `openai-compatible`. |
| `base_url` | Optional endpoint. Its host must also be listed in `scope`. |
| `model` | Optional model name. |
| `secret_ref` | Optional. `env:NAME`, same rule as target auth. |

```yaml
models:
  attacker:
    provider: openai-compatible
    base_url: http://127.0.0.1:11434/v1
    model: llama3.1
```
