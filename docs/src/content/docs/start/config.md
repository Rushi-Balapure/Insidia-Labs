---
title: insidia.yaml
description: Configure insidia.yaml for AI and application security scans. Set targets, request formats, allowed hosts, credentials, model endpoints, and engine options.
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
| `url` | for every kind except `repo` | Where to send the check, such as `http://127.0.0.1:8080/chat`. The path may hold `{{payload}}`, as in `http://127.0.0.1:8000/users/{{payload}}`. |
| `path` | for `repo` | Directory to scan, such as `.` or `services/api`. |
| `command` | no | A list of strings accepted by the schema. Local command execution is not available in this release; use a URL target. |
| `method` | no | HTTP method. Default `POST`. Set `GET` for an app that reads the attack from the query string or the path. |
| `request_template` | no | Body template for `POST`. See [Placeholders](#placeholders). |
| `response_selector` | no | JSONPath into the response. The sample uses `$.choices[0].message.content`. |
| `query` | no | Query string as a map of strings. Put a placeholder in a value, as in `name: "{{payload}}"`. |
| `headers` | no | Extra request headers as a map of strings. |
| `auth` | no | How to send a credential. The secret stays in the environment. |
| `rate_limit` | no | `rps` (default `5`) and `concurrency` (default `1`). Both must be positive. With `concurrency` above 1, a check sends that many payloads at once, which speeds up a slow target. |
| `timeout` | no | Seconds to wait for one reply, from 1 to 900. Default `60`. Raise it for a model that takes longer to answer. |
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

### Placeholders

Each check sends many attack strings. A placeholder marks where each one goes. Without one, a `GET` target receives the same request every time and nothing is tested.

| Placeholder | Replaced with | Use it in |
| --- | --- | --- |
| `{{payload}}` | The attack string as is. | `query` values, the `url` path, `request_template` |
| `{{prompt}}` | Same as `{{payload}}`. Reads better for a chat app. | `request_template` |
| `{{prompt_json}}` | The attack as a JSON string literal, quotes included. | `request_template`, so quotes and newlines in the attack stay valid JSON |
| `{{conversation_json}}` | A JSON array with one `{"role": "user", "content": ...}` message. | `request_template` for OpenAI-style message lists |

With no `request_template`, a `POST` sends `{"prompt": "<attack>"}`. `api: openai` and `api: anthropic` send a `messages` list instead.

### A web app that reads the query string

The default method is `POST`. An app that reads `?name=` answers a `POST` with an error such as HTTP 405 or 501, and the scan stops that target with a hint. Set `method: GET` and put the placeholder in `query`. A placeholder written into the URL, as in `url: http://127.0.0.1:5000/hello?name={{payload}}`, works too, but it still needs `method: GET`.

```yaml
targets:
  shop:
    kind: web
    url: http://127.0.0.1:5000/hello
    method: GET
    query:
      name: "{{payload}}"
  users:
    kind: api
    url: http://127.0.0.1:5000/users/{{payload}}
    method: GET
```

### A chat app with its own JSON shape

```yaml
targets:
  bot:
    kind: chat
    url: http://127.0.0.1:8080/chat
    request_template: '{"message": {{prompt_json}}}'
    response_selector: "$.reply"
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

L1 does not call the judge.

`attacker` and `judge` are the only roles. Each role has:

| Field | What to put |
| --- | --- |
| `provider` | Required. `openai-compatible`, `anthropic`, or `gemini`. For Ollama or OpenAI, use `openai-compatible`. |
| `base_url` | Required when configuring a role for a scan. Its host must also be listed in `scope`. |
| `model` | Required when configuring a role for a scan. The model name served by the endpoint. |
| `secret_ref` | Optional. `env:NAME`, same rule as target auth. |

```yaml
models:
  attacker:
    provider: openai-compatible
    base_url: http://127.0.0.1:11434/v1
    model: llama3.1
```

This example also needs `127.0.0.1` in `scope`. The full generated config above already includes it.
