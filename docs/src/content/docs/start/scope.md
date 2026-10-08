---
title: Scope
description: Insidia scans only hosts you list, and non-local hosts need authorized true.
---

Every URL Insidia calls must sit on a host in `scope`. `insidia init` writes:

```yaml
scope:
  - host: localhost
  - host: 127.0.0.1
  - host: "::1"
```

Those three are local. To scan anything else, add the host and set `authorized: true` yourself:

```yaml
scope:
  - host: localhost
  - host: staging.example.com
    authorized: true
```

`authorized: true` is your statement that you may test that host. An agent must not add it unless you asked for that host. A scan that includes a non-local host also needs `--yes`.

Rate limits on a target default to a small number of requests per second. Keep them on.

A model endpoint is a host too. If you set `models.attacker` or `models.judge` to a URL, that host has to be in scope.

Insidia does not scan a host just because it appears in a link inside your app.
