# 0002 Relay mode and tunnel mode

The runner has two ways to reach a target. Relay mode forwards application messages and returns the response. Tunnel mode carries raw HTTP through an outbound WireGuard tunnel for classic web and API tests. Phase 0 does not implement either path. Both terminate in `engine/hub`.
