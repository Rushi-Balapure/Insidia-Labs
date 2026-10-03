# 0006 The hub is Go inside the Python brain

`engine/hub` is Go because it terminates long-lived runner connections. It lives in the cloud brain, not in the customer runner. The runner is a separate Go module.
