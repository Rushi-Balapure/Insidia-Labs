# 0008 No plaintext customer values

Anything a customer typed, uploaded, or that we captured is encrypted with AES-256-GCM before it reaches Postgres. Each org has wrapped data, secrets, and blind-index keys. Associated data is the org, table, column, and row, so a copied ciphertext does not decrypt in another row. Application roles are not superusers and do not bypass row-level security. Audit rows are append-only.
