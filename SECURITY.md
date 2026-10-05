# Security

## Reporting a vulnerability

Email [insidialabs@gmail.com](mailto:insidialabs@gmail.com). Please do not open a public issue for a vulnerability in Insidia itself.

Include what you ran, the version or commit, and the impact. We will reply with a plan and a credit, if you want one, once a fix is ready.

## Scanning other people's systems

Insidia is a security testing tool. Point it only at systems you are allowed to test.

- The CLI scans hosts listed in `insidia.yaml`.
- Any host other than localhost needs `authorized: true` from the person who owns the target.
- Do not use Insidia Cloud, the hosted models, or a local run to attack a system you do not have permission to test.

## Secrets

Do not commit credentials, customer data, or scan evidence. Production configuration stays out of this repository.
