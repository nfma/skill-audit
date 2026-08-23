# skill-audit Component Security Notes

This policy extends the repository-root `SECURITY.md` for the shipped CLI and
skill component.

## Component Boundary

The CLI scans prompt injection, tool misuse and exfiltration, sensitive-data
exposure, supply-chain risk, unexpected code execution, and behavioral
manipulation. Findings and compliance results are heuristic signals; their
absence is not a safety certification.

## Postinstall Contract

`scripts/postinstall.cjs` may detect CI and existing local hook configuration and
print an informational message. It must not install hooks, make network requests,
modify files, collect data, or execute scanned content. Hook installation remains
an explicit user action. Any change that weakens these constraints is security
relevant.
