# Security Policy

## Reporting a vulnerability

Email **security@cyberwarriornetwork.com** with details and a reproduction. Do **not** open a
public issue for a vulnerability. We aim to acknowledge within 2 business days.

## Threat model (what this tool guarantees)

- **The pipeline never executes ingested code.** Sources are read as text or parsed as an AST.
- **No network calls in the core pipeline.** The receipt is signed locally; verification is offline.
- **Receipts are tamper-evident.** The Ed25519 signature covers a hash of the deterministic
  ontology; altering the evidence breaks verification. Receipts are *cert-only* — anyone can
  verify from the certificate alone, with no server and no trust in us.
- **Signing keys never leave the host.** The receipt private key is generated locally and is
  gitignored (`*.pem`, `receipt_ed25519*`); it must never be committed.

## Scope

In scope: the `openagentontology` package, the CI gate (`ci/`), and the receipt format.
Out of scope: third-party agents you scan (their behavior is what the tool *measures*).
