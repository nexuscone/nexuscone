# Security policy

Nexuscone is a cryptographic audit primitive. A subtle bug in the hash chain, the signing layer, or the anchor verification path can silently weaken the integrity guarantees an operator believes they have. We take security reports seriously and respond fast.

## Reporting a vulnerability

Please do not file a public GitHub issue for a security report.

Report security issues by email to **`osi@aperintel.com`** with the subject line `[Nexuscone Security]`. Encrypt sensitive details with the maintainer's public key if you have it; otherwise plaintext is acceptable for an initial contact.

Include in your report:

- The affected version or versions (`pip show nexuscone` for installed version, or the commit SHA if you are testing `main`).
- A clear description of the issue and the impact you observed.
- A minimal reproducer if you have one.
- Whether you have publicly disclosed any part of the issue already (and where).
- Any proposed fix or mitigation, if you have one in mind.

You will receive an acknowledgement within **72 hours**. We aim to confirm whether the report reproduces and to share a preliminary fix timeline within **7 days**. For critical issues affecting the chain integrity, signature path, or anchor verification, we will prioritise a patch release within **14 days** of confirmation.

## Disclosure policy

We follow coordinated disclosure. Once a fix is released, we will:

- Publish a GitHub Security Advisory describing the issue, the affected versions, the fix, and any required operator action.
- Credit the reporter in the advisory by name and link, unless the reporter requests anonymity.
- Bump the package on PyPI with a patch version and note the security fix in the changelog.

We do not run a paid bug-bounty programme at this time. We are happy to acknowledge reporters publicly and to provide a written reference for security researchers who help us.

## Scope

In scope:

- The `nexuscone` package as published on PyPI.
- The `nexuscone-verify` CLI binary.
- The optional signing extra (`nexuscone[signing]`).
- The optional anchor backends (OpenTimestamps integration, RFC 3161 client).
- The chain hash format and verification protocol.

Out of scope:

- Operator misconfiguration (for example, storing the private signing key in a public location).
- Vulnerabilities in dependencies that we cannot fix from our side; please report those upstream and let us know so we can pin or work around.
- Generic denial-of-service issues against any service the operator chooses to run on top of Nexuscone.

## Supported versions

Security fixes are backported to:

| Version line | Supported |
|---|---|
| 0.2.x         | Yes |
| 0.1.x         | No, upgrade to 0.2.x |
| `main`        | Tracking |

Older lines are not maintained. If you cannot upgrade, please get in touch and we will discuss the smallest viable patch.

## Cryptographic primitives

Nexuscone uses well-established primitives from established libraries. We do not roll our own crypto. If you find a soundness issue in a primitive itself, please report it upstream first; we will track the fix and bump our pin.

| Primitive | Library |
|---|---|
| SHA-256 hash chain  | Python `hashlib` (stdlib, OpenSSL-backed) |
| Ed25519 signing     | `cryptography` |
| RFC 3161 timestamping | `rfc3161-client` |
| OpenTimestamps anchoring | `opentimestamps` |

## Thank you

Independent reviewers and security researchers materially improve the integrity guarantees the substrate offers. If you have spent time investigating, please tell us. We would rather hear about a problem than not.
