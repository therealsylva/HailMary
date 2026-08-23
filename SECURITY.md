# Security policy

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability. Use GitHub's private vulnerability reporting feature for this repository and include:

- The affected version or commit
- Reproduction conditions
- Security impact
- Whether disclosure is time-sensitive
- A proposed remediation, if available

Reports should not contain real operational keys, production bundles, customer data or protected network details.

## Scope

The following are treated as security boundaries:

- `.hail`, `.mary`, `.hmpub` and `.hmk` parsing
- Signature, encryption, key derivation and trust decisions
- Approval thresholds and replay protection
- Controller/agent mutual TLS and certificate enrollment
- Path confinement, task allowlists and command profiles
- Audit-chain integrity and agent execution journals

HailMary does not make removable media intrinsically safe. Transfer-station hardening, malware scanning, physical custody, host full-disk encryption, operating-system access control and organizational key ceremonies remain deployment responsibilities.

## Supported versions

Until the first stable release, only the latest tagged release receives security fixes.
