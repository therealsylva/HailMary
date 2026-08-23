# Threat model

## Security objectives

- Only pre-enrolled operators can authorize jobs
- High-risk jobs require independent authorized identities
- Bundle modification, substitution and replay are detected
- Only intended recipients can read bundle payloads
- Internal nodes accept work only from the enrolled controller connection
- Jobs cannot select arbitrary filesystem paths, services or commands
- Results retain job and node attribution
- Audit deletion or modification becomes detectable from the first changed entry onward

## Assumptions

- Initial public-key and certificate enrollment occurs through an authenticated physical ceremony
- Private-key passwords, host access controls and TLS private keys remain protected
- The controller and agents have trustworthy clocks within the organization's permitted skew
- The protected internal network permits agent-initiated TLS connections to the controller
- Transfer stations enforce media policy before a bundle reaches HailMary
- Local administrators define safe task policies and command profiles

## Addressed threats

| Threat | Control |
|---|---|
| Modified bundle | ECDSA signatures and AES-GCM authentication |
| Stolen inbound media | Recipient encryption |
| Replayed instruction | Unique IDs, persistent monotonic sender sequences and expiry |
| One compromised operator | Configurable two-person approval for disruptive/critical actions |
| Path traversal or symlink escape | Named paths, canonical confinement and symlink rejection |
| Arbitrary command injection | Typed actions, fixed local argv profiles and no shell |
| Agent impersonation | TLS client CA plus exact leaf-certificate fingerprint enrollment |
| Controller impersonation | Agent-pinned CA and TLS server-name verification |
| Crash-induced duplicate mutation | Persistent execution journal and uncertain-state refusal |
| Audit-row modification | SHA-256 hash chain verified by `controller audit-verify` |
| Partially copied `.hail` | Stable-file delay plus metadata checks before local spooling |
| USB removal during import | Complete local copy is made before verification and queueing |
| Repeated file or listener restart | Content-addressed archive and exact-bundle idempotency |
| Malformed automatic input | Normal bundle limits and verification, then local quarantine |
| Unbounded data processing | Bundle, frame, log, output and artifact limits |

## Residual risks

- A compromised controller can dispatch jobs that already satisfy its local policy context and can forge controller-signed `.mary` files.
- Enough compromised authorized operators can approve malicious but syntactically valid work.
- USB firmware attacks, malicious filesystem drivers and transfer-station compromise are outside the bundle parser.
- Deleting the end of an audit database is not detectable without exporting or anchoring the latest audit head elsewhere.
- Software key files remain accessible to a host administrator after the password is supplied. High-assurance deployments should integrate a TPM, smart card or HSM backend.
- Task-specific native tools can have their own vulnerabilities and side effects.
- Denial of service through media destruction, job withholding or database deletion is not prevented.

HailMary is not a cross-domain certification by itself. The complete deployment—including people, media, transfer stations, operating systems and physical controls—requires independent assessment.
