# HailMary bundle protocol v1

## Encoding

Bundles use UTF-8 JSON and JSON Canonicalization Scheme serialization for all cryptographic inputs. The parser applies a 64 MiB default file limit. `.hail` and `.mary` are data containers, never executables.

Top-level structure:

```json
{
  "format": "hailmary.bundle",
  "version": 1,
  "protected": {},
  "ciphertext": "BASE64",
  "signatures": []
}
```

The protected header contains the bundle and job IDs, kind, sender, timestamps, sender sequence, plaintext SHA-256, cipher suite, payload nonce and recipient key wraps.

## Cryptographic suite

| Purpose | Algorithm |
|---|---|
| Payload confidentiality and integrity | AES-256-GCM |
| Key agreement | ECDH over NIST P-256 |
| Key derivation | HKDF-SHA-256 |
| Bundle signatures | ECDSA P-256 with SHA-256 |
| Private-key protection | Argon2id and AES-256-GCM |
| Key identifiers | SHA-256 over DER SubjectPublicKeyInfo |

Every bundle gets a random 256-bit content-encryption key. The payload is encrypted once. For each recipient, HailMary creates an ephemeral P-256 key, derives an independent wrapping key and encrypts the content key. This permits the controller and designated reviewers to decrypt the same `.hail` without sharing private keys.

Signatures cover a domain separator, the canonical protected header and raw ciphertext. A co-signer can add a signature without changing the protected data or invalidating earlier signatures.

## Trust

A signature's `key_id` selects a pre-enrolled public key. The included identity label is never itself a trust anchor. The controller requires:

- Every submitted signature to be cryptographically valid and trusted
- At least one trusted signature belonging to the declared sender
- The configured number of distinct authorized operator identities
- Each counted signer to permit the action and its risk level

Revoked trust entries do not verify. Trust distribution and revocation cross the boundary through the organization's approved key ceremony.

## Replay and time controls

Each operator identity has a monotonically increasing sequence. A controller rejects a sequence equal to or lower than the latest accepted value for that sender. Bundle and job identifiers are unique database keys. `created_at`, `not_before` and `expires_at` are signed and must match the encrypted payload.

Sites must provide a trustworthy controller clock. Large clock rollback can interfere with validity enforcement and is outside the file format's ability to solve.

## Internal agent protocol

Agents use length-prefixed canonical JSON over TLS 1.3 mutual authentication. A frame begins with a four-byte unsigned big-endian payload length. The default maximum is 64 MiB.

Requests are `ping`, `claim` and `complete`. The controller validates the presented leaf-certificate SHA-256 against the configured fingerprint for the claimed node ID. Agents initiate every connection; they expose no management listener.

The internal protocol is distinct from the air-gap carrier. It does not cross the external security boundary.
