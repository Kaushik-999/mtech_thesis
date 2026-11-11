# Glossary

| Term | Beginner-friendly meaning |
|---|---|
| Aadhaar Secure QR | An issuer-defined signed QR credential format; this project does not implement its real parser |
| Artefact | One concrete issued object or byte string, such as one QR envelope |
| Authentication | Establishing a particular claim about origin or identity under a defined trust model |
| Base64 | Reversible representation of bytes as printable characters; not encryption |
| Binding | An authenticated relationship between a credential and a subject/status record |
| Byte | An eight-bit unit of data; signatures operate on exact sequences of bytes |
| Canonical encoding | A defined, deterministic representation of permitted data |
| Certificate | A signed statement about a public key, often including identity, purpose, and validity dates |
| Credential | An issuer's statement about a subject; not necessarily proof of current status |
| Credential ID | A label for a credential; may change when it is reissued |
| Decoder | Software that turns QR pixels into message bytes |
| Deactivation / revocation | An issuer's lifecycle decision; this prototype does not determine either |
| DER / PEM / SPKI | DER is a binary ASN.1 encoding; PEM wraps bytes as text; SubjectPublicKeyInfo describes a public key |
| Digital signature | A private-key-generated value used to check integrity and key origin of a message |
| Encoding | Representing data in a format; generally reversible and not secret |
| Encryption | Protecting content so only holders of suitable secrets can recover it; not performed here |
| Fingerprint | A digest of a specific object; useful for comparison but not automatically trusted |
| Freshness | How recent the evidence is relative to the decision being made |
| Hash / digest | A fixed-length function of bytes; collisions are possible in principle |
| Identity-level status | A lifecycle decision about one issuer identity, potentially covering many credentials |
| Integrity | Detectability of unauthorized changes to protected bytes |
| Issuer | The entity that signs and is responsible for a credential |
| Key rotation | Replacing signing keys while defining which historical keys/signatures remain acceptable |
| Linkability | The ability to connect multiple observations to the same object or subject |
| MGF1 | A mask generation function used inside RSA-PSS; its hash choice is part of the protocol |
| Offline | The verification operation can run without contacting a network service |
| Opaque ID | A label without directly readable identity fields; still potentially linkable |
| Parser | Software that interprets message structure; parsing does not establish authenticity |
| Pigeonhole principle | More objects than containers force at least one container to hold multiple objects |
| Pin / trust anchor | Independently accepted key material or a key fingerprint used by local trust policy |
| Private/public key | Secret signing material and shareable verification material in this project |
| PSS | Probabilistic Signature Scheme: the RSA signature encoding chosen for the synthetic protocol |
| QR code | A visual representation of data with error correction; not inherently authentic or secret |
| Replay | Reusing an old valid presentation; not prevented by a signature alone |
| RSA | The asymmetric cryptographic system used through the cryptography library |
| Salt | Random input in PSS, making repeated signatures potentially different |
| SHA-256 | A hash function producing a 256-bit digest |
| Status handle | An issuer-defined lookup label whose relation to a status record must be authenticated |
| Synthetic | Created for research with fictional data and no UIDAI issuance claim |
| Trust | A policy decision that a specific key is authorized for a specific purpose |
| UUIDv4 | A random identifier with 122 random bits; negligible collision probability is not a registry guarantee |
| Verification | Checking a specified condition; always state whether it means syntax, signature, trust, or status |
| Virtual environment | A project-specific Python installation/dependency environment |

