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
| Deactivation / revocation | An issuer's lifecycle decision; Phase 2 simulates permanent subject deactivation and per-credential revocation, never real UIDAI status |
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
| Assigned count | Number of allocated positions signed into a snapshot; unused byte padding is not an assigned credential |
| Atomic transaction | A group of database changes that commits together or leaves the previous committed state |
| Binding sidecar | A separate signed assertion supplied with a credential, authenticating its relationship to a list position |
| Bitmap / bitstring | A packed sequence of bits; this research list uses one bit per credential |
| Credential-level revocation | Cancelling one issued credential without necessarily deactivating its subject or siblings |
| Dense allocation | Assigning positions 0, 1, 2, … without gaps or reuse within a list namespace |
| Epoch | An issuer's increasing snapshot version number; it is not a time source |
| Equivocation | An issuer authenticates inconsistent statements, such as different snapshots with the same epoch |
| Expiry | Exclusive deadline after which a snapshot must not be accepted under this policy |
| Fan-out | Number of credential positions affected when one private subject is deactivated |
| Full update | Transfer of the complete signed snapshot; it is not a delta |
| High-water epoch | Highest accepted version retained as local rollback history |
| Internal subject ID | Fictional issuer-private identity identifier that groups several credentials; absent from public snapshots |
| LSB0 | Least significant bit is position zero within each byte: index i uses mask 1 shifted by i modulo 8 |
| Maximum snapshot age | Local policy limiting the interval between signed issued-at and verifier time |
| NOT_REVOKED_AS_OF_SNAPSHOT | Assigned position is zero in an authentic acceptable snapshot; no guarantee about unseen later events |
| p95 | A percentile statistic; this benchmark uses nearest rank over seven samples, and lookup samples are batch means |
| Permanent revocation | This experimental rule allows a bit to change from 0 to 1 only; reactivation is absent |
| Reissuance | Giving an enabled subject another credential with a fresh UUID and fresh status index |
| Role trust | Separately authorizing keys for credential, binding and snapshot statements |
| Rollback | Presenting or restoring an older state after a newer state was accepted |
| Snapshot | An issuer-signed complete status view with namespace, epoch, time bounds and assigned count |
| Stable index linkability | Ability to associate presentations that reveal the same list/index pair |
| STALE_SNAPSHOT | Authenticated evidence fails the selected age or expiry rule, so no accepted bit decision is returned |
| Status index | Unique integer position allocated to a credential within a named list; not a private subject ID |
| Synchronization | Receiving and authenticating a newer snapshot and durably updating verifier state |
| Trusted clock | A time source whose behavior is suitable for a security policy; signatures on timestamps do not supply one |
| Witness | In future accumulator work, auxiliary proof data for a membership or non-membership statement; not implemented here |
| Zero knowledge | A cryptographic proof property that does not follow merely from omitting names or using opaque indices |

