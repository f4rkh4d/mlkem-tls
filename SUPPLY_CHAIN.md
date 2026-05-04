# supply chain

## runtime dependencies (release builds)

| crate          | role                                                | maintainer       | audit history                                                                                              |
|----------------|-----------------------------------------------------|------------------|------------------------------------------------------------------------------------------------------------|
| `mlkem-rs`     | post-quantum half (FIPS 203 ML-KEM)                 | @f4rkh4d         | not audited yet. has formal proofs of field + compression invariants and dudect-style timing evidence       |
| `x25519-dalek` | classical half (X25519)                             | dalek-cryptography | independently reviewed; widely used in audited stacks (rustls, IPFS, age)                                |
| `rand_core`    | `RngCore` + `CryptoRng` traits only                 | rust-random      | trait surface only, no crypto in this crate                                                                |
| `subtle`       | constant-time primitives                            | dalek-crypto     | constant-time hardening reviewed informally; widely used in audited stacks                                |
| `zeroize`      | wipe-on-drop                                        | RustCrypto       | small surface, audited transitively                                                                        |

dev-deps (`rand`, `hex`) are not part of any release artifact.

## license discipline

every dep here is under MIT, Apache-2.0, BSD-3-Clause, or ISC. nothing
permissive-incompatible.

## reproducible installation

```sh
cargo install --locked mlkem-tls --version 0.2.0
```

`--locked` makes cargo honor the lockfile shipped in the published
crate.

## why this dep set

minimal on purpose. anything bigger (a full TLS stack, a generic kem
trait, a pq-crypto framework) defeats the point of a stand-alone hybrid
combiner. you compose `mlkem-tls` into your protocol; `mlkem-tls` does
not compose anything into you.

## what we will not do

- pull in pre-1.0 crypto crates beyond `mlkem-rs` (which we own).
- add `unsafe` blocks. zero today, zero planned.
- accept git deps. only published crates.io versions.
