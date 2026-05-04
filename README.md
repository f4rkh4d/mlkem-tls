# mlkem-tls

`X25519MLKEM768` and `X25519MLKEM1024` hybrid post-quantum kems, per [draft-ietf-tls-ecdhe-mlkem][1]. wire-format compatible with the TLS 1.3 codepoint `0x11EC`, which Cloudflare, Chrome, Firefox and `rustls >= 0.23.27` ship today. stand-alone, decoupled from any specific TLS library, RustCrypto-trait friendly, `no_std` compatible.

[![crates.io](https://img.shields.io/crates/v/mlkem-tls.svg)](https://crates.io/crates/mlkem-tls)
[![docs.rs](https://img.shields.io/docsrs/mlkem-tls)](https://docs.rs/mlkem-tls)
[![downloads](https://img.shields.io/crates/d/mlkem-tls.svg)](https://crates.io/crates/mlkem-tls)
[![ci](https://github.com/f4rkh4d/mlkem-tls/actions/workflows/ci.yml/badge.svg)](https://github.com/f4rkh4d/mlkem-tls/actions)
[![msrv](https://img.shields.io/badge/msrv-1.70-blue.svg)](#)
[![no_std](https://img.shields.io/badge/no__std-yes-success.svg)](#)
[![license](https://img.shields.io/crates/l/mlkem-tls.svg)](#license)

## why this exists

rustls already ships X25519MLKEM768 inside its TLS stack. but the hybrid combiner is wired into rustls and not exposed as a reusable kem. anyone outside rustls, custom QUIC stacks, Noise variants, MLS PQ ciphersuites, embedded TLS, HPKE PQ extensions, currently has to re-implement the byte concat and shared-secret combiner by hand. `x-wing` exists but is a different CFRG construction with a different byte layout, not wire-compatible with the TLS hybrid that browsers actually ship.

`mlkem-tls` is the TLS-WG hybrid combiner as a stand-alone crate, with the byte order and shared-secret layout pinned to the IETF draft.

## construction

- **classical half:** [x25519-dalek](https://crates.io/crates/x25519-dalek) (audited, constant-time)
- **post-quantum half:** [mlkem-rs](https://crates.io/crates/mlkem-rs) (FIPS 203 ML-KEM, pure rust)
- **combiner:** concatenation, ML-KEM bytes first. matches §1.5 of the draft. no kdf wrapper.

| variant            | encaps key | ciphertext | shared secret | TLS codepoint |
|--------------------|-----------:|-----------:|--------------:|--------------:|
| X25519MLKEM768     | 1216 B     | 1120 B     | 64 B          | 0x11EC        |
| X25519MLKEM1024    | 1600 B     | 1600 B     | 64 B          | (non-standard) |

byte order on the wire (matches the draft):

```
encaps_key   = mlkem_pk || x25519_pk
ciphertext   = mlkem_ct || x25519_eph_pk
shared_secret = mlkem_ss || x25519_ss
```

security falls back to the *stronger* of the two halves: a quantum adversary that breaks X25519 still cannot read traffic protected by the resulting key, and a classical adversary that breaks ML-KEM still cannot read traffic protected by it.

## install

```sh
cargo add mlkem-tls
```

## usage

```rust
use mlkem_tls::X25519MlKem768;
use rand::thread_rng;

let mut rng = thread_rng();

// bob: generate the long-term hybrid keypair, send ek over the wire.
let (bob_ek, bob_dk) = X25519MlKem768::keygen(&mut rng);

// alice: encapsulate against bob's encaps key.
let (ct, alice_ss) = X25519MlKem768::encapsulate(&bob_ek, &mut rng);

// bob: decapsulate to recover the same 64-byte shared secret.
let bob_ss = X25519MlKem768::decapsulate(&bob_dk, &ct);
assert_eq!(alice_ss.as_bytes(), bob_ss.as_bytes());
```

## features

- `std` (default): standard-library hooks on the dependencies.

disable defaults to compile against `core` + `alloc`:

```sh
cargo add mlkem-tls --no-default-features
```

## testing

`tests/round_trip.rs` covers honest handshake round-trip on both 768 and 1024, exact byte-size assertions per the draft, wire-byte serialization round-trip, and `TryFrom` length errors.

## audit readiness

documents at the repo root for anyone commissioning a third-party audit:

- [`SECURITY.md`](SECURITY.md) public threat model, scope, what is and is not under audit
- [`SUPPLY_CHAIN.md`](SUPPLY_CHAIN.md) every runtime dep with role + maintainer + audit history

the post-quantum half [`mlkem-rs`](https://github.com/f4rkh4d/mlkem-rs) ships its own audit-readiness pack (`SECURITY.md`, `SIDE_CHANNELS.md`, `AUDIT_SCOPE.md`, `FORMAL_VERIFICATION.md`, `SUPPLY_CHAIN.md`) plus 10 kani-verified formal proofs and a dudect-style timing harness.

## not audited

the post-quantum half delegates to [`mlkem-rs`](https://crates.io/crates/mlkem-rs), which is unaudited. for production cryptography please use rustls's built-in PQ provider, which ships rustcrypto's audited [`ml-kem`](https://crates.io/crates/ml-kem) plus the same X25519 hybrid combiner. this crate exists for stacks that don't use rustls and need the hybrid combiner as a stand-alone reusable kem.

## links

- [draft-ietf-tls-ecdhe-mlkem][1]
- [draft-ietf-tls-hybrid-design](https://datatracker.ietf.org/doc/draft-ietf-tls-hybrid-design/)
- [mlkem-rs](https://github.com/f4rkh4d/mlkem-rs)
- [x25519-dalek](https://github.com/dalek-cryptography/curve25519-dalek)
- [rustls PQ writeup](https://rustls.dev/perf/2024-12-17-pq-kx/)

[1]: https://datatracker.ietf.org/doc/draft-ietf-tls-ecdhe-mlkem/

## related crates

other small rust pieces shipped alongside this one:

- [`mlkem-rs`](https://github.com/f4rkh4d/mlkem-rs) FIPS 203 ML-KEM in pure rust (the post-quantum half this crate composes with x25519-dalek)
- [`bashward`](https://github.com/f4rkh4d/bashward) checkpoint and rewind for bash side-effects in claude code
- [`skill-scan`](https://github.com/f4rkh4d/skill-scan) local prompt-injection scanner for claude skills, MCP, AGENTS.md
- [`pluvgo`](https://github.com/f4rkh4d/pluvgo) fast neovim plugin manager, single rust binary, no neovim required to install

## license

dual-licensed under MIT or Apache-2.0, at your option.
