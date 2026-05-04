# security

## reporting a vulnerability

email **hello@frkhd.com** with subject `mlkem-tls security`. coordinated
disclosure preferred, embargo on request. please do not file a public
github issue for cryptographic findings.

## scope

`mlkem-tls` is a hybrid kem composition over two upstream crates:

- the post-quantum half is [`mlkem-rs`][1]. cryptographic concerns there
  are tracked in that crate's [`SECURITY.md`][2] / [`SIDE_CHANNELS.md`][3].
- the classical half is [`x25519-dalek`][4] from the audited
  curve25519-dalek family.

this crate adds:

1. the wire-byte concatenation defined by [draft-ietf-tls-ecdhe-mlkem][5]
2. the shared-secret combiner (ML-KEM ss followed by X25519 ss, no kdf)
3. `kem`-trait-shaped public api with constant-time equality + zeroize

these three steps are byte-shuffles and are themselves trivially
constant-time. no secret-dependent branches, no secret-indexed table
lookups.

## security claim

against a passive or active classical adversary: at least the security
of x25519. against a quantum adversary: at least the security of
ml-kem-768 (or ml-kem-1024 for `X25519MlKem1024`). hybrid composition
under standard assumptions implies the resulting kem is at least as
strong as the *stronger* of the two halves at any given moment, because
the shared secret is derived from both ML-KEM's ss and X25519's ss
concatenated.

## what is and is not audited

- **not audited.** no third-party security audit has been performed on
  this crate. its post-quantum dependency (`mlkem-rs`) is also not
  audited; its classical dependency (`x25519-dalek`) is.
- the wire-byte layout has been cross-checked against the IETF draft's
  size table. see `tests/round_trip.rs` for the assertions.
- if you need an audited hybrid path in production, use rustls 0.23.27+
  which ships X25519MLKEM768 inline using rustcrypto's audited
  `ml-kem` crate.

## what we promise to fix immediately

- any divergence from the wire byte order or sizes specified in
  [draft-ietf-tls-ecdhe-mlkem-04 §1.5][5].
- any panic on attacker-controlled bytes through the public api.
- any place a secret-dependent value reaches a non-`subtle`
  comparison or a branch.

## contact

- email: hello@frkhd.com
- github: [@f4rkh4d](https://github.com/f4rkh4d)

[1]: https://github.com/f4rkh4d/mlkem-rs
[2]: https://github.com/f4rkh4d/mlkem-rs/blob/main/SECURITY.md
[3]: https://github.com/f4rkh4d/mlkem-rs/blob/main/SIDE_CHANNELS.md
[4]: https://github.com/dalek-cryptography/curve25519-dalek
[5]: https://datatracker.ietf.org/doc/draft-ietf-tls-ecdhe-mlkem/
