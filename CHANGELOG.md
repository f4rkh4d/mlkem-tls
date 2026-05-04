# changelog

format follows [keep-a-changelog](https://keepachangelog.com).
this project uses [semver](https://semver.org/).

## [0.2.0]

### added
- [`SECURITY.md`](SECURITY.md): public threat model, scope (the wire-byte concat + the shared-secret combiner), what we promise to fix immediately, vuln disclosure.
- [`SUPPLY_CHAIN.md`](SUPPLY_CHAIN.md): every runtime dep with role + maintainer + audit history. licence discipline note. reproducible-install recipe.
- `tests/wire_format.rs`: regression tests asserting the byte layout of every public type matches `draft-ietf-tls-ecdhe-mlkem-04 §1.5` (1216 / 1120 / 1600 / 1600 byte sizes for ek / ct across the two parameter sets, ML-KEM bytes first, X25519 bytes second).

### notes
- this is an audit-readiness release. no algorithm changes. brings the crate's documentation surface to parity with `mlkem-rs` 0.11.0.

## [0.1.0]

initial release.
