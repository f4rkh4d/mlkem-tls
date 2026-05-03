# changelog

format follows [keep-a-changelog](https://keepachangelog.com).
this project uses [semver](https://semver.org/).

## [0.1.0]

### added
- initial release. `X25519MlKem768` and `X25519MlKem1024` hybrid kems matching draft-ietf-tls-ecdhe-mlkem-04 byte order on the wire (ml-kem first, x25519 second).
- per-level newtypes: `EncapsKey768/1024`, `DecapsKey768/1024`, `Ciphertext768Hybrid`/`Ciphertext1024Hybrid`, `SharedSecret768Hybrid`/`SharedSecret1024Hybrid`. `Clone`, ct-eq `PartialEq`, `Zeroize` + `ZeroizeOnDrop` on the secret-bearing types.
- `TryFrom<&[u8]>` on every byte-typed newtype with a `LengthError` that names expected vs got.
- `as_bytes()` for fixed-size accessors and `AsRef<[u8]>` for the slice-typed callers.
- `no_std` support gated on the `std` default feature.
