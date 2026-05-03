//! # mlkem-tls
//!
//! `X25519MLKEM768` and `X25519MLKEM1024` hybrid post-quantum kems, per
//! [draft-ietf-tls-ecdhe-mlkem][1]. wire-format compatible with the
//! TLS 1.3 codepoint `0x11EC`, which Cloudflare, Chrome, Firefox and
//! `rustls >= 0.23.27` ship today.
//!
//! ## hybrid construction
//!
//! - **classical half:** [x25519-dalek][2] (audited, constant-time).
//! - **post-quantum half:** [mlkem-rs][3] (FIPS 203 ML-KEM in pure rust).
//! - **combiner:** concatenation of the two shared secrets, ML-KEM first.
//!   no kdf wrapper. matches §1.5 of draft-ietf-tls-ecdhe-mlkem-04.
//!
//! the wire byte order also matches the draft: ML-KEM bytes come first,
//! X25519 bytes come second, both for public keys (sent client to server)
//! and ciphertext (sent server to client).
//!
//! security falls back to the *stronger* of the two halves: a quantum
//! adversary that breaks X25519 still cannot read traffic protected by
//! the resulting key, and a classical adversary that breaks ML-KEM still
//! cannot read traffic protected by it.
//!
//! ## quick start
//!
//! ```
//! use mlkem_tls::X25519MlKem768;
//! use rand::thread_rng;
//!
//! let mut rng = thread_rng();
//!
//! // bob: generate the long-term hybrid keypair, send the encaps key over the wire.
//! let (bob_ek, bob_dk) = X25519MlKem768::keygen(&mut rng);
//!
//! // alice: encapsulate against bob's encaps key.
//! let (ct, alice_ss) = X25519MlKem768::encapsulate(&bob_ek, &mut rng);
//!
//! // bob: decapsulate to recover the same 64-byte shared secret.
//! let bob_ss = X25519MlKem768::decapsulate(&bob_dk, &ct);
//! assert_eq!(alice_ss.as_bytes(), bob_ss.as_bytes());
//! ```
//!
//! ## variants
//!
//! - [`X25519MlKem768`]: TLS codepoint `0x11EC`. encaps key 1216 B, ciphertext 1120 B,
//!   shared secret 64 B. this is the one browsers ship.
//! - [`X25519MlKem1024`]: non-standard symmetric variant for those who want the
//!   higher security category. encaps key 1600 B, ciphertext 1600 B,
//!   shared secret 64 B.
//!
//! ## features
//!
//! - `std` (default): standard-library hooks on the dependencies. disable for
//!   `no_std` + `alloc` builds (cortex-m, wasm32).
//!
//! ## not audited
//!
//! the post-quantum half delegates to `mlkem-rs`, which is unaudited. for
//! production cryptography, please use rustls's built-in PQ provider, which
//! ships rustcrypto's audited `ml-kem` plus the same X25519 hybrid combiner.
//! this crate exists for stacks that don't use rustls (custom QUIC, MLS PQ
//! ciphersuites, HPKE PQ extensions, embedded TLS) and need the hybrid
//! combiner as a stand-alone reusable kem.
//!
//! [1]: https://datatracker.ietf.org/doc/draft-ietf-tls-ecdhe-mlkem/
//! [2]: https://crates.io/crates/x25519-dalek
//! [3]: https://crates.io/crates/mlkem-rs

#![cfg_attr(not(feature = "std"), no_std)]
#![warn(clippy::all, clippy::pedantic)]
#![warn(missing_debug_implementations)]
#![allow(clippy::missing_errors_doc, clippy::missing_panics_doc)]

use rand_core::{CryptoRng, RngCore};
use subtle::ConstantTimeEq;
use x25519_dalek::{PublicKey as XPub, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// length of the X25519 public key in bytes.
pub const X25519_BYTES: usize = 32;

/// length of the X25519 shared secret in bytes.
pub const X25519_SS_BYTES: usize = 32;

/// length of the ML-KEM portion of the shared secret in bytes.
pub const MLKEM_SS_BYTES: usize = 32;

/// total hybrid shared-secret length: ML-KEM ss (32) || X25519 ss (32).
pub const SHARED_SECRET_BYTES: usize = MLKEM_SS_BYTES + X25519_SS_BYTES;

/// returned when bytes handed to `try_from` have the wrong length.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LengthError {
    pub expected: usize,
    pub got: usize,
}

impl core::fmt::Display for LengthError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "wrong byte length: expected {}, got {}",
            self.expected, self.got
        )
    }
}

#[cfg(feature = "std")]
impl std::error::Error for LengthError {}

// internal helper: build an x25519 secret from 32 random bytes.
fn x25519_keypair_from_seed(seed: [u8; 32]) -> (StaticSecret, XPub) {
    let sk = StaticSecret::from(seed);
    let pk = XPub::from(&sk);
    (sk, pk)
}

// internal helper: hand a CryptoRng's bytes to x25519 and the rest to ml-kem.
fn fill_seed_pair<R: RngCore + CryptoRng>(rng: &mut R) -> ([u8; 32], [u8; 64]) {
    let mut x = [0u8; 32];
    let mut m = [0u8; 64];
    rng.fill_bytes(&mut x);
    rng.fill_bytes(&mut m);
    (x, m)
}

// per the draft, ML-KEM-768 secret-key serialized form already includes ek + h(ek) + z;
// for the hybrid we additionally store the X25519 secret alongside.

/// macro instantiating one hybrid level. `$pq` is the pure-rust ml-kem entry
/// point, `$pq_pk`/`$pq_sk`/`$pq_ct` are its byte sizes.
macro_rules! hybrid_kem {
    ($name:ident, $pq:ident, $pq_pk_ty:ident, $pq_sk_ty:ident, $pq_ct_ty:ident,
     $ek_ty:ident, $dk_ty:ident, $ct_ty:ident, $ss_ty:ident,
     $pq_pk:expr, $pq_sk:expr, $pq_ct:expr,
     $ek_size:expr, $dk_size:expr, $ct_size:expr) => {
        #[derive(Debug)]
        pub struct $name;

        impl $name {
            /// encaps-key size on the wire (ML-KEM ek then X25519 pub).
            pub const ENCAPSULATION_KEY_SIZE: usize = $ek_size;
            /// decaps-key opaque size (ML-KEM dk then X25519 secret).
            pub const DECAPSULATION_KEY_SIZE: usize = $dk_size;
            /// hybrid ciphertext size on the wire (ML-KEM ct then X25519 pub).
            pub const CIPHERTEXT_SIZE: usize = $ct_size;
            /// 64-byte hybrid shared secret (ML-KEM ss || X25519 ss).
            pub const SHARED_SECRET_SIZE: usize = SHARED_SECRET_BYTES;

            pub fn keygen<R: RngCore + CryptoRng>(rng: &mut R) -> ($ek_ty, $dk_ty) {
                let (x_seed, m_seed) = fill_seed_pair(rng);
                let (xsk, xpk) = x25519_keypair_from_seed(x_seed);
                let (mpk, msk) = mlkem::$pq::keygen_deterministic(&m_seed);

                let mut ek = [0u8; $ek_size];
                ek[..$pq_pk].copy_from_slice(mpk.as_bytes());
                ek[$pq_pk..].copy_from_slice(xpk.as_bytes());

                let mut dk = [0u8; $dk_size];
                dk[..$pq_sk].copy_from_slice(msk.as_bytes());
                dk[$pq_sk..].copy_from_slice(&xsk.to_bytes());

                ($ek_ty(ek), $dk_ty(dk))
            }

            pub fn encapsulate<R: RngCore + CryptoRng>(
                ek: &$ek_ty,
                rng: &mut R,
            ) -> ($ct_ty, $ss_ty) {
                let mpk_bytes: &[u8; $pq_pk] =
                    (&ek.0[..$pq_pk]).try_into().expect("ek length checked");
                let xpk_bytes: &[u8; X25519_BYTES] =
                    (&ek.0[$pq_pk..]).try_into().expect("ek length checked");
                let mpk = mlkem::$pq_pk_ty::from_bytes(mpk_bytes);
                let xpk = XPub::from(*xpk_bytes);

                // ml-kem encapsulate
                let (mct, mss) = mlkem::$pq::encapsulate(&mpk, rng);

                // ephemeral x25519 keypair, agree with the responder's public key.
                let mut x_seed = [0u8; 32];
                rng.fill_bytes(&mut x_seed);
                let xsk = ReusableSecretWrapper::from(x_seed);
                let xpk_eph = XPub::from(&xsk.0);
                let xss = xsk.0.diffie_hellman(&xpk);

                let mut ct = [0u8; $ct_size];
                ct[..$pq_ct].copy_from_slice(mct.as_bytes());
                ct[$pq_ct..].copy_from_slice(xpk_eph.as_bytes());

                let mut ss = [0u8; SHARED_SECRET_BYTES];
                ss[..MLKEM_SS_BYTES].copy_from_slice(mss.as_bytes());
                ss[MLKEM_SS_BYTES..].copy_from_slice(xss.as_bytes());

                ($ct_ty(ct), $ss_ty(ss))
            }

            pub fn decapsulate(dk: &$dk_ty, ct: &$ct_ty) -> $ss_ty {
                let msk_bytes: &[u8; $pq_sk] =
                    (&dk.0[..$pq_sk]).try_into().expect("dk length checked");
                let xsk_bytes: &[u8; X25519_BYTES] =
                    (&dk.0[$pq_sk..]).try_into().expect("dk length checked");
                let msk = mlkem::$pq_sk_ty::from_bytes(msk_bytes);
                let xsk = StaticSecret::from(*xsk_bytes);

                let mct_bytes: &[u8; $pq_ct] =
                    (&ct.0[..$pq_ct]).try_into().expect("ct length checked");
                let xpk_bytes: &[u8; X25519_BYTES] =
                    (&ct.0[$pq_ct..]).try_into().expect("ct length checked");
                let mct = mlkem::$pq_ct_ty::from_bytes(mct_bytes);
                let xpk = XPub::from(*xpk_bytes);

                let mss = mlkem::$pq::decapsulate(&msk, &mct);
                let xss = xsk.diffie_hellman(&xpk);

                let mut ss = [0u8; SHARED_SECRET_BYTES];
                ss[..MLKEM_SS_BYTES].copy_from_slice(mss.as_bytes());
                ss[MLKEM_SS_BYTES..].copy_from_slice(xss.as_bytes());
                $ss_ty(ss)
            }
        }

        #[derive(Clone)]
        pub struct $ek_ty(pub(crate) [u8; $ek_size]);
        #[derive(Clone, ZeroizeOnDrop)]
        pub struct $dk_ty(pub(crate) [u8; $dk_size]);
        #[derive(Clone)]
        pub struct $ct_ty(pub(crate) [u8; $ct_size]);
        #[derive(Clone, ZeroizeOnDrop)]
        pub struct $ss_ty(pub(crate) [u8; SHARED_SECRET_BYTES]);

        impl $ek_ty {
            pub fn as_bytes(&self) -> &[u8; $ek_size] {
                &self.0
            }
            pub fn from_bytes(b: &[u8; $ek_size]) -> Self {
                Self(*b)
            }
        }
        impl $dk_ty {
            pub fn as_bytes(&self) -> &[u8; $dk_size] {
                &self.0
            }
            pub fn from_bytes(b: &[u8; $dk_size]) -> Self {
                Self(*b)
            }
        }
        impl $ct_ty {
            pub fn as_bytes(&self) -> &[u8; $ct_size] {
                &self.0
            }
            pub fn from_bytes(b: &[u8; $ct_size]) -> Self {
                Self(*b)
            }
        }
        impl $ss_ty {
            pub fn as_bytes(&self) -> &[u8; SHARED_SECRET_BYTES] {
                &self.0
            }
        }

        impl AsRef<[u8]> for $ek_ty {
            fn as_ref(&self) -> &[u8] {
                &self.0
            }
        }
        impl AsRef<[u8]> for $ct_ty {
            fn as_ref(&self) -> &[u8] {
                &self.0
            }
        }
        impl AsRef<[u8]> for $ss_ty {
            fn as_ref(&self) -> &[u8] {
                &self.0
            }
        }
        impl AsRef<[u8]> for $dk_ty {
            fn as_ref(&self) -> &[u8] {
                &self.0
            }
        }

        impl TryFrom<&[u8]> for $ek_ty {
            type Error = LengthError;
            fn try_from(b: &[u8]) -> Result<Self, LengthError> {
                if b.len() != $ek_size {
                    return Err(LengthError {
                        expected: $ek_size,
                        got: b.len(),
                    });
                }
                let mut a = [0u8; $ek_size];
                a.copy_from_slice(b);
                Ok(Self(a))
            }
        }
        impl TryFrom<&[u8]> for $ct_ty {
            type Error = LengthError;
            fn try_from(b: &[u8]) -> Result<Self, LengthError> {
                if b.len() != $ct_size {
                    return Err(LengthError {
                        expected: $ct_size,
                        got: b.len(),
                    });
                }
                let mut a = [0u8; $ct_size];
                a.copy_from_slice(b);
                Ok(Self(a))
            }
        }
        impl TryFrom<&[u8]> for $dk_ty {
            type Error = LengthError;
            fn try_from(b: &[u8]) -> Result<Self, LengthError> {
                if b.len() != $dk_size {
                    return Err(LengthError {
                        expected: $dk_size,
                        got: b.len(),
                    });
                }
                let mut a = [0u8; $dk_size];
                a.copy_from_slice(b);
                Ok(Self(a))
            }
        }

        impl PartialEq for $ek_ty {
            fn eq(&self, other: &Self) -> bool {
                self.0.ct_eq(&other.0).into()
            }
        }
        impl Eq for $ek_ty {}
        impl PartialEq for $ct_ty {
            fn eq(&self, other: &Self) -> bool {
                self.0.ct_eq(&other.0).into()
            }
        }
        impl Eq for $ct_ty {}
        impl PartialEq for $ss_ty {
            fn eq(&self, other: &Self) -> bool {
                self.0.ct_eq(&other.0).into()
            }
        }
        impl Eq for $ss_ty {}
        impl PartialEq for $dk_ty {
            fn eq(&self, other: &Self) -> bool {
                self.0.as_slice().ct_eq(other.0.as_slice()).into()
            }
        }
        impl Eq for $dk_ty {}

        impl core::fmt::Debug for $ek_ty {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                write!(
                    f,
                    concat!(stringify!($ek_ty), "(..{} bytes..)"),
                    self.0.len()
                )
            }
        }
        impl core::fmt::Debug for $dk_ty {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                write!(f, concat!(stringify!($dk_ty), "(..REDACTED..)"))
            }
        }
        impl core::fmt::Debug for $ct_ty {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                write!(
                    f,
                    concat!(stringify!($ct_ty), "(..{} bytes..)"),
                    self.0.len()
                )
            }
        }
        impl core::fmt::Debug for $ss_ty {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                write!(f, concat!(stringify!($ss_ty), "(..REDACTED..)"))
            }
        }

        impl Zeroize for $dk_ty {
            fn zeroize(&mut self) {
                self.0.zeroize();
            }
        }
        impl Zeroize for $ss_ty {
            fn zeroize(&mut self) {
                self.0.zeroize();
            }
        }
    };
}

// thin newtype around x25519-dalek's StaticSecret so we can construct it from
// a fixed seed inside the macro context. (the upstream constructor takes the
// raw 32-byte seed via `From<[u8; 32]>`.)
struct ReusableSecretWrapper(StaticSecret);
impl From<[u8; 32]> for ReusableSecretWrapper {
    fn from(b: [u8; 32]) -> Self {
        Self(StaticSecret::from(b))
    }
}

// ml-kem-768: pq pk 1184, pq sk 2400, pq ct 1088
// hybrid ek = 1184 + 32 = 1216
// hybrid dk = 2400 + 32 = 2432
// hybrid ct = 1088 + 32 = 1120
hybrid_kem!(
    X25519MlKem768,
    MlKem768,
    PublicKey768,
    SecretKey768,
    Ciphertext768,
    EncapsKey768,
    DecapsKey768,
    Ciphertext768Hybrid,
    SharedSecret768Hybrid,
    1184,
    2400,
    1088,
    1216,
    2432,
    1120
);

// ml-kem-1024: pq pk 1568, pq sk 3168, pq ct 1568
// hybrid ek = 1568 + 32 = 1600
// hybrid dk = 3168 + 32 = 3200
// hybrid ct = 1568 + 32 = 1600
hybrid_kem!(
    X25519MlKem1024,
    MlKem1024,
    PublicKey1024,
    SecretKey1024,
    Ciphertext1024,
    EncapsKey1024,
    DecapsKey1024,
    Ciphertext1024Hybrid,
    SharedSecret1024Hybrid,
    1568,
    3168,
    1568,
    1600,
    3200,
    1600
);
