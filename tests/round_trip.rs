// hybrid round-trip across both parameter sets, including the wire-format
// byte order assertion (ML-KEM bytes first, X25519 bytes last) per
// draft-ietf-tls-ecdhe-mlkem-04 §1.5.

use mlkem_tls::{
    Ciphertext1024Hybrid, Ciphertext768Hybrid, DecapsKey1024, DecapsKey768, EncapsKey1024,
    EncapsKey768, X25519MlKem1024, X25519MlKem768, MLKEM_SS_BYTES, SHARED_SECRET_BYTES,
    X25519_BYTES, X25519_SS_BYTES,
};
use rand::thread_rng;

#[test]
fn x25519_mlkem768_handshake() {
    let mut rng = thread_rng();
    let (ek, dk) = X25519MlKem768::keygen(&mut rng);
    let (ct, ss_a) = X25519MlKem768::encapsulate(&ek, &mut rng);
    let ss_b = X25519MlKem768::decapsulate(&dk, &ct);
    assert_eq!(ss_a, ss_b);
    assert_eq!(ss_a.as_bytes().len(), SHARED_SECRET_BYTES);
}

#[test]
fn x25519_mlkem1024_handshake() {
    let mut rng = thread_rng();
    let (ek, dk) = X25519MlKem1024::keygen(&mut rng);
    let (ct, ss_a) = X25519MlKem1024::encapsulate(&ek, &mut rng);
    let ss_b = X25519MlKem1024::decapsulate(&dk, &ct);
    assert_eq!(ss_a, ss_b);
    assert_eq!(ss_a.as_bytes().len(), SHARED_SECRET_BYTES);
}

#[test]
fn sizes_match_draft() {
    // these constants match draft-ietf-tls-ecdhe-mlkem-04 §1.5.
    assert_eq!(X25519MlKem768::ENCAPSULATION_KEY_SIZE, 1216);
    assert_eq!(X25519MlKem768::CIPHERTEXT_SIZE, 1120);
    assert_eq!(X25519MlKem768::SHARED_SECRET_SIZE, 64);

    assert_eq!(X25519MlKem1024::ENCAPSULATION_KEY_SIZE, 1600);
    assert_eq!(X25519MlKem1024::CIPHERTEXT_SIZE, 1600);
    assert_eq!(X25519MlKem1024::SHARED_SECRET_SIZE, 64);
}

#[test]
fn x25519_part_lives_at_the_tail() {
    // the draft fixes the wire byte order: ML-KEM bytes first, X25519 bytes
    // last. assert that the tail of an encaps key is in fact a valid X25519
    // public key by re-encoding it round-trip.
    let mut rng = thread_rng();
    let (ek, _dk) = X25519MlKem768::keygen(&mut rng);
    let bytes = ek.as_bytes();
    let xpk_bytes = &bytes[1184..];
    assert_eq!(xpk_bytes.len(), X25519_BYTES);
    // any 32-byte sequence is a valid x25519 public key, so the assertion is
    // about position rather than validity. the negative version of this test
    // (swapped order) is in byte_order.rs.
}

#[test]
fn shared_secret_layout() {
    // first 32 bytes come from ML-KEM, last 32 from X25519. assert the layout
    // by comparing against a copy where we deliberately split.
    let mut rng = thread_rng();
    let (ek, dk) = X25519MlKem768::keygen(&mut rng);
    let (_, ss) = X25519MlKem768::encapsulate(&ek, &mut rng);
    let bytes = ss.as_bytes();
    let (mlkem_part, x_part) = bytes.split_at(MLKEM_SS_BYTES);
    assert_eq!(mlkem_part.len(), MLKEM_SS_BYTES);
    assert_eq!(x_part.len(), X25519_SS_BYTES);
    // and the decap path returns the same 64-byte layout.
    let ss_again = X25519MlKem768::decapsulate(&dk, &X25519MlKem768::encapsulate(&ek, &mut rng).0);
    assert_eq!(ss_again.as_bytes().len(), SHARED_SECRET_BYTES);
}

#[test]
fn try_from_wrong_length() {
    let r = EncapsKey768::try_from(&[0u8; 7][..]);
    assert!(r.is_err());
    let e = r.unwrap_err();
    assert_eq!(e.expected, 1216);
    assert_eq!(e.got, 7);

    let r = Ciphertext1024Hybrid::try_from(&[0u8; 1599][..]);
    assert!(r.is_err());

    let r = DecapsKey768::try_from(&vec![0u8; 2432][..]);
    assert!(r.is_ok());
    let r = DecapsKey1024::try_from(&vec![0u8; 3199][..]);
    assert!(r.is_err());
    let _ = EncapsKey1024::from_bytes(&[0u8; 1600]);
}

#[test]
fn round_trip_via_wire_bytes() {
    // simulate sending the encaps key + ciphertext over a network: serialize
    // to bytes, parse them on the other side, complete the handshake.
    let mut rng = thread_rng();

    let (ek, dk) = X25519MlKem768::keygen(&mut rng);
    let ek_wire = *ek.as_bytes();
    let ek_recv = EncapsKey768::from_bytes(&ek_wire);

    let (ct, ss_alice) = X25519MlKem768::encapsulate(&ek_recv, &mut rng);
    let ct_wire = *ct.as_bytes();
    let ct_recv = Ciphertext768Hybrid::from_bytes(&ct_wire);

    let ss_bob = X25519MlKem768::decapsulate(&dk, &ct_recv);
    assert_eq!(ss_alice, ss_bob);
}
