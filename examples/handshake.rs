// minimal alice/bob hybrid handshake using X25519MlKem768.
//
//   cargo run --release --example handshake
//
// prints the byte sizes of every wire artifact, so you can grep them
// against the draft-ietf-tls-ecdhe-mlkem table without opening rfc-pdf.

use mlkem_tls::X25519MlKem768;
use rand::thread_rng;

fn main() {
    let mut rng = thread_rng();

    // bob: long-term hybrid keypair. send the encaps key over the wire.
    let (bob_ek, bob_dk) = X25519MlKem768::keygen(&mut rng);
    println!(
        "ek (sent client->server)  {} bytes  ({} ml-kem || {} x25519)",
        bob_ek.as_bytes().len(),
        1184,
        32,
    );

    // alice: encapsulate against bob's encaps key.
    let (ct, alice_ss) = X25519MlKem768::encapsulate(&bob_ek, &mut rng);
    println!(
        "ct (sent server->client)  {} bytes  ({} ml-kem || {} x25519)",
        ct.as_bytes().len(),
        1088,
        32,
    );

    // bob: decapsulate, recover the same 64-byte shared secret.
    let bob_ss = X25519MlKem768::decapsulate(&bob_dk, &ct);

    println!(
        "ss                        {} bytes  ({} ml-kem || {} x25519)",
        alice_ss.as_bytes().len(),
        32,
        32,
    );

    assert_eq!(alice_ss.as_bytes(), bob_ss.as_bytes());
    println!();
    println!("alice ss matches bob ss. hybrid handshake complete.");

    // print first 8 bytes of the shared secret in hex so you can see the
    // value actually agrees, without dumping the whole 64-byte secret.
    let head: String = alice_ss
        .as_bytes()
        .iter()
        .take(8)
        .map(|b| format!("{:02x}", b))
        .collect();
    println!("first 8 bytes of ss: {}...", head);
}
