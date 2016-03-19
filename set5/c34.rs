#![allow(non_snake_case)]
use c33::{mod_exp, P_STR, G_STR};
use set2::{decrypt_aes_cbc, encrypt_aes_cbc};
use crypto::sha1::Sha1;
use crypto::digest::Digest;
use rand;
use rand::Rng;
use ramp::int::{Int, RandomInt};
use std::sync::mpsc;
use std::sync::mpsc::{Receiver, SyncSender};
use std::thread;

// I know this is ugly; too bad
struct Msg {
    // p, g, pubkey are all bigints encoded as Strings so as to be Send-able
    p: Option<String>,
    g: Option<String>,
    pubkey: Option<String>,
    payload: Option<(Vec<u8>, Vec<u8>)> // (ciphertext, iv)
}

fn sha1(msg: &[u8]) -> Vec<u8> {
    let mut h = Sha1::new();
    h.input(msg);
    let mut digest = [0u8; 20];
    h.result(&mut digest);
    digest.to_vec()
}

// Returns (secret payload, secure payload exchange succeeded)
fn alice(rx: Receiver<Msg>, tx: SyncSender<Msg>) -> (Vec<u8>, bool) {
    let mut rng = rand::thread_rng();

    let p = Int::from_str_radix(P_STR, 16).unwrap();
    let g = Int::from_str_radix(G_STR, 16).unwrap();

    let a = rng.gen_int_range(&Int::zero(), &p);
    let A = mod_exp(&g, &a, &p);

    let msg1 = Msg {
        p: Some(P_STR.to_string()),
        g: Some(G_STR.to_string()),
        pubkey: Some(A.to_str_radix(16, false)),
        payload: None
    };

    // Send p, g, A
    tx.send(msg1).unwrap();

    // Receive B
    let msg2 = rx.recv().unwrap();

    let B = Int::from_str_radix(&msg2.pubkey.unwrap(), 16).unwrap();
    let s = mod_exp(&B, &a, &p);

    // Derive key from shared secret s
    let key = &sha1(s.to_str_radix(16, false).as_bytes())[0..16];
    let mut iv = [0u8; 16];
    // Make a random message payload to get echoed back by Bob
    let mut payload_plaintext = [0u8; 32];
    rng.fill_bytes(&mut iv);
    rng.fill_bytes(&mut payload_plaintext);
    let payload_ciphertext = encrypt_aes_cbc(&payload_plaintext, &key, &iv);

    let msg3 = Msg {
        p: None,
        g: None,
        pubkey: None,
        payload: Some((payload_ciphertext, iv.to_vec()))
    };

    // Send AES-CBC(SHA1(s)[0:16], iv=random(16), msg) + iv
    tx.send(msg3).unwrap();

    // Recieve AES-CBC(SHA1(s)[0:16], iv=random(16), Alice's msg) + iv
    let msg4 = rx.recv().unwrap();

    let (given_ciphertext, given_iv) = msg4.payload.unwrap();
    let given_plaintext = decrypt_aes_cbc(&given_ciphertext, &key, &given_iv);

    // Return if Bob's payload matches ours and his IV is different from ours (to detect replay)
    let success = payload_plaintext == &*given_plaintext && iv != &*given_iv;

    (payload_plaintext.to_vec(), success)
}

fn bob(rx: Receiver<Msg>, tx: SyncSender<Msg>) {
    let mut rng = rand::thread_rng();

    // Receive p, g, A
    let msg1 = rx.recv().unwrap();

    let g = Int::from_str_radix(&msg1.g.unwrap(), 16).unwrap();
    let p = Int::from_str_radix(&msg1.p.unwrap(), 16).unwrap();
    let A = Int::from_str_radix(&msg1.pubkey.unwrap(), 16).unwrap();

    let b = rng.gen_int_range(&Int::zero(), &p);
    let s = mod_exp(&A, &b, &p);
    let B = mod_exp(&g, &b, &p);

    let msg2 = Msg {
        p: None,
        g: None,
        pubkey: Some(B.to_str_radix(16, false)),
        payload: None
    };

    // Send B
    tx.send(msg2).unwrap();

    // Receive AES-CBC(SHA1(s)[0:16], iv=random(16), msg) + iv
    let msg3 = rx.recv().unwrap();

    // Derive key from shared secret s
    let key = &sha1(s.to_str_radix(16, false).as_bytes())[0..16];
    let (payload_ciphertext, given_iv) = msg3.payload.unwrap();
    let payload_plaintext = decrypt_aes_cbc(&payload_ciphertext, &key, &given_iv);

    // Take the message and re-encrypt it with a different IV and send it back
    let mut new_iv = [0u8; 16];
    rng.fill_bytes(&mut new_iv);
    let payload_ciphertext = encrypt_aes_cbc(&payload_plaintext, &key, &new_iv);

    let msg4 = Msg {
        p: None,
        g: None,
        pubkey: None,
        payload: Some((payload_ciphertext, new_iv.to_vec()))
    };

    // Send AES-CBC(SHA1(s)[0:16], iv=random(16), Alice's msg) + iv
    tx.send(msg4).unwrap();
}

// Returns the intercepted secret message
fn mallory(a_rx: Receiver<Msg>, a_tx: SyncSender<Msg>, b_rx: Receiver<Msg>,
           b_tx: SyncSender<Msg>) -> Vec<u8> {
    let mut msg1 = a_rx.recv().unwrap();
    let p = msg1.p.clone(); // Save p for injection later
    msg1.pubkey = p.clone(); // Swap A out for p
    b_tx.send(msg1).unwrap();

    let mut msg2 = b_rx.recv().unwrap();
    msg2.pubkey = p.clone(); // Swap B out for p
    a_tx.send(msg2).unwrap();

    let msg3 = a_rx.recv().unwrap();
    let (payload_ciphertext, given_iv) = msg3.payload.clone().unwrap();
    // Most important part: We fixed the "public keys" of this DH exchange to be p
    // The shared secret s is 0 because p^x mod p = 0 forall x
    // Now that we know this, deriving the key is as simple as taking SHA1("0")[0..16]
    let s = Int::zero();
    let key = &sha1(s.to_str_radix(16, false).as_bytes())[0..16];
    let payload_plaintext = decrypt_aes_cbc(&payload_ciphertext, &key, &given_iv);
    b_tx.send(msg3).unwrap(); // Relay without modification; we already won

    let msg4 = b_rx.recv().unwrap();
    a_tx.send(msg4).unwrap(); // Relay without modification; we already won

    payload_plaintext
}

#[test]
fn tst34() {
    // Each actor has their own thread, and has channels to other threads based on the topology
    // given in the challenge statement

    // Test normal case

    let (a_tx, b_rx) = mpsc::sync_channel(0);
    let (b_tx, a_rx) = mpsc::sync_channel(0);

    let handle = thread::spawn(move || { alice(a_rx, a_tx) });
    thread::spawn(move || { bob(b_rx, b_tx) });

    let (_, success) = handle.join().unwrap(); // Alice returns true if the exchange succeeded
    assert!(success);

    // Test malicious case

    let (a_tx, ma_rx) = mpsc::sync_channel(0);
    let (ma_tx, a_rx) = mpsc::sync_channel(0);
    let (b_tx, mb_rx) = mpsc::sync_channel(0);
    let (mb_tx, b_rx) = mpsc::sync_channel(0);

    let alice_handle = thread::spawn(move || { alice(a_rx, a_tx) });
    let mallory_handle = thread::spawn(move || { mallory(ma_rx, ma_tx, mb_rx, mb_tx) });
    thread::spawn(move || { bob(b_rx, b_tx) });

    // Alice returns true if the exchange succeeded and also returns the secret payload
    let (payload, alice_success) = alice_handle.join().unwrap();
    // Mallory returns the payload intercepted from MitM-ing Alice and Bob's connection
    let intercepted_payload = mallory_handle.join().unwrap();

    assert!(alice_success);
    assert_eq!(payload, intercepted_payload);
}
