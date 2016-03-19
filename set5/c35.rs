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

type ParamFunc = Box<Fn(&Int) -> Int + Send>;
type SecretsFunc = Box<Fn(&Int) -> Vec<Int> + Send>;

// I know this is ugly; too bad
struct Msg {
    // p, g, pubkey are all bigints encoded as Strings so as to be Send-able
    p: Option<String>,
    g: Option<String>,
    pubkey: Option<String>,
    payload: Option<(Vec<u8>, Vec<u8>)>, // (ciphertext, iv)
    ack: bool
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

    let msg1 = Msg {
        p: Some(P_STR.to_string()),
        g: Some(G_STR.to_string()),
        pubkey: None,
        payload: None,
        ack: false
    };

    // Send p, g
    tx.send(msg1).unwrap();

    // Receive ACK
    let msg2 = rx.recv().unwrap();
    assert!(msg2.ack);

    let a = rng.gen_int_range(&Int::zero(), &p);
    let A = mod_exp(&g, &a, &p);

    let msg3 = Msg {
        p: None,
        g: None,
        pubkey: Some(A.to_str_radix(16, false)),
        payload: None,
        ack: false,
    };

    // Send A
    tx.send(msg3).unwrap();

    // Receive B
    let msg4 = rx.recv().unwrap();

    let B = Int::from_str_radix(&msg4.pubkey.unwrap(), 16).unwrap();
    let s = mod_exp(&B, &a, &p);

    // Derive key from shared secret s
    let key = &sha1(s.to_str_radix(16, false).as_bytes())[0..16];
    let mut iv = [0u8; 16];
    rng.fill_bytes(&mut iv);
    // Make a utf-8 message payload to get echoed back by Bob
    //let payload_plaintext = "Viele Grüße\x00\x01\x02".as_bytes();
    let payload_plaintext = "Viele Grüße!!!".as_bytes();
    let payload_ciphertext = encrypt_aes_cbc(&*payload_plaintext, &key, &iv);

    let msg5 = Msg {
        p: None,
        g: None,
        pubkey: None,
        payload: Some((payload_ciphertext, iv.to_vec())),
        ack: false
    };

    // Send AES-CBC(SHA1(s)[0:16], iv=random(16), msg) + iv
    tx.send(msg5).unwrap();

    // Recieve AES-CBC(SHA1(s)[0:16], iv=random(16), Alice's msg) + iv
    let msg6 = rx.recv().unwrap();

    let (given_ciphertext, new_iv) = msg6.payload.unwrap();
    let given_plaintext = decrypt_aes_cbc(&given_ciphertext, &key, &new_iv);

    // Return if Bob's payload matches ours and his IV is different from ours (to detect replay)
    let success = payload_plaintext == &*given_plaintext && iv != &*new_iv;

    (payload_plaintext.to_vec(), success)
}

fn bob(rx: Receiver<Msg>, tx: SyncSender<Msg>) {
    let mut rng = rand::thread_rng();

    // Receive p, g
    let msg1 = rx.recv().unwrap();

    let g = Int::from_str_radix(&msg1.g.unwrap(), 16).unwrap();
    let p = Int::from_str_radix(&msg1.p.unwrap(), 16).unwrap();

    let msg2 = Msg {
        p: None,
        g: None,
        pubkey: None,
        payload: None,
        ack: true
    };

    // Send ACK
    tx.send(msg2).unwrap();

    // Receive A
    let msg3 = rx.recv().unwrap();

    let A = Int::from_str_radix(&msg3.pubkey.unwrap(), 16).unwrap();
    let b = rng.gen_int_range(&Int::zero(), &p);
    let s = mod_exp(&A, &b, &p);
    let B = mod_exp(&g, &b, &p);

    let msg4 = Msg {
        p: None,
        g: None,
        pubkey: Some(B.to_str_radix(16, false)),
        payload: None,
        ack: false
    };

    // Send B
    tx.send(msg4).unwrap();

    // Receive AES-CBC(SHA1(s)[0:16], iv=random(16), msg) + iv
    let msg5 = rx.recv().unwrap();

    // Derive key from shared secret s
    let key = &sha1(s.to_str_radix(16, false).as_bytes())[0..16];
    let (payload_ciphertext, given_iv) = msg5.payload.unwrap();
    let payload_plaintext = decrypt_aes_cbc(&payload_ciphertext, &key, &given_iv);

    // Take the message and re-encrypt it with a different IV and send it back
    let mut new_iv = [0u8; 16];
    rng.fill_bytes(&mut new_iv);
    let payload_ciphertext = encrypt_aes_cbc(&payload_plaintext, &key, &new_iv);

    let msg6 = Msg {
        p: None,
        g: None,
        pubkey: None,
        payload: Some((payload_ciphertext, new_iv.to_vec())),
        ack: false
    };

    // Send AES-CBC(SHA1(s)[0:16], iv=random(16), Alice's msg) + iv
    tx.send(msg6).unwrap();
}

// Returns the intercepted secret message
fn mallory(a_rx: Receiver<Msg>, a_tx: SyncSender<Msg>, b_rx: Receiver<Msg>,
           b_tx: SyncSender<Msg>, fiddle_g: &ParamFunc, s_guess: &SecretsFunc) -> Vec<u8> {
    // Intercept p,g; we only need p
    let mut msg1 = a_rx.recv().unwrap();
    let p = Int::from_str_radix(&msg1.p.clone().unwrap(), 16).unwrap();
    let bad_g = fiddle_g(&p);

    // inject a malicious g parameter
    msg1.g = Some(bad_g.to_str_radix(16, false));
    b_tx.send(msg1).unwrap();

    // Pass on ACK
    let msg2 = b_rx.recv().unwrap();
    a_tx.send(msg2).unwrap();

    // Pass on A
    let msg3 = a_rx.recv().unwrap();
    b_tx.send(msg3).unwrap();

    // Pass on B
    let msg4 = b_rx.recv().unwrap();
    a_tx.send(msg4).unwrap();

    // Pass on AES-CBC(SHA1(s)[0:16], iv=random(16), msg) + iv
    let msg5 = a_rx.recv().unwrap();
    let (payload_ciphertext, given_iv) = msg5.payload.clone().unwrap();
    b_tx.send(msg5).unwrap();

    // Pass on AES-CBC(SHA1(s)[0:16], iv=random(16), Alice's msg) + iv
    let msg6 = b_rx.recv().unwrap();
    a_tx.send(msg6).unwrap();

    // We already know Alice's secret s because we gave Bob a bad g parameter, and he sent Alice
    // B = g^b = (some predictable number). And since g is so bad, we also know what g^(a*b) is.
    let mut possible_plaintexts: Vec<Vec<u8>> = Vec::new();
    for s in s_guess(&p) {
        let key = &sha1(s.to_str_radix(16, false).as_bytes())[0..16];
        let payload_plaintext = decrypt_aes_cbc(&payload_ciphertext, &key, &given_iv);
        possible_plaintexts.push(payload_plaintext);
    }
    most_likely_plaintext(possible_plaintexts)
}

// Just pick the most ASCII-like plaintext
fn most_likely_plaintext(plaintexts: Vec<Vec<u8>>) -> Vec<u8> {
    let mut winning_ascii_count = 0usize;
    let mut winning_plaintext: Vec<u8> = Vec::new();
    for p in plaintexts.into_iter() {
        let mut ascii_count = 0;
        for &c in &p {
            if c >= 33 && c <= 126 { ascii_count += 1; }
        }
        if ascii_count >= winning_ascii_count {
            winning_plaintext = p;
            winning_ascii_count = ascii_count;
        }
    }

    winning_plaintext
}

// Returns a list of tuples of functions that return malicious values g given p and functions
// returning the resulting possible values of s given p
fn get_malicious_parameters() -> Vec<(ParamFunc, SecretsFunc)> {
    let mut params: Vec<(ParamFunc, SecretsFunc)> = Vec::new();

    let g_1 = |_: &Int| {
        Int::from(1)
    };
    let g_1_s_guess = |_: &Int| {
        vec![Int::from(1)]
    };
    params.push((Box::new(g_1), Box::new(g_1_s_guess)));

    let g_p = |p: &Int| {
        p.clone()
    };
    let g_p_s_guess = |_: &Int| {
        vec![Int::from(0)]
    };
    params.push((Box::new(g_p), Box::new(g_p_s_guess)));

    let g_p_1 = |p: &Int| {
        p - Int::from(1)
    };
    let g_p_1_s_guess = |p: &Int| {
        vec![Int::from(1), p - 1]
    };
    params.push((Box::new(g_p_1), Box::new(g_p_1_s_guess)));

    params
}

#[test]
fn tst35() {
    // Test normal case

    let (a_tx, b_rx) = mpsc::sync_channel(0);
    let (b_tx, a_rx) = mpsc::sync_channel(0);

    let handle = thread::spawn(move || { alice(a_rx, a_tx) });
    thread::spawn(move || { bob(b_rx, b_tx) });

    let (_, success) = handle.join().unwrap(); // Alice returns true if the exchange succeeded
    assert!(success);

    // Test malicious case

    for (g_fiddle, s_guess) in get_malicious_parameters() {
        let (a_tx, ma_rx) = mpsc::sync_channel(0);
        let (ma_tx, a_rx) = mpsc::sync_channel(0);
        let (b_tx, mb_rx) = mpsc::sync_channel(0);
        let (mb_tx, b_rx) = mpsc::sync_channel(0);

        let alice_handle = thread::spawn(move || { alice(a_rx, a_tx) });
        let mallory_handle = thread::spawn(move || { mallory(ma_rx, ma_tx, mb_rx, mb_tx, &g_fiddle,
                                                             &s_guess) });
        thread::spawn(move || { bob(b_rx, b_tx) });

        // Alice returns true if the exchange succeeded and also returns the secret payload
        // Alice probably won't succeed, because Bob will have a different g than Alice
        let (payload, _alice_success) = alice_handle.join().unwrap();
        // Mallory returns the payload intercepted from MitM-ing Alice and Bob's connection
        let intercepted_payload = mallory_handle.join().unwrap();

        // Mallory will succeed; since Mallory only needs to corrupt one party: Alice
        assert_eq!(payload, intercepted_payload);
    }
}
