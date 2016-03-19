#![allow(non_snake_case)]
use set1::encode_hex;
use c33::mod_exp;
use crypto::sha2::Sha256;
use crypto::digest::Digest;
use crypto::hmac::Hmac;
use crypto::mac::Mac;
use rand;
use rand::Rng;
use ramp::int::{Int, RandomInt};
use std::sync::mpsc;
use std::sync::mpsc::{Receiver, SyncSender};
use std::thread;

pub static G_STR: &'static str = "2";
pub static K_STR: &'static str = "3";
pub static N_STR: &'static str = "000001ffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\
                                  ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\
                                  ffffffff";

// I know this is ugly; too bad
pub struct Msg {
    pub email: Option<String>,
    pub salt: Option<Vec<u8>>,
    pub param: Option<String>, // Generic DH "thing" encoded as a string
    pub mac: Option<Vec<u8>>,
    pub ok: Option<bool>,
}

pub fn sha256(msg: &[u8]) -> Vec<u8> {
    let mut h = Sha256::new();
    h.input(msg);
    let mut digest = [0u8; 256];
    h.result(&mut digest);
    digest.to_vec()
}

pub fn hmac_sha256(key: &[u8], msg: &[u8]) -> Vec<u8> {
    let mut hmac = Hmac::new(Sha256::new(), key);
    hmac.input(msg);
    let mut digest = [0u8; 256];
    hmac.raw_result(&mut digest);
    digest.to_vec()
}

pub fn bigint_from_bytes(bytes: &[u8]) -> Int {
    let hex = encode_hex(&bytes);
    Int::from_str_radix(&hex, 16).unwrap()
}

pub fn srp_server(rx: Receiver<Msg>, tx: SyncSender<Msg>, known_email: &str, password: &[u8]) {
    let N = Int::from_str_radix(N_STR, 16).unwrap();
    let g = Int::from_str_radix(G_STR, 16).unwrap();
    let k = Int::from_str_radix(K_STR, 16).unwrap();

    let mut rng = rand::thread_rng();
    let mut salt = [0u8; 32];
    rng.fill_bytes(&mut salt);

    let b = rng.gen_uint_below(&N);
    // let b = 230498 % &N;

    // Put xH and x in this scope so we can't use them after here
    let v = {
        let salted = [&salt[..], password].concat();
        let xH = sha256(&*salted);
        let x = bigint_from_bytes(&xH);
        mod_exp(&g, &x, &N)
    };

    let msg1 = rx.recv().unwrap();

    let given_email = msg1.email.unwrap();
    assert_eq!(&given_email, known_email);

    let A_str = msg1.param.unwrap();
    let A = Int::from_str_radix(&A_str, 16).unwrap();

    let B = (((k * &v) % &N) + mod_exp(&g, &b, &N)) % &N;
    let B_str = B.to_str_radix(16, false);

    let msg2 = Msg {
        email: None,
        salt: Some(salt.to_vec()),
        param: Some(B_str.clone()),
        mac: None,
        ok: None,
    };

    tx.send(msg2).unwrap();

    let AB = A_str + &B_str;
    let uH = sha256(AB.as_bytes());
    let u = bigint_from_bytes(&uH);

    let tmp = (A * mod_exp(&v, &u, &N)) % &N;
    let S = mod_exp(&tmp, &b, &N);
    let S_str = S.to_str_radix(16, false);
    let K = sha256(S_str.as_bytes());

    let msg3 = rx.recv().unwrap();
    let received_mac = msg3.mac.unwrap();

    let correct_mac = hmac_sha256(&K, &salt);
    let ok = received_mac == correct_mac;

    let msg4 = Msg {
        email: None,
        salt: None,
        param: None,
        mac: None,
        ok: Some(ok),
    };

    tx.send(msg4).unwrap();
}

fn client(rx: Receiver<Msg>, tx: SyncSender<Msg>, email: &str, password: &[u8]) -> bool {
    let N = Int::from_str_radix(N_STR, 16).unwrap();
    let g = Int::from_str_radix(G_STR, 16).unwrap();
    let k = Int::from_str_radix(K_STR, 16).unwrap();

    let mut rng = rand::thread_rng();
    let a = rng.gen_uint_below(&N);
    let A = mod_exp(&g, &a, &N);
    let A_str = A.to_str_radix(16, false);

    let msg1 = Msg {
        email: Some(email.to_string()),
        salt: None,
        param: Some(A_str.clone()),
        mac: None,
        ok: None,
    };

    tx.send(msg1).unwrap();

    let msg2 = rx.recv().unwrap();

    let salt = msg2.salt.unwrap();
    let B_str = msg2.param.unwrap();
    let B = Int::from_str_radix(&B_str, 16).unwrap();

    let AB = A_str + &B_str;
    let uH = sha256(AB.as_bytes());
    let u = bigint_from_bytes(&uH);

    let salted = [&salt[..], password].concat();
    let xH = sha256(&*salted);
    let x = bigint_from_bytes(&xH);

    let tmp1 = (B - (k * mod_exp(&g, &x, &N) % &N)) % &N;
    let tmp2 = (u * x) + a;
    let S = mod_exp(&tmp1, &tmp2, &N);
    let S_str = S.to_str_radix(16, false);

    let K = sha256(S_str.as_bytes());
    let mac = hmac_sha256(&K, &salt);

    let msg3 = Msg {
        email: None,
        salt: None,
        param: None,
        mac: Some(mac),
        ok: None,
    };

    tx.send(msg3).unwrap();

    let msg4 = rx.recv().unwrap();

    msg4.ok.unwrap()
}

#[test]
fn tst36() {
    let email = "alice@example.com";
    let password = b"donoharm";

    let (s_tx, c_rx) = mpsc::sync_channel(0);
    let (c_tx, s_rx) = mpsc::sync_channel(0);

    thread::spawn(move || srp_server(s_rx, s_tx, email, password));
    let client_handle = thread::spawn(move || client(c_rx, c_tx, email, password));

    let success = client_handle.join().unwrap(); // Alice returns true if the exchange succeeded
    assert!(success);
}
