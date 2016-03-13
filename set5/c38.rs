#![allow(non_snake_case)]
use c36::{bigint_from_bytes, hmac_sha256, sha256, G_STR, N_STR};
use c33::mod_exp;
use rand;
use rand::Rng;
use ramp::int::{Int, RandomInt};
use std::sync::mpsc;
use std::sync::mpsc::{Receiver, SyncSender};
use std::thread;

static DICTIONARY: &'static [&'static [u8]] =
    &[b"movefastbreakthings", b"herestothemisfits", b"uberbutforX", b"10xlyfe",
      b"standingscrumorbust", b"gottabehungry", b"ballmercurve", b"donoharm"];

// I know this is ugly; too bad
pub struct Msg {
    pub email: Option<String>,
    pub salt: Option<Vec<u8>>,
    pub param: Option<String>, // Generic DH "thing" encoded as a string
    pub nonce: Option<String>, // Takes the random u value
    pub mac: Option<Vec<u8>>,
    pub ok: Option<bool>,
}

fn simple_srp_server(rx: Receiver<Msg>, tx: SyncSender<Msg>, known_email: &str, password: &[u8]) {
    let N = Int::from_str_radix(N_STR, 16).unwrap();
    let g = Int::from_str_radix(G_STR, 16).unwrap();

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

    let A = {
        let A_str = msg1.param.unwrap();
        Int::from_str_radix(&A_str, 16).unwrap()
    };

    let B_str = {
        let B = mod_exp(&g, &b, &N);
        B.to_str_radix(16, false)
    };

    let u = {
        let mut uA = [0u8; 128];
        rng.fill_bytes(&mut uA);
        bigint_from_bytes(&uA)
    };
    let u_str = u.to_str_radix(16, false);

    let msg2 = Msg {
        email: None,
        salt: Some(salt.to_vec()),
        param: Some(B_str.clone()),
        nonce: Some(u_str.clone()),
        mac: None,
        ok: None,
    };

    tx.send(msg2).unwrap();

    let K = {
        let tmp = (&A * mod_exp(&v, &u, &N)) % &N;
        let S = mod_exp(&tmp, &b, &N);
        let S_str = S.to_str_radix(16, false);
        sha256(S_str.as_bytes())
    };

    let msg3 = rx.recv().unwrap();
    let received_mac = msg3.mac.unwrap();

    let correct_mac = hmac_sha256(&K, &salt);
    let ok = received_mac == correct_mac;

    let msg4 = Msg {
        email: None,
        salt: None,
        param: None,
        nonce: None,
        mac: None,
        ok: Some(ok),
    };

    tx.send(msg4).unwrap();
}

// Returns Some(client password) or None
fn evil_simple_srp_server(rx: Receiver<Msg>, tx: SyncSender<Msg>,
                          known_email: &str) -> Option<Vec<u8>> {
    let N = Int::from_str_radix(N_STR, 16).unwrap();
    let g = Int::from_str_radix(G_STR, 16).unwrap();

    let mut rng = rand::thread_rng();
    let mut salt = [0u8; 32];
    rng.fill_bytes(&mut salt);

    let b = rng.gen_uint_below(&N);
    // let b = 230498 % &N;

    let msg1 = rx.recv().unwrap();

    let given_email = msg1.email.unwrap();

    let A = {
        let A_str = msg1.param.unwrap();
        Int::from_str_radix(&A_str, 16).unwrap()
    };

    let B_str = {
        let B = mod_exp(&g, &b, &N);
        B.to_str_radix(16, false)
    };

    let u = {
        let mut uA = [0u8; 128];
        rng.fill_bytes(&mut uA);
        bigint_from_bytes(&uA)
    };
    let u_str = u.to_str_radix(16, false);

    let msg2 = Msg {
        email: None,
        salt: Some(salt.to_vec()),
        param: Some(B_str.clone()),
        nonce: Some(u_str.clone()),
        mac: None,
        ok: None,
    };

    tx.send(msg2).unwrap();

    let msg3 = rx.recv().unwrap();
    let received_mac = msg3.mac.unwrap();

    // Regardless of what we receive, just send back "ok"
    let msg4 = Msg {
        email: None,
        salt: None,
        param: None,
        nonce: None,
        mac: None,
        ok: Some(true),
    };

    tx.send(msg4).unwrap();

    // Dictionary attack here
    for &pw_guess in DICTIONARY {
        let v = {
            let salted = [&salt[..], pw_guess].concat();
            let xH = sha256(&*salted);
            let x = bigint_from_bytes(&xH);
            mod_exp(&g, &x, &N)
        };

        let K = {
            let tmp = (&A * mod_exp(&v, &u, &N)) % &N;
            let S = mod_exp(&tmp, &b, &N);
            let S_str = S.to_str_radix(16, false);
            sha256(S_str.as_bytes())
        };

        let mac = hmac_sha256(&K, &salt);

        // Found it
        if mac == received_mac {
            return Some(pw_guess.to_vec());
        }
    }
    // Couldn't guess the password
    return None;
}



fn simple_srp_client(rx: Receiver<Msg>, tx: SyncSender<Msg>, email: &str,
                     password: &[u8]) -> bool {
    let N = Int::from_str_radix(N_STR, 16).unwrap();
    let g = Int::from_str_radix(G_STR, 16).unwrap();

    let mut rng = rand::thread_rng();
    let a = rng.gen_uint_below(&N);
    let A = mod_exp(&g, &a, &N);
    let A_str = A.to_str_radix(16, false);

    let msg1 = Msg {
        email: Some(email.to_string()),
        salt: None,
        param: Some(A_str.clone()),
        nonce: None,
        mac: None,
        ok: None,
    };

    tx.send(msg1).unwrap();

    let msg2 = rx.recv().unwrap();

    let salt = msg2.salt.unwrap();
    let B = {
        let B_str = msg2.param.unwrap();
        Int::from_str_radix(&B_str, 16).unwrap()
    };
    let u = {
        let u_str = msg2.nonce.unwrap();
        Int::from_str_radix(&u_str, 16).unwrap()
    };

    let x = {
        let salted = [&salt[..], password].concat();
        let xH = sha256(&*salted);
        bigint_from_bytes(&xH)
    };

    let K = {
        let tmp1 = &a + (&u * &x);
        let S = mod_exp(&B, &tmp1, &N);
        let S_str = S.to_str_radix(16, false);
        sha256(S_str.as_bytes())
    };

    let mac = hmac_sha256(&K, &salt);

    let msg3 = Msg {
        email: None,
        salt: None,
        param: None,
        nonce: None,
        mac: Some(mac),
        ok: None,
    };

    tx.send(msg3).unwrap();

    let msg4 = rx.recv().unwrap();

    msg4.ok.unwrap()
}

#[test]
fn tst38() {
    let email = "alice@example.com";
    let password = b"donoharm";

    // Test the normal case
    {
        let (s_tx, c_rx) = mpsc::sync_channel(0);
        let (c_tx, s_rx) = mpsc::sync_channel(0);

        thread::spawn(move || simple_srp_server(s_rx, s_tx, email, password));
        let client_handle = thread::spawn(move || simple_srp_client(c_rx, c_tx, email, password));

        // Alice returns true iff the exchange succeeded
        let success = client_handle.join().unwrap();
        assert!(success);
    }

    // Now try to crack the password
    {
        let (s_tx, c_rx) = mpsc::sync_channel(0);
        let (c_tx, s_rx) = mpsc::sync_channel(0);

        let evil_server_handle = thread::spawn(move || evil_simple_srp_server(s_rx, s_tx, email));
        let client_handle = thread::spawn(move || simple_srp_client(c_rx, c_tx, email, password));

        let _ = client_handle.join();
        let cracked_password = evil_server_handle.join().unwrap().unwrap();
        assert_eq!(&*cracked_password, &password[..]);
    }
}
