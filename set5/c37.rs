#![allow(non_snake_case)]
use c36::{Msg, N_STR, hmac_sha256, server, sha256};
use ramp::int::Int;
use std::sync::mpsc;
use std::sync::mpsc::{Receiver, SyncSender};
use std::thread;

fn evil_client(rx: Receiver<Msg>, tx: SyncSender<Msg>, email: &str, bad_param: &Int) -> bool {
    // Pick our bad A value
    let A_str = bad_param.to_str_radix(16, false);

    let msg1 = Msg {
        email: Some(email.to_string()),
        salt: None,
        param: Some(A_str.clone()),
        mac: None,
        ok: None
    };

    tx.send(msg1).unwrap();

    let msg2 = rx.recv().unwrap();

    let salt = msg2.salt.unwrap();
    // From our choice of A, we're guaranteed a key of 0
    let S = Int::from(0);
    let S_str = S.to_str_radix(16, false);

    let K = sha256(S_str.as_bytes());
    let mac = hmac_sha256(&K, &salt);

    let msg3 = Msg {
        email: None,
        salt: None,
        param: None,
        mac: Some(mac),
        ok: None
    };

    tx.send(msg3).unwrap();

    let msg4 = rx.recv().unwrap();

    msg4.ok.unwrap()
}

#[test]
fn tst37() {
    let email = "alice@example.com";
    let password = b"donoharm";

    // Any multiple of N works as a "zero key"
    let zero = Int::from(0);
    let N = Int::from_str_radix(N_STR, 16).unwrap();

    // Try A = 0 == 0 (mod N)
    {
        let (s_tx, c_rx) = mpsc::sync_channel(0);
        let (c_tx, s_rx) = mpsc::sync_channel(0);

        thread::spawn(move || { server(s_rx, s_tx, email, password) });
        let client_handle = thread::spawn(move || { evil_client(c_rx, c_tx, email, &zero) });

        // Alice returns true if the exchange succeeded
        let success = client_handle.join().unwrap();
        assert!(success);
    }

    // Try A = N == 0 (mod N)
    {
        let (s_tx, c_rx) = mpsc::sync_channel(0);
        let (c_tx, s_rx) = mpsc::sync_channel(0);

        thread::spawn(move || { server(s_rx, s_tx, email, password) });
        let client_handle = thread::spawn(move || { evil_client(c_rx, c_tx, email, &N) });

        // Alice returns true if the exchange succeeded
        let success = client_handle.join().unwrap();
        assert!(success);
    }
}
