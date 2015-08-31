use set1::{decode_hex, encode_hex};
use crypto::hmac::Hmac;
use crypto::sha1::Sha1;
use curl;
use crypto::mac::Mac;
use time::precise_time_ns;
use tiny_http;
use std::thread;
use std::thread::sleep_ms;

pub fn hmac_sha1(msg: &[u8], key: &[u8]) -> Vec<u8> {
    let mut h = Hmac::new(Sha1::new(), key);
    h.input(msg);
    h.result().code().to_vec()
}

fn insecure_compare(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    for i in 0..a.len() {
        if a[i] != b[i] {
            return false;
        }
        sleep_ms(50);
    }

    true
}

// Run an http server on localhost:9999
pub fn run_server(hmac_key: &[u8]) {
    let hmac_key_copy = hmac_key.to_vec();

    // Make a new thread and return; the thread will outlive this function and die
    // only when the program exits
    let server = tiny_http::ServerBuilder::new().with_port(9999).build().unwrap();
    thread::spawn(move || {
        loop {
            // Looking for GET /test with headers file:blah, signature:7af24...
            // 400 on bad request, 500 on bad mac, 200 on good mac
            let req = server.recv().unwrap(); // Blocks until somebody connects
            if !(req.method() == &tiny_http::Method::Get) || !(req.url().trim_matches('/') == "test") {
                req.respond(tiny_http::Response::empty(400));
                continue;
            }

            let mut file: Option<String> = None;
            let mut signature: Option<String> = None;

            // Scope this because req is borrowed here and you can't call req.respond()
            // while req is borrowed
            {
                let headers = req.headers();
                for h in headers {
                    if h.field.as_str() == "file" {
                        // Box the &str into String so we don't have a borrow issue
                        file = Some(h.value.as_str().to_string())
                    }
                    else if h.field.as_str() == "signature" {
                        signature = Some(h.value.as_str().to_string());
                    }
                }
            }

            if file.is_none() || signature.is_none() {
                req.respond(tiny_http::Response::empty(400));
                continue;
            }

            let calculated_mac = hmac_sha1(file.unwrap().as_bytes(), &*hmac_key_copy);
            let given_mac = decode_hex(&signature.unwrap());

            if insecure_compare(&*calculated_mac, &*given_mac) {
                req.respond(tiny_http::Response::empty(200));
            }
            else {
                req.respond(tiny_http::Response::empty(500));
            }
        }
    });
}

pub fn test_sig(msg: &[u8], mac: &[u8]) -> bool {
    let res = curl::http::handle().get("http://localhost:9999/test")
                                  .header("signature", &*encode_hex(mac))
                                  .header("file", &*String::from_utf8_lossy(msg))
                                  .exec().unwrap();
    match res.get_code() {
        200 => true,
        500 => false,
        _   => panic!("Internal error on msg: '{}' sig: '{}'",
                      String::from_utf8_lossy(msg), encode_hex(mac))
    }
}

// Note: This function uses 20 MAC bytes and a tester that sleeps for 50ms; it takes
// 40 minutes and 32 seconds to complete
fn find_mac(msg: &[u8]) -> Vec<u8> {
    let mut mac = [0u8; 20];

    // The sleep period is long enough; just pick the byte that takes the longest
    // on the testing function
    for i in 0..mac.len() {
        let mut longest_delay = 0u64;
        let mut longest_delay_byte: Option<u8> = None;
        for b in 0..256 {
            let byte = b as u8;
            mac[i] = byte;

            let before = precise_time_ns();
            test_sig(msg, &mac);
            let after = precise_time_ns();

            let diff = after - before;
            if diff > longest_delay {
                longest_delay = diff;
                longest_delay_byte = Some(byte);
            }
        }
        mac[i] = longest_delay_byte.unwrap();
        println!("c31: cracked {} mac bytes", i+1);
    }
    if !test_sig(msg, &mac) {
        panic!("Couldn't break MAC!");
    }

    mac.to_vec()
}

#[test]
fn tst31() {
    let key = b"BLUISH SUBMARINE";
    let msg = b"Hello my baby hello my honey";
    run_server(key);

    let cracked_mac = find_mac(msg);

    assert!(test_sig(msg, &*cracked_mac));
}
