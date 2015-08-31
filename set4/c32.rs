use set1::encode_hex;
use c31::{run_server, test_sig};
use time::precise_time_ns;
use std::thread::sleep_ms;

// Same as c31.rs except sleep for 1ms instead of 50
fn insecure_compare(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    for i in 0..a.len() {
        if a[i] != b[i] {
            return false;
        }
        sleep_ms(1);
    }

    true
}

// Takes about 5 minutes with 5 tries per byte and 9 minutes with 10 tries
// per byte; both work as long as there are no other intensive processes
// running on the computer at the same time
fn find_mac(msg: &[u8]) -> Vec<u8> {
    let mut mac = [0u8; 20];
    // Try each byte n times and use the average time
    let tries_per_byte = 5;

    for i in 0..mac.len() {
        let mut longest_delay = 0f64;
        let mut longest_delay_byte: Option<u8> = None;
        // Pick the byte that takes the longest on average to test
        for b in 0..256 {
            let byte = b as u8;
            mac[i] = byte;
            let mut byte_total_delay = 0;
            for _ in 0..tries_per_byte {
                let before = precise_time_ns();
                test_sig(msg, &mac);
                let after = precise_time_ns();

                let diff = after - before;
                byte_total_delay += diff;
            }
            let byte_avg_delay = byte_total_delay as f64 / tries_per_byte as f64;

            if byte_avg_delay > longest_delay {
                longest_delay = byte_avg_delay;
                longest_delay_byte = Some(byte);
            }
        }
        mac[i] = longest_delay_byte.unwrap();
        println!("c32: cracked {} mac bytes", i+1);
        //println!("Known mac: {}", encode_hex(&mac[..i+1]));
    }

    mac.to_vec()
}

#[test]
fn tst32() {
    let key = b"BLUISH SUBMARINE";
    let msg = b"Hello my baby hello my honey";
    run_server(key, insecure_compare);

    let cracked_mac = find_mac(msg);

    assert!(test_sig(msg, &*cracked_mac));
}
