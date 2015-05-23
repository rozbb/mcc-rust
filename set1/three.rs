use two::{decode_hex, xor_bytes};
use std::f64::INFINITY;

fn index_of_coincidence(bytes: &[u8]) -> f64 {
    let histogram: &mut [usize; 26] = &mut [0; 26];
    for c in bytes {
        match *c {
             65...90 => histogram[(c-65) as usize] += 1,
            97...122 => histogram[(c-97) as usize] += 1,
                   _ => ()
        }
    }

    let mut acc: f64 = 0f64;
    for f in histogram {
        let g = *f as f64;
        acc += g*(g-1f64) / (26f64*25f64);
    }
    acc
}

// How far away is bytes from English?
fn analyze(bytes: &[u8]) -> f64 {
    (0.065 - index_of_coincidence(bytes)).abs()
}

pub fn make_key_vec(key_byte: u8, len: usize) -> Vec<u8> {
    let mut v = Vec::new();
    for _ in 0..len {
        v.push(key_byte);
    }
    v
}

pub fn test_all_keys(input: &[u8]) -> (u8, f64) {
    let mut winning_key = 0;
    let mut lowest_err = INFINITY;
    for u in 0..255 {
        let test_vec = make_key_vec(u, input.len());
        let xored = xor_bytes(input, &test_vec);
        /*{
            let s = String::from_utf8(xored.clone());
            if s.is_ok() { println!("{}", s.unwrap()); }
        }*/
        let err = analyze(&xored);
        if err < lowest_err {
            lowest_err = err;
            winning_key = u;
        }
    }

    (winning_key, lowest_err)
}

#[test]
fn tst3 () {
    let b = decode_hex("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736");
    let (winning_key, min_err) = test_all_keys(&b);
    println!("{} won with an error of {}", winning_key, min_err);
    let winning_key_vec = make_key_vec(winning_key, b.len());
    let xored = xor_bytes(&b, &winning_key_vec);
    println!("Plaintext: \"{}\"", String::from_utf8(xored).unwrap());
}
