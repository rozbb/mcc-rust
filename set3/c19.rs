use c18::get_aes_ctr;
use set1::{decode_b64, get_lines, xor_bytes};
use set2::make_vec;
use rand;
use rand::Rng;
use std::ascii::AsciiExt;
use std::cmp::Ordering;
use std::f64;

fn get_ciphertexts() -> Vec<Vec<u8>> {
    let lines = get_lines("c19.txt").iter().map(|s| decode_b64(s))
                                    .collect::<Vec<Vec<u8>>>();

    let mut key = [0u8; 16];
    let nonce = [0u8; 8];
    let mut rng = rand::thread_rng();
    rng.fill_bytes(&mut key);

    let ciphertexts = lines.iter().map(|l| {
        let mut ctr = get_aes_ctr(&key, &nonce);
        ctr(l)
    }).collect::<Vec<Vec<u8>>>();

    ciphertexts
}

pub fn english_error(bytes: &[u8]) -> f64 {
    let s = match String::from_utf8(bytes.to_vec()) {
        Ok(t) => t,
        Err(_) => return f64::INFINITY
    };

    let mut count = 0f64;
    for c in s.to_ascii_lowercase().chars() {
        if !c.is_ascii() { return f64::INFINITY; } // We only want ascii
        match c as u8 {
               b'a'...b'z' | b' ' => count += 1f64,
                b'\x00'...b'\x08'
              | b'\x0B'...b'\x0C'
              | b'\x0E'...b'\x1F'
              | b'\x7F'...b'\xFF' => return f64::INFINITY,
                                _ => ()
        }
    }
    1f64 / (count / s.len() as f64)
}

fn crack_ciphertexts(ciphertexts: &[&[u8]]) -> Vec<String> {
    let min_line_len = ciphertexts.iter().map(|line| line.len())
                                  .min().unwrap();
    let n_lines = ciphertexts.len();
    let mut columns: Vec<Vec<u8>> = Vec::new();
    for _ in 0..min_line_len {
        columns.push(Vec::new());
    }
    for i in 0..n_lines {
        for j in 0..min_line_len {
            columns[j].push(ciphertexts[i][j]);
        }
    }
    let mut key = Vec::new();
    for column in columns {
        let mut column_err = f64::INFINITY;
        let mut winning_key_byte: Option<u8> = None;

        for b in 0usize..256 {
            let key_byte = b as u8;
            let key_vec = make_vec(key_byte, min_line_len);

            let column_plaintext = xor_bytes(&key_vec, &column);
            let key_byte_err = english_error(&column_plaintext);
            match key_byte_err.partial_cmp(&column_err) {
                Some(Ordering::Less) => {
                    column_err = key_byte_err;
                    winning_key_byte = Some(key_byte);
                },
                _ => ()
            }
        }
        key.push(winning_key_byte.unwrap());
    }

    ciphertexts.iter().map(|l| xor_bytes(&key, l))
               .map(|c| String::from_utf8_lossy(&c).into_owned())
               .collect::<Vec<String>>()
}

#[test]
fn tst19() {
    let ciphertexts = get_ciphertexts();
    let borrowed = ciphertexts.iter().map(|b| &**b).collect::<Vec<&[u8]>>();
    println!("Challenge 19 approximate plaintext:");
    let plaintexts = crack_ciphertexts(&borrowed);
    for line in plaintexts {
        println!("\t{}", line);
    }
}
