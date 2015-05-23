use two::{decode_hex, xor_bytes};
use three::{make_key_vec, test_all_keys};
use std::borrow::Borrow;
use std::f64::INFINITY;
use std::fs::File;
use std::io::{BufReader, BufRead};

fn get_lines(filename: &str) -> Vec<String> {
    let mut out = Vec::<String>::new();
    let file = File::open(filename).unwrap();
    let buf = BufReader::new(file);

    for line in buf.lines() {
        out.push(line.unwrap().to_owned());
    }
    out
}

fn test_all(ciphertexts: &[&str]) -> (u8, usize, f64) {
    let mut lowest_err = INFINITY;
    let mut winning_line_idx = 0usize;
    let mut winning_key = 0;
    for (i, ct) in ciphertexts.iter().enumerate() {
        let (key, err) = test_all_keys(&decode_hex(ct));
        if err < lowest_err {
            println!("New winning idx: {}", i);
            lowest_err = err;
            winning_line_idx = i;
            winning_key = key;
        }
    }
    (winning_key, winning_line_idx, lowest_err)
}

#[test]
fn tst4() {
    let lines = get_lines("four.txt");
    let borrowed = lines.iter().map(|s| s.borrow()).collect::<Vec<&str>>();
    let (key, idx, err) = test_all(&borrowed[..]);
    let key_vec = make_key_vec(key, lines[0].len());
    let xored = xor_bytes(&decode_hex(&lines[idx]), &key_vec);
    println!("Plaintext: \"{}\"", String::from_utf8(xored).unwrap());
}
