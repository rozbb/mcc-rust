use iterslide::SlideIterator;

use two::{decode_hex, xor_bytes};
use three::{analyze, make_key_vec, test_all_keys};
use std::ascii::AsciiExt;
use std::borrow::Borrow;
use std::collections::HashMap;
use std::f64;
use std::fs::File;
use std::io::{BufReader, BufRead};
use std::str::FromStr;

fn get_lines(filename: &str) -> Vec<String> {
    let mut out = Vec::<String>::new();
    let file = File::open(filename).unwrap();
    let buf = BufReader::new(file);

    buf.lines().map(|s| s.unwrap()).collect()
}

fn fill_bigram_hashmap() -> HashMap<String, f64> {
    let mut out = HashMap::<String, f64>::new();
    for line in get_lines("bigrams.txt") {
        let mut i = line.split(' ');
        let key = i.next().unwrap(); let val = i.next().unwrap();
        out.insert(key.to_string(), f64::from_str(val).unwrap());
    }

    out
}

// How far away is this from English?
fn chi_sq_monogram(s: String) -> f64 {

    let histogram: &mut [usize; 26] = &mut [0; 26];
    for c in s.to_lowercase().chars() {
        if !c.is_ascii() { return f64::INFINITY; } // We only want ascii
        match c as u8 {
                      b'a'...b'z' => histogram[((c as u8)-97) as usize] += 1,
                b'\x00'...b'\x08'
              | b'\x0B'...b'\x0C'
              | b'\x0E'...b'\x1F'
              | b'\x7F'...b'\xFF' => return f64::INFINITY,
                                _ => ()
        }
    }
    let total = histogram.iter().fold(0, |acc, &f| acc + f) as f64;
    
    let english_freqs = [0.08167, 0.01492, 0.02782, 0.04253f64,
                         0.12702, 0.02228, 0.02015, 0.06094,
                         0.06966, 0.00153, 0.00772, 0.04025,
                         0.02406, 0.06749, 0.07507, 0.01929,
                         0.00095, 0.05987, 0.06327, 0.09056,
                         0.02758, 0.00978, 0.02360, 0.00150,
                         0.01974, 0.00074];

    let mut err = 0f64;
    for i in 0..histogram.len() {
        let diff = (histogram[i] as f64) - total*english_freqs[i];
        err += diff*diff / (total*english_freqs[i]);
    }
    err
}

// There are 676 possible bigrams; 30 is NOT good enough
fn chi_sq_bigram(s: String) -> f64 {
    for c in s.to_lowercase().chars() {
        if !c.is_ascii() { return f64::INFINITY; } // We only want ascii
        match c as u8 {
                b'\x00'...b'\x08'
              | b'\x0B'...b'\x0C'
              | b'\x0E'...b'\x1F'
              | b'\x7F'...b'\xFF' => return f64::INFINITY,
                                _ => ()
        }
    }

    let mut histogram = HashMap::<String, usize>::new();
    for chrs in s.to_lowercase().chars().slide(2) {
        let mut bi = String::new();
        bi.push(chrs[0]); bi.push(chrs[1]);
        let curr = *histogram.get(&bi).unwrap_or(&0);
        let _ = histogram.insert(bi, curr+1);
    }
    //let total = histogram.values().fold(0, |acc, &f| acc + f) as f64;
    let total = (s.len()-1) as f64;

    let eng_bi_freqs: HashMap<String, f64> = fill_bigram_hashmap();

    let mut err = 0f64;
    for (key, eng_freq) in eng_bi_freqs.iter() {
        let diff = (*histogram.get(key).unwrap_or(&0) as f64) - total*eng_freq;
        err += diff*diff / (total*eng_freq);
    }
    
    err
}

fn braindead_err(s: String) -> f64 {
    let mut err = 0f64;
    let english_freqs = [0.08167, 0.01492, 0.02782, 0.04253f64,
                         0.12702, 0.02228, 0.02015, 0.06094,
                         0.06966, 0.00153, 0.00772, 0.04025,
                         0.02406, 0.06749, 0.07507, 0.01929,
                         0.00095, 0.05987, 0.06327, 0.09056,
                         0.02758, 0.00978, 0.02360, 0.00150,
                         0.01974, 0.00074];
    for c in s.to_lowercase().chars() {
        if !c.is_ascii() { return f64::INFINITY; } // We only want ascii
        match c as u8 {
                      b'a'...b'z' => err += english_freqs[((c as u8)-97) as usize],
                b'\x00'...b'\x08'
              | b'\x0B'...b'\x0C'
              | b'\x0E'...b'\x1F'
              | b'\x7F'...b'\xFF' => return f64::INFINITY,
                                _ => ()
        }
    }

    1f64 / err
}

fn extra_braindead_err(s: String) -> f64 {
    let mut count = 0f64;
    for c in s.to_lowercase().chars() {
        if !c.is_ascii() { return f64::INFINITY; } // We only want ascii
        match c as u8 {
                b'a'...b'z'       => count += 1f64,
                b'\x00'...b'\x08'
              | b'\x0B'...b'\x0C'
              | b'\x0E'...b'\x1F'
              | b'\x7F'...b'\xFF' => return f64::INFINITY,
                                _ => ()
        }
    }
    1f64 / (count / s.len() as f64)
}

fn test_all<F: Copy+Fn(String) -> f64>(ciphertexts: &[&str],
                                       err_func: F) -> (u8, usize, f64) {
    let mut lowest_err = f64::INFINITY;
    let mut winning_line_idx = 0usize;
    let mut winning_key = 0;
    for (i, ct) in ciphertexts.iter().enumerate() {
        let (key, err) = test_all_keys(&decode_hex(ct), err_func);
        if err < lowest_err {
            //println!("New winning err: {}", err);
            lowest_err = err;
            winning_line_idx = i;
            winning_key = key;
        }
    }
    (winning_key, winning_line_idx, lowest_err)
}

#[test]
fn tst4() {
    // braindead_err and extra_braindead_err both work here.
    // chi_sq_monogram does not because "R4^Ho+[7tRO_dV)84fi##[R3LihkwG" has
    //   a lower score than "Now that the party is jumping\n"...go figure.
    // chi_sq_bigram also does not work and I'm not entirely certain why
    let err_func = braindead_err;
    let lines = get_lines("four.txt");
    let borrowed = lines.iter().map(|s| s.borrow()).collect::<Vec<&str>>();

    let (key, idx, err) = test_all(&borrowed[..], err_func);

    let key_vec = make_key_vec(key, lines[0].len());
    let xored = xor_bytes(&decode_hex(&lines[idx]), &key_vec);
    let plaintext = String::from_utf8(xored).unwrap();
    println!("Plaintext (err {:1.3}): \"{}\"", err, plaintext);
    println!("Correct answer err: {}", err_func("Now that the party is jumping\n".to_string()));
    assert_eq!(plaintext, "Now that the party is jumping\n");
}
