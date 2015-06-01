use one::decode_hex;
use two::{encode_hex, xor_bytes};
use three::{coincidence_err, make_key_vec, test_all_keys};
use four::{chi_sq_monogram, chi_sq_bigram, braindead_err, extra_braindead_err};
use std::fs::File;
use std::io::{BufReader, Read};

pub fn dump_file(filename: &str) -> String {
    let file = File::open(filename).unwrap();
    let mut buf = BufReader::new(file);

    let mut out = String::new();
    let _ = buf.read_to_string(&mut out).unwrap(); // Panic on read error

    out
}

fn hamming_dist(a: &[u8], b: &[u8]) -> u32 {
    if a.len() != b.len() {
        panic!("Hamming distance only works for strings of equal length!");
    }

    a.iter().zip(b)
     .fold(0u32, |acc, (&x,&y)| acc + (x^y).count_ones())
}

fn b64_to_sextet(b: char) -> u8 {
    match b {
        'A'...'Z' => (b as u8) - 65,
        'a'...'z' => (b as u8) - 71,
        '0'...'9' => (b as u8) + 4,
              '+' => 62u8,
              '/' => 63u8,
              '=' => 0u8, // Placeholder value, caller should handle this
               _  => panic!("Invalid base64 input!")
    }
}

pub fn decode_b64(b64: &str) -> Vec<u8> {
    let mut out = Vec::<u8>::new();

    let chars: Vec<char> = b64.chars().collect();

    for chunk in (&chars).chunks(4) {
        if chunk.len() != 4 {
            panic!("Base64 input's length is not a multiple of four!");
        }

        let vals: Vec<u8> = chunk.iter().map(|&i| b64_to_sextet(i)).collect();
        let (a,b,c,d) = (vals[0], vals[1], vals[2], vals[3]);

        let x: u8 = (a << 2) | (b >> 4);
        out.push(x);

        if chunk[2] == '=' { break; }
        let y: u8 = ((b & 15) << 4) | (c >> 2);
        out.push(y);

        if chunk[3] == '=' { break; }
        let z: u8 = ((c & 3) << 6) | d;
        out.push(z);
    }

    out
}

fn hamming_score(bytes: &[u8], chunk_size: usize) -> f64 {
    // Just average the first 4 chunks
    let mut it = bytes.chunks(chunk_size).take(4);
    let mut prev = it.next().unwrap(); // Pop off the first chunk
    let mut running_avg = 0f64;
    for c in it {
        let score: u32 = hamming_dist(c, prev);
        running_avg += (score as f64) / (4*chunk_size) as f64;
        prev = c;
    }

    running_avg
}

fn sorted_key_sizes(ciphertext: &[u8]) -> Vec<(usize, f64)> {
    let mut out = Vec::<(usize, f64)>::new(); // (key_size, hamming_score)
    for size in 2..40usize {
        let score = hamming_score(ciphertext, size);
        out.push((size, score));
    }
    out.sort_by(|&(_,a), &(_,b)| a.partial_cmp(&b).unwrap()); // Sort ascending by hamming_score

    out
}

// Returns the greedy lowest-error key and the average error
fn break_with_key_size(ciphertext: &[u8], key_size: usize) -> (Vec<u8>, f64) {
    // Split ciphertext into repeating-key xored substrings
    let mut substrs = Vec::<Vec<u8>>::new();
    for _ in 0..key_size {
        substrs.push(Vec::<u8>::new());
    }

    for chunk in ciphertext.chunks(key_size) {
        for (i, byte) in chunk.iter().enumerate() {
            substrs[i].push(*byte);
        }
    }

    let mut key = Vec::<u8>::new();
    let mut avg_err = 0f64;
    for substr in substrs {
        // God dammit, why is braindead_err always better than chi_sq_monogram?!
        let (key_byte, err) = test_all_keys(&substr, braindead_err);
        key.push(key_byte);
        avg_err += err / (key_size as f64);
    }

    (key, avg_err)
}

#[test]
fn tst6() {
    assert_eq!(hamming_dist(&"this is a test".as_bytes(),
                            &"wokka wokka!!!".as_bytes()),
               37);

    assert_eq!(decode_b64("TG9yZW0gaXBzdW0gZG9sb3Igc2l0IGFtZXQsIGNvbnNlY3RldHVy\
                           IGFkaXBpc2NpbmcgZWxpdC4gRG9uZWMgYSBkaWFtIGxlY3R1cw=="),
               "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Donec a diam lectus".as_bytes());

    assert_eq!(decode_b64("SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"),
               decode_hex("49276d206b696c6c696e6720796f757220627261696e206c\
                           696b65206120706f69736f6e6f7573206d757368726f6f6d"));

    // Strip all whitespace
    let ciphertext_b64: String = dump_file("six.txt").split_whitespace().collect();
    let ciphertext_bytes: Vec<u8> = decode_b64(&ciphertext_b64);
    let mut keysize_err_tuples = sorted_key_sizes(&ciphertext_bytes);
    keysize_err_tuples.truncate(5); // Only test the top 4

    let mut key_err_tuples = keysize_err_tuples.iter().map(|&(keysize, _)| 
                                                           break_with_key_size(&ciphertext_bytes, keysize))
                                                      .collect::<Vec<(Vec<u8>, f64)>>();
    key_err_tuples.sort_by(|&(_,b), &(_,d)| b.partial_cmp(&d).unwrap());

    let (final_key, final_err) = key_err_tuples.remove(0); // Pop off front
    let key_vec = make_key_vec(&final_key, ciphertext_bytes.len());
    let xored = xor_bytes(&ciphertext_bytes, &key_vec);
    let plaintext = String::from_utf8(xored).unwrap();
    //println!("Plaintext (err {:1.3}):\n{}", final_err, plaintext);
    assert!(plaintext.starts_with("I'm back and I'm ringin' the bell"));
}
