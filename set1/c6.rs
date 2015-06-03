use util::{decode_b64, decode_hex, dump_file, encode_hex};
use c2::xor_bytes;
use c3::{coincidence_err, make_key_vec, test_all_keys};
use c4::{chi_sq_monogram, chi_sq_bigram, braindead_err, extra_braindead_err};

fn hamming_dist(a: &[u8], b: &[u8]) -> u32 {
    if a.len() != b.len() {
        panic!("Hamming distance only works for strings of equal length!");
    }

    a.iter().zip(b)
     .fold(0u32, |acc, (&x,&y)| acc + (x^y).count_ones())
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
    let ciphertext_b64: String = dump_file("c6.txt").split_whitespace().collect();
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
