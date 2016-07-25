use set1::decode_b64;
use std::usize;
use std::io::{self, Write};
use crypto::rc4::Rc4;
use crypto::symmetriccipher::SynchronousStreamCipher;
use rand::{self, Rng};

// Takes a prefix and calculates E_k(prefix || secret) where secret is determined by
// make_oracle and k is randomly generated every time the oracle is called
type RandomKeyEncryptionOracle = Box<Fn(&[u8]) -> Vec<u8>>;

fn make_oracle(secret: &[u8]) -> RandomKeyEncryptionOracle {
    let secret_copy = secret.to_vec();
    let oracle = move |prefix: &[u8]| {
        let mut rng = rand::thread_rng();
        // RC4 doesn't have a fixed key size but we'll stick with 128 bits
        let mut key = [0u8; 16];
        rng.fill_bytes(&mut key);
        let in_buf = [prefix, &*secret_copy].concat();

        let mut rc4 = Rc4::new(&key);
        let mut out_buf = vec![0u8; in_buf.len()];
        rc4.process(&*in_buf, &mut out_buf);

        out_buf
    };

    Box::new(oracle)
}

fn most_frequent_byte(histogram: &[usize]) -> u8 {
    histogram.iter().enumerate().fold((0, 0),
        |acc: (usize, usize), x: (usize, &usize)| {
            let (winning_idx, winning_freq) = acc;
            let (idx, &freq) = x;
            if freq > winning_freq {
              (idx, freq)
            }
            else {
              (winning_idx, winning_freq)
            }
        }).0 as u8
}

fn recover_first_32_bytes(oracle: &RandomKeyEncryptionOracle) -> Vec<u8> {
    let ciphertext_len = oracle(b"").len();
    let mut plaintext = vec![b' '; ciphertext_len];

    // Biases can be found here: http://www.isg.rhul.ac.uk/tls/biases.pdf
    let z32_bias = 224u8;
    let z16_bias = 240u8;

    for i in 0..16 {
        // We use two probes on ciphertext indices 15 and 31 (which are the bytes whose biases are
        // noted above) that, using a prefix for shifting, correspond to probe1_idx and probe2_idx
        // in the plaintext.
        let probe1_idx: isize = ((ciphertext_len - i) as isize) - 16 - 1;
        let probe2_idx: isize = ((ciphertext_len - i) as isize) - 1;
        let prefix = vec![b'A'; 32 - ciphertext_len + i];
        let mut c16_histogram = [0usize; 256];
        let mut c32_histogram = [0usize; 256];

        // Do 2^24 iterations of random encryption in order to amplify the known biases.
        // Any lower exponent seems to be too small to filter out the noise
        for _ in 0..(1usize << 24) {
            let ciphertext = oracle(&*prefix);
            c16_histogram[ciphertext[15] as usize] += 1;
            c32_histogram[ciphertext[31] as usize] += 1;
        }

        // The most frequent ciphertext byte will correspond to the most frequent key byte xored
        // with the plaintext byte at that position
        let c16_winner = most_frequent_byte(&c16_histogram);
        let c32_winner = most_frequent_byte(&c32_histogram);
        let p16 = c16_winner ^ z16_bias;
        let p32 = c32_winner ^ z32_bias;

        if probe1_idx >= 0 {
            plaintext[probe1_idx as usize] = p16;
        }
        if probe2_idx >= 0 {
            plaintext[probe2_idx as usize] = p32;
        }

        print!("\u{001b}[K\rRecovered plaintext: \"{}\"", String::from_utf8_lossy(&*plaintext));
        io::stdout().flush().ok().expect("Could not flush stdout");
    }
    println!("");

    plaintext
}

#[test]
fn tst56() {
    let oracle = {
        let secret = decode_b64("QkUgU1VSRSBUTyBEUklOSyBZT1VSIE9WQUxUSU5F");
        make_oracle(&*secret)
    };
    let result = recover_first_32_bytes(&oracle);
    assert_eq!(&*result, b"BE SURE TO DRINK YOUR OVALTINE");
}
