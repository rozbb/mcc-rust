use c18::{BytesTransformer, move_out_first_n};
use c21::get_mt;
use set1::xor_bytes;
use set2::make_vec;
use byteorder::{BigEndian, WriteBytesExt};
use rand;
use rand::Rng;
use std::u16;
use time::get_time;

// key is 16 bytes; nonce is 8 bytes
fn get_mt_stream_cipher(seed: u16) -> BytesTransformer {
    let mut mt = get_mt(seed as u32);

    // This does both encryption and decryption
    let transformer = move |input: &[u8]| {
        let mut output: Vec<u8> = Vec::new();
        let mut keystream_buf = Vec::new();

        for chunk in input.chunks(4) {
            // Get 4 more bytes if necessary
            if chunk.len() > keystream_buf.len() {
                let rand_n: u32 = mt(1)[0];
                keystream_buf.write_u32::<BigEndian>(rand_n).unwrap();
            }

            // Pop out key bytes from the beginning of the buffer as we use them
            let used_key_bytes = move_out_first_n(&mut keystream_buf, chunk.len());
            let xored = xor_bytes(chunk, &used_key_bytes);
            output.extend(xored);
        }

        output
    };

    Box::new(transformer)
}

// Returns (seed, ciphertext) for testing purposes
fn ciphertext_oracle() -> (u16, Vec<u8>) {
    let mut rng = rand::thread_rng();
    let seed = rng.gen::<u16>();
    let mut mtsc = get_mt_stream_cipher(seed);

    let n_random_bytes: usize = rng.gen_range(4, 20);
    let mut random_bytes: Vec<u8> = Vec::new();
    for _ in 0..n_random_bytes {
        random_bytes.push(rng.gen::<u8>());
    }

    let plaintext = [random_bytes, make_vec(b'A', 14)].concat();

    (seed, mtsc(&plaintext))
}

fn find_seed(ciphertext: &[u8]) -> Option<u16> {
    let known_plaintext = make_vec(b'A', 14);
    let unknown_pt_len = ciphertext.len()-14;
    let corres_ct_bytes = ciphertext.iter().cloned().skip(unknown_pt_len)
                                    .collect::<Vec<u8>>();
    let known_keystream = xor_bytes(&known_plaintext, &corres_ct_bytes);


    for m in 0usize..(u16::MAX as usize)+1 {
        let seed = m as u16;

        let mut mt = get_mt(seed as u32);
        let mt_output: Vec<u32>  = mt((ciphertext.len()/4)+1);
        let mut mt_output_bytes: Vec<u8> = Vec::new();
        for n in mt_output.into_iter() {
            mt_output_bytes.write_u32::<BigEndian>(n).unwrap();
        }

        let corres_keystream_bytes = &mt_output_bytes[unknown_pt_len..unknown_pt_len+14];

        if corres_keystream_bytes == &*known_keystream {
            return Some(seed);
        }
    }

    None
}

// Arbitrary procedure; just take the 4th number from the PRNG
fn get_password_token() -> u32 {
    let now = get_time().sec as u32;
    let mut mt = get_mt(now);

    mt(4)[3]
}

fn is_valid_token(token: u32) -> bool {
    let now = get_time().sec as u32;
    for seed in (now-20)..(now+20) {
        let mut mt = get_mt(seed);
        if mt(4)[3] == token {
            return true;
        }
    }

    false
}

#[test]
fn tst24() {
    let mut rng = rand::thread_rng();
    let seed = rng.gen::<u16>();

    let mut mtsc1 = get_mt_stream_cipher(seed);
    let mut mtsc2 = get_mt_stream_cipher(seed);

    // Make sure two identical stream ciphers are inverses of each other
    let s = rng.gen_iter::<u8>().take(50).collect::<Vec<u8>>();
    assert_eq!(mtsc2(&mtsc1(&s)), s);

    // Derive the PRNG seed from a ciphertext with a (partially) known plaintext
    let (seed, ciphertext) = ciphertext_oracle();
    let guessed_seed = find_seed(&ciphertext).unwrap();
    assert_eq!(seed, guessed_seed);

    let n_tokens = 100;
    // Holds the token and whether it's real or not
    let mut tokens: Vec<(u32, bool)> = Vec::new();

    // Do a coin flip for the validity of every token we add
    for _ in 0..n_tokens {
        let is_real = rng.gen::<bool>();
        let token: u32 = if is_real { get_password_token() }
                         else { rng.gen::<u32>() };
        tokens.push((token, is_real));
    }

    // Now make sure the checker agrees with our construction
    // There's a relatively low (0.061%) chance that there's a false positive
    for (token, is_real) in tokens.into_iter() {
        assert_eq!(is_real, is_valid_token(token));
    }
}
