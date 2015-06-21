use set1::decode_b64;
use c10::AES_BLOCK_SIZE;
use c11::encrypt_aes_ecb;
use c12::{last_n_from, make_vec};
use rand;
use rand::Rng;
use std::collections::HashMap;

type Encryptor = Box<FnMut(&[u8]) -> Vec<u8>>;
type CipherBlockFinder = Box<FnMut(&[u8], usize) -> Vec<u8>>;

// Make an oracle that makes a 1-16 byte (inclusive) random
// prefix on every call and a fixed 138 byte suffix
fn get_oracle() -> Encryptor {
    let mut rng = rand::thread_rng();
    let mut key = [0; 16];
    rng.fill_bytes(&mut key);

    let b64 ="Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg\
              aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq\
              dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg\
              YnkK".to_string();
    let suffix = decode_b64(&b64);

    let oracle = move |plaintext: &[u8]| {
        let prefix_len = rng.gen_range(1usize, 17usize);
        let prefix = rng.gen_iter::<u8>().take(prefix_len)
                        .collect::<Vec<u8>>();
        let mut modified_plaintext = prefix;
        modified_plaintext.extend(plaintext.to_vec());
        modified_plaintext.extend(suffix.clone());

        encrypt_aes_ecb(&modified_plaintext, &key)
    };

    Box::new(oracle)
}

// Returns an oracle that gets the ciphertext block `offset` blocks after
// the ciphertext block that corresponds to the given plaintext
fn get_ciphertext_cipher_block_finder(mut oracle: Encryptor) -> CipherBlockFinder {
    let spam_size = 5usize;
    // Make a bunch of copies of the plaintext block
    let spam = make_vec(b'Z', spam_size * AES_BLOCK_SIZE);

    let spam_ciphertext = oracle(&spam);
    let mut blocks = spam_ciphertext.chunks(AES_BLOCK_SIZE);
    // Pick the third block cuz why not
    let marker = blocks.nth(2).unwrap().to_vec();
    // Make sure that its neighbor is the same
    assert!(blocks.next().unwrap() == &*marker);

    // Now that we've established a marker, return a closure that
    // already knows it so the above doesn't have to run every iteration

    let closure = move |input: &[u8], offset: usize| {
        if input.len() > AES_BLOCK_SIZE {
            panic!("CipherBlockFinder doesn't accept inputs of len > AES_BLOCK_SIZE!");
        }

        let mut oracle_input = make_vec(b'Z', AES_BLOCK_SIZE);
        oracle_input.extend(input.to_vec());

        let mut post_marker_idx = None;
        let mut ciphertext: Vec<u8> = Vec::new();

        while post_marker_idx.is_none() {
            ciphertext = oracle(&oracle_input);
            for (i, block) in ciphertext.chunks(AES_BLOCK_SIZE).enumerate() {
                // We can't possibly match on the first block; there is always a
                // non-null prefix; if we match, it's because the prefix is 'Z'
                if block == &*marker && i != 0 {
                    post_marker_idx = Some(i+1);
                    break;
                }
            }
        }
        let target_idx = post_marker_idx.unwrap() + offset;
        ciphertext.chunks(AES_BLOCK_SIZE).nth(target_idx).unwrap().to_vec()
    };

    Box::new(closure)
}

// Must compensate for random prefixes; use a CipherBlockFinder
fn make_hashmap(prefix: &[u8],
                cipher_block_finder: &mut CipherBlockFinder) -> HashMap<Vec<u8>, u8> {
    let mut out: HashMap<Vec<u8>, u8> = HashMap::new();
    // Recall range is exclusive on the upper bound
    for b in 0usize..256 {
        let byte = b as u8;
        let mut plaintext_block = prefix.to_vec();
        plaintext_block.push(byte);
        let ciphertext_block = cipher_block_finder(&plaintext_block, 0);
        out.insert(ciphertext_block, byte);
    }

    out
}

fn decrypt_suffix(cipher_block_finder: &mut CipherBlockFinder) -> Vec<u8> {
    let suffix_size = 138usize; // Is this cheating?
    let suffix_blocks = (suffix_size / AES_BLOCK_SIZE) + 1;
    let mut suffix: Vec<u8> = Vec::new();
    for n_block in 0..suffix_blocks {
        for n_byte in 1..AES_BLOCK_SIZE+1 {
            if suffix.len() == suffix_size {
                return suffix;
            }

            // block_size-1 known fixed bytes at a time; we must figure
            // out the last byte

            let filler = make_vec(b'B', AES_BLOCK_SIZE - n_byte);

            let mut all_known = filler.clone();
            all_known.extend(suffix.clone());

            let fixed_bytes = last_n_from(all_known, AES_BLOCK_SIZE - 1);

            let ct_block_hashmap = make_hashmap(&fixed_bytes, cipher_block_finder);
            let ct_block = cipher_block_finder(&filler, n_block);
            let suffix_byte = *ct_block_hashmap.get(&ct_block).unwrap();
            suffix.push(suffix_byte);
            println!("({}) {}", suffix.len(), String::from_utf8_lossy(&suffix));
        }
    }

    suffix
}

#[test]
fn tst14() {
    let oracle = get_oracle();
    let mut cipher_block_finder = get_ciphertext_cipher_block_finder(oracle);
    let secret = decrypt_suffix(&mut cipher_block_finder);
    let secret_str = String::from_utf8_lossy(&secret);

    assert!(secret_str.starts_with("Rollin' in my 5.0\n"));
    assert!(secret_str.ends_with("Did you stop? No, I just drove by\n"));
}
