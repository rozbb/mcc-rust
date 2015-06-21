use set1::decode_b64;
use c11::encrypt_aes_ecb;
use rand;
use rand::Rng;
use std::iter;
use std::collections::HashMap;

pub type Encryptor = Box<Fn(&[u8]) -> Vec<u8>>;

// Not the same oracle from c11. This is a fixed-key ECB oracle
fn get_oracle() -> Encryptor {
    let mut rng = rand::thread_rng();
    let mut key = [0; 16];
    rng.fill_bytes(&mut key);

    let b64 ="Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
              aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
              dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
              YnkK".to_string().split_whitespace().collect::<String>();
    let suffix = decode_b64(&b64);

    let oracle = move |plaintext: &[u8]| {
        let mut modified_plaintext = plaintext.to_vec();
        modified_plaintext.extend(suffix.clone());

        encrypt_aes_ecb(&modified_plaintext, &key)
    };

    Box::new(oracle)
}

pub fn make_vec(byte: u8, size: usize) -> Vec<u8> {
    iter::repeat(byte).take(size).collect()
}

fn find_block_size(oracle: &Encryptor) -> usize {
    let mut size = 1usize;
    let base_len = oracle(b"").len();
    loop {
        let input = make_vec(b'A', size);
        let new_len = oracle(&input).len();
        if new_len > base_len {
            return new_len - base_len;
        }
        else {
            size += 1;
        }
    }
}

fn find_suffix_size(oracle: &Encryptor) -> usize {
    let mut size = 1usize;
    let base_len = oracle(b"").len();
    loop {
        let input = make_vec(b'A', size);
        let new_len = oracle(&input).len();
        // We pushed the internal plaintext just past the block
        // size boundary
        if new_len > base_len {
            return base_len - (size - 1);
        }
        else {
            size += 1;
        }
    }
}

fn using_ecb(oracle: &Encryptor, block_size: usize) -> bool {
    let two_blocks = make_vec(b'A', 2*block_size);
    let ciphertext = oracle(&two_blocks);
    let mut chunk_iter = ciphertext.chunks(block_size);

    chunk_iter.next().unwrap() == chunk_iter.next().unwrap()
}

pub fn last_n_from(v: Vec<u8>, n: usize) -> Vec<u8> {
    let mut out = v.iter().rev().take(n)
                   .cloned().collect::<Vec<u8>>();
    out.reverse();
    out
}

// Makes a hashmap of all the possible ecb ciphertext blocks
// given a prefix of length block_size-1
fn make_hashmap(prefix: &[u8], oracle: &Encryptor,
                    block_size: usize) -> HashMap<Vec<u8>, u8> {
    let mut out: HashMap<Vec<u8>, u8> = HashMap::new();
    for byte in 0u8..255 {
        let mut plaintext_block = prefix.to_vec();
        plaintext_block.push(byte);
        let ciphertext_block = oracle(&plaintext_block)[..block_size].to_vec();
        out.insert(ciphertext_block, byte);
    }

    out
}

fn decrypt_suffix(oracle: Encryptor) -> Vec<u8> {
    let block_size = find_block_size(&oracle);
    let suffix_size = find_suffix_size(&oracle);
    let suffix_blocks = (suffix_size / block_size) + 1;
    let mut suffix: Vec<u8> = Vec::new();
    for n_block in 0..suffix_blocks {
        for n_byte in 1..block_size+1 {
            if suffix.len() == suffix_size {
                return suffix;
            }
            let filler = make_vec(b'A', block_size - n_byte);

            // block_size-1 known fixed bytes at a time; we must figure
            // out the last byte
            let mut all_known = filler.clone();
            all_known.extend(suffix.clone());
            let fixed_bytes = last_n_from(all_known, block_size - 1);
            let ct_block_hashmap = make_hashmap(&fixed_bytes, &oracle, block_size);
            let ct_block = oracle(&filler)[block_size*n_block..block_size*(n_block+1)].to_vec();
            let suffix_byte = *ct_block_hashmap.get(&ct_block).unwrap();
            suffix.push(suffix_byte);
        }
    }
    suffix
}

#[test]
fn tst12() {
    let oracle = get_oracle();
    let secret = decrypt_suffix(oracle);
    let secret_str = String::from_utf8_lossy(&secret);

    assert!(secret_str.starts_with("Rollin' in my 5.0\n"));
    assert!(secret_str.ends_with("Did you stop? No, I just drove by\n"));
}
