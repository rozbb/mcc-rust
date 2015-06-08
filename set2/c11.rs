use c09::pkcs7_pad;
use c10::{decrypt_block_ecb, encrypt_aes_cbc, encrypt_block_ecb, AES_BLOCK_SIZE};
use rand;
use rand::Rng;

#[derive(Copy, Clone, PartialEq, Eq)]
enum CipherMode {
    ECB,
    CBC
}

pub fn encrypt_aes_ecb(plaintext: &[u8], key: &[u8]) -> Vec<u8> {
    let padded = pkcs7_pad(plaintext, AES_BLOCK_SIZE);

    padded.chunks(AES_BLOCK_SIZE)
          .flat_map(|block| encrypt_block_ecb(block, key))
          .collect()
}

// Not needed, but why not
pub fn decrypt_aes_ecb(ciphertext: &[u8], key: &[u8]) -> Vec<u8> {
    ciphertext.chunks(AES_BLOCK_SIZE)
              .flat_map(|block| decrypt_block_ecb(block, key))
              .collect()
}

// Need FnMut because rng mutates
fn get_random_oracle() -> (Box<FnMut(&[u8]) -> Vec<u8>>, CipherMode) {
    let mut rng = rand::thread_rng();
    let mut key = [0; 16];
    rng.fill_bytes(&mut key);

    let cipher_mode = match rng.gen::<bool>() {
         true => CipherMode::ECB,
        false => CipherMode::CBC
    };

    let encryptor = move |plaintext: &[u8]| {
        let prefix_len: usize = rng.gen_range(5, 11);
        let suffix_len: usize = rng.gen_range(5, 11);

        let prefix = rng.gen_iter::<u8>().take(prefix_len)
                        .collect::<Vec<u8>>();
        let suffix = rng.gen_iter::<u8>().take(suffix_len)
                        .collect::<Vec<u8>>();

        let mut modified_plaintext = prefix;
        modified_plaintext.extend(plaintext.to_vec());
        modified_plaintext.extend(suffix);

        match cipher_mode {
            CipherMode::ECB => encrypt_aes_ecb(&modified_plaintext, &key),
            CipherMode::CBC => {
                let mut iv = [0; 16];
                rng.fill_bytes(&mut iv);
                encrypt_aes_cbc(&modified_plaintext, &key, &iv)
            }
        }
    };

    (Box::new(encryptor), cipher_mode)
}

fn guess_cipher_mode(mut oracle: Box<FnMut(&[u8]) -> Vec<u8>>) -> CipherMode {
    // Pad out the rest of the prefix and suffix blocks and make two blocks
    // of 'A' after the first block
    let plaintext = [b'A'; 2*AES_BLOCK_SIZE + 2*(AES_BLOCK_SIZE - 5)];
    let ciphertext = oracle(&plaintext);
    // Skip the first ciphertext block; Check the filled blocks' ciphertext
    let mut chunk_iter = ciphertext.chunks(AES_BLOCK_SIZE).skip(1);
    // If identical sequential plaintext blocks encrypt to identical
    // sequential ciphertext blocks, it's ECB
    if chunk_iter.next().unwrap() == chunk_iter.next().unwrap() {
        CipherMode::ECB
    } else {
        CipherMode::CBC
    }
}

fn test_guesser() -> bool {
    let (oracle, ciphermode) = get_random_oracle();
    let ciphermode_guess = guess_cipher_mode(oracle);

    ciphermode_guess == ciphermode
}

#[test]
fn tst11() {
    assert_eq!(decrypt_aes_ecb(&encrypt_aes_ecb(b"YELLOW SUBMARINE", &[0; 16]), &[0; 16]),
               b"YELLOW SUBMARINE");

    let n_correct = (0..100).fold(0usize, |acc, _| acc + (test_guesser() as usize));
    assert_eq!(n_correct, 100);
}
