use set1::xor_bytes;
use set2::{AES_BLOCK_SIZE, decrypt_aes_cbc, make_vec};
use rand;
use rand::Rng;

type BytesGenerator = Box<FnMut() -> Vec<u8>>;
type Tester = Box<Fn(&[u8]) -> Option<Vec<u8>>>;

// Ciphertext source to mimic real intercepted ciphertext
// Key/IV is returned for testing purposes
fn get_source_tester_key() -> (BytesGenerator, Tester, Vec<u8>) {
    let mut rng = rand::thread_rng();
    let mut iv = [0; 16];
    rng.fill_bytes(&mut iv);
    let key = iv; // Super spooky

    // This can actually be random; it doesn't matter
    let ciphertext_source = move || {
        let mut buf = [0u8; 64];
        rng.fill_bytes(&mut buf);

        buf.to_vec()
    };

    // Checks if plaintext has non-ASCII bytes and "accidentally" returns the result if so
    let ascii_tester = move |ciphertext: &[u8]| {
        let plaintext = decrypt_aes_cbc(ciphertext, &key.to_vec(), &iv.to_vec());
        for &byte in plaintext.iter() {
            if byte > 127 {
                return Some(plaintext.clone());
            }
        }

        None
    };

    (Box::new(ciphertext_source), Box::new(ascii_tester), key.to_vec())
}

fn find_key(ciphertext_source: &mut BytesGenerator, ascii_tester: &Tester) -> Vec<u8> {
    // Loop until we get ciphertext that triggers an ASCII error (almost guaranteed
    // to happen on the 1st try)
    loop {
        let ciphertext = ciphertext_source();
        let zero_block = make_vec(0u8, AES_BLOCK_SIZE);
        let first_ct_block = &ciphertext[..AES_BLOCK_SIZE];

        let tester_input = [first_ct_block.to_vec(), zero_block,
                            first_ct_block.to_vec()].concat();
        let tester_output = match ascii_tester(&tester_input) {
            None => continue,
            Some(v) => v
        };

        let key = xor_bytes(&tester_output[..AES_BLOCK_SIZE],
                            &tester_output[2*AES_BLOCK_SIZE..3*AES_BLOCK_SIZE]);
        return key;
    }
}

#[test]
fn tst27() {
    let (mut ciphertext_source, ascii_tester, real_key) = get_source_tester_key();
    let guessed_key = find_key(&mut ciphertext_source, &ascii_tester);

    assert_eq!(real_key, guessed_key);
}
