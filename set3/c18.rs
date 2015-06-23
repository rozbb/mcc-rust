use set1::{decode_b64, xor_bytes};
use set2::{encrypt_block_ecb, make_vec};
use byteorder::{LittleEndian, WriteBytesExt};

type BytesTransformer = Box<FnMut(&[u8]) -> Vec<u8>>;

fn get_aes_ctr(key: &[u8], nonce: &[u8]) -> BytesTransformer {
    let key_copy = key.to_vec(); // For lifetime purposes
    let reverse_nonce = nonce.iter().rev().cloned().collect::<Vec<u8>>();
    let mut counter = 0u64;

    // This does both encryption and decryption
    let transformer = move |input: &[u8]| {
        let mut output: Vec<u8> = Vec::new();

        for chunk in input.chunks(16) {
            let mut counter_vec: Vec<u8> = Vec::new();
            counter_vec.write_u64::<LittleEndian>(counter).unwrap();

            // Our block is 8 bytes of nonce and 8 bytes of counter, both encoded
            // as little-endian vectors
            let pre_keystream_block = [reverse_nonce.clone(), counter_vec].concat();
            let keystream_block = encrypt_block_ecb(&pre_keystream_block, &*key_copy);

            output.extend(xor_bytes(chunk, &keystream_block[..chunk.len()]));

            counter += 1
        }

        output
    };

    Box::new(transformer)
}

#[test]
fn tst18() {
    let key = b"YELLOW SUBMARINE";
    let zero_nonce = make_vec(0x00u8, 8);
    let ciphertext = decode_b64(
                     "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==");

    let mut ctr_a = get_aes_ctr(key, &*zero_nonce);
    let mut ctr_b = get_aes_ctr(key, &*zero_nonce);

    let plaintext = ctr_a(&ciphertext);
    // Make sure a CTR of constant state is an involution (the inverse of itself)
    assert_eq!(ctr_b(&plaintext), ciphertext);

    let plaintext_str = String::from_utf8_lossy(&plaintext);
    assert_eq!(plaintext_str, "Yo, VIP Let's kick it Ice, Ice, baby Ice, Ice, baby ");
}
