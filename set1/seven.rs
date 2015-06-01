use two::{encode_hex};
use six::{decode_b64, dump_file};
use openssl::crypto::symm;

pub fn decrypt_aes_ecb(ciphertext: &[u8], key: &[u8]) -> Vec<u8> {
    symm::decrypt(symm::Type::AES_128_ECB, key, Vec::<u8>::new(), ciphertext)
}

#[test]
fn tst7() {
    let file_contents: String = dump_file("seven.txt").split_whitespace().collect();
    let bytes = decode_b64(&file_contents);
    let decrypted = decrypt_aes_ecb(&bytes, &"YELLOW SUBMARINE".bytes().collect::<Vec<u8>>());
    let plaintext = String::from_utf8(decrypted).unwrap();
    assert!(plaintext.starts_with("I'm back and I'm ringin' the bell"));
}
