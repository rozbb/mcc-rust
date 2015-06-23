use c09::pkcs7_pad;
use set1::{decode_b64, dump_file, xor_bytes};
use crypto::{buffer, aes, blockmodes};
use crypto::buffer::{ReadBuffer, WriteBuffer};
use crypto::symmetriccipher::{Decryptor, Encryptor};

pub const AES_BLOCK_SIZE: usize = 16;

// I know calling this for every block is inefficient. Sue me
pub fn encrypt_block_ecb(plaintext: &[u8], key: &[u8]) -> Vec<u8> {
    if plaintext.len() != AES_BLOCK_SIZE {
        panic!("encrypt_block_ecb only takes one block at a time!");
    }
    if key.len() != 16 {
        panic!("encrypt_block_ecb only takes 128 bit keys!");
    }
    let mut encryptor = aes::ecb_encryptor(aes::KeySize::KeySize128, key, blockmodes::NoPadding);
    let mut read_buffer = buffer::RefReadBuffer::new(plaintext);
    let mut buffer = [0; AES_BLOCK_SIZE];
    let mut write_buffer = buffer::RefWriteBuffer::new(&mut buffer);

    // At least panic if something goes wrong
    let _ = encryptor.encrypt(&mut read_buffer, &mut write_buffer, true).unwrap();

    write_buffer.take_read_buffer().take_remaining().to_vec()
}

pub fn decrypt_block_ecb(ciphertext: &[u8], key: &[u8]) -> Vec<u8> {
    if ciphertext.len() != AES_BLOCK_SIZE {
        panic!("decrypt_block_ecb only takes one block at a time!");
    }
    if key.len() != 16 {
        panic!("decrypt_block_ecb only takes 128 bit keys!");
    }
    let mut decryptor = aes::ecb_decryptor(aes::KeySize::KeySize128, key, blockmodes::NoPadding);
    let mut read_buffer = buffer::RefReadBuffer::new(ciphertext);
    let mut buffer = [0; AES_BLOCK_SIZE];
    let mut write_buffer = buffer::RefWriteBuffer::new(&mut buffer);

    let _ = decryptor.decrypt(&mut read_buffer, &mut write_buffer, true).unwrap();

    write_buffer.take_read_buffer().take_remaining().to_vec()
}

// Pretty diagrams here:
// https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_Block_Chaining_.28CBC.29
pub fn encrypt_aes_cbc(plaintext: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    if plaintext.len() % AES_BLOCK_SIZE != 0 {
        panic!("AES plaintext should be in 16 byte blocks!");
    }

    let mut ciphertext: Vec<u8> = Vec::new();
    let mut prev_ciphertext_block = iv.to_vec();

    for block in plaintext.chunks(AES_BLOCK_SIZE) {
        let xored = xor_bytes(&prev_ciphertext_block, &block);
        let ciphertext_block = encrypt_block_ecb(&xored, key);
        ciphertext.extend(ciphertext_block.clone());
        prev_ciphertext_block = ciphertext_block;
    }

    ciphertext
}

pub fn decrypt_aes_cbc(ciphertext: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    let mut plaintext: Vec<u8> = Vec::new();
    let mut prev_ciphertext_block = iv.to_vec();

    if ciphertext.len() % AES_BLOCK_SIZE != 0 {
        panic!("AES ciphertext should be in 16 byte blocks!");
    }

    for block in ciphertext.chunks(AES_BLOCK_SIZE) {
        let decrypted_block = decrypt_block_ecb(block, key);
        let plaintext_block = xor_bytes(&decrypted_block, &prev_ciphertext_block);
        plaintext.extend(plaintext_block);
        prev_ciphertext_block = block.to_vec();
    }

    plaintext
}

#[test]
fn tst10() {
    let iv = [0u8; 16].to_vec();
    let key = b"YELLOW SUBMARINE";

    assert_eq!(&decrypt_aes_cbc(&encrypt_aes_cbc(b"ABCDEFGHIJKLMNOP", key, &iv), key, &iv),
               b"ABCDEFGHIJKLMNOP");

    let raw_contents: String = dump_file("c10.txt").split_whitespace().collect();
    let decoded: Vec<u8> = decode_b64(&raw_contents);
    let plaintext = decrypt_aes_cbc(&decoded, key, &iv);
    let plaintext_str = String::from_utf8_lossy(&plaintext);

    assert!(plaintext_str.starts_with("I'm back and I'm ringin' the bell"));
    assert!(plaintext_str.ends_with("Play that funky music \n\x04\x04\x04\x04"));
}
