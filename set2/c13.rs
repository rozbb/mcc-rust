use c09::{minimal_pad, pkcs7_pad};
use c10::AES_BLOCK_SIZE;
use c11::{decrypt_aes_ecb, encrypt_aes_ecb, make_vec};
use rand;
use rand::Rng;
use std::collections::HashMap;

type Cookie = HashMap<String, String>;
type CookieEncryptor = Box<Fn(&str) -> Vec<u8>>;
type CookieDecryptor = Box<Fn(&[u8]) -> String>;

fn decode_cookie(encoded: &str) -> Cookie {
    let mut cookie: Cookie = HashMap::new();
    for item in encoded.split('&') {
        let kv = item.split('=').collect::<Vec<_>>();
        if kv.len() != 2 {
            panic!("Bad input to decode_cookie! {:?}", item);
        }
        cookie.insert(kv[0].to_string(), kv[1].to_string());
    }

    cookie
}

fn sanitize(unclean: &str) -> String {
    unclean.replace("&", "%").replace("=", "%")
}

// Apparently not necessary, I'll keep it
/*fn encode_cookie(cookie: &Cookie) -> String {
    cookie.iter().map(|(key, val)| format!("{}={}", sanitize(key), sanitize(val)))
          .collect::<Vec<_>>().connect("&")
}*/

fn encode_account_cookie(cookie: &Cookie) -> String {
    let keys = ["email", "uid", "role"];
    let values = keys.iter().map(|&k| cookie.get(k).unwrap());
    keys.iter().zip(values).map(|(k, v)| format!("{}={}", *k, &v))
        .collect::<Vec<_>>().join("&")
}

fn profile_for(email: &str) -> String {
    let mut cookie: Cookie = HashMap::new();
    cookie.insert("email".into(), sanitize(email));
    cookie.insert("uid".into(), "10".into());
    cookie.insert("role".into(), "user".into());

    encode_account_cookie(&cookie)
}

// Get an encryptor and decryptor using the same random key
fn get_oracle_pair() -> (CookieEncryptor, CookieDecryptor) {
    let mut rng = rand::thread_rng();
    let mut key = [0; 16];
    rng.fill_bytes(&mut key);

    let enc = move |plaintext: &str| {
        let plaintext: Vec<u8> = profile_for(plaintext).bytes().collect();
        let padded = minimal_pad(&plaintext, AES_BLOCK_SIZE);
        encrypt_aes_ecb(&padded, &key.to_vec())
    };

    let dec = move |ciphertext: &[u8]| {
        // Decrypt and unpad the ciphertext
        let mut decrypted = decrypt_aes_ecb(ciphertext, &key.to_vec());
        let orig_len = decrypted.len();
        let pad_len = decrypted[orig_len-1] as usize;
        decrypted.truncate(orig_len - pad_len);
        String::from_utf8_lossy(&*decrypted).into_owned()
    };

    (Box::new(enc), Box::new(dec))
}

fn make_admin_ciphertext(oracle: &CookieEncryptor) -> Vec<u8> {
    // First find and copy the ciphertext block for
    // admin\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b
    // Then we align 'role=' to the end of a block boundary, and paste the previous
    // ciphertext to the next block.
    let admin_block = pkcs7_pad(b"admin", AES_BLOCK_SIZE);
    let left_padding = make_vec(b'A', AES_BLOCK_SIZE - "email=".len());
    // This has to be 2 blocks long in order to get admin at the beginning of a block
    let admin_email = String::from_utf8_lossy(&*[left_padding, admin_block].concat()).into_owned();
    let admin_ciphertext_block = oracle(&admin_email).into_iter()
                                                     .skip(AES_BLOCK_SIZE)
                                                     .take(AES_BLOCK_SIZE)
                                                     .collect::<Vec<u8>>();

    // This is present in every string we make; we pad using the email field until
    // this string takes up exactly 3 blocks, so that 'role=' is at the end of the block
    let overhead_len = "email=&uid=xx&role=".len();
    let email_bytes = make_vec(b'A', AES_BLOCK_SIZE - (overhead_len % AES_BLOCK_SIZE));
    let email_str = String::from_utf8_lossy(&*email_bytes).into_owned();

    // This is a 'role=user' ciphertext where 'user' is at the beginning of the last block
    let ordinary_input = oracle(&email_str);
    let ordinary_input_len = ordinary_input.len();

    // Now paste admin_ciphertext_block over the last block of ordinary_input
    ordinary_input.into_iter()
                  .take(ordinary_input_len - AES_BLOCK_SIZE)
                  .chain(admin_ciphertext_block)
                  .collect()
}

#[test]
fn tst13() {
    // Quick unit test of the en/decode functions
    let test_cookie = "email=foo@bar.com&uid=10&role=user";
    assert_eq!(encode_account_cookie(&decode_cookie(test_cookie)), test_cookie);

    // Forge a cookie with 'role=admin' using an encryption oracle
    let (enc, dec) = get_oracle_pair();
    let forged_ciphertext = make_admin_ciphertext(&enc);
    let decoded_cookie = decode_cookie(&dec(&forged_ciphertext));
    assert_eq!(decoded_cookie["role"], "admin");
}
