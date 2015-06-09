use c09::pkcs7_pad;
use c10::AES_BLOCK_SIZE;
use c11::{decrypt_aes_ecb, encrypt_aes_ecb};
use c12::make_vec;
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
    let clean = unclean.to_string();
    clean.replace("&", "%");
    clean.replace("=", "%");
    clean
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
        .collect::<Vec<_>>().connect("&")
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
        encrypt_aes_ecb(&plaintext, &key.to_vec())
    };

    let dec = move |ciphertext: &[u8]| {
        String::from_utf8_lossy(&decrypt_aes_ecb(ciphertext, &key.to_vec())).into_owned()
    };

    (Box::new(enc), Box::new(dec))
}

fn make_admin_ciphertext(oracle: &CookieEncryptor) -> Vec<u8> {
    // First find the ciphertext block for
    // "role=admin\x06\x06\x06\x06\x06\x06"
    let preimage_copy_block = pkcs7_pad(b"role=admin", AES_BLOCK_SIZE);
    let left_padding = make_vec(b'A', AES_BLOCK_SIZE - "email=".len());
    let email_str = [left_padding, preimage_copy_block].iter()
                    .map(|x| String::from_utf8_lossy(x).into_owned())
                    .fold(String::new(), |acc, s| acc + &s);
    let copy_block = oracle(&email_str)[AES_BLOCK_SIZE..AES_BLOCK_SIZE*2].to_vec();

    // Now align "role=" on a block boundary so we can paste the block
    let mut email_len = AES_BLOCK_SIZE -
                        (("email=&uid=xx&".len() + AES_BLOCK_SIZE) % AES_BLOCK_SIZE);
    if email_len < 7usize {
        email_len += AES_BLOCK_SIZE; // Because why not
    }
    let aligning_email = String::from_utf8_lossy(&make_vec(b'A', email_len-6)).into_owned()
                         + "@a.com";
    let mut final_ciphertext = oracle(&aligning_email);
    // Delete the last ciphertext block
    for _ in 0..AES_BLOCK_SIZE {
        final_ciphertext.pop();
    }
    // And replace it with the role=admin block
    final_ciphertext.extend(copy_block);

    final_ciphertext
}

#[test]
fn tst13() {
    let test_cookie = "email=foo@bar.com&uid=10&role=user";
    assert_eq!(encode_account_cookie(&decode_cookie(test_cookie)),
               test_cookie);

    let (enc, dec) = get_oracle_pair();
    let forged_ciphertext = make_admin_ciphertext(&enc);
    let decrypted_cookie = dec(&forged_ciphertext);

    let correct_suffix = String::from_utf8_lossy(&pkcs7_pad(b"role=admin", AES_BLOCK_SIZE))
                                                 .into_owned();
    assert!(decrypted_cookie.ends_with(&correct_suffix));
}
