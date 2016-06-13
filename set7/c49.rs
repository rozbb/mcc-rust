use set1::xor_bytes;
use set2::{encrypt_aes_cbc, make_vec, minimal_pad, AES_BLOCK_SIZE};
use std::collections::HashMap;
use rand::{self, Rng};

const ALICE_UID: usize = 13;
const MALLORY_UID: usize = 37;

// Sanitized and unsanitized versions of fixed- and variable-IV MAC oracles.
// The sanitized versions return the full sanitized message, and its MAC
// The unsanitized versions are only used in test functions.
type SanVarMacOracle = Box<Fn(&[u8], &[u8], &[u8], &[u8]) -> (Vec<u8>, Vec<u8>)>;
type VarMacOracle = Box<Fn(&[u8], &[u8]) -> Vec<u8>>;
type SanFixedMacOracle = Box<Fn(&[u8], &[&[u8]]) -> (Vec<u8>, Vec<u8>)>;
type FixedMacOracle = Box<Fn(&[u8]) -> Vec<u8>>;

pub fn cbc_mac(plaintext: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    // This is still possible using PKCS7 padding, but it's just a bit more of a pain
    let padded = minimal_pad(plaintext, AES_BLOCK_SIZE);
    encrypt_aes_cbc(&*padded, key, iv).chunks(AES_BLOCK_SIZE).last().unwrap().to_vec()
}

// Basically just key=value from split('&')
fn decode_url(url: &[u8]) -> HashMap<&[u8], Vec<u8>> {
    let mut map: HashMap<&[u8], Vec<u8>> = HashMap::new();
    for kv in url.split(|&byte| byte == b'&') {
        let mut it = kv.split(|&byte| byte == b'=');
        let (key, val) = (it.next().unwrap(), it.next().unwrap());
        if map.contains_key(key) {
            panic!("Tried to decode url with a repeating key: {}", String::from_utf8_lossy(url));
        }
        map.insert(key, val.to_vec());
    }
    map
}

// Basicall just key=value from split(';')
fn decode_tx_list(tx_list: &[u8]) -> HashMap<&[u8], Vec<u8>> {
    let mut map: HashMap<&[u8], Vec<u8>> = HashMap::new();
    for kv in tx_list.split(|&byte| byte == b';') {
        let mut it = kv.split(|&byte| byte == b':');
        let (to, amt) = (it.next().unwrap(), it.next().unwrap());
        if map.contains_key(to) {
            panic!("Tried to decode tx list with repeated 'to' form: {}",
                   String::from_utf8_lossy(to));
        }
        map.insert(to, amt.to_vec());
    }
    map
}

// Escapes '&' and '=' for url parameters
fn sanitize(param: &[u8]) -> Vec<u8> {
    param.iter().map(|&byte| {
        if byte == b'&' || byte == b'=' {
            b'%'
        }
        else {
            byte
        }
    }).collect()
}

// Returns true iff there are no control characters in the input that might mess up the url parsing
// routines
fn is_clean(s: &[u8]) -> bool {
    !(s.contains(&b'=') || s.contains(&b'&') || s.contains(&b'&') || s.contains(&b':') ||
        s.contains(&b';'))
}

// Returns oracles that will give you the MAC of your message iff the "from" field corresponds to
// the preset uid that the oracle was created with; one uid for the client, one for the attacker
// The first oracle is a master oracle that does not check the UID of the input. This is to be used
// in the testing function.
fn make_var_iv_oracle(uid: usize) -> (VarMacOracle, SanVarMacOracle) {
    let mut rng = rand::thread_rng();
    let mut key = make_vec(0u8, AES_BLOCK_SIZE);
    rng.fill_bytes(&mut key);
    let key_copy = key.clone();

    let master_oracle = move |message: &[u8], iv: &[u8]| {
        cbc_mac(message, &*key_copy, iv)
    };

    // Sanitize all the inputs and put the message together in the right format
    let sanitized_oracle = move |from: &[u8], to: &[u8], amt: &[u8], iv: &[u8]| {
        let (from_san, to_san, amt_san) = (sanitize(from), sanitize(to), sanitize(amt));
        let mandatory_from = format!("{}", uid).into_bytes();
        assert_eq!(&*from_san, &*mandatory_from);

        let message = [b"from=", &*from_san, b"&to=", &*to_san, b"&amount=", &*amt_san].concat();

        let mac = cbc_mac(&*message, &*key, iv);
        (message, mac)
    };

    (Box::new(master_oracle), Box::new(sanitized_oracle))
}

// Does the same thing as make_var_iv_oracle, but with a fixed IV and a slightly different message
// format (tx_list instead of a single 'to=&amount=')
fn make_fixed_iv_oracle(uid: usize) -> (FixedMacOracle, SanFixedMacOracle) {
    let mut rng = rand::thread_rng();
    let mut key = [0u8; AES_BLOCK_SIZE].to_vec();
    rng.fill_bytes(&mut key);
    let key_copy = key.clone();

    let master_oracle = move |message: &[u8]| {
        // IV is fixed to 0 for simplicity
        let iv = [0u8; AES_BLOCK_SIZE];
        return cbc_mac(message, &*key_copy, &iv);
    };

    // Sanitize all the inputs and put the message together in the right format
    let sanitized_oracle = move |from: &[u8], tx_list: &[&[u8]]| {
        let iv = [0u8; AES_BLOCK_SIZE];
        let from_san = sanitize(from);
        let mandatory_from = format!("{}", uid).into_bytes();
        assert_eq!(&*from_san, &*mandatory_from);
        let mut message = [b"from=", &*from_san, b"&tx_list="].concat();

        let first_tx = tx_list[0];
        let mut parts = first_tx.split(|&byte| byte == b':');
        let (to_san, amt_san) = {
            let (to, amt) = (parts.next().unwrap().to_vec(), parts.next().unwrap().to_vec());
            (sanitize(&*to), sanitize(&*amt))
        };

        message.extend(&*to_san);
        message.extend(b":");
        message.extend(&*amt_san);

        // Parse the rest of the tx_list and put a ';' before each pair
        for tx in &tx_list[1..] {
            let mut parts = tx.split(|&byte| byte == b':');
            let (to_san, amt_san) = {
                let (to, amt) = (parts.next().unwrap().to_vec(), parts.next().unwrap().to_vec());
                (sanitize(&*to), sanitize(&*amt))
            };
            message.extend(b";");
            message.extend(&*to_san);
            message.extend(b":");
            message.extend(&*amt_san);
        }

        let mac = cbc_mac(&*message, &*key, &iv);
        (message, mac)
    };

    (Box::new(master_oracle), Box::new(sanitized_oracle))
}

// Forges a message using CBC-MAC with a user-defined IV; returns a plaintext, an IV, and a MAC
fn forge_var_iv(var_iv_oracle: &SanVarMacOracle, target_uid: usize) ->
    (Vec<u8>, Vec<u8>, Vec<u8>) {
    // We have full control over the first block. Make a message where everything is as we want it
    // except the 'from=' is us instead of Alice. Call this message S. Call the mac (with IV = 0)
    // of that message M. Let T denote the desired message, that is 'from=<alice_uid>'. Then pick
    // an IV such that IV ⊕ T = S. Then IV = T ⊕ S. Thus, we return T, IV.
    let mallory_uid = format!("{}", MALLORY_UID).into_bytes();
    let desired_amount = format!("{}", 1000000).into_bytes();
    let zero_iv = [0u8; AES_BLOCK_SIZE];

    let (allowed_msg, allowed_mac) = var_iv_oracle(&*mallory_uid, &*mallory_uid, &*desired_amount,
                                                   &zero_iv);
    let desired_msg = format!("from={}&to={}&amount={}", target_uid, MALLORY_UID, 1000000)
        .into_bytes();
    let iv = xor_bytes(&allowed_msg[..AES_BLOCK_SIZE], &desired_msg[..AES_BLOCK_SIZE]);

    (desired_msg, iv, allowed_mac)
}

// Extends a given message using CBC-MAC with a fixed (zero) IV; returns a plaintext and a MAC
fn extend_fixed_iv(fixed_iv_oracle: &SanFixedMacOracle, message: &[u8], given_mac: &[u8]) ->
    (Vec<u8>, Vec<u8>) {
    // We are given C_n (the MAC) and P_1...P_n; We want to calculate E(P_{n+1} ⊕ C_n) We can
    // actually turn this oracle into an ECB oracle. First, arbitrarily choose a plaintext B.  Note
    // we don't have full control over B, since it must begin with "from=<mallory_uid>".  Calculate
    // R = CBC-MAC(B). Now let F = R ⊕ P_{n+1} ⊕ C_n. If we calculate CBC-MAC(B || F), we get E(R ⊕
    // F) = E(R ⊕ R ⊕ P_{n+1} ⊕ C_n) = E(P_{n+1} ⊕ C_n) as desired. We need only ensure that the
    // '&' and '=' characters don't appear in F. If they do, we can tweak B until F is clean.
    // Ready? Break!
    let mut rng = rand::thread_rng();
    let mallory_uid = format!("{}", MALLORY_UID).into_bytes();

    // We let B be "from=&tx_list=<filler_bytes>:1" (that is, empty values for everything but
    // the 'to' uid of the tx list)
    let required_text = b"from=xx&tx_list=:1";
    let mut filler = make_vec(0u8, AES_BLOCK_SIZE - (required_text.len() % AES_BLOCK_SIZE));

    let extension = format!(";{}:{}", MALLORY_UID, 1_000_000).into_bytes();
    let padded_extension = minimal_pad(&*extension, AES_BLOCK_SIZE);
    // We can only extend the padded original message
    let padded_message = minimal_pad(message, AES_BLOCK_SIZE);
    // This is the message we will forge a MAC for
    let final_message = [&*padded_message, &*extension].concat();
    // This is P_{n+1} ⊕ C_n
    let xored_extension = xor_bytes(&*padded_extension, given_mac);

    loop {
        rng.fill_bytes(&mut filler);
        if !is_clean(&*filler) {
            continue;
        }
        let tx = [&*filler, b":0"].concat();
        // This is R = CBC-MAC(B)
        let (_, allowed_mac) = fixed_iv_oracle(&*mallory_uid, &[&*tx]);
        // This is F = R ⊕ P_{n+1} ⊕ C_n. This will be used as a fake amount at the end of the
        // constructed message
        let extension_block = xor_bytes(&*allowed_mac, &*xored_extension);
        // This will be sanitized; if we have illegal bytes, try again with a different
        // random filler
        if !is_clean(&*extension_block) {
            continue;
        }
        let extended_tx = [&*tx, &*extension_block].concat();
        // This calculates CBC-MAC(B || F)
        let (_, final_mac) = fixed_iv_oracle(&*mallory_uid, &[&*extended_tx]);
        return (final_message, final_mac);
    }
}

#[test]
fn tst49() {
    // Quick unit test
    {
        let decoded = decode_url(b"foo=bar&baz=baf&bob=biz");
        assert_eq!(&decoded[&b"foo"[..]], b"bar");
        assert_eq!(&decoded[&b"baz"[..]], b"baf");
        assert_eq!(&decoded[&b"bob"[..]], b"biz");
    }

    // Test variable IV forgery
    {
        let alice_uid = format!("{}", ALICE_UID).into_bytes();
        let (master_oracle, mallory_oracle) = make_var_iv_oracle(MALLORY_UID);

        let (forged_msg, iv, forged_mac) = forge_var_iv(&mallory_oracle, ALICE_UID);
        let decoded = decode_url(&*forged_msg);

        assert_eq!(master_oracle(&*forged_msg, &*iv), forged_mac);
        assert_eq!(&*decoded[&b"from"[..]], &*alice_uid);
    }

    // Test fixed IV message extension
    {
        let alice_msg = format!("from={}&tx_list=17:84;33:90", ALICE_UID).into_bytes();
        let alice_uid = format!("{}", ALICE_UID).into_bytes();
        let mallory_uid = format!("{}", MALLORY_UID).into_bytes();

        let (master_oracle, mallory_oracle) = make_fixed_iv_oracle(MALLORY_UID);
        let alice_mac = master_oracle(&*alice_msg);

        let (forged_msg, forged_mac) = extend_fixed_iv(&mallory_oracle, &*alice_msg, &*alice_mac);
        let decoded = decode_url(&*forged_msg);
        let tx_list = decode_tx_list(&*decoded[&b"tx_list"[..]]);

        assert_eq!(&*decoded[&b"from"[..]], &*alice_uid);
        assert_eq!(master_oracle(&*forged_msg), forged_mac);
        assert_eq!(&*tx_list[&*mallory_uid], &*b"1000000");
    }

    // Mitigation
    // * One possible way to prevent the length extension attack is to prepend the length at the
    //   beginning of the plaintext and ensure that the plaintext is padded to at least 2 blocks.
    // * Another more obvious potential mitigation is to be much stricter with input formatting.
    //   Data that the oracle receives could be strictly constrained to ASCII characters. Since the
    //   attack relies on being able to use arbitrary bytes (minus '&', ':', ';', '=') in the
    //   plaintext, this ought to prevent at least the naive approach taken here.
    // * Last mitigation: don't use this algorithm :)
}
