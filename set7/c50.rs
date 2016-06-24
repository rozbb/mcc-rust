use c49::cbc_mac;
use set1::{decode_hex, encode_hex, xor_bytes};
use set2::{decrypt_block_ecb, encrypt_block_ecb, minimal_pad, AES_BLOCK_SIZE};
use rand::{self, Rng};

const AES_KEY: &'static [u8] = b"YELLOW SUBMARINE";

fn cbc_hash(message: &[u8]) -> Vec<u8> {
    let iv = [0u8; AES_BLOCK_SIZE];
    cbc_mac(message, AES_KEY, &iv)
}

fn make_js_collision(desired_plaintext: &[u8], desired_hash: &[u8]) -> Vec<u8> {
    // We are given k, IV (which is zero), P_1, P_2, ..., P_n, and C_n. We denote the ciphertext
    // block that we are constructing by B_1, B_2, C_1, ..., C_n, in that order. Similarly, the
    // plaintext blocks will be denoted as Q_1, Q_2, P_1, ..., P_n. We can calculate the hash by
    // working in reverse. Let S_n = D_k(C_n). We want to pick a C_{n-1} such that C_{n-1} ⊕ P_n =
    // S_n. So let C_{n-1} = P_n ⊕ S_n. We continue similarly, letting C_{n-i-1} = P_{n-i} ⊕
    // D_k(C_{n-i}). Finally, P_1 = D_k(C_1) ⊕ B_1. Letting B_1 = P_1 ⊕ D_k(C_1) means that Q_2 is
    // filled with garbage. But no matter! We let Q_1 represent the beginning of a Javascript
    // string, and construct a P_0 and C_0 to represent the end of a Javascript string. This should
    // encapsulate all the bytes inside Q_2. We use some randomness in the generation of P_0 in
    // order to make sure we can find a Q_2 that doesn't contain a double-quote byte or a backslash
    // byte(which might prematurely end the string or escape something that doesn't exist).

    let padded_plaintext = minimal_pad(desired_plaintext, AES_BLOCK_SIZE);
    let mut running_ct_block: Vec<u8> = desired_hash.to_vec();

    for pt_block in padded_plaintext.chunks(AES_BLOCK_SIZE).rev() {
        let decrypted_ct_block = decrypt_block_ecb(&*running_ct_block, AES_KEY);
        running_ct_block = xor_bytes(&*decrypted_ct_block, pt_block);
    }

    // At this point, running_ct_block = C_0. So let's make P_0. Recall this is a suffix to the
    // garbage block and a prefix to the code that we were given. This should do nothing when the
    // Javascript is evaluated. All together, the first 3 blocks of our whole message should look
    // like {;;var garbage="<garbage>";var ___blahh;}
    let mut rng = rand::thread_rng();
    let fixed_pt_len = "\";var ___;}".len();
    loop {
        let mut random_ascii: Vec<u8> = Vec::new();
        for _ in 0..(AES_BLOCK_SIZE - fixed_pt_len) {
            let chr = rng.gen_range(b'a', b'z' + 1);
            random_ascii.push(chr);
        }

        let after_garbage_block = [b"\";var ___", &*random_ascii, b";}"].concat();
        let before_garbage_block = b"{;;var garbage=\"".to_vec();
        assert_eq!(after_garbage_block.len(), AES_BLOCK_SIZE);
        assert_eq!(before_garbage_block.len(), AES_BLOCK_SIZE);

        // Calculate B_2
        let decrypted_ct_block = decrypt_block_ecb(&*running_ct_block, AES_KEY);
        let b2 = xor_bytes(&*decrypted_ct_block, &*after_garbage_block);

        // Calculate Q_2 given B_2 and B_1. Since we need E_k(Q_2 ⊕ B_1) = B_2, we let
        // Q_2 = B_1 ⊕ D_k(B_2)

        // This is B_1
        let encrypted_before = encrypt_block_ecb(&*before_garbage_block, AES_KEY);
        // This is D_k(B_2);
        let decrypted_after = decrypt_block_ecb(&*b2, AES_KEY);
        // This is Q_2
        let garbage_block = xor_bytes(&*encrypted_before, &*decrypted_after);

        // Q_2 cannot escape the Javascript string; if it does, try again (since we're using some
        // randomly-generated values, the outcome should not be the same next iteration)
        if garbage_block.contains(&b'\\') || garbage_block.contains(&b'"') {
            continue;
        }

        let final_message = [before_garbage_block, garbage_block, after_garbage_block,
                             desired_plaintext.to_vec()].concat();
        return final_message;
    }
}

#[test]
fn tst50() {
    let original_digest_str = "296b8d7cb78a243dda4d0a61d33bbdd1";
    // Unit test
    {
        let alert_str = b"alert('MZA who was that?');\n";
        let digest = cbc_hash(alert_str);
        assert_eq!(&encode_hex(&*digest), original_digest_str);
    }

    // Forgery attack
    {
        let desired_digest = decode_hex(original_digest_str);
        let target_plaintext = b"alert('Ayo, the Wu is back!');";

        let colliding_plaintext = make_js_collision(target_plaintext, &*desired_digest);
        println!("colliding plaintext == {}", String::from_utf8_lossy(&*colliding_plaintext));
        let digest = cbc_hash(&*colliding_plaintext);

        assert_eq!(&encode_hex(&*digest), original_digest_str);
    }
    // I tried to implement the MAC checking and DOM-insertion behavior in Javascript, but I ended
    // up fighting with the crypto library I chose to make it give me proper CBC encryption and I
    // gave up.
}
