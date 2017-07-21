use c43::{derive_priv_key, hash_int, G_STR, P_STR, Q_STR};
use set1::{dump_file, encode_hex};
use set5::{inv_mod, mod_exp, sha1};
use itertools::Itertools;
use ramp::Int;

// Returns a list of messages and signatures
fn get_msgs_sigs(filename: &str) -> Vec<(Vec<u8>, (Int, Int))> {
    let contents = dump_file(filename);
    let lines = contents.lines();
    let mut entries: Vec<(Vec<u8>, (Int, Int))> = Vec::new();
    // Each entry is 4 lines: msg, s, r, H(msg)
    for mut entry in lines.chunks(4).into_iter() {
        let msg_str = entry.next().unwrap();
        let s_str = entry.next().unwrap();
        let r_str = entry.next().unwrap();
        let h_str = entry.next().unwrap();

        let msg = msg_str[5..].as_bytes().to_vec();
        let s = Int::from_str_radix(&s_str[3..], 10).unwrap();
        let r = Int::from_str_radix(&r_str[3..], 10).unwrap();
        let h = Int::from_str_radix(&h_str[3..], 16).unwrap();

        // Make sure the hash of the message matches
        // Compare the integers, since there might be a leading zero in the str
        assert_eq!(hash_int(&msg), h);

        entries.push((msg, (r, s)));
    }
    entries
}

fn mod_abs(a: &Int, m: &Int) -> Int {
    if a < &0 {
        (m - a) % m
    }
    else {
        a % m
    }
}

fn crack_priv_key(msgs_sigs: Vec<(Vec<u8>, (Int, Int))>, pub_key: &Int) -> Int {
    let p = Int::from_str_radix(P_STR, 16).unwrap();
    let q = Int::from_str_radix(Q_STR, 16).unwrap();
    let g = Int::from_str_radix(G_STR, 16).unwrap();

    for i in 0..msgs_sigs.len() {
        for j in 0..msgs_sigs.len() {
            let (ref m1, (ref r1, ref s1)) = msgs_sigs[i];
            let (ref m2, (_, ref s2)) = msgs_sigs[j];
            let s_diff = mod_abs(&(s1 - s2), &q);
            let m_diff = mod_abs(&(hash_int(m1) - hash_int(m2)), &q);
            // We need the inverse of s_diff. If it's 0, move along
            if s_diff == 0 {
                continue;
            }
            // If these messages used the same k, then this is it
            let k_guess = (m_diff * inv_mod(&s_diff, &q).unwrap()) % &q;
            let priv_key = derive_priv_key(m1, (r1, s1), &k_guess);
            // Check that this priv_key generates the given pub_key
            if &mod_exp(&g, &priv_key, &p) == pub_key {
                return priv_key
            }
        }
    }

    panic!("No reused k values found!");
}

#[test]
fn tst44() {
    let pub_key = Int::from_str_radix(
        "2d026f4bf30195ede3a088da85e398ef869611d0f68f0713d51c9c1a3a26c95105d915e2d8cdf26d056b86b8a\
         7b85519b1c23cc3ecdc6062650462e3063bd179c2a6581519f674a61f1d89a1fff27171ebc1b93d4dc57bceb7\
         ae2430f98a6a4d83d8279ee65d71c1203d2c96d65ebbf7cce9d32971c3de5084cce04a2e147821",
        16
    ).unwrap();

    let msgs_sigs = get_msgs_sigs("44.txt");
    let priv_key = crack_priv_key(msgs_sigs, &pub_key);
    let priv_key_hash = encode_hex(&sha1(&priv_key.to_str_radix(16, false).as_bytes()));

    assert_eq!(&*priv_key_hash, "ca8f6f7c66fa362d40760d135b763eb8527d3d52");
}
