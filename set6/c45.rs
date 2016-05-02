use c43::{hash_int, P_STR, Q_STR};
use set5::{inv_mod, mod_exp};
use std::usize;
use ramp::{Int, RandomInt};
use rand::{self, Rng};

fn verify(message: &[u8], (r, s): (&Int, &Int), pub_key: &Int, g: &Int) -> bool {
    let p = Int::from_str_radix(P_STR, 16).unwrap();
    let q = Int::from_str_radix(Q_STR, 16).unwrap();
    // This assertion has to be ommitted for the g = 0 exploit to work
    // assert!(r > &Int::zero());
    assert!(s > &Int::zero());
    assert!(r < &q);
    assert!(s < &q);

    let w = inv_mod(s, &q).unwrap();
    let u1 = (&hash_int(&message) * &w) % &q;
    let u2 = (r * &w) % &q;
    let v = ((mod_exp(g, &u1, &p) * mod_exp(&pub_key, &u2, &p)) % &p) % &q;

    &v == r
}

#[test]
fn tst45() {
    let mut rng = rand::thread_rng();
    let p = Int::from_str_radix(P_STR, 16).unwrap();
    let q = Int::from_str_radix(Q_STR, 16).unwrap();
    // Test g = 0
    // Note that r = ((g^k) % p) % q = 0
    // When verifying, v = ((g^(u1) * y^(u2)) % p) % q = 0
    // This works regardless of s, pubkey, or message. So test with random values
    {
        let mut rand_msg = [0u8; 256];
        // Nothing depends on the pubkey; any pubkey works
        let rand_pubkey = rng.gen_int_range(&Int::one(), &q);
        let rand_s = rng.gen_int_range(&Int::one(), &q);
        rng.fill_bytes(&mut rand_msg);
        assert!(verify(&rand_msg, (&Int::zero(), &rand_s), &rand_pubkey, &Int::zero()));
    }

    // Test g = 1 (mod p) = p * coeff + 1
    // The signature (r, s) where r = (pubkey^z mod p) mod q, s = r * z_inv (mod q), z != 0
    // is a valid signature for any message under the given pubkey
    {
        let coeff = rng.gen_range(0, usize::MAX);
        let g = &p * &Int::from(coeff) + &Int::one();
        // r and s depend on the choice of the pubkey
        let rand_pubkey = rng.gen_int_range(&Int::one(), &p);
        // Choice of z (nonzero) is arbitrary
        let rand_z = rng.gen_int_range(&Int::one(), &q);
        let r = &mod_exp(&rand_pubkey, &rand_z, &p) % &q;
        let s = (&inv_mod(&rand_z, &q).unwrap() * &r) % &q;
        let msg1 = b"Hello, world";
        let msg2 = b"Goodbye, world";
        let mut rand_msg = [0u8; 256];
        rng.fill_bytes(&mut rand_msg);
        assert!(verify(msg1, (&r, &s), &rand_pubkey, &g));
        assert!(verify(msg2, (&r, &s), &rand_pubkey, &g));
        assert!(verify(&rand_msg, (&r, &s), &rand_pubkey, &g));
    }
}
