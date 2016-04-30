use set1::encode_hex;
use set5::{inv_mod, mod_exp, sha1};
use ramp::{Int, RandomInt};
use rand;

static Q_STR: &'static str = "f4f47f05794b256174bba6e9b396a7707e563c5b";

static P_STR: &'static str =
    "800000000000000089e1855218a0e7dac38136ffafa72eda7859f2171e25e65eac698c1702578b07dc2a1076da241\
     c76c62d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebeac04f48c3c84afb796d61e5a4f9a8fda812ab59\
     494232c7d2b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc871a584471bb1";

static G_STR: &'static str =
    "5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119458fef538b8fa4046c8db53039db620c094c9fa077ef\
     389b5322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a0470f5b64c36b625a097f1651fe775323556fe00b3\
     608c887892878480e99041be601a62166ca6894bdd41a7054ec89f756ba9fc95302291";

// Returns (r, s, k), where (r, s) is the signature and k is a secret
// k is only returned for testing purposes
type Signer = Box<FnMut(&[u8]) -> (Int, Int, Int)>;

// Generate an Int from a message through its hash
fn hash_int(message: &[u8]) -> Int {
    let hash = encode_hex(&sha1(message));
    Int::from_str_radix(&hash, 16).unwrap()
}

// Returns a private key, a pubkey, and a signer
// The private key is returned only for testing purposes
fn make_signer() -> (Int, Int, Signer) {
    let mut rng = rand::thread_rng();
    let p = Int::from_str_radix(P_STR, 16).unwrap();
    let q = Int::from_str_radix(Q_STR, 16).unwrap();
    let g = Int::from_str_radix(G_STR, 16).unwrap();

    let priv_key = rng.gen_int_range(&Int::one(), &q);
    let priv_key_copy = priv_key.clone();
    let pub_key = mod_exp(&g, &priv_key, &p);

    let signer = move |message: &[u8]| {
        let mut k = Int::zero();
        let mut r = Int::zero();
        while r == 0 {
            k = rng.gen_int_range(&Int::one(), &q);
            r = mod_exp(&g, &k, &p) % &q;
        }
        let k_inv = inv_mod(&k, &q).unwrap();

        let h = hash_int(message);
        let s = (&k_inv * (h + &priv_key * &r)) % &q;

        (r, s, k)
    };

    (priv_key_copy, pub_key, Box::new(signer))
}

fn verify(message: &[u8], (r, s): (&Int, &Int), pub_key: &Int) -> bool {
    let p = Int::from_str_radix(P_STR, 16).unwrap();
    let q = Int::from_str_radix(Q_STR, 16).unwrap();
    let g = Int::from_str_radix(G_STR, 16).unwrap();
    assert!(r > &Int::zero());
    assert!(s > &Int::zero());
    assert!(r < &q);
    assert!(s < &q);

    let w = inv_mod(s, &q).unwrap();
    let u1 = (&hash_int(&message) * &w) % &q;
    let u2 = (r * &w) % &q;
    let v = ((mod_exp(&g, &u1, &p) * mod_exp(&pub_key, &u2, &p)) % &p) % &q;

    &v == r
}

// This is simple if we're given k
fn derive_priv_key(message: &[u8], (r, s): (&Int, &Int), k: &Int) -> Int {
    let q = Int::from_str_radix(Q_STR, 16).unwrap();
    let r_inv = inv_mod(&r, &q).unwrap();
    &(r_inv * (s * k - &hash_int(message))) % q
}

// Derive the private key when we don't have k, but we know that 0 < k < 65536
fn crack_priv_key(message: &[u8], (r, s): (&Int, &Int), pub_key: &Int) -> Int {
    let p = Int::from_str_radix(P_STR, 16).unwrap();
    let g = Int::from_str_radix(G_STR, 16).unwrap();

    for _k_guess in 1..65536 {
        let k_guess = Int::from(_k_guess);
        // Derive a private key based on the guess
        let priv_key = derive_priv_key(message, (r, s), &k_guess);
        // If the correct public key is gotten from the derived private key, we're done
        if &mod_exp(&g, &priv_key, &p) == pub_key {
            return priv_key;
        }
    }
    panic!("No valid k found!");
}

#[test]
fn tst43() {
    // Unit testing
    let message = b"Do you see any Teletubbies in here?";
    let (priv_key, pub_key, mut signer) = make_signer();
    // Signature
    let (r, s, k) = signer(message);
    // Make sure DSA works
    assert!(verify(message, (&r, &s), &pub_key));
    // Make sure the private key is properly recovered
    assert_eq!(&derive_priv_key(message, (&r, &s), &k), &priv_key);

    // Now the cracking part
    let given_pubkey = Int::from_str_radix(
        "84ad4719d044495496a3201c8ff484feb45b962e7302e56a392aee4abab3e4bdebf2955b4736012f21a080840\
         56b19bcd7fee56048e004e44984e2f411788efdc837a0d2e5abb7b555039fd243ac01f0fb2ed1dec568280ce6\
         78e931868d23eb095fde9d3779191b8c0299d6e07bbb283e6633451e535c45513b2d33c99ea17",
        16
    ).unwrap();
    let given_message =
        b"For those that envy a MC it can be hazardous to your health\n\
          So be friendly, a matter of life and death, just like a etch-a-sketch\n";
    let (given_r, given_s) = (
        Int::from_str_radix("548099063082341131477253921760299949438196259240", 10).unwrap(),
        Int::from_str_radix("857042759984254168557880549501802188789837994940", 10).unwrap(),
    );

    let cracked_priv_key = crack_priv_key(given_message, (&given_r, &given_s), &given_pubkey);
    let hash = sha1(&cracked_priv_key.to_str_radix(16, false).as_bytes());
    let priv_key_hash_str = encode_hex(&hash);

    assert_eq!(&*priv_key_hash_str, "0954edd5e0afe5542a4adf012611a91912a3ec16");
}
