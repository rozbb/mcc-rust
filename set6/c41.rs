use ramp::{Int, RandomInt};
use rand;
use std::collections::BTreeSet;
use set5::{mod_exp, inv_mod, PRIMES};

type OptDecryptor = Box<FnMut(&Int) -> Option<Int>>;

fn encrypt(m: &Int, e: &Int, n: &Int) -> Int {
    assert!(m < n);
    assert!(m != &Int::zero());

    mod_exp(m, e, n)
}

// Returns a decryptor, the encryption exponent, and modulus
fn make_random_oracle() -> (OptDecryptor, Int, Int) {
    let mut rng = rand::thread_rng();
    // Pick 2 primes randomly
    let mut primes = rand::sample(&mut rng, PRIMES, 2)
                           .iter()
                           .map(|&s| Int::from_str_radix(s, 16).unwrap())
                           .collect::<Vec<Int>>();
    let (p, q) = (primes.pop().unwrap(), primes.pop().unwrap());
    // Modulus
    let n = &p * &q;
    let n_copy = n.clone();
    // Totient ϕ(pq) = (p-1)(q-1) for p, q prime
    let et = (p - Int::one()) * (q - Int::one());
    // Encryption exponent
    let e = Int::from(3);
    // Decryption exponent
    let d = inv_mod(&e, &et).expect("No mod inverse of encryption exponent!");

    let mut history: BTreeSet<Int> = BTreeSet::new();

    let decryptor = move |ciphertext: &Int| {
        assert!(ciphertext < &n);
        if history.contains(ciphertext) {
            return None;
        }
        else {
            history.insert(ciphertext.clone());
            let plaintext: Int = mod_exp(ciphertext, &d, &n);
            return Some(plaintext);
        }
    };

    (Box::new(decryptor), e.clone(), n_copy)
}

fn tricky_decrypt(oracle: &mut OptDecryptor, ciphertext: &Int, e: &Int, n: &Int) -> Int {
    let mut rng = rand::thread_rng();
    let s = rng.gen_int_range(&Int::from(2), &n);
    // We could keep trying if this fails; but I won't because it probably won't fail
    let s_inv = inv_mod(&s, n).expect("No mod inverse of random S!");

    let modified_ciphertext = (mod_exp(&s, e, n) * ciphertext) % n;
    let modified_plaintext = oracle(&modified_ciphertext).expect("Oracle denied decryption!");
    let original_plaintext = (&s_inv * &modified_plaintext) % n;

    original_plaintext
}

#[test]
fn tst40() {
    println!("Starting");
    let mut rng = rand::thread_rng();
    let (mut decryptor, e, n) = make_random_oracle();
    // Make a random message then see if we can crack it
    let message = rng.gen_int_range(&Int::from(2), &n);
    let ciphertext = encrypt(&message, &e, &n);

    // Decrypt it so it ends up in the oracle's history and make sure it's impossible to
    // decrypt again
    let _ = decryptor(&message).unwrap();
    assert!(decryptor(&message).is_none());

    let cracked_message = tricky_decrypt(&mut decryptor, &ciphertext, &e, &n);
    assert_eq!(cracked_message, message);
}
