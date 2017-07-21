use c39::{extended_gcd, inv_mod, PRIMES};
use c33::mod_exp;
use std::mem;
use ramp::int::{Int, RandomInt};
use rand;
use rand::Rng;

// Find the nth root of a
fn find_root(a: &Int, n: usize) -> Int {
    let two = Int::from(2);
    let mut high = Int::one();
    while &high.pow(n) < a {
        high = &high * &two;
    }
    let mut low = &high / 2;
    while low < high {
        let mid: Int = &(&low + &high) / &two;
        let pow: Int = mid.pow(n);
        if low < mid && &pow < a {
            low = mid;
        }
        else if high > mid && &pow > a {
            high = mid;
        }
        else {
            return mid;
        }
    }
    low + 1
}

fn decrypt_with_factorization(ciphertext: &Int, p: &Int, q: &Int, exponent: usize) -> Int {
    // Totient ϕ(pq) = (p-1)(q-1) for p, q prime
    let et = (p - Int::one()) * (q - Int::one());
    // Decryption exponent
    let d = inv_mod(&Int::from(exponent), &et).expect("No mod inverse!");
    let n = p * q;
    mod_exp(ciphertext, &d, &n)
}

// Use the chinese remainder theorem to find a common solution to m^3 in a system of 3 pairwise
// relatively prime moduli
fn decrypt_with_crt(ciphertexts: &Vec<Int>, moduli: &Vec<Int>, exponent: usize) -> Int {
    let moduli_product = moduli.iter().fold(Int::one(), |r, s| r * s);
    let m_s = moduli.iter().map(|n| &moduli_product / n).collect::<Vec<Int>>();
    let result = ciphertexts.iter()
                            .zip(m_s.iter())
                            .zip(moduli.iter())
                            .map(|((c, m), n)| c * m * inv_mod(m, n).unwrap())
                            .fold(Int::zero(), |r, s| (r + s) % &moduli_product);

    assert!(&(&result % moduli.get(0).unwrap()) == ciphertexts.get(0).unwrap());
    assert!(&(&result % moduli.get(1).unwrap()) == ciphertexts.get(1).unwrap());
    assert!(&(&result % moduli.get(2).unwrap()) == ciphertexts.get(2).unwrap());

    let root = find_root(&result, exponent);
    root
}

fn crack_message(ciphertexts: &Vec<Int>, moduli: &Vec<Int>, exponent: usize) -> Int {
    // First see if any of the moduli share exactly one common factor
    for i in 0..moduli.len() {
        for j in (i+1)..moduli.len() {
            let (n_0, n_1): (&Int, &Int) = (moduli.get(i).unwrap(), moduli.get(j).unwrap());
            let (gcd, _, _) = extended_gcd(n_0, n_1);

            // We have a common factor
            if &gcd > &Int::one() && &gcd < n_0 && &gcd < n_1 {
                let p = n_0 / gcd;
                let q = n_0 / &p;
                return decrypt_with_factorization(ciphertexts.get(i).unwrap(), &p, &q, exponent);
            }
        }
    }
    // All moduli are pairwise relatively prime; Use the Chinese Remainder Theorem
    decrypt_with_crt(ciphertexts, moduli, exponent)
}

#[test]
fn tst40() {
    let mut rng = rand::thread_rng();
    let exponent = 3usize;
    // Use 6 distinct primes or reuse up to 3 of them
    let n_primes_1 = rng.gen_range(3, 7);
    // Second time, don't reuse anything; want to test CRT
    let n_primes_2 = 6;
    for n_primes in &[n_primes_1, n_primes_2] {
        let primes = rand::sample(&mut rng, PRIMES, *n_primes)
                           .iter()
                           .map(|&s| Int::from_str_radix(s, 16).unwrap())
                           .collect::<Vec<Int>>();
        let mut moduli = (&*primes).windows(2)
                                   .map(|ps| &ps[0] * &ps[1])
                                   .collect::<Vec<Int>>();
        // Trim the moduli down to as many non-prime-sharing as possible
        let mut i = 1usize;
        while moduli.len() > 3 {
            moduli.remove(i);
            i += 1;
        }

        let message = rng.gen_int_range(&Int::from(2), moduli.iter().min().unwrap());
        let ciphertexts = moduli.iter()
                                .map(|n| mod_exp(&message, &Int::from(exponent), n))
                                .collect::<Vec<Int>>();
        let cracked = crack_message(&ciphertexts, &moduli, exponent);
        assert_eq!(message, cracked);
    }
}
