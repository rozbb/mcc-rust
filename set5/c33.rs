use ramp::int::{Int, RandomInt};
use rand;

pub static P_STR: &'static str = "\
    ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024\
    e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd\
    3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec\
    6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f\
    24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361\
    c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552\
    bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff\
    fffffffffffff";
pub static G_STR: &'static str = "2";

// Stolen and modified from https://github.com/jsanders/rust-rsa/blob/master/src/rsa/primes.rs#L32
// Thank you jsanders!
// Modular exponentiation by squaring
pub fn mod_exp(base: &Int, exponent: &Int, modulus: &Int) -> Int {
    let (zero, one) = (Int::zero(), Int::one());
    let mut result = one.clone();
    let mut base_acc = base.clone();
    let mut exponent_acc = exponent.clone();

    while exponent_acc > zero {
        // Accumulate current base if current exponent bit is 1
        if (&exponent_acc & &one) == one {
            result = result * &base_acc;
            result = result % modulus;
        }
        // Get next base by squaring
        base_acc = base_acc.dsquare() % modulus;

        // Get next bit of exponent
        exponent_acc = exponent_acc >> 1;
    }

    result
}

#[allow(non_snake_case)]
#[test]
fn tst33() {
    let p = Int::from_str_radix(P_STR, 16).unwrap();
    let g = Int::from_str_radix(G_STR, 16).unwrap();

    // Generate random numbers from 0..p
    let mut rng = rand::thread_rng();
    let a = rng.gen_int_range(&Int::zero(), &p);
    let b = rng.gen_int_range(&Int::zero(), &p);

    let A = mod_exp(&g, &a, &p);
    let B = mod_exp(&g, &b, &p);

    let s_b = mod_exp(&B, &a, &p);
    let s_a = mod_exp(&A, &b, &p);

    assert_eq!(s_a, s_b);
}
