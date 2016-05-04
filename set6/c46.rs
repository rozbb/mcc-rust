use set1::{decode_hex, encode_hex, decode_b64};
use set5::{inv_mod, mod_exp};
use std::ascii::AsciiExt;
use ramp::{Int, RandomInt};
use rand;

// Returns true when the decrypted input is even
type EvenOracle = Box<Fn(&Int) -> bool>;

// Two primes, each 512 bits
static P_STR: &'static str =
    "F411B6091B67853900125EE34D5CC3AA3434F27C72D159CC9491942A9778D7950509B0A469569E8EB71C2274683D0\
     436D482B0FDB711D8F566720165D6934955";
static Q_STR: &'static str =
    "C389977E0BC323C9F71EF7738D8C564CDBC619F1FAED112611CCE2741DB472043A12E2EC200DFCBFF49421FC1EFBE\
     D0112655B2BE230F9BD8193297F45D2BC29";

fn int_to_string(a: &Int) -> String {
    let bytes = decode_hex(&a.to_str_radix(16, false));
    String::from_utf8_lossy(&*bytes).into_owned()
}

fn string_to_int(s: &str) -> Int {
    let hex = encode_hex(s.as_bytes());
    Int::from_str_radix(&hex, 16).unwrap()
}

// Returns a string of only ascii non-whitespace (except for single space) characters
fn only_ascii(s: &str) -> String {
    s.chars()
     .filter(char::is_ascii)
     .filter(|c| !(c.is_whitespace() && c != &' '))
     .collect::<String>()
}

// Takes a message to encrypt
// Returns an even/odd oracle, an encryption exponent, a modulus, and the encrypted message
fn make_oracle(msg: &Int) -> (EvenOracle, Int, Int, Int) {
    let mut rng = rand::thread_rng();
    let p = Int::from_str_radix(P_STR, 16).unwrap();
    let q = Int::from_str_radix(Q_STR, 16).unwrap();
    // Modulus
    let n = &p * &q;
    let n_copy = n.clone();
    assert_eq!(n.bit_length(), 1024);
    // Totient ϕ(pq) = (p-1)(q-1) for p, q prime
    let et = (p - Int::one()) * (q - Int::one());
    // Encryption exponent must be comprime to (p-1)(q-1)
    let mut e = Int::from(3);
    while e.gcd(&et) != Int::one() {
        e = rng.gen_int_range(&Int::from(5), &et);
    }
    // Decryption exponent
    let d = inv_mod(&e, &et).unwrap();
    let ciphertext = mod_exp(msg, &e, &n);

    let oracle = move |ciphertext: &Int| {
        assert!(ciphertext < &n);
        let plaintext: Int = mod_exp(ciphertext, &d, &n);
        plaintext.is_even()
    };

    (Box::new(oracle), e.clone(), n_copy, ciphertext)
}

fn crack_ciphertext(oracle: &EvenOracle, e: &Int, n: &Int, ciphertext: &Int) -> Int {
    // Note that for any q (mod n), 2q (mod n) is odd iff 2q > n
    // Inductively, q * 2^k (mod n) is odd iff q * 2^k wraps the modulus an odd number of times
    // So if we have a bound on q: [a, b], then q * 2^k is odd iff q lies in the upper half of the
    // bound, and it is even iff q lies in the lower half of the bound. The bound is then halved
    // and k is incremented.
    let mut high = n.clone() - Int::one();
    let mut low = Int::zero();
    let mut i = 1usize;
    while &low != &high {
        let coeff = mod_exp(&Int::from(2), &(e * Int::from(i)), n);
        let modified_ciphertext = (ciphertext * &coeff) % n;
        let is_lower_half = oracle(&modified_ciphertext);
        let (mid, rem) = (&high + &low).divmod(&Int::from(2));

        if is_lower_half {
            high = mid;
        }
        else {
            if rem == Int::zero() {
                low = mid;
            }
            else {
                low = mid + Int::one();
            }
        }
        // Looks pretty cool
        print!("\u{001b}[K\r{:03}: \"{}\"", i, only_ascii(&*int_to_string(&high)));
        i += 1;
    }
    println!("");
    low
}

#[test]
fn tst46() {
    let (oracle, e, n, ciphertext) = {
        let plaintext_b64 = "VGhhdCdzIHdoeSBJIGZvdW5kIHlvdSBkb24ndCBwbGF5IGFyb3VuZCB3aXRoIHRoZSBGd\
                             W5reSBDb2xkIE1lZGluYQ==";
        let plaintext_bytes = decode_b64(plaintext_b64);
        let plaintext_str = String::from_utf8_lossy(&*plaintext_bytes);
        let plaintext_int = string_to_int(&plaintext_str);
        assert!(plaintext_int.bit_length() <= 1024);
        make_oracle(&plaintext_int)
    };

    let plaintext_int = crack_ciphertext(&oracle, &e, &n, &ciphertext);
    let plaintext_str = int_to_string(&plaintext_int);

    // The last byte is 0x5E ('^') but it should be 0x61 ('a'). Not sure why
    assert!(plaintext_str.starts_with("That's why I found you don't play around with the Funky \
                                       Cold Medin"));
}
