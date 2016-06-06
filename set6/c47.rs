use c46::{string_to_int};
use set1::{encode_hex};
use set5::{inv_mod, mod_exp};
use std::cmp::{min, max};
use ramp::{Int, RandomInt};
use rand::{self, Rng};

// Returns true iff the plaintext of the input is PKCS1v1.5 conformant
// Plaintext must be of the form 00 02 P 00 D
// where P (padding) is at least 8 nonzero bytes, and D is the data
// The modulus is 256 bits, so D must be at most 21 bytes
pub type PaddingOracle = Box<Fn(&Int) -> bool>;

// Two primes, each 128 bits
static P_STR: &'static str = "E9C91EF2352925B46A49892CBE932BE1";
static Q_STR: &'static str = "DE876DADCA9F097AE18853C9725E1273";

struct Params {
    B: Int,
    s: Int,
    c0: Int,
    e: Int,
    n: Int,
    oracle: PaddingOracle,
}

// Returns ceil(a / b)
fn divceil(a: &Int, b: &Int) -> Int {
    let (q, r) = a.divmod(b);
    if r > 0 {
        q + Int::one()
    }
    else {
        q
    }
}

// Takes a message to encrypt
// Returns a padding oracle, an encryption exponent, a modulus, and the encrypted message
pub fn make_oracle(msg: &Int, p: &Int, q: &Int) -> (PaddingOracle, Int, Int, Int) {
    let mut rng = rand::thread_rng();
    // Modulus
    let n = p * q;
    //assert_eq!(&n, &Int::from_str_radix(N_STR, 10).unwrap());
    let n_copy = n.clone();
    let n_byte_len = ((n.bit_length() + 7) / 8) as usize;
    //assert_eq!(n.bit_length(), 256);
    // Totient ϕ(pq) = (p-1)(q-1) for p, q prime
    let totient = (p - &Int::one()) * (q - &Int::one());
    // Encryption exponent must be comprime to (p-1)(q-1)
    let mut e = Int::from(3);
    while e.gcd(&totient) != Int::one() {
        e = rng.gen_int_range(&Int::from(5), &totient);
    }
    //let e = Int::from_str_radix(E_STR, 10).unwrap();
    // Decryption exponent
    let d = inv_mod(&e, &totient).unwrap();
    //let d = Int::from_str_radix(D_STR, 10).unwrap();

    // If we format with PKCS1v1.5, the message can only fit if it's at most 21 bytes
    let mut msg_hex = msg.to_str_radix(16, false);

    // Hex is odd length; add a leading 0
    if msg_hex.len() % 2 == 1 {
        msg_hex.insert(0, '0');
    }
    let padding_len = n_byte_len - 3 - msg_hex.len() / 2;
    //println!("padding len == {}", padding_len);
    assert!(padding_len >= 8);

    // Padding must be nonzero
    let mut padding: Vec<u8> = Vec::new();
    while padding.len() < padding_len {
        let byte = rng.gen::<u8>();
        if byte != 0 {
            padding.push(byte);
        }
    }

    let padding_hex = encode_hex(&padding);
    let pkcs_plaintext_hex = ["0002", &padding_hex, "00", &msg_hex].concat();
    let pkcs_plaintext = Int::from_str_radix(&pkcs_plaintext_hex, 16).unwrap();
    //println!("msg_hex == {}", &msg_hex);
    //println!("pkcs plaintext == {}", pkcs_plaintext.to_str_radix(16, false));
    //let pkcs_plaintext = Int::from_str_radix(MSG_STR, 16).unwrap();
    assert!(pkcs_plaintext < n);
    let pkcs_ciphertext = mod_exp(&pkcs_plaintext, &e, &n);

    let oracle = move |ciphertext: &Int| {
        if ciphertext >= &n {
            return false;
        }
        let plaintext: Int = mod_exp(ciphertext, &d, &n);
        // plaintext can't be so small as to start with 0000
        if (plaintext.bit_length() + 15) / 8 != (n.bit_length() + 7) / 8 {
            return false;
        }
        let hex = plaintext.to_str_radix(16, false);
        // hex won't start with 02 because leading 0s are removed. So just make sure that it starts
        // with 2 and its length is odd
        if hex.len() % 2 != 1 || &hex[0..1] != "2" {
            return false;
        }
        return true;
    };

    assert!(oracle(&pkcs_ciphertext));

    (Box::new(oracle), e.clone(), n_copy, pkcs_ciphertext)
}

// Returns the message part of a PKCS-padded plaintext
pub fn extract_message(padded: &Int) -> Int {
    let mut hex = padded.to_str_radix(16, false);
    // If the length is odd, insert a leading 0
    if hex.len() % 2 == 1 {
        hex.insert(0, '0');
    }
    let mut msg_start: Option<usize> = None;
    for (i, pair) in hex.as_bytes().chunks(2).enumerate() {
        let (a, b) = (pair[0], pair[1]);
        if a == b'0' && b == b'0' {
            msg_start = Some(2*(i+1));
        }
    }
    let msg_hex = &hex[msg_start.expect("Malformed message")..];
    return Int::from_str_radix(msg_hex, 16).unwrap();
}

// Step 2a
// Search for the smallest s1 >= n/(3B) such that c0(s1)^e (mod n) passes the oracle
fn step2a(params: &Params) -> Int {
    let (B, n, e, c0, oracle) = (&params.B, &params.n, &params.e, &params.c0, &params.oracle);
    //println!("2a: B == {}, n == {}", B, n);
    let s_lower = n / &(3 * B);
    for s in (s_lower..n.clone()) {
        let ct = (c0 * &mod_exp(&s, e, n)) % n;
        //println!("calculating {} * {}^{} (mod {})", c0, &s, e, n);
        if oracle(&ct) {
            //println!("2a: Winning ct == {}", &ct);
            //println!("Step 2a returned {}", &s);
            return s
        }
    }
    // The loop completed without breaking
    panic!("Failed to find s1!");
}

// Step 2b
// Search for the smallest _s > s such that c0(_s)^e (mod n) passes the oracle
fn step2b(params: &Params) -> Int {
    println!("RUNNING 2B");
    let (s, e, n, c0, oracle) = (&params.s, &params.e, &params.n, &params.c0, &params.oracle);
    let mut _s = s + &Int::one();
    for _s in (s + &Int::one()..n.clone()) {
        if oracle(&((c0 * &mod_exp(&_s, e, n)) % n)) {
            //println!("2b returning {}", &_s);
            return _s;
        }
    }
    panic!("Failed to find next si!");
}

// Step 2c
// Only one interval left
fn step2c(params: &Params, intervals: &Vec<(Int, Int)>) -> Int {
    let (B, s, c0, n, e, oracle) = (&params.B, &params.s, &params.c0, &params.n, &params.e,
                                    &params.oracle);
    let &(ref a, ref b) = intervals.iter().next().unwrap();
    // Lower (inclusive) and upper (exclusive) bounds for r and s
    //println!("2c: b == {}, s == {}, B == {}, n == {}", b, s, B, n);
    let r_lower: Int = divceil(&(2 * (b * s - 2 * B)), n);
    //println!("r_lower == {}", r_lower);

    let mut i = false;
    for r in (r_lower..n.clone()) {
        let s_lower: Int = divceil(&(2 * B + &r * n), b);
        let s_upper: Int = divceil(&(3 * B + &r * n), a);

        let mut _s = s_lower.clone();
        for  _s in (s_lower..s_upper) {
            if !i {
                //println!("2c starting with (r,s) == ({}, {})", &r, &_s);
                i = true;
            }
            let ct = (c0 * &mod_exp(&_s, e, n)) % n;
            if oracle(&ct) {
                //println!("2c returning (r,s) == ({}, {})", &r, &_s);
                return _s;
            }
        }
    }
    panic!("Failed to find si for single interval!");
}

// Step 3
// Narrow the solution set
fn step3(params: &Params, intervals: &Vec<(Int, Int)>) -> Vec<(Int, Int)> {
    //let mut new_intervals: Vec<(Int, Int)> = intervals.clone();
    let mut new_intervals: Vec<(Int, Int)> = Vec::new();
    let (B, n, s, oracle) = (&params.B, &params.n, &params.s, &params.oracle);
    //println!("3: got s == {}, intervals {:?}", s, &intervals);

    for &(ref a, ref b) in intervals.iter() {
        // Lower (inclusive) and upper (inclusive) bounds on r
        let r_lower = divceil(&(a * s - 3 * B + &Int::one()), n);
        let r_upper = &(b * s - 2 * B) / n;
        //println!("(r_lower, r_upper) == ({}, {})", &r_lower, &r_upper);

        for r in (r_lower..r_upper + Int::one()) {
            // Define a new interval
            let lower = max(a, &divceil(&(2 * B + &r * n), s)).clone();
            let upper = min(b, &((3 * B - &Int::one() + &r * n) / s)).clone();
            if lower <= upper {
                //println!("3: Inserting ({}, {})", &lower, &upper);
                insert_interval(&mut new_intervals, lower, upper);
            }
        }
    }

    new_intervals
}

fn insert_interval(intervals: &mut Vec<(Int, Int)>, lower: Int, upper: Int) {
    let mut to_remove: Vec<&(Int, Int)> = Vec::new();
    let (mut running_lower, mut running_upper) = (lower, upper);

    // Merge all intervals that overlap with the one being inserted
    intervals.retain(|&(ref a, ref b): &(Int, Int)| {
        if &running_upper < a || &running_lower > b {
            return true;
        }
        running_lower = min(running_lower.clone(), a.clone());
        running_upper = min(running_upper.clone(), b.clone());
        return false;
    });
    intervals.push((running_lower, running_upper));
}

pub fn bleichenbacher(oracle: PaddingOracle, ciphertext: &Int, e: &Int, n: &Int) -> Int {
    // The ciphertext should be valid
    assert!(oracle(ciphertext));

    let k = ((n.bit_length() + 7) / 8) as usize;
    let B = Int::from(2).pow(8 * (k - 2));
    let s = Int::one();
    let c0 = (ciphertext * &mod_exp(&s, e, n)) % n;

    let mut params = Params {
        B: B.clone(),
        s: s,
        c0: c0,
        e: e.clone(),
        n: n.clone(),
        oracle: oracle
    };
    params.s = step2a(&params);

    let mut intervals: Vec<(Int, Int)> = Vec::new();
    intervals.push((2 * &B, 3 * &B - Int::one()));
    intervals = step3(&params, &intervals);

    loop {
        //println!("intervals == {:?}", &intervals);
        //println!("s == {}", &params.s);
        if intervals.len() >= 2 {
            params.s = step2b(&params);
        }
        else {
            // Step 4 - Check if we're done
            let &(ref a, ref b) = intervals.iter().next().unwrap();
            // If the last remaining interval is of the form (a, a), we're done
            if (a - b) == 0 {
                // Honestly not sure why the paper specifies that this should return a*s^(-1) mod n
                // when the result is actually just a :\
                return a.clone();
                //let m = (a * &inv_mod(&params.s, &params.n).unwrap()) % &params.n;
                //return m;
            }
            else {
                params.s = step2c(&params, &intervals);
            }
        }
        intervals = step3(&params, &intervals);
    }
}

#[test]
fn tst47() {
    let p = Int::from_str_radix(P_STR, 16).unwrap();
    let q = Int::from_str_radix(Q_STR, 16).unwrap();
    let orig_msg = string_to_int("kick it, CC");
    let (oracle, e, n, c) = {
        make_oracle(&orig_msg, &p, &q)
    };

    // This is padded; extract the msg part of it
    let recovered_plaintext = bleichenbacher(oracle, &c, &e, &n);
    let recovered_msg = extract_message(&recovered_plaintext);
    assert_eq!(recovered_msg, orig_msg);
}
