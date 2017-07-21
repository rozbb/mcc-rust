use set1::encode_hex;
use set5::sha256;
use ramp::Int;
use rand::{self, Rng};

// Find the cube root of the smallest perfect cube greater than or equal to a
fn find_cube_root(a: &Int) -> Int {
    let two = Int::from(2);
    let three = Int::from(3);
    let mut high = Int::one();
    while &high.pow(3) < a {
        high = &high * &two;
    }
    let mut low = &high / 2;
    while low < high {
        let mid: Int = &(&low + &high) / &two;

        // Recall (x+1)^3 = x^3 + 3x^2 + 3x. Anything inside this is the best we can get
        let threshold = (&three * &mid * &mid) + (&three * &mid) + Int::one();
        let pow: Int = mid.pow(3);
        let dist = a - &pow;

        // We're within the threshold and greater than the true root
        if &dist.clone().abs() < &threshold && &dist <= &Int::zero() {
            return mid;
        }

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

// Find a cube root of something of the form 00 01 ff...ff 00 HASH_LEN HASH GARBAGE
fn forge_sig(msg: &[u8], mod_size: usize) -> Int {
    let two = Int::from(2);
    let pos = mod_size - 8 * 50;

    // Want to represent 00 01 ff ff ... ff hash_len hash garbage
    // This is 2^(mod_size - 7) - 2^(pos) + d * 2^(pos - (hash_len_in_bytes - 240)) + garbage

    let hash = encode_hex(&sha256(msg));
    let hash_len_str = format!("{:02x}", hash.len() / 2);

    // The important parts of the sig
    let d_str: String = ["00", &*hash_len_str, &*hash].concat();
    let d = Int::from_str_radix(&d_str, 16).unwrap();

    let cube = &two.pow(mod_size - 7) - &two.pow(pos) + &d * &two.pow(pos - 8 * (hash.len() - 30));
    let root = find_cube_root(&cube);

    root
}

fn verify(message: &[u8], sig: &Int) -> bool {
    macro_rules! try_match (
        ($e:expr) => (
            if let Some(x) = $e { x } else { return false; }
        )
    );

    let cube = sig.pow(3);
    let cube_str = cube.to_str_radix(16, false);

    if !cube_str.starts_with("1ff") {
        return false;
    }

    let hash_idx = 4 + try_match!(cube_str.find("ff00"));
    let hash_len = 2 * try_match!(
        usize::from_str_radix(&cube_str[hash_idx..(hash_idx + 2)], 16).ok()
    );
    let hash = &cube_str[(hash_idx + 2)..(hash_idx + 2 + hash_len)];

    hash == encode_hex(&*sha256(message))
}
#[test]
fn tst42() {
    let mut rng = rand::thread_rng();

    // Modulus size needs to be sufficiently large to find a cube root
    let modulus_size = 8 * rng.gen_range(256, 1250);

    let msg = b"hi mom";
    let sig = forge_sig(msg, modulus_size);
    assert!(verify(msg, &sig));
}
