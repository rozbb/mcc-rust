use c21::{Generator, get_mt, mt_extract_number, mt_generate_numbers, MTState};
use rand;
use rand::Rng;

fn t4(y: u32) -> u32 {
    y ^ (y >> 18)
}

fn u4(x: u32) -> u32 {
    // First 18 bits of x and untempered
    let a = x & 0xffffc000;
    // Last 14 bits of x
    let b = x & 0x3fff;
    // Last 14 bits of untempered
    let c = (a >> 18) ^ b;

    a | c
}

fn t3(y: u32) -> u32 {
    y ^ ((y << 15) & 0xefc60000)
}

fn u3(x: u32) -> u32 {
    // Last 15 bits of x and untempered
    let a = x & 0x7fff;
    // Second-to-last 15 bits of magic number
    let b = 0xefc60000 & 0x3fff8000;
    // Second-to-last 15 bits of x
    let c = x & 0x3fff8000;
    // Second-to-last 15 bits of untempered
    let d = ((a << 15) & b) ^ c;
    //assert_eq!(d, 8);
    // Bits 16, 17 of untempered
    let e = d & 0x18000;
    // First two bits of magic number
    let f = 0xefc60000 & 0xc0000000;
    // First two bits of x
    let g = x & 0xc0000000;
    // First two bits of untempered
    let h = ((e << 15) & f) ^ g;

    h | d | a
}

fn t2(y: u32) -> u32 {
    y ^ ((y << 7) & 0x9d2c5680)
}

fn u2(x: u32) -> u32 {
    // Last 7 bits of x and untempered
    let a = x & 0x7f;
    // Second-to-last 7 bits of magic number
    let b = 0x9d2c5680 & 0x3f80;
    // Second-to-last 7 bits of x
    let c = x & 0x3f80;
    // Second-to-last 7 bits of untempered
    let d = ((a << 7) & b) ^ c;
    // Third-to-last 7 bits of magic number
    let e = 0x9d2c5680 & 0x1fc000;
    // Third-to-last 7 bits of x
    let f = x & 0x1fc000;
    // Third-to-last 7 bits of untempered
    let g = ((d << 7) & e) ^ f;
    // Fourth-to-last 7 bits of magic number
    let h = 0x9d2c5680 & 0xfe00000;
    // Fourth-to-last 7 bits of x
    let i = x & 0xfe00000;
    // Fourth-to-last 7 bits of untempered
    let j = ((g << 7) & h) ^ i;
    // Bits 8,9,10,11 of untempered;
    let k = j & 0x1e00000;
    // First four bits of magic number
    let l = 0x9d2c5680 & 0xf0000000;
    // First four bits of x
    let m = x & 0xf0000000;
    // First four bits of untempered;
    let n = ((k << 7) & l) ^ m;

    n | j | g | d | a
}

fn t1(y: u32) -> u32 {
    y ^ (y >> 11)
}

fn u1(x: u32) -> u32 {
    // First 11 bits of x and untempered
    let a = x & 0xffe00000;
    // Second 11 bits of x
    let b = x & 0x1ffc00;
    // Second 11 bits of untempered
    let c = (a >> 11) ^ b;
    // Last 9 bits of x
    let d = x & 0x3ff;
    // Last 9 bits of untempered
    let e = (c >> 11) ^ d;

    a | c | e
}

fn untemper(x: u32) -> u32 {
    let seq: &[fn(u32) -> u32] = &[u4, u3, u2, u1];
    seq.iter().fold(x, |acc, f| f(acc)) // What's a pipe operator?
}

fn clone_mt(mt: &mut Generator) -> Generator {
    let mut index = 0usize;

    let mut state: MTState = [0; 624];
    for (i, n) in mt(624).into_iter().enumerate() {
        state[i] = untemper(n);
    }

    // Same code as the MT implementation except the state is already initialized
    let generator = move |n_words: usize| {
        let mut ret: Vec<u32> = Vec::new();

        for _ in 0..n_words {
            if index == 0 {
                mt_generate_numbers(&mut state);
            }
            ret.push(mt_extract_number(&state, index));
            index = (index + 1) % 624;
        }

        ret
    };

    Box::new(generator)
}

#[test]
fn tst23() {
    let mut rng = rand::thread_rng();

    // Make sure the untemper functions are the inverses of the temper functions
    for _ in 0..200_000 {
        let i = rng.gen_range(0u64, (1 << 31)) as u32;
        assert_eq!(u1(t1(i)), i);
        assert_eq!(u2(t2(i)), i);
        assert_eq!(u3(t3(i)), i);
        assert_eq!(u4(t4(i)), i);
    }

    // Make sure the cloned PRNG gives us the same output as the PRNG
    let seed = rng.gen::<u32>();
    let mut real_mt = get_mt(seed);
    let mut cloned_mt = clone_mt(&mut real_mt);

    let cloned_output = cloned_mt(2);
    let real_output = real_mt(2);

    assert_eq!(real_output, cloned_output);
}
