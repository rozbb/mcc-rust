#![allow(unused_mut, unused_variables)]
// ^ Warnings are from the expansion of the get_unpacked_states! macro

use md4_crypto::md4::{Md4, State};
use md4_crypto::digest::Digest;
use md4_crypto::cryptoutil;
use rand::{self, Rng};

const MD4_BLOCK_SIZE: usize = 64;
const MD4_U32_BLOCK_SIZE: usize = MD4_BLOCK_SIZE / 4;

trait GetBit {
    fn bit(self, n: u8) -> Self;
}

impl GetBit for u32 {
    #[inline]
    fn bit(self, n: u8) -> u32 {
        if n < 32 {
            self & (1 << n)
        } else {
            0u32
        }
    }
}

macro_rules! get_unpacked_states {
    ( $m: ident, $( $u:ident ),* ) => {
        let mut states = get_states($m);
        $(
            let mut $u = states.remove(0);
        )*
    };
}

macro_rules! var_eq {
    ( $x: expr, $y: expr, $bit: expr ) => {
        $x = $x ^ ($x.bit($bit) ^ $y.bit($bit));
    }
}

macro_rules! const_eq {
    // $c is 0 or 1
    ( $x: expr, $c: expr, $bit: expr ) => {
        assert!($c == 0 || $c == 1);
        $x = $x ^ (($c << $bit) ^ $x.bit($bit));
    }
}

#[inline]
fn f(x: u32, y: u32, z: u32) -> u32 {
    (x & y) | (!x & z)
}

#[inline]
fn op1(a: u32, b: u32, c: u32, d: u32, k: u32, s: u32) -> u32 {
    a.wrapping_add(f(b, c, d)).wrapping_add(k).rotate_left(s)
}

fn round1_modifications(m: &mut [u32]) {
    get_unpacked_states!(m, s0);
    let (a0, b0, c0, d0) = (s0.a, s0.b, s0.c, s0.d);

    // Round 1, iteration 1
    let mut a1 = op1(a0, b0, c0, d0, m[0], 3);
    var_eq!(a1, b0, 6);
    m[0] = a1.rotate_right(3).wrapping_sub(a0).wrapping_sub(f(b0, c0, d0));

    let mut d1 = op1(d0, a1, b0, c0, m[1], 7);
    const_eq!(d1, 0, 6);
    var_eq!(d1, a1, 7);
    var_eq!(d1, a1, 10);
    m[1] = d1.rotate_right(7).wrapping_sub(d0).wrapping_sub(f(a1, b0, c0));

    let mut c1 = op1(c0, d1, a1, b0, m[2], 11);
    const_eq!(c1, 1, 6);
    const_eq!(c1, 1, 7);
    const_eq!(c1, 0, 10);
    var_eq!(c1, d1, 25);
    m[2] = c1.rotate_right(11).wrapping_sub(c0).wrapping_sub(f(d1, a1, b0));

    let mut b1 = op1(b0, c1, d1, a1, m[3], 19);
    const_eq!(b1, 1, 6);
    const_eq!(b1, 0, 7);
    const_eq!(b1, 0, 10);
    const_eq!(b1, 0, 25);
    m[3] = b1.rotate_right(19).wrapping_sub(b0).wrapping_sub(f(c1, d1, a1));

    // Round 1, iteration 2

    let mut a2 = op1(a1, b1, c1, d1, m[4], 3);
    const_eq!(a2, 1, 7);
    const_eq!(a2, 1, 10);
    const_eq!(a2, 0, 25);
    var_eq!(a2, b1, 13);
    m[4] = a2.rotate_right(3).wrapping_sub(a1).wrapping_sub(f(b1, c1, d1));

    let mut d2 = op1(d1, a2, b1, c1, m[5], 7);
    const_eq!(d2, 0, 13);
    var_eq!(d2, a2, 18);
    var_eq!(d2, a2, 19);
    var_eq!(d2, a2, 20);
    var_eq!(d2, a2, 21);
    const_eq!(d2, 1, 25);
    m[5] = d2.rotate_right(7).wrapping_sub(d1).wrapping_sub(f(a2, b1, c1));

    let mut c2 = op1(c1, d2, a2, b1, m[6], 11);
    var_eq!(c2, d2, 12);
    const_eq!(c2, 0, 13);
    var_eq!(c2, d2, 14);
    const_eq!(c2, 0, 18);
    const_eq!(c2, 0, 19);
    const_eq!(c2, 1, 20);
    const_eq!(c2, 0, 21);
    m[6] = c2.rotate_right(11).wrapping_sub(c1).wrapping_sub(f(d2, a2, b1));

    let mut b2 = op1(b1, c2, d2, a2, m[7], 19);
    const_eq!(b2, 1, 12);
    const_eq!(b2, 1, 13);
    const_eq!(b2, 0, 14);
    var_eq!(b2, c2, 16);
    const_eq!(b2, 0, 18);
    const_eq!(b2, 0, 19);
    const_eq!(b2, 0, 20);
    const_eq!(b2, 0, 21);
    m[7] = b2.rotate_right(19).wrapping_sub(b1).wrapping_sub(f(c2, d2, a2));

    // Round 1, iteration 3

    let mut a3 = op1(a2, b2, c2, d2, m[8], 3);
    const_eq!(a3, 1, 12);
    const_eq!(a3, 1, 13);
    const_eq!(a3, 1, 14);
    const_eq!(a3, 0, 16);
    const_eq!(a3, 0, 18);
    const_eq!(a3, 0, 19);
    const_eq!(a3, 0, 20);
    var_eq!(a3, b2, 22);
    const_eq!(a3, 1, 21);
    var_eq!(a3, b2, 25);
    m[8] = a3.rotate_right(3).wrapping_sub(a2).wrapping_sub(f(b2, c2, d2));

    let mut d3 = op1(d2, a3, b2, c2, m[9], 7);
    const_eq!(d3, 1, 12);
    const_eq!(d3, 1, 13);
    const_eq!(d3, 1, 14);
    const_eq!(d3, 0, 16);
    const_eq!(d3, 0, 19);
    const_eq!(d3, 1, 20);
    const_eq!(d3, 1, 21);
    const_eq!(d3, 0, 22);
    const_eq!(d3, 1, 25);
    var_eq!(d3, a3, 29);
    m[9] = d3.rotate_right(7).wrapping_sub(d2).wrapping_sub(f(a3, b2, c2));

    let mut c3 = op1(c2, d3, a3, b2, m[10], 11);
    const_eq!(c3, 1, 16);
    const_eq!(c3, 0, 19);
    const_eq!(c3, 0, 20);
    const_eq!(c3, 0, 21);
    const_eq!(c3, 0, 22);
    const_eq!(c3, 0, 25);
    const_eq!(c3, 1, 29);
    var_eq!(c3, d3, 31);
    m[10] = c3.rotate_right(11).wrapping_sub(c2).wrapping_sub(f(d3, a3, b2));

    let mut b3 = op1(b2, c3, d3, a3, m[11], 19);
    const_eq!(b3, 0, 19);
    const_eq!(b3, 1, 20);
    const_eq!(b3, 1, 21);
    var_eq!(b3, c3, 22);
    const_eq!(b3, 1, 25);
    const_eq!(b3, 0, 29);
    const_eq!(b3, 0, 31);
    m[11] = b3.rotate_right(19).wrapping_sub(b2).wrapping_sub(f(c3, d3, a3));

    // Round 1, iteration 4

    let mut a4 = op1(a3, b3, c3, d3, m[12], 3);
    const_eq!(a4, 0, 22);
    const_eq!(a4, 0, 25);
    var_eq!(a4, b3, 26);
    var_eq!(a4, b3, 28);
    const_eq!(a4, 1, 29);
    const_eq!(a4, 0, 31);
    m[12] = a4.rotate_right(3).wrapping_sub(a3).wrapping_sub(f(b3, c3, d3));

    let mut d4 = op1(d3, a4, b3, c3, m[13], 7);
    const_eq!(d4, 0, 22);
    const_eq!(d4, 0, 25);
    const_eq!(d4, 1, 26);
    const_eq!(d4, 1, 28);
    const_eq!(d4, 0, 29);
    const_eq!(d4, 1, 31);
    m[13] = d4.rotate_right(7).wrapping_sub(d3).wrapping_sub(f(a4, b3, c3));

    let mut c4 = op1(c3, d4, a4, b3, m[14], 11);
    var_eq!(c4, d4, 18);
    const_eq!(c4, 1, 22);
    const_eq!(c4, 1, 25);
    const_eq!(c4, 0, 26);
    const_eq!(c4, 0, 28);
    const_eq!(c4, 0, 29);
    m[14] = c4.rotate_right(11).wrapping_sub(c3).wrapping_sub(f(d4, a4, b3));

    let mut b4 = op1(b3, c4, d4, a4, m[15], 19);
    const_eq!(b4, 0, 18);
    var_eq!(b4, c4, 25);
    const_eq!(b4, 1, 26);
    const_eq!(b4, 1, 28);
    const_eq!(b4, 0, 29);
    m[15] = b4.rotate_right(19).wrapping_sub(b3).wrapping_sub(f(c4, d4, a4));
}

// Just do a5. I can't figure out how to do any more than that. It's fast enough though :)
// a5 a5,18 = c4,18, a5,25 = 1, a5,26 = 0, a5,28 = 1, a5,31 = 1
fn round2_modifications(m: &mut [u32]) {
    get_unpacked_states!(m, s0, s1, s2, s3, s4);
    let a5_conds: &[u32] = &[s4.c.bit(18), 1 << 25, 0, 1 << 28, 1 << 31];

    for (i, &bit) in [18, 25, 26, 28, 31].iter().enumerate() {
        get_unpacked_states!(m, s0, s1, s2, s3, s4, s5);
        if s5.a.bit(bit) != a5_conds[i as usize] {
            s1.a ^= 1 << bit;

            m[0] ^= 1 << (bit - 3);
            m[1] = s1.d.rotate_right(7).wrapping_sub(s0.d).wrapping_sub(f(s1.a, s0.b, s0.c));
            m[2] = s1.c.rotate_right(11).wrapping_sub(s0.c).wrapping_sub(f(s1.d, s1.a, s0.b));
            m[3] = s1.b.rotate_right(19).wrapping_sub(s0.b).wrapping_sub(f(s1.c, s1.d, s1.a));
            m[4] = s2.a.rotate_right(3).wrapping_sub(s1.a).wrapping_sub(f(s1.b, s1.c, s1.d));
        }
    }
}

#[inline]
fn apply_diff(mut m: &mut [u32]) {
    m[1] ^= 1u32 << 31;
    m[2] ^= (1u32 << 31) ^ (1u32 << 28);
    m[12] ^= 1u32 << 16;
}

// Return all the intermediate states of the MD4 calculation
fn get_states(input: &[u32]) -> Vec<State> {
    assert_eq!(input.len(), 16);

    let mut msg = [0u8; 16*4];
    cryptoutil::write_u32v_le(&mut msg, input);

    let mut h = Md4::new();
    h.input(&msg);
    let mut digest = [0u8; 16];
    h.result(&mut digest);
    h.get_intermediate_states()
}

// Return the MD4 digest
fn get_digest(input: &[u32]) -> Vec<u8> {
    assert_eq!(input.len(), 16);

    let mut msg = [0u8; 16*4];
    cryptoutil::write_u32v_le(&mut msg, input);

    let mut h = Md4::new();
    h.input(&msg);
    let mut digest = [0u8; 16];
    h.result(&mut digest);
    digest.to_vec()
}

// Fill the buffer with random u32s
fn rand_msg_buf(mut m: &mut [u32]) {
    let mut rng = rand::thread_rng();
    for i in 0..m.len() {
        m[i] = rng.gen();
    }
}

fn hamming_dist(a: &[u32], b: &[u32]) -> u32 {
    a.iter().zip(b.iter()).map(|(x, y)| x ^ y).map(u32::count_ones).fold(0u32, |x, a| x + a)
}

// This is the collision found in Wang's paper
fn test_collision() {
    let collision1 = &[0x4d7a9c83, 0x56cb927a, 0xb9d5a578, 0x57a7a5ee, 0xde748a3c, 0xdcc366b3,
                       0xb683a020, 0x3b2a5d9f, 0xc69d71b3, 0xf9e99198, 0xd79f805e, 0xa63bb2e8,
                       0x45dd8e31, 0x97e31fe5, 0x2794bf08, 0xb9e8c3e9];
    let collision2 = &[0x4d7a9c83, 0xd6cb927a, 0x29d5a578, 0x57a7a5ee, 0xde748a3c, 0xdcc366b3,
                       0xb683a020, 0x3b2a5d9f, 0xc69d71b3, 0xf9e99198, 0xd79f805e, 0xa63bb2e8,
                       0x45dc8e31, 0x97e31fe5, 0x2794bf08, 0xb9e8c3e9];

    assert_eq!(get_digest(&*collision1), get_digest(&*collision2));
}

#[test]
fn tst55() {
    // Some unit tests
    test_collision();

    {
        let mut m = [0u32; 16];
        let mut n: [u32; 16];
        rand_msg_buf(&mut m);

        let m0 = m.to_vec();
        let mut m1 = m0.clone();
        round1_modifications(&mut m1);

        let n = m1.clone();
        round1_modifications(&mut m1);
        // Round 1 should be idempotent
        assert_eq!(hamming_dist(&*n, &*m1), 0);

        let mut m2 = m1.clone();
        round2_modifications(&mut m2);

        let n = m2.clone();
        round2_modifications(&mut m2);
        // Round 2 should be idempotent
        assert_eq!(hamming_dist(&*n, &*m2), 0);

        let mut m3 = m2.clone();
        round1_modifications(&mut m3);
        // Round 2 should not clobber round 1
        assert_eq!(hamming_dist(&*m2, &*m3), 0);
    }

    let mut m = [0u32; 16];
    let mut n: [u32; 16];
    let mut dist_after_mods: u32;
    let mut dist_after_diff: u32;
    loop {
        rand_msg_buf(&mut m);
        let m_before_mods = m;
        round1_modifications(&mut m);
        dist_after_mods = hamming_dist(&m_before_mods, &m);
        round2_modifications(&mut m);
        n = m;
        apply_diff(&mut n);

        // Should be 4, since the diff is 4 bits
        dist_after_diff = hamming_dist(&m, &n);

        if get_digest(&m) == get_digest(&n) {
            break;
        }
    }
    assert_eq!(get_digest(&m), get_digest(&n));
    assert!(dist_after_diff > 0); // m != n

    println!("Found collision");
    println!(" M: {:08x} {:08x}", m[0], m[1]);
    for ms in m[2..].chunks(2) {
        println!("    {:08x} {:08x}", ms[0], ms[1]);
    }
    println!("M': {:08x} {:08x}", n[0], n[1]);
    for ms in n[2..].chunks(2) {
        println!("    {:08x} {:08x}", ms[0], ms[1]);
    }

    println!("");
    println!("Hamming distance from original message: {}", dist_after_mods);
    println!("Hamming distance between collisions: {}", dist_after_diff);
}
