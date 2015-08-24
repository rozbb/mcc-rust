// This file was copied and modified from https://searchcode.com/codesearch/view/8665452/
// Original author: Eric Holk

fn md4_core(ra: u32, rb: u32, rc: u32, rd: u32, orig_msg: &[u8], pad: bool) -> (u32, u32, u32, u32) {
    let orig_len: u64 = (orig_msg.len() * 8usize) as u64;

    let mut msg = orig_msg.to_vec();
    if pad {
        msg.push(0x80u8);
        let mut bitlen = orig_len + 8u64;
        while (bitlen + 64u64) % 512u64 > 0u64 {
            msg.push(0u8);
            bitlen += 8u64;
        }

        // append length
        let mut i = 0u64;
        while i < 8u64 {
            msg.push((orig_len >> (i * 8u64)) as u8);
            i += 1u64;
        }
    } else {
        assert_eq!(msg.len() % 64, 0);
    }

    let mut a = ra;
    let mut b = rb;
    let mut c = rc;
    let mut d = rd;

    fn round_1(x: &[u32], a: u32, b: u32, c: u32, d:u32, k: usize, s: u32) -> u32 {
        a.wrapping_add((b & c) | (!b & d)).wrapping_add(x[k]).rotate_left(s)
    }

    fn round_2(x: &[u32], a: u32, b: u32, c: u32, d:u32, k: usize, s: u32) -> u32 {
        a.wrapping_add((b & c) | ((b & d) | (c & d))).wrapping_add(x[k]).wrapping_add(0x5a827999u32).rotate_left(s)
    }

    fn round_3(x: &[u32], a: u32, b: u32, c: u32, d:u32, k: usize, s: u32) -> u32 {
        a.wrapping_add(b ^ c ^ d).wrapping_add(x[k]).wrapping_add(0x6ed9eba1u32).rotate_left(s)
    }

    let mut x = [0u32; 16];
    let mut i = 0usize;
    let e = msg.len();
    while i < e {
        let aa = a;
        let bb = b;
        let cc = c;
        let dd = d;

        let mut j = 0;
        let mut base = i;
        while j < 16 {
            x[j] = (msg[base] as u32) + ((msg[base + 1] as u32) << 8) +
                ((msg[base + 2] as u32) << 16) +
                ((msg[base + 3] as u32) << 24);
            j += 1;
            base += 4;
        }

        let mut j = 0usize;
        while j < 16 {
            a = round_1(&x, a, b, c, d, j, 3);
            j += 1;
            d = round_1(&x, d, a, b, c, j, 7);
            j += 1;
            c = round_1(&x, c, d, a, b, j, 11);
            j += 1;
            b = round_1(&x, b, c, d, a, j, 19);
            j += 1;
        }

        j = 0;
        while j < 4 {
            a = round_2(&x, a, b, c, d, j, 3);
            d = round_2(&x, d, a, b, c, j+4, 5);
            c = round_2(&x, c, d, a, b, j+8, 9);
            b = round_2(&x, b, c, d, a, j+12, 13);
            j += 1;
        }

        j = 0;
        while j < 8 {
            let jj = if j > 2 { j - 3 } else { j };
            a = round_3(&x, a, b, c, d, jj, 3);
            d = round_3(&x, d, a, b, c, jj+8, 9);
            c = round_3(&x, c, d, a, b, jj+4, 11);
            b = round_3(&x, b, c, d, a, jj+12, 15);
            j += 2;
        }

        a = a.wrapping_add(aa);
        b = b.wrapping_add(bb);
        c = c.wrapping_add(cc);
        d = d.wrapping_add(dd);
        i += 64;
    }

    (a, b, c, d)
}

fn make_digest(a: u32, b: u32, c: u32, d: u32) -> Vec<u8> {
    [a, b, c, d].iter().fold(Vec::<u8>::new(), |mut acc: Vec<u8>, u: &u32| {
        for i in 0..4 {
            let byte = (u >> (i * 8u32)) as u8;
            acc.push(byte);
        }
        acc
    })
}

pub fn md4_normal(msg: &[u8]) -> Vec<u8> {
    let (a, b, c, d) = md4_core(0x67452301u32, 0xefcdab89u32, 0x98badcfeu32, 0x10325476u32, msg, true);
    make_digest(a, b, c, d)
}

pub fn md4_no_pad(msg: &[u8]) -> Vec<u8> {
    let (a, b, c, d) = md4_core(0x67452301u32, 0xefcdab89u32, 0x98badcfeu32, 0x10325476u32, msg, false);
    make_digest(a, b, c, d)
}

pub fn md4_custom(ra: u32, rb: u32, rc: u32, rd: u32, msg: &[u8], pad: bool) -> Vec<u8> {
    let (a, b, c, d) = md4_core(ra, rb, rc, rd, msg, pad);
    make_digest(a, b, c, d)
}

fn hexify(m: &[u8]) -> String {
    m.iter().fold(String::new(), |mut acc: String, u: &u8| {
        acc.push_str(&format!("{:02x}", u));
        acc
    })
}

fn md4_text(msg: &str) -> String { hexify(&*md4_normal(msg.as_bytes())) }

#[test]
fn tst_md4() {
    assert_eq!(md4_text(""), "31d6cfe0d16ae931b73c59d7e0c089c0");
    assert_eq!(md4_text("a"), "bde52cb31de33e46245e05fbdbd6fb24");
    assert_eq!(md4_text("abc"), "a448017aaf21d8525fc10ae87aa6729d");
    assert_eq!(md4_text("message digest"), "d9130a8164549fe818874806e1c7014b");
    assert_eq!(md4_text("abcdefghijklmnopqrstuvwxyz"), "d79e1c308aa5bbcdeea8ed63df412da9");
    assert_eq!(md4_text("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"),
               "043f8582f241db351ce627e153e7f0e4");
    assert_eq!(md4_text("12345678901234567890123456789012345678901234567890123456789012345678901234567890"),
               "e33b4ddc9c38f2199c3e7b164fcc0536");
}
