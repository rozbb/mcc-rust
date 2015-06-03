use util::{decode_hex, encode_hex};

pub fn xor_bytes(a: &[u8], b: &[u8]) -> Vec<u8> {
    let mut out = a.to_owned();
    for (i, val) in out.iter_mut().enumerate() {
        *val = *val ^ b[i];
    }

    out
}

pub fn xor_hex(a: &str, b: &str) -> Vec<u8> {
    if a.len() != b.len() {
        panic!("xor_hex must take arguments of equal length!");
    }
    xor_bytes(&decode_hex(a), &decode_hex(b))
}

#[test]
fn tst2() {
    let a = "1c0111001f010100061a024b53535009181c";
    let b = "686974207468652062756c6c277320657965";
    let xored = xor_hex(a, b);

    assert_eq!(encode_hex(&xored), "746865206b696420646f6e277420706c6179");
}
