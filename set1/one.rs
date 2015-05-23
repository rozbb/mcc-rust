fn nibble_to_byte(c: u8) -> u8 {
    match c as char {
        '0'...'9' => c - 48,
        'a'...'f' => c - 87,
                _ => panic!("Input is not valid hex! {}", c as char)
    }
}

pub fn decode_hex(input: &str) -> Vec<u8> {
    let mut hex = String::new();
    // If there aren't an even number of nibbles, prepend '0'
    if (input.len() % 2) == 1 {
        hex.push('0');
    }
    hex.push_str(input);

    let mut bytes = Vec::<u8>::new();
    for chunk in hex.as_bytes().chunks(2) {
        let a: u8 = nibble_to_byte(chunk[0]);
        let b: u8 = nibble_to_byte(chunk[1]);

        bytes.push(((a << 4) | b) as u8);
    }

    bytes
}

pub fn hex_to_b64(hex: &str) -> String {
    let bytes: Vec<u8> = decode_hex(hex);
    let mut out = String::new();

    for chunk in bytes.chunks(3) {
        // If the length of bytes isn't divisible by 3, assume
        // the rest is 0
        let missing = 3 - chunk.len();
        let x: u8 = chunk[0]; // The first element is guaranteed
        let y: u8 = *chunk.get(1).unwrap_or(&0);
        let z: u8 = *chunk.get(2).unwrap_or(&0);

        let a: u8 = x >> 2;
        let b: u8 = ((x & 3) << 4) | (y >> 4);
        let c: u8 = ((y & 15) << 2) | (z >> 6);
        let d: u8 = z & 63;

        for (idx, val) in [a,b,c,d].iter().enumerate() {
            if idx > (3 - missing) { break; }
            match *val {
                 0...25 => out.push(((val+65) as u8) as char),
                26...51 => out.push(((val+71) as u8) as char),
                52...61 => out.push(((val-4)  as u8) as char),
                     62 => out.push('+'),
                     63 => out.push('/'),
                      _ => () // Not possible
            }
        }

        for _ in 0..missing {
            out.push('=');
        }
    }

    out
}

#[test]
fn tst1() {
    assert_eq!(
        hex_to_b64("49276d206b696c6c696e6720796f757220627261696e206c696b652061\
                     20706f69736f6e6f7573206d757368726f6f6d"),
        "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
    );
}
