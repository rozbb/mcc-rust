use std::fs::File;
use std::io::{BufRead, BufReader, Read};

fn char_to_nibble(c: u8) -> u8 {
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
        let a: u8 = char_to_nibble(chunk[0]);
        let b: u8 = char_to_nibble(chunk[1]);

        bytes.push(((a << 4) | b) as u8);
    }

    bytes
}

fn nibble_to_char(nibble: u8) -> char {
    match nibble {
          0...9 => (nibble + 48) as char,
        10...15 => (nibble + 87) as char,
                _ => panic!("Input is bigger than a nibble! {:08x}", nibble)
    }
}

pub fn encode_hex(input: &[u8]) -> String {
    let mut out = String::new();
    for byte in input {
        let high = nibble_to_char(byte >> 4);
        let low = nibble_to_char(byte & 15);

        out.push(high); out.push(low);
    }

    out
}

fn b64_to_sextet(b: char) -> u8 {
    match b {
        'A'...'Z' => (b as u8) - 65,
        'a'...'z' => (b as u8) - 71,
        '0'...'9' => (b as u8) + 4,
              '+' => 62u8,
              '/' => 63u8,
              '=' => 0u8, // Placeholder value, caller should handle this
               _  => panic!("Invalid base64 input!")
    }
}

pub fn decode_b64(b64: &str) -> Vec<u8> {
    let mut out = Vec::<u8>::new();

    let chars: Vec<char> = b64.chars().collect();

    for chunk in (&chars).chunks(4) {
        if chunk.len() != 4 {
            panic!("Base64 input's length is not a multiple of four!");
        }

        let vals: Vec<u8> = chunk.iter().map(|&i| b64_to_sextet(i)).collect();
        let (a,b,c,d) = (vals[0], vals[1], vals[2], vals[3]);

        let x: u8 = (a << 2) | (b >> 4);
        out.push(x);

        if chunk[2] == '=' { break; }
        let y: u8 = ((b & 15) << 4) | (c >> 2);
        out.push(y);

        if chunk[3] == '=' { break; }
        let z: u8 = ((c & 3) << 6) | d;
        out.push(z);
    }

    out
}

pub fn dump_file(filename: &str) -> String {
    let file = File::open(filename).unwrap();
    let mut buf = BufReader::new(file);

    let mut out = String::new();
    let _ = buf.read_to_string(&mut out).unwrap(); // Panic on read error

    out
}

pub fn get_lines(filename: &str) -> Vec<String> {
    let file = File::open(filename).unwrap();
    let buf = BufReader::new(file);

    buf.lines().map(|s| s.unwrap()).collect()
}

