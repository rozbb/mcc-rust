use byteorder::{BigEndian, LittleEndian, ReadBytesExt, WriteBytesExt};
use md4::{md4_normal, md4_custom_no_pad};
use rand;
use rand::Rng;
use std::io::BufReader;

// Copied from c28.rs
type MacGenerator = Box<Fn(&[u8]) -> Vec<u8>>;
type MacVerifier = Box<Fn(&[u8], &[u8]) -> bool>;

// Rewritten from c28.rs; uses md4 instead of sha1
fn get_mac_pair(key: &[u8]) -> (MacGenerator, MacVerifier) {
    let generator_key_copy: Vec<u8> = key.to_vec();
    let verifier_key_copy = generator_key_copy.clone();

    let generator = move |message: &[u8]| {
        let buf: Vec<u8> = [&*generator_key_copy,  message].concat();
        md4_normal(&*buf)
    };

    let verifier = move |message: &[u8], mac: &[u8]| {
        let buf: Vec<u8> = [&*verifier_key_copy, message].concat();
        md4_normal(&*buf) == mac
    };

    (Box::new(generator), Box::new(verifier))
}

// Same as c29.rs except the length is encoded in little endian
fn md_padding(msg_len: usize) -> Vec<u8> {
    let mut padding: Vec<u8> = Vec::new();
    padding.push(128u8);
    // Remaining bytes left until the length is 56 mod 64
    let rem = (64 + (56 - ((msg_len + 1) % 64) as i16)) % 64;
    for _ in 0..rem {
        padding.push(0u8);
    }

    // Length of message in bits, as a 64 bit unsigned int
    let len = (msg_len * 8usize) as u64;
    padding.write_u64::<LittleEndian>(len).unwrap();

    padding
}

// Nearly identical to forge() in c29.rs; only changes are calling conventions
fn forge(given_msg: &[u8], valid_mac: &[u8], test: &MacVerifier) -> (Vec<u8>, Vec<u8>) {
    let suffix = b";admin=true";

    let mut mac_stream = BufReader::new(valid_mac);

    let a = mac_stream.read_u32::<LittleEndian>().unwrap();
    let b = mac_stream.read_u32::<LittleEndian>().unwrap();
    let c = mac_stream.read_u32::<LittleEndian>().unwrap();
    let d = mac_stream.read_u32::<LittleEndian>().unwrap();

    for i in 0..65 {
        // Padding of the original message
        let glue_padding = md_padding(i + given_msg.len());
        // Padding of the extended message
        let total_padding = md_padding(i + given_msg.len() + glue_padding.len() + suffix.len());
        let padded_suffix = [suffix.to_vec(), total_padding].concat();

        let extended_msg = [given_msg.to_vec(), md_padding(i + given_msg.len()),
                            suffix.to_vec()].concat();
        let forged_mac = md4_custom_no_pad(a, b, c, d, &padded_suffix);

        if test(&*extended_msg, &*forged_mac) {
            return (extended_msg, forged_mac);
        }
    }

    // Should never happen
    panic!("Could not forge!");
}

// Identical to tst29() in c29.rs
#[test]
fn tst30() {
    let msg = b"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon";
    let key = b"YELLOW SUBMARINE";

    let (oracle, verifier) = get_mac_pair(key);
    let valid_mac = oracle(msg);

    let (new_msg, forged_mac) = forge(msg, &*valid_mac, &verifier);

    let real_mac = oracle(&*new_msg);
    assert_eq!(real_mac, forged_mac);
    assert!(new_msg.ends_with(b";admin=true"));
}
