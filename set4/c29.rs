use c28::{get_mac_pair, MacVerifier};
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use rand;
use rand::Rng;
use sha1::Sha1;
use std::io::BufReader;

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
    padding.write_u64::<BigEndian>(len).unwrap();

    padding
}

// Returns a tuple of the new message and forged MAC
fn forge(given_msg: &[u8], valid_mac: &[u8], test: &MacVerifier) -> (Vec<u8>, Vec<u8>) {
    let suffix = b";admin=true";

    // Write the given MAC into the SHA1 state registers
    let mut h = Sha1::new();
    let mut mac_stream = BufReader::new(valid_mac);
    for i in 0..5 {
        let reg_value = mac_stream.read_u32::<BigEndian>().unwrap();
        h.set_register(i, reg_value);
    }

    for i in 0..65 {
        // Padding of the original message
        let glue_padding = md_padding(i + given_msg.len());
        // Padding of the extended message
        let total_padding = md_padding(i + given_msg.len() + glue_padding.len() + suffix.len());
        let padded_suffix = [suffix.to_vec(), total_padding].concat();

        // Make a new copy of the fresh SHA1 instance with the modified registers
        let mut g = h.clone();
        g.update(&*padded_suffix);

        let extended_msg = [given_msg.to_vec(), md_padding(i + given_msg.len()),
                            suffix.to_vec()].concat();
        let forged_mac = g.digest_no_pad();

        if test(&*extended_msg, &*forged_mac) {
            return (extended_msg, forged_mac);
        }
    }

    // Should never happen
    panic!("Could not forge!");
}

#[test]
fn tst29() {
    // Part 1: Test the SHA1 padding code
    let mut rng = rand::thread_rng();
    let rand_msg_len = rng.gen_range(1, 88);
    let mut rand_buf = [0u8; 100];
    rng.fill_bytes(&mut rand_buf);

    let rand_msg = &rand_buf[0..rand_msg_len];
    // Pad the message ourself and see if it matches later
    let padded = [rand_msg, &*md_padding(rand_msg.len())].concat();

    let mut g = Sha1::new();
    let mut h = Sha1::new();
    g.update(rand_msg);
    h.update(&*padded);
    // See if the digests of the library's padded message and ours match up
    assert_eq!(g.digest(), h.digest_no_pad());

    // Part 2: Test the SHA1 length extension exploit
    let msg = b"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon";
    let key = b"YELLOW SUBMARINE";

    let (oracle, verifier) = get_mac_pair(key);
    let valid_mac = oracle(msg);

    let (new_msg, forged_mac) = forge(msg, &*valid_mac, &verifier);

    let real_mac = oracle(&*new_msg);
    assert_eq!(real_mac, forged_mac);
    assert!(new_msg.ends_with(b";admin=true"));
}
