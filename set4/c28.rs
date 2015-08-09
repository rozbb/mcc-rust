use sha1::Sha1;

type MacGenerator = Box<Fn(&[u8]) -> Vec<u8>>;
type Verifier = Box<Fn(&[u8], &[u8]) -> bool>;

fn get_mac_pair(key: &[u8]) -> (MacGenerator, Verifier) {
    let generator_key_copy: Vec<u8> = key.to_vec();
    let verified_key_copy = generator_key_copy.clone();

    let generator = move |message: &[u8]| {
        let mut h = Sha1::new();
        let buf: Vec<u8> = [&*generator_key_copy,  message].concat();
        h.update(&*buf);

        h.digest()
    };

    let verifier = move |mac: &[u8], message: &[u8]| {
        let mut h = Sha1::new();
        let buf: Vec<u8> = [&*verified_key_copy, message].concat();
        h.update(&*buf);

        h.digest() == mac
    };

    (Box::new(generator), Box::new(verifier))
}

#[test]
fn c28() {
    let key = b"YELLOW SUBMARINE";
    let (m, v) = get_mac_pair(key);

    let message = b"testing testing 123";
    let valid_mac = m(message);
    let invalid_mac = valid_mac.iter().map(|&b| b.wrapping_add(17u8))
                               .collect::<Vec<u8>>();

    assert!( v(&valid_mac, message));
    assert!(!v(&invalid_mac, message));
}
