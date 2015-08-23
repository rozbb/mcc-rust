use sha1::Sha1;

pub type MacGenerator = Box<Fn(&[u8]) -> Vec<u8>>;
pub type MacVerifier = Box<Fn(&[u8], &[u8]) -> bool>;

pub fn get_mac_pair(key: &[u8]) -> (MacGenerator, MacVerifier) {
    let generator_key_copy: Vec<u8> = key.to_vec();
    let verifier_key_copy = generator_key_copy.clone();

    let generator = move |message: &[u8]| {
        let mut h = Sha1::new();
        let buf: Vec<u8> = [&*generator_key_copy,  message].concat();
        h.update(&*buf);

        h.digest()
    };

    let verifier = move |message: &[u8], mac: &[u8]| {
        let mut h = Sha1::new();
        let buf: Vec<u8> = [&*verifier_key_copy, message].concat();
        h.update(&*buf);

        h.digest() == mac
    };

    (Box::new(generator), Box::new(verifier))
}

#[test]
fn tst28() {
    let key = b"YELLOW SUBMARINE";
    let (m, v) = get_mac_pair(key);

    let message = b"testing testing 123";
    let valid_mac = m(message);
    let invalid_mac = valid_mac.iter().map(|&b| b.wrapping_add(17u8))
                               .collect::<Vec<u8>>();

    assert!( v(message, &valid_mac));
    assert!(!v(message, &invalid_mac));
}
