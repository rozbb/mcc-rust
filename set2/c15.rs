pub fn pkcs7_unpad(input: &[u8]) -> Option<Vec<u8>> {
    let mut out = input.to_vec();
    let pad_len = *out.last().unwrap();
    for _ in 0u8..pad_len {
        let pad_byte = out.pop();

        if pad_byte.is_none()
             || pad_byte.unwrap() != pad_len {
            return None;
        }
    }
    Some(out)
}

#[test]
fn tst15() {
    let a = pkcs7_unpad(b"ICE ICE BABY\x04\x04\x04\x04");
    let b = pkcs7_unpad(b"ICE ICE BABY\x05\x05\x05\x05");
    let c = pkcs7_unpad(b"ICE ICE BABY\x01\x02\x03\x04");
    assert!(a.is_some());
    assert_eq!(a.unwrap(), b"ICE ICE BABY");
    assert_eq!(b, None);
    assert_eq!(c, None);
}
