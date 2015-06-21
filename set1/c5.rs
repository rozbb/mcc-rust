use c2::{encode_hex, xor_bytes};

pub fn xor_bytes_repeating(plaintext: &[u8], key: &[u8]) -> Vec<u8> {
    plaintext.chunks(key.len())
             .flat_map(|chunk| xor_bytes(chunk, &key[..chunk.len()]))
             .collect()
}

fn xor_string_repeating(message: &str, key: &str) -> String {
    encode_hex(&xor_bytes_repeating(message.as_bytes(), key.as_bytes()))
}

#[test]
fn tst5() {
    let plaintext = "Burning 'em, if you ain't quick and nimble\n\
                     I go crazy when I hear a cymbal";
    let key = "ICE";
    let expected = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272\
                    a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f";

    assert_eq!(xor_string_repeating(&plaintext, &key), expected);
}
