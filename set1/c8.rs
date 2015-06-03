use util::{decode_hex, get_lines};
use std::collections::HashMap;

// Returns the index of the ECB-encrypted ciphertext; None if it cannot be found
fn detect_repeating_blocks(ciphertexts: &[&[u8]], block_size: usize) -> Option<usize> {
    for (idx, bytes) in ciphertexts.iter().enumerate() {
        let mut hm = HashMap::<Vec<u8>, bool>::new();

        for chunk in bytes.chunks(block_size) {
            let chunk_vec = chunk.to_vec();
            // This text has been repeated
            if hm.contains_key(&chunk_vec) {
                return Some(idx);
            }

            hm.insert(chunk_vec, true);
        }
    }

    None
}

#[test]
fn tst8 () {
    let lines: Vec<String> = get_lines("c8.txt");
    let ciphertexts: Vec<Vec<u8>> = lines.iter().map(|line| decode_hex(line)).collect();
    let ciphertexts_ref = &ciphertexts.iter().map(|line| &**line).collect::<Vec<_>>();
    let idx = detect_repeating_blocks(ciphertexts_ref, 16usize).unwrap();
    assert_eq!(idx, 132);
}
