use set1::{decode_b64, get_lines,xor_bytes};
use set2::{AES_BLOCK_SIZE, decrypt_aes_cbc, encrypt_aes_cbc,
           make_vec, pkcs7_pad, pkcs7_unpad};
use rand;
use rand::Rng;

type Checker = Box<Fn(&[u8]) -> bool>;

// Returns a tuple of ciphertext, IV, and oracle. Note: the
// oracle treats the first block of ciphertext as the IV
fn get_padding_oracle(line_number: usize) -> (Vec<u8>, Vec<u8>, Checker) {
    let mut rng = rand::thread_rng();
    let mut key = [0; 16];
    let mut iv = [0; AES_BLOCK_SIZE];
    rng.fill_bytes(&mut key);
    rng.fill_bytes(&mut iv);

    let lines = get_lines("c17.txt");
    let plaintext_choices = lines.iter().map(|s| decode_b64(s))
                                 .collect::<Vec<_>>();
    //let choice_idx = rng.gen_range(0, lines.len());
    let choice_idx = line_number;

    let plaintext_choice = &plaintext_choices[choice_idx];
    let padded = pkcs7_pad(&plaintext_choice, AES_BLOCK_SIZE);
    let ciphertext_choice = encrypt_aes_cbc(&padded, &key, &iv);

    let oracle = move |input: &[u8]| {
        // We don't take the IV explicitly, it's actually the first block
        // of input (makes code cleaner)
        let (iv, ciphertext) = input.split_at(AES_BLOCK_SIZE);
        let plaintext = decrypt_aes_cbc(ciphertext, &key, iv);
        pkcs7_unpad(&plaintext).is_some()
    };

    (ciphertext_choice, iv.to_vec(), Box::new(oracle))
}

fn get_pad_len(ciphertext_block: &[u8], iv: &[u8],
               padding_oracle: &Checker) -> usize {
    // If the unmodified ciphertext+iv don't produce valid
    // plaintext, then it was never padded in the first place
    let mut orig_data = iv.to_vec();
    orig_data.extend(ciphertext_block.to_vec());
    if !padding_oracle(&orig_data) {
        return 0;
    }

    let mut modified_iv = iv.to_vec();
    // Flip bits until the oracle says the padding is broken
    for i in 0..AES_BLOCK_SIZE {
        modified_iv[i] ^= 1u8;

        let mut modified_ct = modified_iv.clone();
        modified_ct.extend(ciphertext_block.to_vec());

        if !padding_oracle(&modified_ct) {
            return AES_BLOCK_SIZE - i;
        }
    }
    // If the above doesn't work, something went terribly wrong
    panic!("get_pad_len() couldn't break the padding!");
}

fn crack_cbc_ciphertext(ciphertext: &[u8], iv: &[u8],
                        padding_oracle: &Checker) -> Vec<u8> {
    let mut plaintext = Vec::new();
    let all_blocks = iv.chunks(AES_BLOCK_SIZE)
                       .chain(ciphertext.chunks(AES_BLOCK_SIZE))
                       .collect::<Vec<_>>();

    // Go through every block that comes before another ciphertext block
    // This includes the IV and excludes the last ciphertext block
    for (block_idx, orig_block) in all_blocks.iter().enumerate()
                                             .take(all_blocks.len()-1) {

        // Buffer for all plaintext found in the target block
        let mut block_plaintext = Vec::new();

        // Get padding len of the next block (the one we're decrypting), using
        // this block as the IV, and the oracle. This is 0 for all blocks but
        // the last one
        let pad_len = if block_idx == all_blocks.len()-2 {
                get_pad_len(all_blocks[block_idx+1], orig_block, padding_oracle)
            } else {
                0usize
            };

        if pad_len > 0 {
            let padding = make_vec(pad_len as u8, pad_len);
            block_plaintext.extend(padding);
        }

        for byte_idx in (0..AES_BLOCK_SIZE-pad_len).rev() {
            let mut xor_block = make_vec(0u8, AES_BLOCK_SIZE);
            let padding_byte = (AES_BLOCK_SIZE - byte_idx) as u8;

            // Fill the end of xor block with the appropriate values
            // to produce a valid padding in the plaintext
            for (i, pt_byte) in ((byte_idx+1)..AES_BLOCK_SIZE)
                                .zip(block_plaintext.iter()) {
                xor_block.remove(i);
                xor_block.insert(i, pt_byte ^ padding_byte);
            }

            let mut winning_byte = None;
            for b in 0usize..256 {
                let test_byte = b as u8;
                xor_block.remove(byte_idx);
                xor_block.insert(byte_idx, test_byte);

                let modified_block = xor_bytes(orig_block, &xor_block);

                // Make the target block (the block we're trying to decrypt) the
                // last block in the ciphertext so the oracle will try to unpad it
                let mut modified_ct = all_blocks[..block_idx+2].to_vec();
                // Swap out the real block for the bit-flipped one
                modified_ct.remove(block_idx);
                modified_ct.insert(block_idx, &modified_block);
                // Flatten the Vec of blocks of bytes to a Vec of bytes
                let modified_ct_flat = modified_ct.iter().flat_map(|&x| x)
                                                  .cloned().collect::<Vec<u8>>();

                if padding_oracle(&modified_ct_flat) {
                    winning_byte = Some(test_byte);
                    break;
                }
            }
            let plaintext_byte = winning_byte.unwrap() ^ padding_byte;
            // Push to the plaintext backwards because we're working backwards
            block_plaintext.insert(0, plaintext_byte);
        }
        plaintext.extend(block_plaintext);
    }

    plaintext
}

#[test]
fn tst17() {
    for i in 0..10 {
        // Note: the line number is only passed to the function for testing purposes.
        // The cracker knows absolutely nothing about the plaintext
        let (ciphertext, iv, oracle) = get_padding_oracle(i);
        let plaintext_bytes = pkcs7_unpad(&crack_cbc_ciphertext(&ciphertext, &iv, &oracle))
                                         .unwrap();
        let plaintext = String::from_utf8_lossy(&plaintext_bytes);

        let expected = match i {
            0 => "000000Now that the party is jumping",
            1 => "000001With the bass kicked in and the Vega's are pumpin'",
            2 => "000002Quick to the point, to the point, no faking",
            3 => "000003Cooking MC's like a pound of bacon",
            4 => "000004Burning 'em, if you ain't quick and nimble",
            5 => "000005I go crazy when I hear a cymbal",
            6 => "000006And a high hat with a souped up tempo",
            7 => "000007I'm on a roll, it's time to go solo",
            8 => "000008ollin' in my five point oh",
            9 => "000009ith my rag-top down so my hair can blow",
            _ => ""
        };

        assert_eq!(plaintext, expected);
        println!("{}", plaintext);
    }
}
