use set1::xor_bytes;
use c10::{decrypt_aes_cbc, encrypt_aes_cbc, AES_BLOCK_SIZE};
use c12::make_vec;
use c15::pkcs7_unpad;
use rand;
use rand::Rng;

type Encryptor = Box<Fn(&[u8]) -> Vec<u8>>;
type Tester = Box<Fn(&[u8]) -> bool>;

fn sanitize(input: &[u8]) -> Vec<u8> {
    input.iter().map(|&byte| {
        if byte == b';' || byte == b'=' {
            b'%' // Replace with this arbitrary character
        } else {
            byte
        }
    }).collect::<Vec<u8>>()
}

fn get_oracle_and_tester() -> (Encryptor, Tester) {
    let mut rng = rand::thread_rng();
    let mut key = [0; 16];
    let mut iv = [0; 16];
    rng.fill_bytes(&mut key);
    rng.fill_bytes(&mut iv);

    let prefix = b"comment1=cooking%20MCs;userdata=";
    let suffix = b";comment2=%20like%20a%20pound%20of%20bacon";

    let cbc_oracle = move |plaintext: &[u8]| {

        let mut modified_plaintext = prefix.to_vec();
        modified_plaintext.extend(sanitize(plaintext));
        modified_plaintext.extend(suffix.to_vec());

        encrypt_aes_cbc(&modified_plaintext,
                        &key.to_vec(), &iv.to_vec())
    };

    // Checks if decrypted ciphertext is valid and has admin=true
    let admin_tester = move |ciphertext: &[u8]| {
        let raw_plaintext = decrypt_aes_cbc(ciphertext,
                                            &key.to_vec(), &iv.to_vec());
        let unpadded_pt = pkcs7_unpad(&raw_plaintext).unwrap();
        let pt_str = String::from_utf8_lossy(&unpadded_pt).to_owned();
        for s in pt_str.split(";") {
            let kv = s.split("=").collect::<Vec<&str>>();
            if kv.len() != 2 {
                return false;
            }
            if kv[0] == "admin" && kv[1] == "true" {
                return true;
            }
        }
        false
    };

    (Box::new(cbc_oracle), Box::new(admin_tester))
}

fn make_admin_ciphertext(cbc_oracle: &Encryptor) -> Vec<u8> {
    // fill prefix to a block boundary, then add two more filler blocks
    let prefix_len = 32;
    let n_prefix_blocks = (prefix_len / AES_BLOCK_SIZE) +
                            if prefix_len % AES_BLOCK_SIZE != 0 { 1usize }
                            else { 0usize };
    let filler_len = ((AES_BLOCK_SIZE - (prefix_len % AES_BLOCK_SIZE)) % AES_BLOCK_SIZE)
                        + 2*AES_BLOCK_SIZE;
    let filler = make_vec(b'A', filler_len);

    let mut ciphertext = cbc_oracle(&filler);

    // Index of the ciphertext block we're gonna mess with
    let malleable_block_idx = n_prefix_blocks;

    // What we want our block to look like post-xor
    let admin = b";admin=true";
    let mut admin_block = make_vec(b'A', AES_BLOCK_SIZE - admin.len());
    admin_block.extend(admin.to_vec());

    {
        let mut malleable_block = ciphertext.chunks_mut(AES_BLOCK_SIZE)
                                            .nth(malleable_block_idx).unwrap();
        let filler_block = make_vec(b'A', AES_BLOCK_SIZE);
        let xor_block = xor_bytes(&filler_block, &admin_block);

        // I'd do this with iters but Vec::map_in_place() is unstable :\
        for (i, b) in xor_block.iter().enumerate() {
            malleable_block[i] ^= *b;
        }
    }

    ciphertext
}

#[test]
fn tst16() {
    let mut success = false;

    // There's an 11.8% chance of getting an unwanted ';' or '=' character, so try a few times
    for _ in 0..10 {
        let (cbc_oracle, admin_tester) = get_oracle_and_tester();
        let ciphertext = make_admin_ciphertext(&cbc_oracle);
        if admin_tester(&ciphertext) {
            success = true;
            break;
        }
    }
    assert!(success);
}
