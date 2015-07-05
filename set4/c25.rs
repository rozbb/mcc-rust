use set1::{dump_file, xor_bytes};
use set2::make_vec;
use set3::get_aes_ctr;
use rand;
use rand::Rng;

type Editor = Box<Fn(&mut [u8], usize, &[u8])>;

// Returns the ciphertext, key, and nonce for testing purposes
fn encrypt_file(filename: &str) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let mut rng = rand::thread_rng();
    let mut rand_key = [0u8; 16];
    let mut rand_nonce = [0u8; 8];
    rng.fill_bytes(&mut rand_key);
    rng.fill_bytes(&mut rand_nonce);

    let contents: String = dump_file(filename);
    let mut e = get_aes_ctr(&rand_key, &rand_nonce);

    (e(contents.as_bytes()), rand_key.to_vec(), rand_nonce.to_vec())
}

fn edit(ciphertext: &mut [u8], key: &[u8], nonce: &[u8],
        offset: usize, new_plaintext: &[u8]) {
    let mut e = get_aes_ctr(key, nonce);

    // "Seek" to the relevant point in our keystream by throwing out all
    // the output that the generator gives before the offset
    let filler = make_vec(b'A', offset);
    e(&filler); // Do nothing with this

    let new_ciphertext = e(new_plaintext);
    for i in offset..offset+new_plaintext.len() {
        ciphertext[i] = new_ciphertext[i];
    }
}

fn fixed_key_nonce_edit(key: &[u8], nonce: &[u8]) -> Editor {
    let key_copy = key.to_vec();
    let nonce_copy = nonce.to_vec();

    let editor = move |ciphertext: &mut [u8], offset: usize,
                       new_plaintext: &[u8]| {
        edit(ciphertext, &*key_copy, &*nonce_copy, offset, new_plaintext)
    };

    Box::new(editor)
}

// Use the editor to make our new plaintext all 0s. CTR will XOR 0 with the keystream,
// returning the unmodified keystream, which is then XORed with the given ciphertext,
// thus revealing the original plaintext
fn get_plaintext(orig_ciphertext: &[u8], editor: &Editor) -> Vec<u8> {
    let mut ciphertext_mut = orig_ciphertext.to_vec();
    let empty_plaintext = make_vec(0u8, orig_ciphertext.len());

    editor(&mut *ciphertext_mut, 0, &empty_plaintext);
    xor_bytes(orig_ciphertext, &ciphertext_mut)
}

#[test]
fn tst25() {
    let (ciphertext, key, nonce) = encrypt_file("c25.txt");
    let attacker_api: Editor = fixed_key_nonce_edit(&key, &nonce);

    let plaintext_raw = get_plaintext(&ciphertext, &attacker_api);
    let plaintext_str = String::from_utf8_lossy(&plaintext_raw).to_owned();

    assert!(plaintext_str.starts_with("I'm back and I'm ringin' the bell"));
    assert!(plaintext_str.ends_with("Play that funky music\n"));
}
