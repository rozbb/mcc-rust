use set2::make_vec;
use set3::get_aes_ctr;
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
    let mut nonce = [0; 8];
    rng.fill_bytes(&mut key);
    rng.fill_bytes(&mut nonce);

    let prefix = b"comment1=cooking%20MCs;userdata=";
    let suffix = b";comment2=%20like%20a%20pound%20of%20bacon";

    let ctr_oracle = move |plaintext: &[u8]| {
        let modified_plaintext = [prefix.to_vec(), sanitize(plaintext),
                                  suffix.to_vec()].concat();
        let mut e = get_aes_ctr(&key.to_vec(), &nonce.to_vec());
        e(&modified_plaintext)

    };

    // Checks if decrypted ciphertext is valid and has admin=true
    let admin_tester = move |ciphertext: &[u8]| {
        let mut d = get_aes_ctr(&key.to_vec(), &nonce.to_vec());
        let raw_pt = d(ciphertext);
        let pt_str = String::from_utf8_lossy(&raw_pt).to_owned();
        println!("pt_str == {}", &pt_str);
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

    (Box::new(ctr_oracle), Box::new(admin_tester))
}

fn make_admin_ciphertext(oracle: &Encryptor) -> Vec<u8> {
    let known_prefix_len = "comment1=cooking%20MCs;userdata=".len(); // Totes not cheating
    let target_pt = b";admin=true;";
    let filler_len = target_pt.len();
    let filler_pt = make_vec(b'A', filler_len);
    let mut ct: Vec<u8> = oracle(&filler_pt);

    for (i, target_byte) in (known_prefix_len..(known_prefix_len+filler_len))
                            .zip(target_pt.iter()) {
        ct[i] ^= b'A' ^ target_byte;
    }

    ct
}

#[test]
fn tst26() {
    let (ctr_oracle, admin_tester) = get_oracle_and_tester();
    let ciphertext = make_admin_ciphertext(&ctr_oracle);
    assert!(admin_tester(&ciphertext));
}
