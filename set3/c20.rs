use c19::{crack_ciphertexts, get_ciphertexts};

#[test]
fn tst20() {
    let ciphertexts = get_ciphertexts("c20.txt");
    let borrowed = ciphertexts.iter().map(|b| &**b).collect::<Vec<&[u8]>>();
    let plaintexts = crack_ciphertexts(&borrowed);
    assert_eq!(plaintexts[8],  "Friday the thirteenth, walking down Elm Street / You ");
    assert_eq!(plaintexts[26], "You want to hear some sounds that not only pounds but");
    assert_eq!(plaintexts[58], "Turn down the bass down / And let the beat just keep ");

    /*for (i, line) in plaintexts.iter().enumerate() {
        println!("({}) {}", i, line);
    }*/
}
