use set2::{encrypt_block_ecb, make_vec, minimal_pad, AES_BLOCK_SIZE};
use std::collections::HashMap;
use rand::{self, Rng};

const BAD_HASH_DIGEST_SIZE: usize = 2;    // 16 bits
const DECENT_HASH_DIGEST_SIZE: usize = 4; // 32 bits

// This is a hash function with a 16-bit digest size. This takes in a block of length
// AES_BLOCK_LENGTH and returns the next state of the hash function
fn bad_hash_step(msg_block: &[u8], state: &[u8]) -> Vec<u8> {
    assert_eq!(msg_block.len(), AES_BLOCK_SIZE);
    assert_eq!(state.len(), BAD_HASH_DIGEST_SIZE);

    // Transform the state into an AES key
    let key = minimal_pad(state, AES_BLOCK_SIZE);
    let mut new_state = encrypt_block_ecb(msg_block, &*key);
    new_state.truncate(BAD_HASH_DIGEST_SIZE);

    new_state
}

// This is the iterated hash function using bad_hash_step
fn bad_hash_iterated(msg: &[u8]) -> Vec<u8> {
    assert!(msg.len() % AES_BLOCK_SIZE == 0);
    let mut state = make_vec(0u8, BAD_HASH_DIGEST_SIZE);
    for msg_block in msg.chunks(AES_BLOCK_SIZE) {
        state = bad_hash_step(msg_block, &*state);
    }
    state
}

// Same as bad_hash_step but with a state that's 32 bits
fn decent_hash_step(msg_block: &[u8], state: &[u8]) -> Vec<u8> {
    assert_eq!(msg_block.len(), AES_BLOCK_SIZE);
    assert_eq!(state.len(), DECENT_HASH_DIGEST_SIZE);

    // Transform the state into an AES key
    let key = minimal_pad(state, AES_BLOCK_SIZE);
    let mut new_state = encrypt_block_ecb(msg_block, &*key);
    new_state.truncate(DECENT_HASH_DIGEST_SIZE);

    new_state
}

// This is the iterated hash function using bad_hash_step
fn decent_hash_iterated(msg: &[u8]) -> Vec<u8> {
    assert!(msg.len() % AES_BLOCK_SIZE == 0);
    let mut state = make_vec(0u8, DECENT_HASH_DIGEST_SIZE);
    for msg_block in msg.chunks(AES_BLOCK_SIZE) {
        state = decent_hash_step(msg_block, &*state);
    }
    state
}

// Returns bad_hash_iterated(msg) || decent_hash_iterated(msg)
fn concat_hash(msg: &[u8]) -> Vec<u8> {
    assert!(msg.len() % AES_BLOCK_SIZE == 0);
    [bad_hash_iterated(msg), decent_hash_iterated(msg)].concat()
}

fn choose_2(n: usize) -> usize {
    n * (n-1) / 2
}

// Given n, this will return a set of size 2^n of messages that all have the same bad_hash digest
fn find_bad_hash_collisions(n: usize) -> Vec<Vec<u8>> {
    let mut rng = rand::thread_rng();
    let mut collisions: Vec<Vec<u8>> = Vec::new();

    // This is for the for loop below; it will extend the empty vectors, thus producing the first
    // actual collisions
    collisions.push(Vec::new());

    while collisions.len() < 2usize.pow(n as u32) {
        //println!("{} bad_hash collisions found", collisions.len());
        let mut new_collisions: Vec<Vec<u8>> = Vec::new();

        // By hypothesis, state should not depend on the choice of the message in collisions
        // Note that this will return the initial state when collisions[0] is empty, which it is
        // the first time this loop is run
        let state = bad_hash_iterated(&*collisions[0]);

        // Find a collision given the state that we get from the previous collision. This doesn't
        // do a birthday attack, but it's pretty fast so who cares
        let mut msg1 = make_vec(0u8, AES_BLOCK_SIZE);
        let mut msg2 = make_vec(0u8, AES_BLOCK_SIZE);
        loop {
            rng.fill_bytes(&mut msg1);
            rng.fill_bytes(&mut msg2);

            let digest1 = bad_hash_step(&*msg1, &*state);
            let digest2 = bad_hash_step(&*msg2, &*state);

            // Found a collision, now we can extend the previous collisions
            if digest1 == digest2 {
                break;
            }
        }

        // This will make new_collisions double the size of collisions
        for prefix in collisions.iter() {
            let ext1 = [prefix, &*msg1].concat();
            let ext2 = [prefix, &*msg2].concat();
            new_collisions.push(ext1);
            new_collisions.push(ext2);
        }

        collisions = new_collisions;
    }

    collisions
}

// We use a birthday attack to check all (n choose 2) pairs of bad_hash collisions. Returns a
// collision pair if it found one, and the number of times decent_hash_iterated was called
fn find_decent_hash_collision(bad_hash_collisions: Vec<Vec<u8>>) ->
    (Option<(Vec<u8>, Vec<u8>)>, usize) {

    // Maps a digest to the message that produced it
    let mut digest_map: HashMap<Vec<u8>, Vec<u8>> = HashMap::new();
    // Number of times we call decent_hash_iterated
    let mut n_hashes = 0usize;

    for msg in bad_hash_collisions {
        let digest = decent_hash_iterated(&*msg);
        n_hashes += 1;

        if digest_map.contains_key(&digest) {
            let other = digest_map.remove(&*digest).unwrap();
            return (Some((msg, other)), n_hashes);
        }
        else {
            digest_map.insert(digest, msg);
        }
    }
    println!("digest_map length is {}", digest_map.len());
    (None, n_hashes)
}

#[test]
fn tst52() {
    // Keep finding a ton of bad_hash collisions and then seeing if any also collide for
    // decent_hash
    let mut n_decent_hash_calls = 0usize;
    loop {
        // We need 2^(24 / 2) of these to give us a 50% chance of finding a collision for
        // decent_hash, which has a state size of 3 bytes (24 bits)
        let bad_hash_collisions = find_bad_hash_collisions(8*DECENT_HASH_DIGEST_SIZE / 2);
        assert!(bad_hash_collisions.len() >= 2usize.pow((8*DECENT_HASH_DIGEST_SIZE / 2) as u32));
        println!("{} new bad_hash collisions found", bad_hash_collisions.len());

        // First let's just make sure that we actually have a list of collisions
        let digest = bad_hash_iterated(&*bad_hash_collisions[0]);
        for msg in bad_hash_collisions.iter() {
            assert_eq!(digest, bad_hash_iterated(msg));
        }

        let (collision_opt, n_hash_calls) = find_decent_hash_collision(bad_hash_collisions);
        n_decent_hash_calls += n_hash_calls;
        match collision_opt {
            // We found a decent_hash collision that's also a bad_hash collision! Make sure that it
            // is indeed a concat_hash collision
            Some(collision) => {
                let concat1 = concat_hash(&*collision.0);
                let concat2 = concat_hash(&*collision.1);
                assert_eq!(&*concat1, &*concat2);
                println!("Found a decent_hash collision");
                //println!("Found a decent_hash collision: ({}, {})", encode_hex(&*collision.0),
                //         encode_hex(&*collision.1));
                break;
            }
            // No decent_hash collision was found. Loop again and generate a brand new random set
            // of bad_hash collisions to try out
            None => {
                println!("No decent_hash collision found. Retrying...");
                continue;
            }
        }
    }

    // The 2^((b1 + b2)/2) estimate
    let naive_hash_estimate = 2usize.pow(
                                (8*(DECENT_HASH_DIGEST_SIZE + BAD_HASH_DIGEST_SIZE) / 2) as u32);
    println!("Made a total of {} calls to decent_hash_iterated", n_decent_hash_calls);
    println!("Naive number of calls would be {}", naive_hash_estimate);
    println!("Efficiency is {}%", 100 * naive_hash_estimate / n_decent_hash_calls);
}
