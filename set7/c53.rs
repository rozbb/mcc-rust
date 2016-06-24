use set2::{encrypt_block_ecb, minimal_pad, AES_BLOCK_SIZE};
use std::collections::HashMap;
use std::usize;
use rand::{self, Rng};

pub const MD_HASH_DIGEST_SIZE: usize = 3; // 24 bits
pub const MD_HASH_BLOCK_SIZE: usize = AES_BLOCK_SIZE;

// Initial state is all 0s
pub fn md_initial_state() -> Vec<u8> {
    vec![0u8; MD_HASH_DIGEST_SIZE]
}

// Nothing new here
pub fn md_hash_step(msg_block: &[u8], state: &[u8]) -> Vec<u8> {
    assert_eq!(msg_block.len(), MD_HASH_BLOCK_SIZE);
    assert_eq!(state.len(), MD_HASH_DIGEST_SIZE);

    let key = minimal_pad(state, MD_HASH_BLOCK_SIZE);
    let mut new_state = encrypt_block_ecb(msg_block, &*key);
    new_state.truncate(MD_HASH_DIGEST_SIZE);

    new_state
}

// Classic MD construction. No length padding.
pub fn md_hash_iterated_no_pad(msg: &[u8], state: &[u8]) -> Vec<u8> {
    assert!(msg.len() % MD_HASH_BLOCK_SIZE == 0);
    let mut running_state = state.to_vec();
    for msg_block in msg.chunks(MD_HASH_BLOCK_SIZE) {
        running_state = md_hash_step(msg_block, &*running_state);
    }
    running_state
}

// MD construction with an additional length padding block at the end. The last block contains the
// right-aligned length of the given message, encoded in hex, with 0 padding on the left
pub fn md_hash_iterated(msg: &[u8]) -> Vec<u8> {
    let length_pad_block = make_length_pad_block(msg.len());
    let padded = [minimal_pad(msg, MD_HASH_BLOCK_SIZE), length_pad_block].concat();
    let state = md_initial_state();
    md_hash_iterated_no_pad(&*padded, &*state)
}

pub fn make_length_pad_block(len: usize) -> Vec<u8> {
    let hex_len = format!("{:x}", len).into_bytes();
    let mut length_pad_block = vec![0u8; MD_HASH_BLOCK_SIZE - hex_len.len()];
    length_pad_block.extend(hex_len);
    length_pad_block
}

// Returns a vector of short-long pairs and the final state of the message. When calculating the
// hash of the expanded message, the result should always be the returned final state, regardless
// of the choice of the element of the tuple at each iteration. This is verified randomly by
// verify_expandable_message
fn make_expandable_message(k: usize) -> (Vec<(Vec<u8>, Vec<u8>)>, Vec<u8>) {
    let mut rng = rand::thread_rng();
    let mut collisions: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
    let mut state = md_initial_state();

    for i in 1..(k+1) {
        // This is the 2^(k-i) prefix to the long collision message
        let mut dummy_prefix = vec![0u8; MD_HASH_BLOCK_SIZE * 2usize.pow((k - i) as u32)];
        rng.fill_bytes(&mut dummy_prefix);
        let prefix_state = md_hash_iterated_no_pad(&*dummy_prefix, &*state);

        // Maps for birthday attack. Maps digest to message
        let mut short_state_map: HashMap<Vec<u8>, Vec<u8>> = HashMap::new();
        let mut long_state_map: HashMap<Vec<u8>, Vec<u8>> = HashMap::new();

        // Make 2 new random vectors on each iteration and see if we've seen their digests before
        // Loop until we find a collision
        loop {
            // This is the single-block
            let mut short_msg = [0u8; MD_HASH_BLOCK_SIZE];
            rng.fill_bytes(&mut short_msg);

            // This is the end of the dummy prefix
            let mut long_msg = [0u8; MD_HASH_BLOCK_SIZE];
            rng.fill_bytes(&mut long_msg);

            let short_digest = md_hash_step(&short_msg, &*state);
            let long_digest = md_hash_step(&long_msg, &prefix_state);

            // Insert the digests
            short_state_map.insert(short_digest.clone(), short_msg.to_vec());
            long_state_map.insert(long_digest.clone(), long_msg.to_vec());

            // Found a collision between this short_digest and a previously-found long_digest
            if long_state_map.contains_key(&*short_digest) {
                let matching_long_msg = long_state_map.remove(&*short_digest).unwrap();
                let whole_long_msg = [dummy_prefix, matching_long_msg].concat();
                collisions.push((short_msg.to_vec(), whole_long_msg));
                state = short_digest;
                break;
            }
            // Found a collision between this long_digest and a previously-found short_digest
            if short_state_map.contains_key(&*long_digest) {
                let matching_short_msg = short_state_map.remove(&*long_digest).unwrap();
                let whole_long_msg = [dummy_prefix, long_msg.to_vec()].concat();
                collisions.push((matching_short_msg, whole_long_msg));
                state = long_digest;
                break;
            }
        }
    }

    (collisions, state)
}

// Verifies that the expandable message was constructed properly
fn verify_expandable_msg(expandable_msg: &Vec<(Vec<u8>, Vec<u8>)>, final_state: &[u8]) {
    let mut rng = rand::thread_rng();

    // Take 10 random paths down the expandable message and assert that the final digest is the
    // same regardless of the path taken
    for _ in 0..10 {
        let mut state = md_initial_state();
        for tuple in expandable_msg.iter() {
            if rng.gen::<bool>() {
                state = md_hash_step(&*tuple.0, &*state);
            }
            else {
                state = md_hash_iterated_no_pad(&*tuple.1, &*state);
            }
        }
        assert_eq!(&*state, final_state);
    }
}

// Given the expandable_msg and final state of the expandable message, this function will find a
// message block that hashes (with the final_state as an input state) to an incremental hash of
// some block in orig_msg (the really long message). It will then construct a new message
// consisting of the expandable message expanded to take up exactly the space just before the
// colliding "bridge" block has been found, the bridge block itself, and the rest of the original
// message.
fn find_collision(orig_msg: &[u8], expandable_msg: Vec<(Vec<u8>, Vec<u8>)>,
                  final_expandable_msg_state: Vec<u8>) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let k = expandable_msg.len();

    // Use these for keeping track of the incremental states in the hash of the given message
    let mut state = md_initial_state();
    let mut orig_msg_inc_states: HashMap<Vec<u8>, usize> = HashMap::new();

    // Construct the map of states to indices into orig_msg.chunks(MD_HASH_BLOCK_SIZE)
    for (i, block) in orig_msg.chunks(MD_HASH_BLOCK_SIZE)
                              .enumerate() {
        // If this is the last block, pad it first
        if i == orig_msg.len() / MD_HASH_BLOCK_SIZE {
            state = md_hash_step(&*minimal_pad(block, MD_HASH_BLOCK_SIZE), &*state);
        }
        else {
            state = md_hash_step(block, &*state);
        }
        // We skip the first k blocks because we need at least k blocks of space for the expanded
        // message to fit
        if i >= k-1 {
            orig_msg_inc_states.insert(state.clone(), i);
        }
    }

    // Now we try to find something that gives us the same digest (given the final expanded message
    // state as an input) as some incremental state of the long message.
    let mut bridge = vec![0u8; MD_HASH_BLOCK_SIZE];
    let bridge_idx: usize;
    loop {
        rng.fill_bytes(&mut bridge);
        let bridge_digest = md_hash_step(&*bridge, &*final_expandable_msg_state);
        if orig_msg_inc_states.contains_key(&*bridge_digest) {
            bridge_idx = orig_msg_inc_states.remove(&*bridge_digest).unwrap();
            break;
        }
    }

    // Use a greedy algorithm for finidng a path through the expandable message with a length of
    // prefix_len
    let prefix_len = MD_HASH_BLOCK_SIZE * bridge_idx;
    let mut constructed_prefix: Vec<u8> = Vec::new();
    for (i, (short_msg, long_msg)) in expandable_msg.into_iter().enumerate() {
        // If we can afford to pick the long message and still have room for filling the rest of
        // the buffer with short messages, go for it
        if constructed_prefix.len() + long_msg.len() + MD_HASH_BLOCK_SIZE*(k-i-1) <= prefix_len {
            constructed_prefix.extend(long_msg);
        }
        // If not, add the short message
        else if constructed_prefix.len() + short_msg.len() <= prefix_len {
            constructed_prefix.extend(short_msg);
        }
        // This means we can't fit any more expandable message blocks into our prefix. This
        // shouldn't be possible
        else {
            unreachable!();
        }
    }

    if constructed_prefix.len() != prefix_len {
        panic!("Constructed prefix length is not correct. This shouldn't be possible");
    }

    // Our full collision message is
    // <20 choices from expandable message> || <bridge> || <original message after bridge>
    let collision_msg = [&*constructed_prefix, &*bridge,
                         &orig_msg[MD_HASH_BLOCK_SIZE * (bridge_idx + 1)..]].concat();

    // Make sure the lengths work out. Otherwise the MD hash will give a different final padding
    // block and we've failed
    assert_eq!(collision_msg.len(), orig_msg.len());

    collision_msg
}

#[test]
fn tst53() {
    let mut rng = rand::thread_rng();
    // We want to pick a k such that we have a 50% chance of finding a collision. Since there are
    // 2^k blocks in the message we create and k blocks in the expandable message, there are
    // r := k*2^k possible pairs to potentially collide. The probability of a single pair not
    // colliding is p := (2^(8*MD_HASH_DIGEST_SIZE)-1)/2^(8*MD_HASH_DIGEST_SIZE). Thus, the
    // likelihood of no collisions occuring for a fixed k is p^r. We fix MD_HASH_DIGEST_SIZE = 3,
    // and solve for k such that p^r > 0.5. We find that k > 19. Thus, k = 20 is used.
    let k = 20usize;

    let (e_msg, e_msg_final_state) = make_expandable_message(k);
    // Unit test: make sure the expandable message is valid
    verify_expandable_msg(&e_msg, &*e_msg_final_state);

    // Make a random really long message whose last block has random length (so we don't know the
    // padding the MD algorithm will use in advance)
    let last_block_len = rng.gen_range(1usize, MD_HASH_BLOCK_SIZE + 1);
    let mut really_long_msg = vec![0u8; MD_HASH_BLOCK_SIZE * (2usize.pow(k as u32) - 2)
                                            + last_block_len];
    rng.fill_bytes(&mut really_long_msg);
    let orig_hash = md_hash_iterated(&*really_long_msg);

    let collision = find_collision(&*really_long_msg, e_msg, e_msg_final_state);
    let collision_hash = md_hash_iterated(&*collision);

    // Make sure we didn't accidentally just copy the input
    assert!(collision != really_long_msg);
    // Make sure this is actually a collision
    assert_eq!(collision_hash, orig_hash);
}
