use c53::{make_length_pad_block, md_hash_step, md_hash_iterated, md_hash_iterated_no_pad,
          md_initial_state, MD_HASH_BLOCK_SIZE};
use set2::minimal_pad;
use std::collections::HashMap;
use rand::{self, Rng};

// This is k
const TREE_DEPTH: usize = 10;

// This is the length of actual datum we're predicting. Note it's not necessarily block-aligned
const BASEBALL_SCORE_SIZE: usize = 44;
// This is the prediction, plus glue, plus padding
const FULL_PREDICTION_SIZE: usize =
    BASEBALL_SCORE_SIZE + (MD_HASH_BLOCK_SIZE - (BASEBALL_SCORE_SIZE % MD_HASH_BLOCK_SIZE)) +
    MD_HASH_BLOCK_SIZE * (TREE_DEPTH + 5);

// I'm sorry for this. It had to be done
struct PairChunkIterator<T> {
    vec: Vec<T>
}

impl<T> Iterator for PairChunkIterator<T> {
    type Item = (T, T);
    fn next(&mut self) -> Option<(T, T)> {
        assert!(self.vec.len() % 2 == 0);
        if self.vec.is_empty() {
            return None;
        }
        Some((self.vec.remove(0), self.vec.remove(0)))
    }
}

trait PairChunker<T> {
    fn into_pairs(self) -> PairChunkIterator<T>;
}

impl<T> PairChunker<T> for Vec<T> {
    fn into_pairs(self) -> PairChunkIterator<T> {
        PairChunkIterator {
            vec: self
        }
    }
}

// These are constructed such that H(message_blocks.0, states.0) = H(message_blocks.1, states.1)
struct CollisionPair {
    states: (Vec<u8>, Vec<u8>),
    message_blocks: (Vec<u8>, Vec<u8>)
}

// Find a pair of messages such that H(msg1, state1) = H(msg2, state2).
// Returns (msg1, msg2, digest)
fn find_collision(state1: &[u8], state2: &[u8]) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let mut rng = rand::thread_rng();

    let mut msg1_map: HashMap<Vec<u8>, Vec<u8>> = HashMap::new();
    let mut msg2_map: HashMap<Vec<u8>, Vec<u8>> = HashMap::new();

    let mut msg1 = [0u8; MD_HASH_BLOCK_SIZE];
    let mut msg2 = [0u8; MD_HASH_BLOCK_SIZE];

    // Make random messages and record their hashes in the maps until a collision is found
    loop {
        rng.fill_bytes(&mut msg1);
        rng.fill_bytes(&mut msg2);
        let digest1 = md_hash_step(&msg1, state1);
        let digest2 = md_hash_step(&msg2, state2);

        msg1_map.insert(digest1.clone(), msg1.to_vec());
        msg2_map.insert(digest2.clone(), msg2.to_vec());

        // Found a collision with the current msg2 and a previous msg1
        if msg1_map.contains_key(&*digest2) {
            return (msg1_map.remove(&*digest2).unwrap(), msg2.to_vec(), digest2);
        }

        // Found a collision with the current msg1 and a previous msg2
        if msg2_map.contains_key(&*digest1) {
            return (msg1.to_vec(), msg2_map.remove(&*digest1).unwrap(), digest1);
        }
    }
}

// Returns the first 2^(k-1) random CollisionPairs and the 2^(k-1) states they map into
fn make_layer(states: Vec<Vec<u8>>) -> (Vec<CollisionPair>, Vec<Vec<u8>>) {
    let mut output_states: Vec<Vec<u8>> = Vec::new();
    let mut collision_pairs: Vec<CollisionPair> = Vec::new();

    for (state1, state2) in states.into_pairs() {
        let (msg1, msg2, next_state) = find_collision(&*state1, &*state2);

        let collision_pair = CollisionPair {
            states: (state1, state2),
            message_blocks: (msg1, msg2)
        };
        collision_pairs.push(collision_pair);
        output_states.push(next_state);
    }

    (collision_pairs, output_states)
}

// Makes a vector of layers of the tree, consisting of CollisionPairs. The first layer has 2^(k-1)
// CollisionPairs. The second layer has 2^(k-2), etc. The last layer has one. The final state hash
// is also returned
fn make_collision_tree(k: usize) -> (Vec<Vec<CollisionPair>>, Vec<u8>) {
    let mut rng = rand::thread_rng();
    // More of a vector of vectors of structs than a tree
    let mut tree: Vec<Vec<CollisionPair>> = Vec::new();

    // Make the initial states of the first layer
    let mut initial_states: Vec<Vec<u8>> = Vec::new();
    for _ in 0..2usize.pow(k as u32) {
        let mut state = md_initial_state();
        rng.fill_bytes(&mut state);
        initial_states.push(state);
    }

    let (first_layer, new_states) = make_layer(initial_states);
    tree.push(first_layer);
    initial_states = new_states;

    // Each layer should be half the size of the previous, since we collide each pair into a single
    // digest
    while initial_states.len() > 1 {
        let (collision_pairs, new_states) = make_layer(initial_states);
        tree.push(collision_pairs);
        initial_states = new_states;
    }

    // Sanity check
    assert_eq!(initial_states.len(), 1);

    let final_state = initial_states.remove(0);
    (tree, final_state)
}

// Pick 10 random paths in the collision tree and assert that the final result of the iterated
// hashes is identical
fn verify_collision_tree(collision_tree: &Vec<Vec<CollisionPair>>, final_tree_state: &[u8]) {
    let mut rng = rand::thread_rng();

    for _ in 0..10 {
        let mut idx = rng.gen_range(0, collision_tree[0].len());
        let mut state: Vec<u8>;

        // Pick first block (a leaf) at random
        {
            let leaves = &collision_tree[0];
            let collision_pair = &leaves[idx];
            let block = {
                if rng.gen::<bool>() {
                    state = collision_pair.states.0.clone();
                    &*collision_pair.message_blocks.0
                }
                else {
                    state = collision_pair.states.1.clone();
                    &*collision_pair.message_blocks.1
                }
            };
            state = md_hash_step(block, &*state);
        }

        // Follow the digests through the tree
        for i in 1..collision_tree.len() {
            // See show_prediction for an explanation of how this part works
            let parity = (idx % 2) == 1;
            idx /= 2;
            let layer = &collision_tree[i];
            let collision_pair = &layer[idx];
            let block = {
                if parity {
                    &*collision_pair.message_blocks.1
                }
                else {
                    &*collision_pair.message_blocks.0
                }
            };
            state = md_hash_step(block, &*state);
        }

        // This should be true regardless of how we got to the top of the tree
        assert_eq!(&*state, final_tree_state)
    }
}

// Returns a commitment to a prediction of length FULL_PREDICTION_SIZE given the final state of a
// collision tree. This simply hashes a length block with the final state as the input state
fn make_commitment(final_tree_state: &[u8]) -> Vec<u8> {
    let length_block = make_length_pad_block(FULL_PREDICTION_SIZE);
    md_hash_step(&*length_block, final_tree_state)
}

// Makes a random vector of length BASEBALL_SCORE_SIZE
fn generate_baseball_scores() -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let mut scores = vec![0u8; BASEBALL_SCORE_SIZE];
    rng.fill_bytes(&mut scores);

    scores
}

// This will return a message of length FULL_PREDICTION_SIZE (not that big) and has scores as a
// prefix. The message will hash under md_hash_iterated to the value of the commitment we generated
// before we knew the scores.
fn show_prediction(scores: &[u8], mut tree: Vec<Vec<CollisionPair>>) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let k = tree.len();
    let padded_scores = minimal_pad(scores, MD_HASH_BLOCK_SIZE);

    // Full number of blocks, minus blocks in padded_scores, minus k blocks for the tree
    let n_glue_blocks = ((FULL_PREDICTION_SIZE - padded_scores.len()) / MD_HASH_BLOCK_SIZE) - k;
    let mut glue: Vec<u8> = vec![0u8; MD_HASH_BLOCK_SIZE * n_glue_blocks];
    let leaves: Vec<CollisionPair> = tree.remove(0);

    // This will hold the position in the current layer of the tree
    let mut layer_match_idx: usize;
    // This will hold scores || glue
    let mut scores_plus_glue: Vec<u8>;
    // This will hold the messages we accumulate by traversing the tree starting at the leaf node
    // that we collided into
    let mut tree_msg_blocks: Vec<u8>;

    // Loop until we have a glue that collides into one of our leaves
    'outer: loop {
        rng.fill_bytes(&mut glue);

        scores_plus_glue = [&*padded_scores, &*glue].concat();
        let scores_plus_glue_digest = md_hash_iterated_no_pad(&*scores_plus_glue,
                                                              &*md_initial_state());

        // Iterate through all the leaves, checking if we found a collision into one of their
        // initial states. If we did, that's our starting point
        for (i, collision_pair) in leaves.iter().enumerate() {
            if &*collision_pair.states.0 == &*scores_plus_glue_digest {
                tree_msg_blocks = collision_pair.message_blocks.0.clone();
                layer_match_idx = i;
                break 'outer;
            }
            if &*collision_pair.states.1 == &*scores_plus_glue_digest {
                tree_msg_blocks = collision_pair.message_blocks.1.clone();
                layer_match_idx = i;
                break 'outer;
            }
        }
    }

    // Now follow the leaf to the root. We've already removed the first layer
    for mut layer in tree.into_iter() {
        // We can actually think of the binary representation of the first layer_match_idx as a
        // path from the leaves to the root node, where the bit at each layer indicates the
        // next state to go into (left or right, if you orient the tree top-down)

        // Parity indicates which state in the state tuple the previous message was mapped to
        let parity = (layer_match_idx % 2) == 1;
        // CollisionPair position in the next layer is just the current index divided by 2
        layer_match_idx /= 2;

        let collision_pair = layer.remove(layer_match_idx);
        let msg_block = {
            if parity {
                collision_pair.message_blocks.1
            }
            else {
                collision_pair.message_blocks.0
            }
        };
        tree_msg_blocks.extend(msg_block);
    }

    let prediction = [scores_plus_glue, tree_msg_blocks].concat();

    // Sanity check
    assert_eq!(prediction.len(), FULL_PREDICTION_SIZE);

    prediction
}

#[test]
fn tst54() {
    let (tree, final_tree_state) = make_collision_tree(TREE_DEPTH);
    // Make sure this was constructed correctly
    verify_collision_tree(&tree, &final_tree_state);

    // The commitment is a function of the final tree state
    let commitment = make_commitment(&*final_tree_state);

    // This is 3 blocks of random garbage. We could not possibly know the value of this before
    // commitment was created
    let scores = generate_baseball_scores();

    // Given the scores a-posteriori, we can generate a valid prediction that begins with the value
    // of the scores, and hashes to the original commitment. Magic!
    let prediction = show_prediction(&*scores, tree);

    assert!(prediction.starts_with(&*scores));
    assert_eq!(md_hash_iterated(&*prediction), commitment);
}
