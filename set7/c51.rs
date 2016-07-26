use set1::decode_b64;
use set2::{make_vec, AES_BLOCK_SIZE};
use std::collections::BTreeMap;
use std::io::{self, Write};
use std::iter;
use std::usize;
use flate2::Compression;
use flate2::write::GzEncoder;
use rand::{self, Rng};

type CompressionOracle = Box<Fn(&[u8]) -> usize>;

enum OracleType {
    Stream,
    Block
}

// Valid base64 characters. They're in ascending ASCII-order so we can binary search the array in
// next_permutation
const CHARSET: &'static [u8] = b"+/0123456789=ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

// We don't actually encrypt anything because there's no need to. We're only returning the length
// of the compressed input, not any plaintext. To mimic the block cipher, we just round the length
// up to the nearest multiple of 16.

// Returns an oracle that outputs the length of the compressed plaintext of (prefix || injected)
fn make_stream_compression_oracle(prefix: &[u8]) -> CompressionOracle {
    let prefix_copy = prefix.to_vec();
    let oracle = move |injected: &[u8]| {
        let mut c = GzEncoder::new(Vec::new(), Compression::Default);
        c.write(&*prefix_copy).unwrap();
        let length = format!("{}", injected.len()).into_bytes();
        c.write(&*length).unwrap();
        c.write(b"\n").unwrap();
        c.write(injected).unwrap();
        c.finish().unwrap().len()
    };

    Box::new(oracle)
}

// Returns an oracle that outputs the length of the compressed plaintext of (prefix || injected),
// rounded up to the nearest multiple of AES_BLOCK_SIZE
fn make_block_compression_oracle(prefix: &[u8]) -> CompressionOracle {
    let prefix_copy = prefix.to_vec();
    let oracle = move |injected: &[u8]| {
        let mut c = GzEncoder::new(Vec::new(), Compression::Default);
        c.write(&*prefix_copy).unwrap();
        let length = format!("{}", injected.len()).into_bytes();
        c.write(&*length).unwrap();
        c.write(b"\r\n").unwrap();
        c.write(injected).unwrap();
        let len = c.finish().unwrap().len();
        AES_BLOCK_SIZE * ((len + AES_BLOCK_SIZE - 1) / AES_BLOCK_SIZE)
    };

    Box::new(oracle)
}

// Given a vector of bytes in CHARSET, return the next permutation of possible strings over CHARSET
// with length perm.len(), or None if all the permutations have been reached, i.e, perm = "zzz...z"
fn next_permutation(mut perm: Vec<u8>) -> Option<Vec<u8>> {
    for i in 0..(perm.len()) {
        let charset_pos = CHARSET.binary_search(&perm[i]).unwrap();
        if charset_pos < CHARSET.len() - 1 {
            perm[i] = CHARSET[charset_pos+1];
            return Some(perm);
        }
        else {
            perm[i] = CHARSET[0];
        }
    }
    None
}

// Takes a vector of strings that result in the same compressed size and computes all the
// n-character extensions of each of the input strings. It returns only the extensions that
// produce the smallest observed compressed size. The heuristic used is as follows: generate a
// fixed number (here, n_perturbations) of random prefixes of a random length between 1 and
// AES_BLOCK_LENGTH. For each input string, iterate through each random prefix. Repeat the input
// string 8 times and prepend the current random prefix to it. Note the compressed size. Do this
// for all random prefixes and all input strings, returning only those that produced the smallest
// recorded compressed size.
fn extend(to_extend: Vec<Vec<u8>>, ext_len: usize, oracle: &CompressionOracle) -> Vec<Vec<u8>> {
    let n_perturbations = 10;
    let mut extended: Vec<Vec<u8>> = Vec::new();
    let mut min_over_extensions = usize::MAX;
    let mut rng = rand::thread_rng();

    // Fill up the prefixes with random strings of random length 1-16
    let mut rand_prefixes: Vec<Vec<u8>> = Vec::new();
    for _ in 0..n_perturbations {
        let rand_prefix_len = rng.gen_range(1, AES_BLOCK_SIZE);
        let mut rand_prefix = make_vec(0u8, rand_prefix_len);
        rng.fill_bytes(&mut rand_prefix);
        rand_prefixes.push(rand_prefix);
    }

    for guess_prefix in to_extend.into_iter() {
        let mut guess_ext_opt: Option<Vec<u8>> = Some(make_vec(CHARSET[0], ext_len));
        while guess_ext_opt.is_some() {
            let guess_ext = guess_ext_opt.unwrap();

            let mut min_over_perturbations = usize::MAX;
            let guess = [&*guess_prefix, &*guess_ext].concat();

            for rand_prefix in rand_prefixes.clone().into_iter() {
                // perturbed_guess = <rand_prefix> + <guess> * 12
                let perturbed_guess: Vec<u8> = iter::once(rand_prefix).chain(
                     iter::repeat(guess.clone()).take(12)).flat_map(|v| v).collect();
                let length = oracle(&*perturbed_guess);

                // Record the minimum of this extension over all perturbations
                if length < min_over_perturbations {
                    min_over_perturbations = length;
                }
            }

            // We found a new global minimum. Clear the previous winners
            if min_over_perturbations < min_over_extensions {
                min_over_extensions = min_over_perturbations;
                extended.clear();
                extended.push(guess);
            }
            // If we matched the global minimum, add the string to the list
            else if min_over_perturbations == min_over_extensions {
                extended.push(guess);
            }

            guess_ext_opt = next_permutation(guess_ext);
        }
    }

    extended
}

// We filter out the given ties by fixing a random string of a random length and prepending it to
// each full guess. This perturbation should be able to bring out differences in compression that
// were otherwised unseen due to bit alignment. A subset of the input is returned
fn filter(ties: Vec<Vec<u8>>, oracle: &CompressionOracle) -> Vec<Vec<u8>> {
    // Map of compressed size => indices of ties that compress to that size
    let mut len_map: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
    let mut min_len = usize::MAX;

    let mut rng = rand::thread_rng();
    let rand_prefix_len = rng.gen_range(1, AES_BLOCK_SIZE);
    let mut rand_prefix = make_vec(0u8, rand_prefix_len);
    rng.fill_bytes(&mut rand_prefix);

    for (i, guess) in ties.iter().enumerate() {
        let perturbed = [&*rand_prefix, guess].concat();
        let compressed_len = oracle(&*perturbed);
        // Only copy this if it has a chance of being one of the winners
        if compressed_len <= min_len {
            min_len = compressed_len;
            if len_map.contains_key(&compressed_len) {
                let mut v = len_map.get_mut(&compressed_len).unwrap();
                v.push(i);
            }
            else {
                let v = vec![i];
                len_map.insert(compressed_len, v);
            }
        }
    }

    // These had the smallest compression size after the perturbation
    let winner_indices = len_map.remove(&min_len).unwrap();

    ties.into_iter()
        .enumerate()
        .filter(|&(i, _)| winner_indices.binary_search(&i).is_ok())
        .map(|(_, v)| v)
        .collect::<Vec<Vec<u8>>>()
}

// Repeatedly runs filter on the input n times
fn multifilter(mut ties: Vec<Vec<u8>>, oracle: &CompressionOracle, n: usize)
    -> Vec<Vec<u8>> {

    for _ in 0..n {
        if ties.len() == 1 {
            break;
        }
        ties = filter(ties, oracle);
    }
    ties
}

fn recover_cookie(cookie_length: usize, oracle: &CompressionOracle, oracle_t: OracleType)
    -> Vec<u8> {

    let step_size = 2;
    let num_ties_threshold = 10;

    // Contains all the winners from each round
    let mut to_extend: Vec<Vec<u8>> = Vec::new();
    to_extend.push(b"Cookie: sessionid=".to_vec());

    for i in 0..((cookie_length + step_size - 1) / step_size) {
        // If the step size doesn't divide the cookie length, we don't want to reduce the step
        // size, since that produces some bad results. Instead, truncate the remaining guesses such
        // that there are exaclty step_size bytes left to extend.
        if i == (cookie_length / step_size) {
            for v in to_extend.iter_mut() {
                v.truncate(cookie_length - step_size);
            }
        }

        // All these plaintexts are tied for compressing to the smallest number; let's narrow it
        let ties = extend(to_extend, step_size, oracle);

        // Okay, so if the number of iterations in multifilter is too high, then we might
        // accidentally delete the correct extension. On the other hand, if it's too low, we might
        // get a lot of potential extensions. The middle ground is to pick a relatively low value
        // and retry the multifilter until we get a reasonably small number of possible extensions.
        // This literally might take forever, so we'll cap the number of retries at 20.
        to_extend = {
            let mut ret = None;
            for _ in 0..20 {
                let ext = match oracle_t {
                    OracleType::Stream => multifilter(ties.clone(), oracle, 1),
                    OracleType::Block => multifilter(ties.clone(), oracle, 10)
                };
                if ext.len() <= num_ties_threshold {
                    ret = Some(ext);
                    break;
                }
            }
            match ret {
                Some(v) => v,
                //None => panic!("Too many possible extensions! Try again")
                None => return Vec::new()
            }
        };

        // Print the number of ties we have and print the first one in the vec. The terminal
        // control codes are to clear the line. It looks pretty
        print!("\u{001b}[K\r(1 /{:2}): {}", to_extend.len(),
               String::from_utf8_lossy(&*to_extend[0]));
        // print! doesn't flush on its own
        io::stdout().flush().ok().expect("Could not flush stdout");
    }

    // Done with our guessing. We might have multiple ties for the last extension. If so, just
    // filter it hard. This isn't guaranteed to give the right answer.
    while to_extend.len() > 1 {
        to_extend = multifilter(to_extend, oracle, 40);
    }
    // Print the final guess on its own
    print!("\u{001b}[K\r{}         \n", String::from_utf8_lossy(&*to_extend[0]));
    to_extend.pop().unwrap()
}

// This test takes a while (~50 seconds) and it's not entirely reliable, but it works about 87% of
// the time and it's pretty cool
#[test]
fn tst51() {
    let (stream_oracle, block_oracle) = {
        let prefix = b"\
            POST / HTTP/1.1\r\n\
            Host: hapless.com\r\n\
            Cookie: sessionid=TmV2ZXIgcmV2ZWFsIHRoZSBXdS1UYW5nIFNlY3JldCE=\r\n\
            Content-Length: ";
        (make_stream_compression_oracle(&*prefix), make_block_compression_oracle(&*prefix))
    };

    let expected_cookie_value = "Never reveal the Wu-Tang Secret!";

    // Test cookie recovery on a simulated stream cipher
    {
        println!("Testing stream cipher");
        let plaintext_guess = recover_cookie(44, &stream_oracle, OracleType::Stream);

        let cookie_guess_bytes = plaintext_guess.splitn(2, |&b| b == b'=')
                                                .skip(1)
                                                .next()
                                                .expect("Guess is not valid cookie syntax");
        let cookie_guess_str = String::from_utf8_lossy(&*cookie_guess_bytes).into_owned();
        let cookie_decoded_bytes = decode_b64(&cookie_guess_str);
        let decoded_guess = String::from_utf8_lossy(&*cookie_decoded_bytes);

        assert_eq!(&decoded_guess, expected_cookie_value);
    }

    // Test cookie recovery on a simulated block cipher
    {
        println!("Testing block cipher");
        let plaintext_guess = recover_cookie(44, &block_oracle, OracleType::Block);

        let cookie_guess_bytes = plaintext_guess.splitn(2, |&b| b == b'=')
                                                .skip(1)
                                                .next()
                                                .expect("Guess is not valid cookie syntax");
        let cookie_guess_str = String::from_utf8_lossy(&*cookie_guess_bytes).into_owned();
        let cookie_decoded_bytes = decode_b64(&cookie_guess_str);
        let decoded_guess = String::from_utf8_lossy(&*cookie_decoded_bytes);

        assert_eq!(&decoded_guess, expected_cookie_value);
    }
}
