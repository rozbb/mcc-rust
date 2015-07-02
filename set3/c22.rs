use c21::get_mt;
use rand;
use rand::Rng;
use time::get_time;

// Simulates seeding the PRNG at some point in the last half hour or so.
// Returns the first number the PRNG outputs, and the seed used (for testing)
fn get_delayed_output() -> (u32, u32) {
    let mut rng = rand::thread_rng();

    let mut now = get_time().sec as u32;
    now -= rng.gen_range(40, 2000);
    let mut mt = get_mt(now);

    let output = mt(1)[0];

    (output, now)
}

// Returns the seed given the output and the knowledge that
// it is the first number output by the generator that was seeded
// within ~2000 seconds of the current time
fn find_seed(output: u32) -> Option<u32> {
    let now = get_time().sec as u32;

    for i in 0u32..5000 {
        let potential_seed = now - i;
        let mut mt = get_mt(potential_seed);

        // Found it
        if mt(1)[0] == output {
            return Some(potential_seed);
        }
    }

    None
}

#[test]
fn tst22() {
    let (output, real_seed) = get_delayed_output();
    let guessed_seed = find_seed(output).unwrap();

    assert_eq!(real_seed, guessed_seed);
}
