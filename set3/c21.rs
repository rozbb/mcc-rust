pub type Generator = Box<FnMut(usize) -> Vec<u32>>;
type MTState = [u32; 624];

fn mt_initialize_state(mut state: &mut MTState, seed: u32) {
    state[0] = seed;
    for i in 1usize..624 {
        // Note: as u32 uses the bottom 32 bits
        state[i] = (0x6c078965u64 * ((state[i-1] ^ (state[i-1] >> 30)) as u64)
                    + (i as u64)) as u32;
    }
}

fn mt_extract_number(state: &MTState, index: usize) -> u32 {
    let mut y: u32 = state[index];
    y ^=  y >> 11;
    y ^= (y << 07) & 0x9d2c5680u32;
    y ^= (y << 15) & 0xefc60000u32;
    y ^=  y >> 18;

    y
}

fn mt_generate_numbers(state: &mut MTState) {
    for i in 0..624 {
        let y: u32 = ((state[i] & 0x80000000u32) as u64
                       + (state[(i+1) % 624] & 0x7fffffffu32) as u64) as u32;
        state[i] = state[(i+397) % 624] ^ (y >> 1);
        if y % 2 != 0 {
            state[i] ^= 0x9908b0dfu32;
        }
    }
}

// Verified against the output of the C++ program on the MersenneTwister website:
//     http://www.math.sci.hiroshima-u.ac.jp/~m-mat/MT/VERSIONS/C-LANG/zubin/MersenneTwister.cpp
//     http://www.math.sci.hiroshima-u.ac.jp/~m-mat/MT/VERSIONS/C-LANG/zubin/MersenneTwister.h
// with appropriate changes in the code in order to choose the seed (5489u32)
pub fn get_mt(seed: u32) -> Generator {
    let mut index = 0usize;
    let mut state: MTState = [0u32; 624];

    mt_initialize_state(&mut state, seed);

    let generator = move |n_words: usize| {
        let mut ret: Vec<u32> = Vec::new();

        for _ in 0..n_words {
            if index == 0 {
                mt_generate_numbers(&mut state);
            }
            ret.push(mt_extract_number(&state, index));
            index = (index + 1) % 624;
        }

        ret
    };

    Box::new(generator)
}

#[test]
fn tst21() {
    let mut gen = get_mt(5489u32);
    let output: Vec<u32> = gen(1000);

    let expected_begin = [3499211612,  581869302, 3890346734, 3586334585,  545404204,
                          4161255391, 3922919429,  949333985, 2715962298, 1323567403u32];
    let expected_end   = [1787387521, 1861566286, 3616058184,   48071792, 3577350513,
                          297480282, 1101405687, 1473439254, 2634793792, 1341017984u32];

    assert_eq!(&output[0..10], &expected_begin);
    assert_eq!(&output[990..1000], &expected_end);
}
