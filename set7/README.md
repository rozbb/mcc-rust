Some of these tests will take a while. Test 53 will take about 7 seconds to run,
and test 51 will take about 40 seconds to run. Furthermore, test 51 has about an
87% success rate (doesn't always make the right guesses when extending the known
plaintext), so more than one run might be necessary. The variance on the runtime
of test 55 is pretty high, but it shouldn't take more than 5 minutes. Test 56
takes a while; 10 minutes on an i7 4790K.

On the plus side, you can run challenge 51 with `--nocapture` and see the
guesses as they're happening. Also run challenge 50 with `--nocapture` to see
the Javascript collision plaintext.

Note: The `md4_crypto` crate is a stripped-down and slightly modified clone of
@bacher09's fork of `rust-crypto`. The fork can be found
[here](https://github.com/bacher09/rust-crypto/tree/634217ca65876f9b601dc532a2ae5554ab5a0a54).
