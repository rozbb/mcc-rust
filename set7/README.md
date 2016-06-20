Some of these tests will take a while. Test 53 will take about 7 seconds to run,
and test 51 will take about 40 seconds to run. Furthermore, test 51 has about an
87% success rate (doesn't always make the right guesses when extending the known
plaintext), so more than one run might be necessary.

On the plus side, you can run challenge 51 with `--nocapture` and see the
guesses as they're happening. Also run challenge 50 with `--nocapture` to see
the Javascript collision plaintext.

The `release` build has been enabled by default in this folder, so no
`--release` flag is necessary.
