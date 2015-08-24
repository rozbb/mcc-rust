# mcc-rust
Rust solutions for the Matasano Crypto Challenges (http://cryptopals.com)

## Dependencies

* Rustc
* Cargo

## Usage

To test the solutions to a particular set, `cd` into the desired set directory and run `cargo test`.

To see the standard output of the tests, run `cargo test -- --nocapture`.

To test one specific challenge, `cd` into the directory of the desired challenge, and run `cargo test -- --test tstNN` where `NN` is the number of the challenge (prefixed with 0 if it's a single digit).

To test one particular challenge and see the stardard output of the test, run `cargo test -- --nocapture --test tstNN`.
