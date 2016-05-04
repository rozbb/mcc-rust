Challenges 43 and 46 do some intensive calculations. When compiled with debug
flags, they take a long time to complete. I recommend that every test in this
set be run with the `--release` flag. For example:

`cargo test --release -- --test tst46 --nocapture` (which looks super cool)

or just

`cargo test --release`
