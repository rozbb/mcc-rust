Challenges 31 and 32 are timing attacks. As such, they may take a long
time, and they only work when no other intensive processes are running on the
computer. Even then, some random delays may throw off time calculations. This is
why the these challenges have been excluded from the `cargo test` set.

Testing `c31.rs` will take 40 minutes and 32 seconds to complete.
Testing `c32.rs` will take about 5 minues to complete.

To run the tests and see their progress, run

`cargo test -- --nocapture --test tstc31`

or

``cargo test -- --nocapture --test tstc32``
