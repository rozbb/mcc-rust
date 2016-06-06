use c46::{string_to_int};
use c47::{bleichenbacher, extract_message, make_oracle};
use ramp::Int;

// Two primes, each 384 bits
static P_STR: &'static str = "E5DB1D0AD3B8DA7F31FB84CE3B5A7733248873F8357F30089A60E5D5677248FA9729\
                              05388C1D31CBD3AB241DB0F7E4B9";
static Q_STR: &'static str = "D82441545EF5B82298D7EE1FFC900CC5AD6EBEC9EF7BB7A2280416CD376DF19416D1\
                              BADBD5F964895CB908683D694031";

#[test]
fn tst48() {
    let p = Int::from_str_radix(P_STR, 16).unwrap();
    let q = Int::from_str_radix(Q_STR, 16).unwrap();
    let orig_msg = string_to_int("kick it, CC");
    let (oracle, e, n, c) = {
        make_oracle(&orig_msg, &p, &q)
    };

    // This is padded; extract the msg part of it
    let recovered_plaintext = bleichenbacher(oracle, &c, &e, &n);
    let recovered_msg = extract_message(&recovered_plaintext);
    assert_eq!(recovered_msg, orig_msg);
}
