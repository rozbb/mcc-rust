// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#![cfg_attr(feature = "with-bench", feature(test))]
#![allow(dead_code, unused_imports, unused_parens)]

extern crate rand;
extern crate rustc_serialize as serialize;
extern crate time;
extern crate libc;

#[cfg(all(test, feature = "with-bench"))]
extern crate test;

mod buffer;
pub mod cryptoutil;
pub mod digest;
pub mod md4;
mod step_by;
