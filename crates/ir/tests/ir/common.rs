//! Shared helpers of the ir tests.

#![allow(
    clippy::expect_used,
    reason = "test helpers fail the test with a message"
)]

use ghidorah_base::Fuel;
use ghidorah_ir::{Arena, BuildError, Builder, Config, Image, Interp, Loc, Stop};

/// Builds a program with one builder closure, or fails the test.
pub fn program(build: impl FnOnce(&mut Builder) -> Result<(), BuildError>) -> Arena {
    let mut b = Builder::new();
    build(&mut b).expect("the program builds");
    b.finish()
}

/// Runs `arena` from `entry` with the locations of `setup`. Gives the stop and the final
/// values of `read` locations.
pub fn run(
    arena: &Arena,
    image: &dyn Image,
    config: Config,
    setup: &[(Loc, u128)],
    entry: u64,
    fuel: u64,
    read: &[Loc],
) -> (Stop, Vec<u128>) {
    let mut interp = Interp::new(arena, image, config);
    for &(loc, value) in setup {
        interp.set_loc(loc, value);
    }
    let stop = interp.run(entry, &mut Fuel::new(fuel));
    let values = read.iter().map(|&loc| interp.loc(loc)).collect();
    (stop, values)
}
