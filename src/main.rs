extern crate bulletproofs_gadgets;
#[cfg(feature = "std")]
use bulletproofs_gadgets::crypto_constants::utils::generate_zero_trees;
use curve25519_dalek::scalar::Scalar;
use std::{
	env,
	fs::{write, File},
	io::prelude::*,
};

fn main() {
	#[cfg(feature = "std")]
	generate_zero_trees();
}
