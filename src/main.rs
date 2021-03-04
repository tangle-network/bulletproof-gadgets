extern crate curve25519_gadgets;
use curve25519_dalek::scalar::Scalar;
#[cfg(feature = "std")]
use curve25519_gadgets::crypto_constants::utils::generate_zero_trees;
use curve25519_gadgets::poseidon::{
	PoseidonBuilder, PoseidonSbox, Poseidon_hash_2,
};
use std::{
	env,
	fs::{write, File},
	io::prelude::*,
};

fn main() {
	#[cfg(feature = "std")]
	generate_zero_trees();
}
