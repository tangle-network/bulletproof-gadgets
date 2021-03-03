extern crate curve25519_gadgets;
use curve25519_dalek::scalar::Scalar;
use curve25519_gadgets::{
	crypto_constants::utils::generate_zero_trees,
	poseidon::{PoseidonBuilder, PoseidonSbox, Poseidon_hash_2},
};
use std::{
	env,
	fs::{write, File},
	io::prelude::*,
};

fn main() { generate_zero_trees(); }
