
use super::*;
use crate::{
	poseidon::{
		allocate_statics_for_prover, allocate_statics_for_verifier,
		sbox::PoseidonSbox, PoseidonBuilder, Poseidon_hash_2, Poseidon_hash_4,
	},
	smt::builder::{SparseMerkleTreeBuilder, DEFAULT_TREE_DEPTH},
	time_based_rewarding::time_based_reward_verif_gadget,
	utils::{get_bits, AllocatedScalar},
};
use bulletproofs::{
	r1cs::{Prover, Verifier},
	BulletproofGens, PedersenGens,
};
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use rand_core::OsRng;

// For benchmarking
#[cfg(feature = "std")]
use std::time::Instant;

#[test]
fn test_time_based_reward_gadget_verification() {
	let width = 6;
	let p_params = PoseidonBuilder::new(width)
		.sbox(PoseidonSbox::Inverse)
		.build();

	let mut test_rng = OsRng::default();
	let origin_chain = Scalar::from(1u32);
	let destination_chain = Scalar::from(2u32);

	/*
	 * MAKE THE ORIGIN CHAIN TREE
	 * - do a deposit at the leaf at index 7
	 */
	let origin_r = Scalar::random(&mut test_rng);
	let origin_nullifier = Scalar::random(&mut test_rng);
	// we want to do a bridge transfer so we commit to a leaf with the destination_chain ID
	let origin_expected_output = Poseidon_hash_4([destination_chain, origin_r, origin_r, origin_nullifier], &p_params);
	let origin_nullifier_hash = Poseidon_hash_2(origin_nullifier, origin_nullifier, &p_params);

	let mut origin_deposit_tree = SparseMerkleTreeBuilder::new()
		.hash_params(p_params.clone())
		.build();

	for i in 1..=10 {
		let index = Scalar::from(i as u32);
		let s = if i == 7 { origin_expected_output } else { index };

		origin_deposit_tree.update(index, s);
	}

	let mut origin_merkle_proof_vec = Vec::<Scalar>::new();
	let mut origin_merkle_proof = Some(origin_merkle_proof_vec);
	let k = Scalar::from(7u32);
	assert_eq!(
		origin_expected_output,
		origin_deposit_tree.get(k, origin_deposit_tree.root, &mut origin_merkle_proof)
	);
	origin_merkle_proof_vec = origin_merkle_proof.unwrap();
	assert!(origin_deposit_tree.verify_proof(
		k,
		origin_expected_output,
		&origin_merkle_proof_vec,
		None
	));
	assert!(origin_deposit_tree.verify_proof(
		k,
		origin_expected_output,
		&origin_merkle_proof_vec,
		Some(&origin_deposit_tree.root)
	));

	/*
	 * MAKE THE DESTINATION CHAIN TREE
	 * - do a deposit at the leaf at index 7
	 */
	for i in 1..=10 {
		let index = Scalar::from(i as u32);
		let s = if i == 7 { destination_expected_output } else { index };

		destination_deposit_tree.update(index, s);
	}

	let mut destination_merkle_proof_vec = Vec::<Scalar>::new();
	let mut destination_merkle_proof = Some(destination_merkle_proof_vec);
	let k = Scalar::from(7u32);
	assert_eq!(
		destination_expected_output,
		destination_deposit_tree.get(k, destination_deposit_tree.root, &mut destination_merkle_proof)
	);
	destination_merkle_proof_vec = destination_merkle_proof.unwrap();
	assert!(destination_deposit_tree.verify_proof(
		k,
		destination_expected_output,
		&destination_merkle_proof_vec,
		None
	));
	assert!(destination_deposit_tree.verify_proof(
		k,
		destination_expected_output,
		&destination_merkle_proof_vec,
		Some(&destination_deposit_tree.root)
	));
}
