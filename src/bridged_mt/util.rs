use super::BridgeTx;
use crate::{
	bridged_mt::bridge_verif_gadget,
	poseidon::{
		allocate_statics_for_prover, allocate_statics_for_verifier,
		builder::Poseidon,
	},
	smt::{builder::DEFAULT_TREE_DEPTH, VanillaSparseMerkleTree},
	utils::{get_bits, AllocatedScalar},
};
use bulletproofs::{
	r1cs::{Prover, R1CSProof, Verifier},
	BulletproofGens, PedersenGens,
};
use curve25519_dalek::{ristretto::CompressedRistretto, scalar::Scalar};
use merlin::Transcript;
use rand_core::{CryptoRng, RngCore};
use std::time::Instant;

#[derive(Debug, Clone)]
pub struct BridgeTxInputs {
	r: Scalar,
	nullifier: Scalar,
	expected_output: Scalar,
	index: Scalar,
	merkle_proof_vec: Vec<Scalar>,
	roots: Vec<Scalar>,
	chain_id: Scalar,
	sn: Scalar,
}

#[derive(Debug, Clone)]
pub struct BridgeTxComms {
	input_comms: Vec<CompressedRistretto>,
	leaf_index_comms: Vec<CompressedRistretto>,
	proof_comms: Vec<CompressedRistretto>,
	diff_comms: Vec<CompressedRistretto>,
}

fn setup_prover<T: RngCore + CryptoRng>(
	tree: VanillaSparseMerkleTree,
	inputs: BridgeTxInputs,
	pc_gens: PedersenGens,
	bp_gens: BulletproofGens,
	p_params: Poseidon,
	mut test_rng: T,
) -> (R1CSProof, BridgeTxComms) {
	let (proof, commitments) = {
		let mut prover_transcript = Transcript::new(b"BridgeGadget");
		let mut prover = Prover::new(&pc_gens, &mut prover_transcript);

		let mut input_comms = vec![];

		let (com_input_r, var_input_r) =
			prover.commit(inputs.r.clone(), Scalar::random(&mut test_rng));
		let alloc_input_r = AllocatedScalar {
			variable: var_input_r,
			assignment: Some(inputs.r),
		};
		input_comms.push(com_input_r);
		let (com_input_nullifier, var_input_nullifier) = prover
			.commit(inputs.nullifier.clone(), Scalar::random(&mut test_rng));
		let alloc_input_nullifier = AllocatedScalar {
			variable: var_input_nullifier,
			assignment: Some(inputs.nullifier),
		};
		input_comms.push(com_input_nullifier);

		let (leaf_com, leaf_var) = prover
			.commit(inputs.expected_output, Scalar::random(&mut test_rng));
		let alloc_leaf_val = AllocatedScalar {
			variable: leaf_var,
			assignment: Some(inputs.expected_output),
		};
		input_comms.push(leaf_com);

		let mut leaf_index_comms = vec![];
		let mut leaf_index_vars = vec![];
		let mut leaf_index_alloc_scalars = vec![];
		for b in get_bits(&inputs.index, DEFAULT_TREE_DEPTH)
			.iter()
			.take(tree.depth)
		{
			let val: Scalar = Scalar::from(*b as u8);
			let (c, v) =
				prover.commit(val.clone(), Scalar::random(&mut test_rng));
			leaf_index_comms.push(c);
			leaf_index_vars.push(v);
			leaf_index_alloc_scalars.push(AllocatedScalar {
				variable: v,
				assignment: Some(val),
			});
		}

		let mut proof_comms = vec![];
		let mut proof_vars = vec![];
		let mut proof_alloc_scalars = vec![];
		for p in inputs.merkle_proof_vec.iter() {
			let (c, v) = prover.commit(*p, Scalar::random(&mut test_rng));
			proof_comms.push(c);
			proof_vars.push(v);
			proof_alloc_scalars.push(AllocatedScalar {
				variable: v,
				assignment: Some(*p),
			});
		}

		let set = inputs.roots.clone();
		let mut diff_comms = vec![];
		let mut diff_vars: Vec<AllocatedScalar> = vec![];
		for i in 0..set.len() {
			let elem = Scalar::from(set[i]);
			let diff = elem - tree.root;

			// Take difference of set element and value, `set[i] - value`
			let (com_diff, var_diff) =
				prover.commit(diff.clone(), Scalar::random(&mut test_rng));
			let alloc_scal_diff = AllocatedScalar {
				variable: var_diff,
				assignment: Some(diff),
			};
			diff_vars.push(alloc_scal_diff);
			diff_comms.push(com_diff);
		}

		let tx = BridgeTx {
			r: alloc_input_r,
			nullifier: alloc_input_nullifier,
			leaf_cm_val: alloc_leaf_val,
			leaf_index_bits: leaf_index_alloc_scalars,
			leaf_proof_nodes: proof_alloc_scalars,
			diff_vars,
			chain_id: inputs.chain_id,
			sn: inputs.sn,
		};

		let num_statics = 4;
		let statics = allocate_statics_for_prover(&mut prover, num_statics);

		let start = Instant::now();
		assert!(bridge_verif_gadget(
			&mut prover,
			&Scalar::zero(), // fee
			&Scalar::zero(), // relayer
			&Scalar::zero(), // recipient
			tree.depth,
			&inputs.roots,
			tx,
			statics,
			&p_params,
		)
		.is_ok());

		println!(
			"For binary tree of height {}, no of multipliers is {} and constraints is {}",
			tree.depth,
			&prover.num_multipliers(),
			&prover.num_constraints()
		);

		let proof = prover.prove_with_rng(&bp_gens, &mut test_rng).unwrap();
		let end = start.elapsed();

		println!("Proving time is {:?}", end);

		(
			proof,
			BridgeTxComms {
				input_comms,
				leaf_index_comms,
				proof_comms,
				diff_comms,
			},
		)
	};

	(proof, commitments)
}

fn setup_verifier<T: RngCore + CryptoRng>(
	proof: R1CSProof,
	depth: usize,
	roots: Vec<Scalar>,
	sn: Scalar,
	chain_id: Scalar,
	bridge_comms: BridgeTxComms,
	pc_gens: PedersenGens,
	bp_gens: BulletproofGens,
	p_params: Poseidon,
	mut test_rng: T,
) {
	let mut verifier_transcript = Transcript::new(b"BridgeGadget");
	let mut verifier = Verifier::new(&mut verifier_transcript);
	let r_val = verifier.commit(bridge_comms.input_comms[0]);
	let nullifier_val = verifier.commit(bridge_comms.input_comms[1]);
	let r_alloc = AllocatedScalar {
		variable: r_val,
		assignment: None,
	};
	let nullifier_alloc = AllocatedScalar {
		variable: nullifier_val,
		assignment: None,
	};

	let var_leaf = verifier.commit(bridge_comms.input_comms[2]);
	let leaf_alloc_scalar = AllocatedScalar {
		variable: var_leaf,
		assignment: None,
	};

	let mut leaf_index_alloc_scalars = vec![];
	for l in bridge_comms.leaf_index_comms {
		let v = verifier.commit(l);
		leaf_index_alloc_scalars.push(AllocatedScalar {
			variable: v,
			assignment: None,
		});
	}

	let mut proof_alloc_scalars = vec![];
	for p in bridge_comms.proof_comms {
		let v = verifier.commit(p);
		proof_alloc_scalars.push(AllocatedScalar {
			variable: v,
			assignment: None,
		});
	}

	let mut diff_alloc_scalars: Vec<AllocatedScalar> = vec![];

	for i in 1..roots.len() + 1 {
		let var_diff = verifier.commit(bridge_comms.diff_comms[i]);
		let alloc_scal_diff = AllocatedScalar {
			variable: var_diff,
			assignment: None,
		};
		diff_alloc_scalars.push(alloc_scal_diff);
	}

	let tx = BridgeTx {
		// private
		r: r_alloc,
		nullifier: nullifier_alloc,
		leaf_cm_val: leaf_alloc_scalar,
		leaf_index_bits: leaf_index_alloc_scalars,
		leaf_proof_nodes: proof_alloc_scalars,
		diff_vars: diff_alloc_scalars,
		// public
		sn,
		chain_id,
	};

	let num_statics = 4;
	let statics =
		allocate_statics_for_verifier(&mut verifier, num_statics, &pc_gens);

	let start = Instant::now();
	assert!(bridge_verif_gadget(
		&mut verifier,
		&Scalar::zero(), // fee
		&Scalar::zero(), // relayer
		&Scalar::zero(), // recipient
		depth,
		&roots,
		tx,
		statics,
		&p_params,
	)
	.is_ok());

	assert!(verifier
		.verify_with_rng(&proof, &pc_gens, &bp_gens, &mut test_rng)
		.is_ok());
	let end = start.elapsed();

	println!("Verification time is {:?}", end);
}
