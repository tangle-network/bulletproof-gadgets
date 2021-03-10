use crate::{
	fixed_deposit_tree::mixer_verif_gadget,
	poseidon::{
		allocate_statics_for_prover, builder::Poseidon, sbox::PoseidonSbox,
		PoseidonBuilder, Poseidon_hash_2,
	},
	smt::{
		builder::{SparseMerkleTreeBuilder, DEFAULT_TREE_DEPTH},
		smt::VanillaSparseMerkleTree,
	},
	utils::{get_bits, AllocatedScalar, ScalarBytes},
};
use alloc::vec::Vec;
use bulletproofs::{
	r1cs::{Prover, R1CSProof},
	BulletproofGens,
};
use curve25519_dalek::{ristretto::CompressedRistretto, scalar::Scalar};
use rand_core::OsRng;
use sp_std::collections::btree_map::BTreeMap;

#[derive(Clone)]
pub struct FixedDepositTree {
	secrets: BTreeMap<ScalarBytes, (Scalar, Scalar, Scalar)>,
	pub hash_params: Poseidon,
	pub tree: VanillaSparseMerkleTree,
}

impl FixedDepositTree {
	pub fn generate_secrets(&mut self) -> Scalar {
		let mut rng = OsRng::default();
		let r = Scalar::random(&mut rng);
		let nullifier = Scalar::random(&mut rng);
		let leaf = Poseidon_hash_2(r, nullifier, &self.hash_params);
		let nullifier_hash =
			Poseidon_hash_2(nullifier, nullifier, &self.hash_params);
		self.add_secrets(leaf, r, nullifier, nullifier_hash);
		leaf
	}

	pub fn add_secrets(
		&mut self,
		leaf: Scalar,
		r: Scalar,
		nullifier: Scalar,
		nullifier_hash: Scalar,
	) {
		self.secrets
			.insert(leaf.to_bytes(), (r, nullifier, nullifier_hash));
	}

	pub fn leaf_data_from_bytes(
		&self,
		r_bytes: [u8; 32],
		nullifier_bytes: [u8; 32],
	) -> (Scalar, Scalar, Scalar, Scalar) {
		let r = Scalar::from_bytes_mod_order(r_bytes);
		let nullifier = Scalar::from_bytes_mod_order(nullifier_bytes);
		// Construct nullifier hash for note
		let nullifier_hash =
			Poseidon_hash_2(nullifier, nullifier, &self.hash_params);
		// Constructing a leaf from the scalars
		let leaf = Poseidon_hash_2(r, nullifier, &self.hash_params);
		(r, nullifier, nullifier_hash, leaf)
	}

	pub fn get_secrets(&self, leaf: Scalar) -> (Scalar, Scalar, Scalar) {
		let (r, nullifier, nullifier_hash) =
			self.secrets.get(&leaf.to_bytes()).unwrap();
		(*r, *nullifier, *nullifier_hash)
	}

	pub fn prove_zk(
		&self,
		root: Scalar,
		leaf: Scalar,
		recipient: Scalar,
		relayer: Scalar,
		bp_gens: &BulletproofGens,
		mut prover: Prover,
	) -> (
		R1CSProof,
		(
			Vec<CompressedRistretto>,
			Scalar,
			Vec<CompressedRistretto>,
			Vec<CompressedRistretto>,
		),
	) {
		let mut rng: OsRng = OsRng::default();
		let mut merkle_proof_vec = Vec::<Scalar>::new();
		let mut merkle_proof = Some(merkle_proof_vec);

		let k = self.tree.leaf_indices.get(&leaf.to_bytes()).unwrap();
		let leaf = self.tree.get(*k, root, &mut merkle_proof);
		merkle_proof_vec = merkle_proof.unwrap();

		let (r, nullifier, nullifier_hash) = self.get_secrets(leaf);

		let mut comms = vec![];
		let (com_r, var_r) = prover.commit(r, Scalar::random(&mut rng));
		let r_alloc = AllocatedScalar {
			variable: var_r,
			assignment: Some(r),
		};
		comms.push(com_r);

		let (com_nullifier, var_nullifier) =
			prover.commit(nullifier, Scalar::random(&mut rng));
		let nullifier_alloc = AllocatedScalar {
			variable: var_nullifier,
			assignment: Some(nullifier),
		};
		comms.push(com_nullifier);

		let (com_leaf, var_leaf) =
			prover.commit(leaf, Scalar::random(&mut rng));
		let leaf_alloc_scalar = AllocatedScalar {
			variable: var_leaf,
			assignment: Some(leaf),
		};
		comms.push(com_leaf);

		let mut leaf_index_comms = vec![];
		let mut leaf_index_alloc_scalars = vec![];
		for b in get_bits(&k, DEFAULT_TREE_DEPTH)
			.iter()
			.take(self.tree.depth)
		{
			let val: Scalar = Scalar::from(*b as u8);
			let (c, v) = prover.commit(val, Scalar::random(&mut rng));
			leaf_index_comms.push(c);
			leaf_index_alloc_scalars.push(AllocatedScalar {
				variable: v,
				assignment: Some(val),
			});
		}

		let mut proof_comms = vec![];
		let mut proof_alloc_scalars = vec![];
		for p in merkle_proof_vec.iter() {
			let (c, v) = prover.commit(*p, Scalar::random(&mut rng));
			proof_comms.push(c);
			proof_alloc_scalars.push(AllocatedScalar {
				variable: v,
				assignment: Some(*p),
			});
		}

		let num_statics = 4;
		let statics = allocate_statics_for_prover(&mut prover, num_statics);

		assert!(mixer_verif_gadget(
			&mut prover,
			&recipient,
			&relayer,
			self.tree.depth,
			&self.tree.root,
			&nullifier_hash,
			r_alloc,
			nullifier_alloc,
			leaf_alloc_scalar,
			leaf_index_alloc_scalars,
			proof_alloc_scalars,
			statics,
			&self.hash_params
		)
		.is_ok());

		let proof = prover.prove_with_rng(bp_gens, &mut rng).unwrap();
		(
			proof,
			(comms, nullifier_hash, leaf_index_comms, proof_comms),
		)
	}
}

pub struct FixedDepositTreeBuilder {
	depth: Option<usize>,
	hash_params: Option<Poseidon>,
	tree: Option<VanillaSparseMerkleTree>,
}

impl Default for FixedDepositTreeBuilder {
	fn default() -> Self { Self::new() }
}

impl FixedDepositTreeBuilder {
	pub fn new() -> Self {
		Self {
			depth: None,
			hash_params: None,
			tree: None,
		}
	}

	pub fn depth(mut self, depth: usize) -> Self {
		self.depth = Some(depth);
		self
	}

	pub fn hash_params(mut self, hash_params: Poseidon) -> Self {
		self.hash_params = Some(hash_params);
		self
	}

	pub fn merkle_tree(mut self, tree: VanillaSparseMerkleTree) -> Self {
		self.tree = Some(tree);
		self
	}

	pub fn build(self) -> FixedDepositTree {
		let depth = self.depth.unwrap_or(DEFAULT_TREE_DEPTH);
		let hash_params = self.hash_params.unwrap_or(
			PoseidonBuilder::new(6).sbox(PoseidonSbox::Inverse).build(),
		);
		let secrets = BTreeMap::new();
		let tree = self.tree.unwrap_or(
			SparseMerkleTreeBuilder::new()
				.depth(depth)
				.hash_params(hash_params.clone())
				.build(),
		);

		FixedDepositTree {
			secrets,
			hash_params,
			tree,
		}
	}
}
