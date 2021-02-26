use crate::{
	poseidon::{builder::Poseidon, sbox::PoseidonSbox, PoseidonBuilder},
	smt::{builder::DEFAULT_TREE_DEPTH, VanillaSparseMerkleTree},
};

#[derive(Clone)]
pub struct RewardGadget {
	depth: usize,
	hash_params: Poseidon,
	tree: VanillaSparseMerkleTree,
}

pub struct RewardGadgetBuilder {
	depth: Option<usize>,
	hash_params: Option<Poseidon>,
	tree: Option<VanillaSparseMerkleTree>,
}

impl RewardGadgetBuilder {
	pub fn new() -> Self {
		Self {
			depth: None,
			hash_params: None,
			tree: None,
		}
	}

	pub fn depth(&mut self, depth: usize) -> &mut Self {
		self.depth = Some(depth);
		self
	}

	pub fn hash_params(&mut self, hash_params: Poseidon) -> &mut Self {
		self.hash_params = Some(hash_params);
		self
	}

	pub fn merkle_tree(&mut self, tree: VanillaSparseMerkleTree) -> &mut Self {
		self.tree = Some(tree);
		self
	}

	pub fn build(&self) -> RewardGadget {
		let depth = self.depth.unwrap_or_else(|| DEFAULT_TREE_DEPTH);
		let hash_params = self.hash_params.clone().unwrap_or_else(|| {
			let width = 6;
			PoseidonBuilder::new(width)
				.sbox(PoseidonSbox::Inverse)
				.build()
		});

		let tree = self.tree.clone().unwrap_or_else(|| {
			VanillaSparseMerkleTree::new(hash_params.clone(), depth)
		});

		RewardGadget {
			depth,
			hash_params,
			tree,
		}
	}
}
