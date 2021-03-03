use crate::poseidon::{builder::Poseidon, sbox::PoseidonSbox, PoseidonBuilder};

#[derive(Clone)]
pub struct TransactionGadget {
	hash_params: Poseidon,
}

pub struct TransactionGadgetBuilder {
	hash_params: Option<Poseidon>,
}

impl TransactionGadgetBuilder {
	pub fn new() -> Self { Self { hash_params: None } }

	pub fn hash_params(&mut self, hash_params: Poseidon) -> &mut Self {
		self.hash_params = Some(hash_params);
		self
	}

	pub fn build(&self) -> TransactionGadget {
		let hash_params = self.hash_params.clone().unwrap_or_else(|| {
			let width = 6;
			PoseidonBuilder::new(width)
				.sbox(PoseidonSbox::Inverse)
				.build()
		});

		TransactionGadget { hash_params }
	}
}
