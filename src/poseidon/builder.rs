use crate::{
	crypto_constants::{poseidon, poseidon::params},
	poseidon::{
		allocate_statics_for_prover, sbox::PoseidonSbox, Poseidon_hash_2_gadget,
	},
	utils::{get_scalar_from_hex, AllocatedScalar},
};
use alloc::{string::String, vec::Vec};
use bulletproofs::{r1cs::Prover, BulletproofGens, PedersenGens};
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use rand_core::{CryptoRng, RngCore};

#[cfg(feature = "std")]
use std::time::Instant;

// const DEFAULT_SECURITY_BITS: usize = 128;

// const LARGEST_ED25519_S: [u8;32] = [
// 0xf8, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
// 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
// 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
// 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
// ];

pub type Matrix = Vec<Vec<Scalar>>;

/// The Poseidon permutation.
#[derive(Clone)]
pub struct Poseidon {
	/// The size of the permutation, in field elements.
	pub width: usize,
	/// Number of full SBox rounds in beginning
	pub full_rounds_beginning: usize,
	/// Number of full SBox rounds in end
	pub full_rounds_end: usize,
	/// Number of partial rounds
	pub partial_rounds: usize,
	/// The S-box to apply in the sub words layer.
	pub sbox: PoseidonSbox,
	/// The round key constants
	pub round_keys: Vec<Scalar>,
	/// The MDS matrix to apply in the mix layer.
	pub mds_matrix: Matrix,
	/// The transcript label for the prover & verifier
	pub transcript_label: &'static [u8],
	/// Pedersen generators for proving/verifying
	pub pc_gens: PedersenGens,
	/// Bulletproof generators for proving/verifying
	pub bp_gens: BulletproofGens,
}

/// Builds a `Poseidon` instance.
pub struct PoseidonBuilder {
	/// The size of the permutation, in field elements.
	width: usize,
	/// Number of full SBox rounds in beginning
	pub full_rounds_beginning: Option<usize>,
	/// Number of full SBox rounds in end
	pub full_rounds_end: Option<usize>,
	/// Number of partial rounds
	pub partial_rounds: Option<usize>,
	/// The S-box to apply in the sub words layer.
	sbox: Option<PoseidonSbox>,
	/// The round key constants
	pub round_keys: Option<Vec<Scalar>>,
	/// The MDS matrix to apply in the mix layer.
	mds_matrix: Option<Matrix>,
	/// The transcript label for the prover & verifier
	transcript_label: Option<&'static [u8]>,
	/// Pedersen generators for proving/verifying
	pc_gens: Option<PedersenGens>,
	/// Bulletproof generators for proving/verifying
	bp_gens: Option<BulletproofGens>,
}

impl PoseidonBuilder {
	pub fn new(width: usize) -> Self {
		PoseidonBuilder {
			width,
			full_rounds_beginning: None,
			full_rounds_end: None,
			partial_rounds: None,
			sbox: None,
			round_keys: None,
			mds_matrix: None,
			transcript_label: None,
			pc_gens: None,
			bp_gens: None,
		}
	}

	pub fn sbox(mut self, sbox: PoseidonSbox) -> Self {
		self.sbox = Some(sbox);
		self
	}

	pub fn round_keys_hex(&mut self, r_keys: Vec<String>) -> &mut Self {
		let cap = if self.full_rounds_beginning.is_some()
			&& self.full_rounds_end.is_some()
			&& self.partial_rounds.is_some()
		{
			(self.full_rounds_beginning.unwrap()
				+ self.partial_rounds.unwrap()
				+ self.full_rounds_end.unwrap())
				* self.width
		} else {
			r_keys.len()
		};
		assert!(cap <= r_keys.len());
		let mut rc = vec![];
		for key in r_keys.iter().take(cap) {
			let c = get_scalar_from_hex(key);
			rc.push(c);
		}
		self.round_keys = Some(rc);

		self
	}

	pub fn transcript_label(mut self, label: &'static [u8]) -> Self {
		self.transcript_label = Some(label);
		self
	}

	pub fn pedersen_gens(mut self, gens: PedersenGens) -> Self {
		self.pc_gens = Some(gens);
		self
	}

	pub fn bulletproof_gens(mut self, gens: BulletproofGens) -> Self {
		self.bp_gens = Some(gens);
		self
	}

	pub fn build(self) -> Poseidon {
		let width = self.width;

		// If an S-box is not specified, determine the optimal choice based on
		// the guidance in the paper.
		let sbox = self.sbox.unwrap_or(PoseidonSbox::Inverse);

		let round_keys =
			self.round_keys.unwrap_or(gen_round_keys(width, &sbox));

		let mds_matrix =
			self.mds_matrix.unwrap_or(gen_mds_matrix(width, &sbox));

		let (partial_rounds, (full_rounds_beginning, full_rounds_end)) =
			gen_round_params(width, &sbox);

		// default pedersen genrators
		let pc_gens = self.pc_gens.unwrap_or_else(PedersenGens::default);
		// default 4096 might not be enough
		let bp_gens = self
			.bp_gens
			.clone()
			.unwrap_or_else(|| BulletproofGens::new(4096, 1));

		let transcript_label =
			self.transcript_label.unwrap_or(b"test_poseidon_transcript");

		Poseidon {
			width,
			full_rounds_beginning,
			full_rounds_end,
			partial_rounds,
			sbox,
			round_keys,
			mds_matrix,
			transcript_label,
			pc_gens,
			bp_gens,
		}
	}
}

impl Poseidon {
	pub fn get_total_rounds(&self) -> usize {
		self.full_rounds_beginning + self.partial_rounds + self.full_rounds_end
	}

	#[cfg(feature = "std")]
	pub fn prove_hash_2<C: CryptoRng + RngCore>(
		&self,
		xl: Scalar,
		xr: Scalar,
		output: Scalar,
		mut rng: &mut C,
	) {
		let total_rounds = self.get_total_rounds();
		let (_proof, _commitments) = {
			let mut prover_transcript = Transcript::new(self.transcript_label);
			let mut prover = Prover::new(&self.pc_gens, &mut prover_transcript);

			let mut comms = vec![];

			let (com_l, var_l) = prover.commit(xl, Scalar::random(&mut rng));
			comms.push(com_l);
			let l_alloc = AllocatedScalar {
				variable: var_l,
				assignment: Some(xl),
			};

			let (com_r, var_r) = prover.commit(xr, Scalar::random(&mut rng));
			comms.push(com_r);
			let r_alloc = AllocatedScalar {
				variable: var_r,
				assignment: Some(xr),
			};

			let num_statics = 4;
			let statics = allocate_statics_for_prover(&mut prover, num_statics);

			let start = Instant::now();
			assert!(Poseidon_hash_2_gadget(
				&mut prover,
				l_alloc,
				r_alloc,
				statics,
				&self,
				&output
			)
			.is_ok());

			println!(
				"For Poseidon hash 2:1 rounds {}, no of constraints is {}, no of multipliers is {}",
				total_rounds,
				&prover.num_constraints(),
				&prover.num_multipliers()
			);

			let proof = prover.prove_with_rng(&self.bp_gens, &mut rng).unwrap();

			let end = start.elapsed();

			println!("Proving time is {:?}", end);
			(proof, comms)
		};
	}
}

pub fn gen_round_params(
	width: usize,
	sbox: &PoseidonSbox,
) -> (usize, (usize, usize)) {
	let params = match sbox {
		PoseidonSbox::Exponentiation3 => match width {
			2 => params::X3_2,
			3 => params::X3_3,
			4 => params::X3_4,
			5 => params::X3_5,
			6 => params::X3_6,
			7 => params::X3_7,
			8 => params::X3_8,
			9 => params::X3_9,
			_ => params::X3_4,
		},
		PoseidonSbox::Exponentiation5 => match width {
			2 => params::X5_2,
			3 => params::X5_3,
			4 => params::X5_4,
			5 => params::X5_5,
			6 => params::X5_6,
			7 => params::X5_7,
			8 => params::X5_8,
			9 => params::X5_9,
			_ => params::X5_4,
		},
		PoseidonSbox::Inverse => match width {
			2 => params::INVERSE_2,
			3 => params::INVERSE_3,
			4 => params::INVERSE_4,
			5 => params::INVERSE_5,
			6 => params::INVERSE_6,
			7 => params::INVERSE_7,
			8 => params::INVERSE_8,
			9 => params::INVERSE_9,
			_ => params::INVERSE_4,
		},
	};
	let full_part = params[0] / 2;
	(params[1], (full_part, full_part))
}

// TODO: Write logic to generate correct round keys.
pub fn gen_round_keys(width: usize, sbox: &PoseidonSbox) -> Vec<Scalar> {
	let round_consts = match sbox {
		PoseidonSbox::Exponentiation3 => match width {
			2 => poseidon::x3_2::ROUND_CONSTS.to_vec(),
			3 => poseidon::x3_3::ROUND_CONSTS.to_vec(),
			4 => poseidon::x3_4::ROUND_CONSTS.to_vec(),
			5 => poseidon::x3_5::ROUND_CONSTS.to_vec(),
			6 => poseidon::x3_6::ROUND_CONSTS.to_vec(),
			7 => poseidon::x3_7::ROUND_CONSTS.to_vec(),
			8 => poseidon::x3_8::ROUND_CONSTS.to_vec(),
			9 => poseidon::x3_9::ROUND_CONSTS.to_vec(),
			_ => poseidon::x3_4::ROUND_CONSTS.to_vec(),
		},

		PoseidonSbox::Exponentiation5 => match width {
			2 => poseidon::x5_2::ROUND_CONSTS.to_vec(),
			3 => poseidon::x5_3::ROUND_CONSTS.to_vec(),
			4 => poseidon::x5_4::ROUND_CONSTS.to_vec(),
			5 => poseidon::x5_5::ROUND_CONSTS.to_vec(),
			6 => poseidon::x5_6::ROUND_CONSTS.to_vec(),
			7 => poseidon::x5_7::ROUND_CONSTS.to_vec(),
			8 => poseidon::x5_8::ROUND_CONSTS.to_vec(),
			9 => poseidon::x5_9::ROUND_CONSTS.to_vec(),
			_ => poseidon::x5_4::ROUND_CONSTS.to_vec(),
		},

		PoseidonSbox::Inverse => match width {
			2 => poseidon::inverse_2::ROUND_CONSTS.to_vec(),
			3 => poseidon::inverse_3::ROUND_CONSTS.to_vec(),
			4 => poseidon::inverse_4::ROUND_CONSTS.to_vec(),
			5 => poseidon::inverse_5::ROUND_CONSTS.to_vec(),
			6 => poseidon::inverse_6::ROUND_CONSTS.to_vec(),
			7 => poseidon::inverse_7::ROUND_CONSTS.to_vec(),
			8 => poseidon::inverse_8::ROUND_CONSTS.to_vec(),
			9 => poseidon::inverse_9::ROUND_CONSTS.to_vec(),
			_ => poseidon::inverse_4::ROUND_CONSTS.to_vec(),
		},
	};

	let mut rc = vec![];
	for r in round_consts.iter() {
		let c = get_scalar_from_hex(r);
		rc.push(c);
	}
	rc
}

// TODO: Write logic to generate correct MDS matrix. Currently loading hardcoded
// constants.
pub fn gen_mds_matrix(width: usize, sbox: &PoseidonSbox) -> Vec<Vec<Scalar>> {
	let mds_entries: Vec<Vec<&str>> = match sbox {
		PoseidonSbox::Exponentiation3 => match width {
			2 => poseidon::x3_2::MDS_ENTRIES
				.to_vec()
				.iter()
				.map(|x| x.to_vec())
				.collect(),
			3 => poseidon::x3_3::MDS_ENTRIES
				.to_vec()
				.iter()
				.map(|x| x.to_vec())
				.collect(),
			4 => poseidon::x3_4::MDS_ENTRIES
				.to_vec()
				.iter()
				.map(|x| x.to_vec())
				.collect(),
			5 => poseidon::x3_5::MDS_ENTRIES
				.to_vec()
				.iter()
				.map(|x| x.to_vec())
				.collect(),
			6 => poseidon::x3_6::MDS_ENTRIES
				.to_vec()
				.iter()
				.map(|x| x.to_vec())
				.collect(),
			7 => poseidon::x3_7::MDS_ENTRIES
				.to_vec()
				.iter()
				.map(|x| x.to_vec())
				.collect(),
			8 => poseidon::x3_8::MDS_ENTRIES
				.to_vec()
				.iter()
				.map(|x| x.to_vec())
				.collect(),
			9 => poseidon::x3_9::MDS_ENTRIES
				.to_vec()
				.iter()
				.map(|x| x.to_vec())
				.collect(),
			_ => poseidon::x3_4::MDS_ENTRIES
				.to_vec()
				.iter()
				.map(|x| x.to_vec())
				.collect(),
		},

		PoseidonSbox::Exponentiation5 => match width {
			2 => poseidon::x5_2::MDS_ENTRIES
				.to_vec()
				.iter()
				.map(|x| x.to_vec())
				.collect(),
			3 => poseidon::x5_3::MDS_ENTRIES
				.to_vec()
				.iter()
				.map(|x| x.to_vec())
				.collect(),
			4 => poseidon::x5_4::MDS_ENTRIES
				.to_vec()
				.iter()
				.map(|x| x.to_vec())
				.collect(),
			5 => poseidon::x5_5::MDS_ENTRIES
				.to_vec()
				.iter()
				.map(|x| x.to_vec())
				.collect(),
			6 => poseidon::x5_6::MDS_ENTRIES
				.to_vec()
				.iter()
				.map(|x| x.to_vec())
				.collect(),
			7 => poseidon::x5_7::MDS_ENTRIES
				.to_vec()
				.iter()
				.map(|x| x.to_vec())
				.collect(),
			8 => poseidon::x5_8::MDS_ENTRIES
				.to_vec()
				.iter()
				.map(|x| x.to_vec())
				.collect(),
			9 => poseidon::x5_9::MDS_ENTRIES
				.to_vec()
				.iter()
				.map(|x| x.to_vec())
				.collect(),
			_ => poseidon::x5_4::MDS_ENTRIES
				.to_vec()
				.iter()
				.map(|x| x.to_vec())
				.collect(),
		},

		PoseidonSbox::Inverse => match width {
			2 => poseidon::inverse_2::MDS_ENTRIES
				.to_vec()
				.iter()
				.map(|x| x.to_vec())
				.collect(),
			3 => poseidon::inverse_3::MDS_ENTRIES
				.to_vec()
				.iter()
				.map(|x| x.to_vec())
				.collect(),
			4 => poseidon::inverse_4::MDS_ENTRIES
				.to_vec()
				.iter()
				.map(|x| x.to_vec())
				.collect(),
			5 => poseidon::inverse_5::MDS_ENTRIES
				.to_vec()
				.iter()
				.map(|x| x.to_vec())
				.collect(),
			6 => poseidon::inverse_6::MDS_ENTRIES
				.to_vec()
				.iter()
				.map(|x| x.to_vec())
				.collect(),
			7 => poseidon::inverse_7::MDS_ENTRIES
				.to_vec()
				.iter()
				.map(|x| x.to_vec())
				.collect(),
			8 => poseidon::inverse_8::MDS_ENTRIES
				.to_vec()
				.iter()
				.map(|x| x.to_vec())
				.collect(),
			9 => poseidon::inverse_9::MDS_ENTRIES
				.to_vec()
				.iter()
				.map(|x| x.to_vec())
				.collect(),
			_ => poseidon::inverse_4::MDS_ENTRIES
				.to_vec()
				.iter()
				.map(|x| x.to_vec())
				.collect(),
		},
	};

	let mut mds: Vec<Vec<Scalar>> = vec![vec![Scalar::zero(); width]; width];
	for i in 0..width {
		for j in 0..width {
			// TODO: Remove unwrap, handle error
			mds[i][j] = get_scalar_from_hex(mds_entries[i][j]);
		}
	}
	mds
}
