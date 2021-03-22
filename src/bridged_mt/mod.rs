use bulletproofs::r1cs::Variable;
use crate::poseidon::Poseidon_hash_4_constraints;

use bulletproofs::r1cs::LinearCombination;
use crate::poseidon::Poseidon_hash_2_constraints;
use crate::utils::constrain_lc_with_scalar;
use bulletproofs::r1cs::ConstraintSystem;
use crate::utils::AllocatedScalar;
use crate::poseidon::builder::Poseidon;
use bulletproofs::r1cs::R1CSError;

use curve25519_dalek::scalar::Scalar;

mod test;

#[derive(Debug, Clone)]
pub struct BridgeTx {
	// private
	r: AllocatedScalar,
	nullifier: AllocatedScalar,
	leaf_cm_val: AllocatedScalar,
	leaf_index_bits: Vec<AllocatedScalar>,
	leaf_proof_nodes: Vec<AllocatedScalar>,
	// public
	sn: Scalar,
	chain_id: Scalar,
}

/// left = (1-leaf_side) * leaf + (leaf_side * proof_node)
/// right = leaf_side * leaf + ((1-leaf_side) * proof_node))
pub fn one_of_many_merkle_tree_verif_gadget<CS: ConstraintSystem>(
	cs: &mut CS,
	depth: usize,
	roots: &[Scalar],
	leaf_val: AllocatedScalar,
	leaf_index_bits: Vec<AllocatedScalar>,
	proof_nodes: Vec<AllocatedScalar>,
	statics: Vec<AllocatedScalar>,
	poseidon_params: &Poseidon,
) -> Result<(), R1CSError> {
	let mut prev_hash = LinearCombination::default();

	let statics: Vec<LinearCombination> =
		statics.iter().map(|s| s.variable.into()).collect();

	for i in 0..depth {
		let leaf_val_lc = if i == 0 {
			LinearCombination::from(leaf_val.variable)
		} else {
			prev_hash.clone()
		};
		let one_minus_leaf_side: LinearCombination =
			Variable::One() - leaf_index_bits[i].variable;

		let (_, _, left_1) =
			cs.multiply(one_minus_leaf_side.clone(), leaf_val_lc.clone());
		let (_, _, left_2) = cs.multiply(
			leaf_index_bits[i].variable.into(),
			proof_nodes[i].variable.into(),
		);
		let left = left_1 + left_2;

		let (_, _, right_1) =
			cs.multiply(leaf_index_bits[i].variable.into(), leaf_val_lc);
		let (_, _, right_2) =
			cs.multiply(one_minus_leaf_side, proof_nodes[i].variable.into());
		let right = right_1 + right_2;

		prev_hash = Poseidon_hash_2_constraints::<CS>(
			cs,
			left,
			right,
			statics.clone(),
			poseidon_params,
		)?;
	}

	// TODO: build the linear combination of (x - root) for each root
	constrain_lc_with_scalar::<CS>(cs, prev_hash, &roots[0]);

	Ok(())
}

pub fn bridged_tree_verif_gadget<CS: ConstraintSystem>(
	cs: &mut CS,
	depth: usize,
	roots: &[Scalar],
	tx: BridgeTx,
	statics: Vec<AllocatedScalar>,
	poseidon_params: &Poseidon,
) -> Result<(), R1CSError> {
	let statics_lc: Vec<LinearCombination> =
		statics.iter().map(|s| s.variable.into()).collect();
	// use hash constraints to generate leaf and constrain by passed in leaf
	let (var_chain_id, _) = cs.allocate_single(Some(tx.chain_id))?;
	let leaf = Poseidon_hash_4_constraints::<CS>(
		cs,
		[
			var_chain_id.into(),
			tx.r.variable.into(),
			tx.r.variable.into(),
			tx.nullifier.variable.into()
		],
		statics_lc.clone(),
		poseidon_params,
	)?;
	let leaf_lc: LinearCombination = tx.leaf_cm_val.variable.into();
	cs.constrain(leaf - leaf_lc);
	// use hash to ensure nullifier_hash is properly taken
	let computed_nullifier_hash = Poseidon_hash_2_constraints::<CS>(
		cs,
		tx.nullifier.variable.into(),
		tx.nullifier.variable.into(),
		statics_lc,
		poseidon_params,
	)?;
	constrain_lc_with_scalar::<CS>(cs, computed_nullifier_hash, &tx.sn);
	// if all is successful, constrain gadget by merkle root construction with
	// merkle proof path
	one_of_many_merkle_tree_verif_gadget(
		cs,
		depth,
		roots,
		tx.leaf_cm_val,
		tx.leaf_index_bits,
		tx.leaf_proof_nodes,
		statics,
		poseidon_params,
	)?;
	Ok(())
}

pub fn bridge_verif_gadget<CS: ConstraintSystem>(
	cs: &mut CS,
	fee: &Scalar,
	relayer: &Scalar,
	recipient: &Scalar,
	depth: usize,
	roots: &[Scalar],
	tx: BridgeTx,
	statics: Vec<AllocatedScalar>,
	poseidon_params: &Poseidon,
) -> Result<(), R1CSError> {
	bridged_tree_verif_gadget(
		cs,
		depth,
		roots,
		tx,
		statics,
		poseidon_params,
	)?;
	// hidden signals for fee relayer and recipient commitments
	let (_, _, _) = cs.multiply(fee.clone().into(), fee.clone().into());
	let (_, _, _) = cs.multiply(relayer.clone().into(), relayer.clone().into());
	let (_, _, _) = cs.multiply(recipient.clone().into(), recipient.clone().into());
	Ok(())
}