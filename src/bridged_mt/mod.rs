use crate::poseidon::Poseidon_hash_4_constraints;
use bulletproofs::r1cs::Variable;

use crate::{
	poseidon::{builder::Poseidon, Poseidon_hash_2_constraints},
	utils::{constrain_lc_with_scalar, AllocatedScalar},
};
use bulletproofs::r1cs::{ConstraintSystem, LinearCombination, R1CSError};

use curve25519_dalek::scalar::Scalar;

#[cfg(test)]
mod tests;

pub mod setup;

#[derive(Debug, Clone)]
pub struct BridgeTx {
	// private
	rho: AllocatedScalar,
	r: AllocatedScalar,
	nullifier: AllocatedScalar,
	leaf_cm_val: AllocatedScalar,
	leaf_index_bits: Vec<AllocatedScalar>,
	leaf_proof_nodes: Vec<AllocatedScalar>,
	diff_vars: Vec<AllocatedScalar>,
	// public
	sn: Scalar,
	chain_id: Scalar,
}

pub fn set_membership_verif_gadget<CS: ConstraintSystem>(
	cs: &mut CS,
	v: LinearCombination,
	diff_vars: Vec<AllocatedScalar>,
	set: &[Scalar],
) -> Result<(), R1CSError> {
	let set_length = set.len();
	// Accumulates product of elements in `diff_vars`
	let mut product: LinearCombination = Variable::One().into();

	for i in 0..set_length {
		// Since `diff_vars[i]` is `set[i] - v`, `diff_vars[i]` + `v` should be
		// `set[i]`
		constrain_lc_with_scalar::<CS>(
			cs,
			diff_vars[i].variable + v.clone(),
			&Scalar::from(set[i]),
		);

		let (_, _, o) =
			cs.multiply(product.clone(), diff_vars[i].variable.into());
		product = o.into();
	}

	// Ensure product of elements if `diff_vars` is 0
	cs.constrain(product);

	Ok(())
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
	diff_vars: Vec<AllocatedScalar>,
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
			(Variable::One() - leaf_index_bits[i].variable).into();

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

	// verify that computed root is a member of a list of merkle roots
	set_membership_verif_gadget(cs, prev_hash, diff_vars, roots)?;

	Ok(())
}

pub fn bridged_tree_verif_gadget<CS: ConstraintSystem>(
	cs: &mut CS,
	depth: usize,
	roots: &[Scalar],
	tx: BridgeTx,
	statics_2: Vec<AllocatedScalar>,
	statics_4: Vec<AllocatedScalar>,
	poseidon_params: &Poseidon,
) -> Result<(), R1CSError> {
	let statics_2_lc: Vec<LinearCombination> =
		statics_2.iter().map(|s| s.variable.into()).collect();
	let statics_4_lc: Vec<LinearCombination> =
		statics_4.iter().map(|s| s.variable.into()).collect();

	// use hash constraints to generate leaf and constrain by passed in leaf
	// let (var_chain_id, _) = cs.allocate_single(Some(tx.chain_id))?;
	let mut var_chain_id: LinearCombination = Variable::One().into();
	var_chain_id = var_chain_id * tx.chain_id;
	let leaf = Poseidon_hash_4_constraints::<CS>(
		cs,
		[
			var_chain_id.into(),
			tx.rho.variable.into(),
			tx.r.variable.into(),
			tx.nullifier.variable.into(),
		],
		statics_4_lc.clone(),
		poseidon_params,
	)?;
	let leaf_lc: LinearCombination = tx.leaf_cm_val.variable.into();
	cs.constrain(leaf - leaf_lc);
	// use hash to ensure nullifier_hash is properly taken
	let computed_nullifier_hash = Poseidon_hash_2_constraints::<CS>(
		cs,
		tx.nullifier.variable.into(),
		tx.nullifier.variable.into(),
		statics_2_lc,
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
		tx.diff_vars,
		statics_2,
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
	statics_2: Vec<AllocatedScalar>,
	statics_4: Vec<AllocatedScalar>,
	poseidon_params: &Poseidon,
) -> Result<(), R1CSError> {
	bridged_tree_verif_gadget(
		cs,
		depth,
		roots,
		tx,
		statics_2,
		statics_4,
		poseidon_params,
	)?;
	// hidden signals for fee relayer and recipient commitments
	let (_, _, _) = cs.multiply(fee.clone().into(), fee.clone().into());
	let (_, _, _) = cs.multiply(relayer.clone().into(), relayer.clone().into());
	let (_, _, _) =
		cs.multiply(recipient.clone().into(), recipient.clone().into());
	Ok(())
}
