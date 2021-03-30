extern crate bulletproofs_gadgets;

#[cfg(feature = "std")]
use bulletproofs_gadgets::crypto_constants::utils::generate_zero_trees;

fn main() {
	#[cfg(feature = "std")]
	generate_zero_trees();
}
