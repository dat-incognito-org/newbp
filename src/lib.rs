extern crate rand;
use rand::thread_rng;
extern crate curve25519_dalek;
use curve25519_dalek::scalar::Scalar;
extern crate merlin;
use merlin::Transcript;
extern crate bulletproofs;
use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};
use ::safer_ffi::prelude::*;

// need & in params to avoid dropping vecs, causing segfault form C.
// missing padding for non-pow-of-2 witness sets
#[ffi_export]
fn bulletproofs_prove_multiple(witness: &repr_c::Vec<u64>, blindings: &repr_c::Vec<[u8; 32]>) -> repr_c::Vec<u8> {
    // clone witness values from input parameters
    let witness_values:Vec<u64> = witness.to_vec();
    // The API takes a blinding factor for the commitment.
    let mut blindings_values:Vec<Scalar> = vec![];
    for s in blindings.iter() {
        blindings_values.push(Scalar::from_bytes_mod_order(*s));
    }
    // Generators for Bulletproofs, valid for proofs up to bitsize 64
    // and aggregation size up to 1.
    let pc_gens = PedersenGens::default();
    let bp_gens = BulletproofGens::new(64, witness_values.len());

    let mut prover_transcript = Transcript::new(b"");
    let (proof, committed_value) = RangeProof::prove_multiple(
        &bp_gens,
        &pc_gens,
        &mut prover_transcript,
        &witness_values,
        &blindings_values,
        64,
    ).expect("A real program could handle errors");
    proof.to_bytes().into()
}

pub extern fn naive_verify() {
}

#[::safer_ffi::cfg_headers]
#[test]
fn generate_headers() -> ::std::io::Result<()> {
    ::safer_ffi::headers::builder()
        .to_file("ext.h")?
        .generate()
}
