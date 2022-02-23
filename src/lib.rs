extern crate rand;
use rand::thread_rng;
extern crate curve25519_dalek;
use curve25519_dalek::scalar::Scalar;
extern crate merlin;
use merlin::Transcript;
extern crate bulletproofs;
use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};
use ::safer_ffi::prelude::*;

#[ffi_export]
fn naive_prove() -> repr_c::Vec<u8> {
    println!("i will start proving!");
    let pc_gens = PedersenGens::default();

    // Generators for Bulletproofs, valid for proofs up to bitsize 64
    // and aggregation size up to 1.
    let bp_gens = BulletproofGens::new(64, 1);

    // A secret value we want to prove lies in the range [0, 2^32)
    let secret_value = 1037574391u64;

    // The API takes a blinding factor for the commitment.
    let blinding = Scalar::random(&mut thread_rng());

    // The proof can be chained to an existing transcript.
    // Here we create a transcript with a doctest domain separator.
    let mut prover_transcript = Transcript::new(b"doctest example");

    // Create a 32-bit rangeproof.
    let (proof, committed_value) = RangeProof::prove_single(
        &bp_gens,
        &pc_gens,
        &mut prover_transcript,
        secret_value,
        &blinding,
        64,
    ).expect("A real program could handle errors");
    println!("before return");
    proof.to_bytes().into()
}

pub extern fn naive_verify() {
    println!("i will start verifying!");
}

#[::safer_ffi::cfg_headers]
#[test]
fn generate_headers() -> ::std::io::Result<()> {
    ::safer_ffi::headers::builder()
        .to_file("ext.h")?
        .generate()
}
