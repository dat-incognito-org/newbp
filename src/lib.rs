extern crate bulletproofs;
extern crate curve25519_dalek;
extern crate merlin;
extern crate rand;
use bulletproofs::*;
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use rand::thread_rng;

#[no_mangle]
pub extern fn naive_prove() {
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
    println!("{:?}", proof);
    println!("{:?}", committed_value);
}

pub extern fn naive_verify() {
    println!("i will start verifying!");
}