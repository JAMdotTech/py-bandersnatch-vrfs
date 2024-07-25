use pyo3::prelude::*;

use ark_ec_vrfs::suites::bandersnatch::edwards as bandersnatch;
use ark_ec_vrfs::{codec, prelude::ark_serialize, suites::bandersnatch::edwards::RingContext};
use bandersnatch::{IetfProof, Input, Output, Public, RingProof, Secret};

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use pyo3::types::PyBytes;
use std::fmt;
use std::error::Error;

const RING_SIZE: usize = 1023;

// This is the IETF `Prove` procedure output as described in section 2.2
// of the Bandersnatch VRFs specification
#[derive(CanonicalSerialize, CanonicalDeserialize)]
struct IetfVrfSignature {
    output: Output,
    proof: IetfProof,
}

// This is the IETF `Prove` procedure output as described in section 4.2
// of the Bandersnatch VRFs specification
#[derive(CanonicalSerialize, CanonicalDeserialize)]
struct RingVrfSignature {
    output: Output,
    // This contains both the Pedersen proof and actual ring proof.
    proof: RingProof,
}

// "Static" ring context data
fn ring_context(ring_data: &Vec<u8>) -> &'static RingContext {
    use std::sync::OnceLock;
    static RING_CTX: OnceLock<RingContext> = OnceLock::new();
    RING_CTX.get_or_init(|| {
        use bandersnatch::PcsParams;
        // use std::{fs::File, io::Read};
        // let manifest_dir =
        //     std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR is not set");
        // let filename = format!("{}/data/zcash-srs-2-11-uncompressed.bin", manifest_dir);
        // let mut file = File::open(filename).unwrap();
        // let mut buf = Vec::new();
        // file.read_to_end(&mut buf).unwrap();
        let pcs_params = PcsParams::deserialize_uncompressed_unchecked(&mut &ring_data[..]).unwrap();
        RingContext::from_srs(RING_SIZE, pcs_params).unwrap()
    })
}

// Construct VRF Input Point from arbitrary data (section 1.2)
fn vrf_input_point(vrf_input_data: &[u8]) -> Input {
    let point =
        <bandersnatch::BandersnatchSha512Ell2 as ark_ec_vrfs::Suite>::data_to_point(vrf_input_data)
            .unwrap();
    Input::from(point)
}

// Prover actor.
struct Prover {
    pub prover_idx: usize,
    pub secret: Secret,
    pub ring: Vec<Public>,
}

impl Prover {
    pub fn new(ring: Vec<Public>, prover_idx: usize) -> Self {
        Self {
            prover_idx,
            secret: Secret::from_seed(&prover_idx.to_le_bytes()),
            ring,
        }
    }

    /// Anonymous VRF signature.
    ///
    /// Used for tickets submission.
    pub fn ring_vrf_sign(&self, ring_data: &Vec<u8>, vrf_input_data: &[u8], aux_data: &[u8]) -> Vec<u8> {
        use ark_ec_vrfs::ring::Prover as _;

        let input = vrf_input_point(vrf_input_data);
        let output = self.secret.output(input);

        // Backend currently requires the wrapped type (plain affine points)
        let pts: Vec<_> = self.ring.iter().map(|pk| pk.0).collect();

        // Proof construction
        let ring_ctx = ring_context(ring_data);
        let prover_key = ring_ctx.prover_key(&pts);
        let prover = ring_ctx.prover(prover_key, self.prover_idx);
        let proof = self.secret.prove(input, output, aux_data, &prover);

        // Output and Ring Proof bundled together (as per section 2.2)
        let signature = RingVrfSignature { output, proof };
        let mut buf = Vec::new();
        signature.serialize_compressed(&mut buf).unwrap();
        buf
    }

    /// Non-Anonymous VRF signature.
    ///
    /// Used for ticket claiming during block production.
    /// Not used with Safrole test vectors.
    pub fn ietf_vrf_sign(&self, vrf_input_data: &[u8], aux_data: &[u8]) -> Vec<u8> {
        use ark_ec_vrfs::ietf::Prover as _;

        let input = vrf_input_point(vrf_input_data);
        let output = self.secret.output(input);

        let proof = self.secret.prove(input, output, aux_data);

        // Output and IETF Proof bundled together (as per section 2.2)
        let signature = IetfVrfSignature { output, proof };
        let mut buf = Vec::new();
        signature.serialize_compressed(&mut buf).unwrap();
        buf
    }
}

type RingCommitment = ark_ec_vrfs::ring::RingCommitment<bandersnatch::BandersnatchSha512Ell2>;

// Verifier actor.
struct Verifier {
    pub commitment: RingCommitment,
    pub ring: Vec<Public>,
    pub ring_data: Vec<u8>
}

impl Verifier {
    fn new(ring_data: Vec<u8>, ring: Vec<Public>) -> Self {
        // Backend currently requires the wrapped type (plain affine points)
        let pts: Vec<_> = ring.iter().map(|pk| pk.0).collect();
        let verifier_key = ring_context(&ring_data).verifier_key(&pts);
        let commitment = verifier_key.commitment();
        Self { ring, commitment, ring_data }
    }

    /// Anonymous VRF signature verification.
    ///
    /// Used for tickets verification.
    ///
    /// On success returns the VRF output hash.
    pub fn ring_vrf_verify(
        &self,
        vrf_input_data: &[u8],
        aux_data: &[u8],
        signature: &[u8],
    ) -> Result<[u8; 32], ()> {
        use ark_ec_vrfs::ring::prelude::fflonk::pcs::PcsParams;
        use ark_ec_vrfs::ring::Verifier as _;
        use bandersnatch::VerifierKey;

        let signature = RingVrfSignature::deserialize_compressed(signature).unwrap();

        let input = vrf_input_point(vrf_input_data);
        let output = signature.output;

        let ring_ctx = ring_context(&self.ring_data);

        // The verifier key is reconstructed from the commitment and the constant
        // verifier key component of the SRS in order to verify some proof.
        // As an alternative we can construct the verifier key using the
        // RingContext::verifier_key() method, but is more expensive.
        // In other words, we prefer computing the commitment once, when the keyset changes.
        let verifier_key = VerifierKey::from_commitment_and_kzg_vk(
            self.commitment.clone(),
            ring_ctx.pcs_params.raw_vk(),
        );
        let verifier = ring_ctx.verifier(verifier_key);
        if Public::verify(input, output, aux_data, &signature.proof, &verifier).is_err() {
            println!("Ring signature verification failure");
            return Err(());
        }
        println!("Ring signature verified");

        // This truncated hash is the actual value used as ticket-id/score in JAM
        let vrf_output_hash: [u8; 32] = output.hash()[..32].try_into().unwrap();
        println!(" vrf-output-hash: {}", hex::encode(vrf_output_hash));
        Ok(vrf_output_hash)
    }

    /// Non-Anonymous VRF signature verification.
    ///
    /// Used for ticket claim verification during block import.
    /// Not used with Safrole test vectors.
    ///
    /// On success returns the VRF output hash.
    pub fn ietf_vrf_verify(
        &self,
        vrf_input_data: &[u8],
        aux_data: &[u8],
        signature: &[u8],
        signer_key_index: usize,
    ) -> Result<[u8; 32], ()> {
        use ark_ec_vrfs::ietf::Verifier as _;

        let signature = IetfVrfSignature::deserialize_compressed(signature).unwrap();

        let input = vrf_input_point(vrf_input_data);
        let output = signature.output;

        let public = &self.ring[signer_key_index];
        if public
            .verify(input, output, aux_data, &signature.proof)
            .is_err()
        {
            println!("Ring signature verification failure");
            return Err(());
        }
        println!("Ietf signature verified");

        // This is the actual value used as ticket-id/score
        // NOTE: as far as vrf_input_data is the same, this matches the one produced
        // using the ring-vrf (regardless of aux_data).
        let vrf_output_hash: [u8; 32] = output.hash()[..32].try_into().unwrap();
        println!(" vrf-output-hash: {}", hex::encode(vrf_output_hash));
        Ok(vrf_output_hash)
    }
}

/// Formats the sum of two numbers as string.
#[pyfunction]
fn sum_as_string(a: usize, b: usize) -> PyResult<String> {
    Ok((a + b).to_string())
}

#[pyfunction]
fn ring_vrf_sign(ring_data: Vec<u8>, prover_key_index: usize, vrf_input_data: &[u8], aux_data: &[u8]) -> PyResult<Vec<u8>> {
    let ring_set: Vec<_> = (0..RING_SIZE)
        .map(|i| Secret::from_seed(&i.to_le_bytes()).public())
        .collect();


    let prover = Prover::new(ring_set.clone(), prover_key_index);
    // let verifier = Verifier::new(&ring_data, ring_set);

    // let vrf_input_data = b"foo";

    //--- Anonymous VRF

    // let aux_data = b"bar";

    // Prover signs some data.
    let ring_signature = prover.ring_vrf_sign(&ring_data, vrf_input_data, aux_data);
    Ok(ring_signature)
}

fn ring_vrf_verify_inner(
        ring_data: &Vec<u8>,
        vrf_input_data: &[u8],
        aux_data: &[u8],
        ring_signature: &[u8],
    ) -> Result<[u8; 32], ()> {
    let ring_set: Vec<_> = (0..RING_SIZE)
        .map(|i| Secret::from_seed(&i.to_le_bytes()).public())
        .collect();

    let verifier = Verifier::new(ring_data.clone(), ring_set);

    verifier.ring_vrf_verify(vrf_input_data, aux_data, &ring_signature)
}

#[pyfunction]
fn ring_vrf_verify(
        ring_data: Vec<u8>,
        vrf_input_data: &[u8],
        aux_data: &[u8],
        ring_signature: &[u8],
    ) -> PyResult<[u8; 32]> {
    Ok(ring_vrf_verify_inner(&ring_data, vrf_input_data, aux_data, ring_signature).unwrap())
}

fn ietf_vrf_sign_inner(secret_key: &[u8], vrf_input_data: &[u8], aux_data: &[u8]) -> Vec<u8> {
    use ark_ec_vrfs::ietf::Prover as _;

    // let secret = Secret::from_seed(&secret_key);
    let secret = Secret::deserialize_compressed(&mut &secret_key[..]).unwrap();
    let input = vrf_input_point(vrf_input_data);
    let output = secret.output(input);

    let proof = secret.prove(input, output, aux_data);

    // Output and IETF Proof bundled together (as per section 2.2)
    let signature = IetfVrfSignature { output, proof };
    let mut buf = Vec::new();
    signature.serialize_compressed(&mut buf).unwrap();
    buf
}

#[pyfunction]
fn ietf_vrf_sign(secret_key: &[u8], vrf_input_data: &[u8], aux_data: &[u8]) -> PyResult<Vec<u8>> {
   Ok(ietf_vrf_sign_inner(secret_key, vrf_input_data, aux_data))
}

#[derive(Debug)]
pub enum VrfError {
    DecodingError,
    VerificationError,
}

impl fmt::Display for VrfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VrfError::DecodingError => write!(f, "Decoding error"),
            VrfError::VerificationError => write!(f, "Verification error"),
        }
    }
}

impl Error for VrfError {}

fn ietf_vrf_verify_inner(public_key: &[u8], vrf_input_data: &[u8], aux_data: &[u8], signature: &[u8]) -> Result<[u8; 32], VrfError> {
    use ark_ec_vrfs::ietf::Verifier as _;

    let public = Public::deserialize_compressed(public_key).unwrap();
    let signature = IetfVrfSignature::deserialize_compressed(signature).unwrap();
    let input = vrf_input_point(vrf_input_data);
    let output = signature.output;

    if public.verify(input, output, aux_data, &signature.proof).is_err() {
        return Err(VrfError::VerificationError)
    }

    let vrf_output_hash: [u8; 32] = output.hash()[..32].try_into().unwrap();
    Ok(vrf_output_hash)
}

#[pyfunction]
fn ietf_vrf_verify(public_key: &[u8], vrf_input_data: &[u8], aux_data: &[u8], signature: &[u8]) -> PyResult<[u8; 32]> {
    Ok(ietf_vrf_verify_inner(public_key, vrf_input_data, aux_data, signature).unwrap())
}

#[pyfunction]
fn secret_from_seed(seed: &[u8]) -> PyResult<Vec<u8>> {
    let secret = Secret::from_seed(&seed);
    let mut secret_key = Vec::new();
    secret.serialize_compressed(&mut secret_key).unwrap();
    Ok(secret_key)
}

#[pyfunction]
fn public_from_secret(secret_key: &[u8]) -> PyResult<Vec<u8>> {
    let secret = Secret::deserialize_compressed(&mut &secret_key[..]).unwrap();
    let mut public_key = Vec::new();
    secret.public().serialize_compressed(&mut public_key).unwrap();
    Ok(public_key)
}

/// A Python module implemented in Rust.
#[pymodule]
fn bandersnatch_vrfs(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(sum_as_string, m)?)?;
    m.add_function(wrap_pyfunction!(ring_vrf_sign, m)?)?;
    m.add_function(wrap_pyfunction!(ring_vrf_verify, m)?)?;
    m.add_function(wrap_pyfunction!(ietf_vrf_sign, m)?)?;
    m.add_function(wrap_pyfunction!(ietf_vrf_verify, m)?)?;
    m.add_function(wrap_pyfunction!(secret_from_seed, m)?)?;
    m.add_function(wrap_pyfunction!(public_from_secret, m)?)?;
    Ok(())
}

#[test]
fn test_ietf_vrf() {
    let prover_idx: usize = 3;
    let secret = Secret::from_seed(&prover_idx.to_le_bytes());

    let mut secret_key = Vec::new();
    secret.serialize_compressed(&mut secret_key).unwrap();
    let secret_key_hex = hex::encode(&secret_key);
    println!("Secret key: {}", secret_key_hex);


    // let public_key = hex::decode("7518285dfdb55145d235f129b81192cd491abedbe1b1393c4592d6ff7a01d015").unwrap();
    let mut public_key = Vec::new();
    secret.public().serialize_compressed(&mut public_key).unwrap();
    let public_key_hex = hex::encode(&public_key);
    println!("public_key_hex: {}", public_key_hex);

    let vrf_input_data = b"foo";
    let aux_data = b"bar";

    let signature = ietf_vrf_sign_inner(&secret_key, vrf_input_data, aux_data);

    let signature_hex = hex::encode(&signature);
    println!("signature_hex: {}", signature_hex);

    let result = ietf_vrf_verify_inner(&public_key, vrf_input_data, aux_data, &signature).unwrap();
    println!("{}", hex::encode(&result));
}
