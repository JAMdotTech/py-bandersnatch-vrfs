use pyo3::prelude::*;

use ark_vrf::reexports::{
    ark_serialize::{self, CanonicalDeserialize, CanonicalSerialize},
};
use ark_vrf::{suites::bandersnatch};
use bandersnatch::{
    BandersnatchSha512Ell2, IetfProof, Input, Output, Public, RingProof,
    RingProofParams, Secret,
};

use pyo3::types::PyBytes;
use std::fmt;
use std::error::Error;
use ark_vrf::ietf::{Proof};
use pyo3::exceptions::PyValueError;

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

// ring context data
fn ring_context(ring_data: &Vec<u8>, ring_size: usize) -> RingProofParams {
    use bandersnatch::PcsParams;
    let pcs_params = PcsParams::deserialize_uncompressed_unchecked(&mut &ring_data[..]).unwrap();
    RingProofParams::from_pcs_params(ring_size, pcs_params).unwrap()
}

// Construct VRF Input Point from arbitrary data (section 1.2)
fn vrf_input_point(vrf_input_data: &[u8]) -> Input {
    let point =
        <BandersnatchSha512Ell2 as ark_vrf::Suite>::data_to_point(vrf_input_data)
            .unwrap();
    Input::from(point)
}

fn vrf_output_point(vrf_output_data: &[u8]) -> Output {
    let point =
        <BandersnatchSha512Ell2 as ark_vrf::Suite>::data_to_point(vrf_output_data)
            .unwrap();
    Output::from(point)
}

// Prover actor.
struct Prover {
    pub prover_idx: usize,
    pub secret: Secret,
    pub ring: Vec<Public>,
    pub ring_size: usize
}

impl Prover {
    pub fn new(ring: Vec<Public>, secret: Secret, prover_idx: usize) -> Self {
        Self {
            prover_idx,
            secret,
            ring_size: ring.len(),
            ring
        }
    }

    /// Anonymous VRF signature.
    ///
    /// Used for tickets submission.
    pub fn ring_vrf_sign(&self, ring_data: &Vec<u8>, vrf_input_data: &[u8], aux_data: &[u8]) -> Vec<u8> {
        use ark_vrf::ring::Prover as _;

        let input = vrf_input_point(vrf_input_data);
        let output = self.secret.output(input);

        // Backend currently requires the wrapped type (plain affine points)
        let pts: Vec<_> = self.ring.iter().map(|pk| pk.0).collect();

        // Proof construction
        let ring_ctx = ring_context(ring_data, self.ring_size);
        let prover_key = ring_ctx.prover_key(&pts);
        let prover = ring_ctx.prover(prover_key, self.prover_idx);
        let proof = self.secret.prove(input, output, aux_data, &prover);

        // Output and Ring Proof bundled together (as per section 2.2)
        let signature = RingVrfSignature { output, proof };
        let mut buf = Vec::new();
        signature.serialize_compressed(&mut buf).unwrap();
        buf
    }
}

type RingCommitment = ark_vrf::ring::RingCommitment<BandersnatchSha512Ell2>;

// Verifier actor.
struct Verifier {
    pub commitment: RingCommitment,
    pub ring: Vec<Public>,
    pub ring_data: Vec<u8>,
    pub ring_size: usize
}

impl Verifier {
    fn new(ring_data: Vec<u8>, ring: Vec<Public>) -> Self {
        // Backend currently requires the wrapped type (plain affine points)
        let pts: Vec<_> = ring.iter().map(|pk| pk.0).collect();
        let ring_size = ring.len();
        let verifier_key = ring_context(&ring_data, ring_size).verifier_key(&pts);
        let commitment = verifier_key.commitment();
        Self { ring, commitment, ring_data, ring_size }
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
    ) -> Result<[u8; 32], VrfError> {
        use ark_vrf::ring::Verifier as _;

        let signature = RingVrfSignature::deserialize_compressed(signature).map_err(|_| VrfError::InvalidSignature)?;

        let input = vrf_input_point(vrf_input_data);
        let output = signature.output;

        let ring_ctx = ring_context(&self.ring_data, self.ring_size);

        // The verifier key is reconstructed from the commitment and the constant
        // verifier key component of the SRS in order to verify some proof.
        // As an alternative we can construct the verifier key using the
        // RingContext::verifier_key() method, but is more expensive.
        // In other words, we prefer computing the commitment once, when the keyset changes.
        let verifier_key = ring_ctx.verifier_key_from_commitment(self.commitment.clone());
        let verifier = ring_ctx.verifier(verifier_key);
        if Public::verify(input, output, aux_data, &signature.proof, &verifier).is_err() {
            // println!("Ring signature verification failure");
            return Err(VrfError::VerificationError);
        }
        // println!("Ring signature verified");

        // This truncated hash is the actual value used as ticket-id/score in JAM
        let vrf_output_hash: [u8; 32] = output.hash()[..32].try_into().unwrap();
        // println!(" vrf-output-hash: {}", hex::encode(vrf_output_hash));
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
    ) -> Result<[u8; 32], VrfError> {
        use ark_vrf::ietf::Verifier as _;

        let signature = IetfVrfSignature::deserialize_compressed(signature).unwrap();

        let input = vrf_input_point(vrf_input_data);
        let output = signature.output;

        let public = &self.ring[signer_key_index];
        if public
            .verify(input, output, aux_data, &signature.proof)
            .is_err()
        {
            // println!("Ring signature verification failure");
            return Err(VrfError::VerificationError);
        }
        // println!("Ietf signature verified");

        // This is the actual value used as ticket-id/score
        // NOTE: as far as vrf_input_data is the same, this matches the one produced
        // using the ring-vrf (regardless of aux_data).
        let vrf_output_hash: [u8; 32] = output.hash()[..32].try_into().unwrap();
        // println!(" vrf-output-hash: {}", hex::encode(vrf_output_hash));
        Ok(vrf_output_hash)
    }
}

pub type PublicKey = [u8; 32];
pub type SecretKey = [u8; 32];

fn vec_array_to_public(ring_public_keys: Vec<Vec<u8>>) -> Vec<Public> {
    let fallback_public = Public::from(RingProofParams::padding_point());

    let ring_set: Vec<Public> = ring_public_keys.iter()
        .map(|key_bytes| {
            Public::deserialize_compressed_unchecked(&mut &key_bytes[..])
                .unwrap_or_else(|_| fallback_public.clone())
        })
        .collect();
    ring_set
}

fn ring_vrf_sign_inner(ring_data: Vec<u8>, ring_public_keys: Vec<Vec<u8>>, secret: Secret, prover_key_index: usize, vrf_input_data: &[u8],
                 aux_data: &[u8]) -> Vec<u8> {
    let ring_set: Vec<Public> = vec_array_to_public(ring_public_keys);

    // Determine prover in the ring_set
    let prover = Prover::new(ring_set.clone(), secret,  prover_key_index);

    // Prover signs some data.
    let ring_signature = prover.ring_vrf_sign(&ring_data, vrf_input_data, aux_data);
    ring_signature
}

#[pyfunction]
fn ring_vrf_sign(ring_data: Vec<u8>, ring_public_keys: Vec<Vec<u8>>, secret_key: Vec<u8>, prover_key_index: usize, vrf_input_data: &[u8],
                 aux_data: &[u8], py: Python) -> PyResult<Py<PyBytes>> {


    let secret = Secret::deserialize_compressed(
        &mut &secret_key[..]
    ).map_err(|err| PyValueError::new_err(format!("Invalid secret_key: {}", err.to_string())))?;

    let ring_signature = ring_vrf_sign_inner(ring_data, ring_public_keys, secret, prover_key_index, vrf_input_data, aux_data);
    Ok(PyBytes::new(py, &ring_signature).into())
}

fn ring_vrf_verify_inner(
        ring_data: Vec<u8>,
        ring_public_keys: Vec<Vec<u8>>,
        vrf_input_data: &[u8],
        aux_data: &[u8],
        ring_signature: &[u8],
    ) -> Result<[u8; 32], VrfError> {

    let ring_set: Vec<Public> = vec_array_to_public(ring_public_keys);

    let verifier = Verifier::new(ring_data.clone(), ring_set);

    verifier.ring_vrf_verify(vrf_input_data, aux_data, &ring_signature)
}

#[pyfunction]
fn ring_vrf_verify(
        ring_data: Vec<u8>,
        ring_public_keys: Vec<Vec<u8>>,
        vrf_input_data: &[u8],
        aux_data: &[u8],
        ring_signature: &[u8],
        py: Python
    ) -> PyResult<Py<PyBytes>> {

    let ring_vrf_output = ring_vrf_verify_inner(
        ring_data, ring_public_keys, vrf_input_data, aux_data, ring_signature
    ).map_err(|err| PyValueError::new_err(format!("Verify failed: {}", err.to_string())))?;

    Ok(PyBytes::new(py, &ring_vrf_output).into())
}

fn ring_ietf_vrf_verify_inner(ring_data: Vec<u8>, ring_public_keys: Vec<Vec<u8>>, signer_key_index: usize, vrf_input_data: &[u8],
        aux_data: &[u8], signature: &[u8],) -> Result<[u8; 32], VrfError> {
    let ring_set: Vec<Public> = vec_array_to_public(ring_public_keys);

    let verifier = Verifier::new(ring_data, ring_set);

    let vrf_output_hash = verifier.ietf_vrf_verify(vrf_input_data, aux_data, &signature, signer_key_index);
    vrf_output_hash
}

#[pyfunction]
fn ring_ietf_vrf_verify(
        ring_data: Vec<u8>,
        ring_public_keys: Vec<Vec<u8>>,
        signer_key_index: usize,
        vrf_input_data: &[u8],
        aux_data: &[u8],
        ring_signature: &[u8],
        py: Python
    ) -> PyResult<Py<PyBytes>> {
    let vrf_output_hash = ring_ietf_vrf_verify_inner(
        ring_data, ring_public_keys, signer_key_index, vrf_input_data, aux_data, ring_signature
    ).unwrap();
    Ok(PyBytes::new(py, &vrf_output_hash).into())
}

fn vrf_output_inner(secret: &Secret, vrf_input_data: &[u8]) -> Vec<u8> {

    let input = vrf_input_point(vrf_input_data);
    let output = secret.output(input);

    let vrf_output_hash: [u8; 32] = output.hash()[..32].try_into().unwrap();
    vrf_output_hash.to_vec()
}

#[pyfunction]
fn vrf_output(secret_key: &[u8], vrf_input_data: &[u8], py: Python) -> PyResult<Py<PyBytes>> {

    let secret = Secret::deserialize_compressed(
        &mut &secret_key[..]
    ).map_err(|err| PyValueError::new_err(format!("Invalid secret_key: {}", err.to_string())))?;

   let vrf_output = crate::vrf_output_inner(&secret, vrf_input_data);
   Ok(PyBytes::new(py, &vrf_output).into())
}

fn ietf_vrf_sign_inner(secret_key: &[u8], vrf_input_data: &[u8], aux_data: &[u8]) -> Vec<u8> {
    use ark_vrf::ietf::Prover as _;

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
fn ietf_vrf_sign(secret_key: &[u8], vrf_input_data: &[u8], aux_data: &[u8], py: Python) -> PyResult<Py<PyBytes>> {
   let signature = ietf_vrf_sign_inner(secret_key, vrf_input_data, aux_data);
   Ok(PyBytes::new(py, &signature).into())
}

#[derive(Debug)]
pub enum VrfError {
    DecodingError,
    VerificationError,
    InvalidSignature,
}

impl fmt::Display for VrfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VrfError::DecodingError => write!(f, "Decoding error"),
            VrfError::VerificationError => write!(f, "Verification error"),
            VrfError::InvalidSignature => write!(f, "Invalid signature"),
        }
    }
}

impl Error for VrfError {}

fn ietf_vrf_verify_inner(public_key: &[u8], vrf_input_data: &[u8], aux_data: &[u8], signature: &[u8]) -> Result<[u8; 32], VrfError> {
    use ark_vrf::ietf::Verifier as _;

    let public = Public::deserialize_compressed(public_key).unwrap();
    let signature = IetfVrfSignature::deserialize_compressed(signature).map_err(|_| VrfError::VerificationError)?;

    let input = vrf_input_point(vrf_input_data);
    let output = signature.output;

    if public.verify(input, output, aux_data, &signature.proof).is_err() {
        return Err(VrfError::VerificationError)
    }

    let vrf_output_hash: [u8; 32] = output.hash()[..32].try_into().unwrap();
    Ok(vrf_output_hash)
}

#[pyfunction]
fn ietf_vrf_verify(public_key: &[u8], vrf_input_data: &[u8], aux_data: &[u8], signature: &[u8], py: Python) -> PyResult<Py<PyBytes>> {
    let ietf_vrf_output = ietf_vrf_verify_inner(
        public_key, vrf_input_data, aux_data, signature
    ).map_err(|err| PyValueError::new_err(format!("Verify failed: {}", err.to_string())))?;

    Ok(PyBytes::new(py, &ietf_vrf_output).into())
}

#[pyfunction]
fn secret_from_seed(seed: &[u8], py: Python) -> PyResult<Py<PyBytes>> {
    let secret = Secret::from_seed(&seed);
    let mut secret_key = Vec::new();
    secret.serialize_compressed(&mut secret_key).unwrap();
    Ok(PyBytes::new(py, &secret_key).into())
}

#[pyfunction]
fn public_from_secret(secret_key: &[u8], py: Python) -> PyResult<Py<PyBytes>> {
    let secret = Secret::deserialize_compressed(&mut &secret_key[..]).unwrap();
    let mut public_key = Vec::new();
    secret.public().serialize_compressed(&mut public_key).unwrap();
    Ok(PyBytes::new(py, &public_key).into())
}

fn serialize_to_vec<S: CanonicalSerialize>(item: &S) -> Vec<u8> {
    let mut vec = Vec::new();
    item.serialize_compressed(&mut vec).unwrap();
    vec
}

#[pyclass]
struct PyProof {

    #[pyo3(get)]
    pub c: Py<PyBytes>,

    #[pyo3(get)]
    pub s: Py<PyBytes>,
}

#[pymethods]
impl PyProof {
    #[new]
    fn new(py: Python, c_data: Vec<u8>, s_data: Vec<u8>) -> Self {
        PyProof {
            c: PyBytes::new(py, &c_data).into(),
            s: PyBytes::new(py, &s_data).into(),
        }
    }
}

impl From<Proof<BandersnatchSha512Ell2>> for PyProof {
    fn from(proof: Proof<BandersnatchSha512Ell2>) -> Self {
        Python::attach(|py| PyProof::new(
            py, serialize_to_vec(&proof.c), serialize_to_vec(&proof.s)
        ))
    }
}

fn generate_vrf_proof_inner(secret_key: &[u8], vrf_input_data: &[u8], vrf_output_data: &[u8], aux_data: &[u8]) -> Proof<BandersnatchSha512Ell2> {
    use ark_vrf::ietf::{Prover};
    let secret = Secret::deserialize_compressed(&mut &secret_key[..]).unwrap();
    let input = vrf_input_point(vrf_input_data);
    let output = vrf_output_point(vrf_output_data);
    secret.prove(input, output, aux_data)
}

#[pyfunction]
fn generate_vrf_proof(secret_key: &[u8], vrf_input_data: &[u8], vrf_output_data: &[u8], aux_data: &[u8]) -> PyResult<PyProof> {
    let proof = generate_vrf_proof_inner(secret_key, vrf_input_data, vrf_output_data, aux_data);
    let py_proof = proof.into();
    Ok(py_proof)
}

fn ring_commitment_inner(ring_data: Vec<u8>, ring_public_keys: Vec<Vec<u8>>) -> Vec<u8> {

    let ring_set: Vec<Public> = vec_array_to_public(ring_public_keys);
    let verifier = Verifier::new(ring_data.clone(), ring_set);

    let mut commitment_bytes = Vec::new();
    verifier.commitment.serialize_compressed(&mut commitment_bytes).unwrap();
    commitment_bytes
}

#[pyfunction]
fn ring_commitment(ring_data: Vec<u8>, ring_public_keys: Vec<Vec<u8>>, py: Python) -> PyResult<Py<PyBytes>> {
    let commitment_bytes = ring_commitment_inner(
        ring_data, ring_public_keys
    );

    Ok(PyBytes::new(py, &commitment_bytes).into())
}


/// A Python module implemented in Rust.
#[pymodule]
fn bandersnatch_vrfs(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(ring_vrf_sign, m)?)?;
    m.add_function(wrap_pyfunction!(ring_vrf_verify, m)?)?;
    m.add_function(wrap_pyfunction!(ring_ietf_vrf_verify, m)?)?;
    m.add_function(wrap_pyfunction!(ring_commitment, m)?)?;
    m.add_function(wrap_pyfunction!(ietf_vrf_sign, m)?)?;
    m.add_function(wrap_pyfunction!(vrf_output, m)?)?;
    m.add_function(wrap_pyfunction!(ietf_vrf_verify, m)?)?;
    m.add_function(wrap_pyfunction!(secret_from_seed, m)?)?;
    m.add_function(wrap_pyfunction!(public_from_secret, m)?)?;
    m.add_function(wrap_pyfunction!(generate_vrf_proof, m)?)?;
    m.add_class::<PyProof>()?;
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs::File, io::Read};
    use ark_vrf::Public;
    use lazy_static::lazy_static;

    lazy_static! {
        static ref RING_DATA: Vec<u8> = {
            let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR is not set");
            let filename = format!("{}/data/zcash-srs-2-11-uncompressed.bin", manifest_dir);
            let mut file = File::open(filename).expect("Failed to open SRS file");
            let mut ring_data = Vec::new();
            file.read_to_end(&mut ring_data).expect("Failed to read SRS file");
            ring_data
        };
    }

    fn load_ring_data(ring_size: usize) -> (Vec<Secret>, Vec<Public<BandersnatchSha512Ell2>>) {

        // Generate secrets and corresponding public keys
        let mut secrets: Vec<Secret> = Vec::with_capacity(ring_size);
        let mut publics: Vec<Public<BandersnatchSha512Ell2>> = Vec::with_capacity(ring_size);

        for i in 0..ring_size {
            let secret = Secret::from_seed(&i.to_le_bytes());
            let public = secret.public();
            secrets.push(secret);
            publics.push(public);
        }
        (secrets, publics)
    }

    fn vec_public_to_array(publics: Vec<Public<BandersnatchSha512Ell2>>) -> Vec<Vec<u8>> {
         let ring_public_keys: Vec<Vec<u8>> = publics.iter()
            .map(|public| {
                let mut key_bytes = Vec::new();
                public.serialize_compressed(&mut key_bytes).unwrap();
                key_bytes
            })
            .collect();
        ring_public_keys
    }

    #[test]
    fn test_ring_vrf() {
        // Setup ring
        let ring_size = 1023;
        let (secrets, publics) = load_ring_data(ring_size);

        let ring_public_keys = vec_public_to_array(publics.clone());

        // Specify the index of the prover in the ring
        let prover_idx = 3;

        let vrf_input_data = b"foo";
        let aux_data = b"bar";

        let secret = secrets[prover_idx].clone();

        let vrf_output = vrf_output_inner(&secret, vrf_input_data);
        assert_eq!(hex::encode(&vrf_output), "6b260bfda2e3ef118c529f30b60dfa4678fbeef3682b55ba002aa8633f1b0364");

        let signature = ring_vrf_sign_inner(RING_DATA.clone(), ring_public_keys.clone(), secret, prover_idx, vrf_input_data, aux_data);
        // let signature_hex = hex::encode(&signature);
        // println!("signature_hex: {}", signature_hex);

        let ring_vrf_output = ring_vrf_verify_inner(RING_DATA.clone(), ring_public_keys.clone(), vrf_input_data, aux_data, &signature).unwrap();
        assert_eq!(hex::encode(&ring_vrf_output), "6b260bfda2e3ef118c529f30b60dfa4678fbeef3682b55ba002aa8633f1b0364");
    }

    #[test]
    fn test_ring_vrf_verify_invalid_signature() {
        let ring_size = 1023;
        let (_, publics) = load_ring_data(ring_size);

        let ring_public_keys = vec_public_to_array(publics);

        let vrf_input_data = b"foo";
        let aux_data = b"bar";
        let signature = hex::decode("3e31c3db69741dbeef0b29aeb1f9370d4bbe2365c18586510db8a640101aa42266709f8da7d09a212d5282804e3b824fa8c0c1ffd13a65633ad16f5dab2002bde335816fb40de9cf2ee723ee7621da69b73676d727bc0a28828a08984620f0d625e5c5bd6eb407733c04877094b35c32a9293bc73637cd3da19a00410b74a6cdccbb1be20256cce76f68db1e1e386119870b8bcbc4ac0969f332715754d49009879ad324888180e0064831edc42201301477554180585eb0cf1199de7b512f0298e791ca47f3e2200cf3d7833c55bfacae40174ad122273f5c65aaa2037c132f8c784c7933752c6047b9d4fe7f0cd17aa87b94379b86927a13bc49e20120184f30de45fea3adfcfe06b8ea99354356be270dd9b5816649a80185c395e5d9c1e48fa4c051bc632ebc4ca02c526c4f1216bfb131c10002598e191c21a8a8f48effb0c6de9d38a089ee00ac7937cfee5f1bb43324e62e3177a22f081420a9fe105dbdff7c2f8c65684502abdf52d8100b6502f5287ac5eae2429b215cbc6645422e3eec15627f384e9f837c8186f11a76987971d9dadc92e1f281f6bf3f4a24633e88acedd8c22c23906136ba88a5feda6b7db40f5e488ae2e2b0b7a4537ef1ee3d7021deb02e8571063716be53a61b095c742b5ab6357561011aee3b2d1c5544537d2260aa70ccea3ff11966503faa898f0bf82a49099e4768edef38ef86c3e5269b10d76755144762d7da583f99e2bd0643580c6f2afb16a8ae1d11b79fc2ed33725b871e545ad010fadc7d9ad95a036ec89555bfaf3587c561032c2179a6746c5aecd2f2b32ecc376fcea547ff57730e0f0dff7cf5a7ceb1fa56919c1ea10c6bae6cbfc6bffbf87a7a1cbb6d5309aea20b8b66057789c4e1ed68c43e20547f3417e72143a968095fa5afe39717d7ca9b732d9edec03e0714ce9806848a38196011010a0ba4b34772be196597a855950db398b587b1d96c1abcdf54c45a029db0f1e577cdcd2db8f998827a33b45904fc260852888c2dd2fee32a9b1ed0879647b392f8dcd197db96f8f5ff3378f52b1d7fd6e6b479babb35f45d922ea79959865330f88ba9b4d09c9e84a2072f32ce34").unwrap();

        let result = ring_vrf_verify_inner(RING_DATA.clone(), ring_public_keys, vrf_input_data, aux_data, &signature);
        assert!(matches!(result, Err(VrfError::InvalidSignature)));
    }

    #[test]
    fn test_ring_ietf_verify() {
        let ring_size = 1023;
        let (secrets, publics) = load_ring_data(ring_size);

        let vrf_input_data = b"foo";
        let aux_data = b"bar";
        let signer_key_index = 3;

        let mut secret_key = Vec::new();
        secrets[signer_key_index].serialize_compressed(&mut secret_key).unwrap();

        let vrf_output = vrf_output_inner(&secrets[signer_key_index], vrf_input_data);
        assert_eq!(hex::encode(&vrf_output), "6b260bfda2e3ef118c529f30b60dfa4678fbeef3682b55ba002aa8633f1b0364");


        let signature = ietf_vrf_sign_inner(&secret_key, vrf_input_data, aux_data);

        let verifier = Verifier::new(RING_DATA.clone(), publics);

        let ring_vrf_output = verifier.ietf_vrf_verify(vrf_input_data, aux_data, &signature, 3).unwrap();

        assert_eq!(hex::encode(&ring_vrf_output), "6b260bfda2e3ef118c529f30b60dfa4678fbeef3682b55ba002aa8633f1b0364")

    }
    #[test]
    fn test_ring_commitment() {
        let ring_size = 1023;
        let (_, publics) = load_ring_data(ring_size);

        let ring_public_keys = vec_public_to_array(publics);
        let commitment_bytes = ring_commitment_inner(RING_DATA.clone(), ring_public_keys);

        assert_eq!(hex::encode(&commitment_bytes), "a722e5a7928fae5fffb6ec1be5831d96e357c5a075c17b89fbf3500705c5efa7c028946920c1306f671b56e7e680aa4faa1c5b0f7a49d8db2588c6b7913ba583a518e7ec2ca694846d7c664cbfde421d4508c6ce31af652f1220e84955ad0eb896c1b168e2dcc743f9eadda76c041db42d39f27a58418f88c0ea67656a224934e12b5dfc8f0f460a95c2d467fa41907b")
    }

    #[test]
    fn test_ietf_vrf() {
        let prover_idx: usize = 3;
        let secret = Secret::from_seed(&prover_idx.to_le_bytes());

        let mut secret_key = Vec::new();
        secret.serialize_compressed(&mut secret_key).unwrap();
        let secret_key_hex = hex::encode(&secret_key);

        assert_eq!(secret_key_hex, "2d1edba09f9ca06a5b9b3555a16959f29a841da69ebe5175694ffa4f8be04f1a");

        let mut public_key = Vec::new();
        secret.public().serialize_compressed(&mut public_key).unwrap();
        let public_key_hex = hex::encode(&public_key);

        assert_eq!(public_key_hex, "7518285dfdb55145d235f129b81192cd491abedbe1b1393c4592d6ff7a01d015");

        let vrf_input_data = b"foo";
        let aux_data = b"bar";

        let signature = ietf_vrf_sign_inner(&secret_key, vrf_input_data, aux_data);

        match ietf_vrf_verify_inner(&public_key, vrf_input_data, aux_data, &signature) {
            Ok(result) => assert_eq!(hex::encode(&result), "6b260bfda2e3ef118c529f30b60dfa4678fbeef3682b55ba002aa8633f1b0364"),
            Err(err) => assert!(false, "Expected Ok, but got Err: {}", err)
        }
    }
}


