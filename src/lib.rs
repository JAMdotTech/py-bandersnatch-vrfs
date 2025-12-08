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

#[pyclass]
struct RingContext {
    ring_ctx: RingProofParams,
    ring: Vec<Public>,
    commitment: RingCommitment,
}

#[pymethods]
impl RingContext {
    #[new]
    fn new(ring_data: &[u8], ring_public_keys: Vec<Vec<u8>>) -> PyResult<Self> {
        let ring = vec_array_to_public(ring_public_keys);
        let ring_size = ring.len();
        let pts: Vec<_> = ring.iter().map(|pk| pk.0).collect();
        let ring_ctx = ring_context(ring_data, ring_size);
        let verifier_key = ring_ctx.verifier_key(&pts);
        let commitment = verifier_key.commitment();
        Ok(Self { ring_ctx, ring, commitment })
    }

    fn ring_vrf_verify(&self, py: Python, vrf_input_data: &[u8], aux_data: &[u8], signature: &[u8]) -> PyResult<Py<PyBytes>> {
        use ark_vrf::ring::Verifier as _;
        let out = py.detach(|| {
            let sig = RingVrfSignature::deserialize_compressed(signature)
                .map_err(|_| VrfError::InvalidSignature)?;
            let input = vrf_input_point(vrf_input_data);
            let output = sig.output;

            let vkey = self.ring_ctx.verifier_key_from_commitment(self.commitment.clone());
            let verifier = self.ring_ctx.verifier(vkey);

            if Public::verify(input, output, aux_data, &sig.proof, &verifier).is_err() {
                return Err(VrfError::VerificationError);
            }
            let mut h = [0u8; 32];
            h.copy_from_slice(&output.hash()[..32]);
            Ok::<[u8;32], VrfError>(h)
        }).map_err(|e: VrfError| PyValueError::new_err(e.to_string()))?;
        Ok(PyBytes::new(py, &out).into())
    }

    fn ring_vrf_sign(&self, py: Python, prover_key_index: usize, secret_key: &[u8], vrf_input_data: &[u8], aux_data: &[u8]) -> PyResult<Py<PyBytes>> {
        use ark_vrf::ring::Prover as _;
        let sig = py.detach(|| {
            let secret = Secret::deserialize_compressed(&mut &secret_key[..]).map_err(|_| VrfError::DecodingError)?;
            let input = vrf_input_point(vrf_input_data);
            let output = secret.output(input);

            let pts: Vec<_> = self.ring.iter().map(|pk| pk.0).collect();
            let pkey = self.ring_ctx.prover_key(&pts);
            let prover = self.ring_ctx.prover(pkey, prover_key_index);

            let proof = secret.prove(input, output, aux_data, &prover);
            let signature = RingVrfSignature { output, proof };
            let mut buf = Vec::with_capacity(512);
            signature.serialize_compressed(&mut buf).unwrap();
            Ok::<Vec<u8>, VrfError>(buf)
        }).map_err(|e: VrfError| PyValueError::new_err(e.to_string()))?;
        Ok(PyBytes::new(py, &sig).into())
    }

    #[getter]
    fn commitment(&self, py: Python) -> PyResult<Py<PyBytes>> {
        let mut bytes = Vec::with_capacity(128);
        self.commitment.serialize_compressed(&mut bytes).unwrap();
        Ok(PyBytes::new(py, &bytes).into())
    }
}


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
fn ring_context(ring_data: &[u8], ring_size: usize) -> RingProofParams {
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

type RingCommitment = ark_vrf::ring::RingCommitment<BandersnatchSha512Ell2>;

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
fn ietf_vrf_verify(
    public_key: &[u8],
    vrf_input_data: &[u8],
    aux_data: &[u8],
    signature: &[u8],
    py: Python,
) -> PyResult<Py<PyBytes>> {
    let out = py
        .detach(|| ietf_vrf_verify_inner(public_key, vrf_input_data, aux_data, signature))
        .map_err(|e| match e {
            VrfError::InvalidSignature => PyValueError::new_err("Verify failed: Invalid signature"),
            VrfError::VerificationError => PyValueError::new_err("Verify failed: Verification error"),
            VrfError::DecodingError => PyValueError::new_err("Verify failed: Decoding error"),
        })?;
    Ok(PyBytes::new(py, &out).into())
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



/// A Python module implemented in Rust.
#[pymodule]
fn bandersnatch_vrfs(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(ietf_vrf_sign, m)?)?;
    m.add_function(wrap_pyfunction!(vrf_output, m)?)?;
    m.add_function(wrap_pyfunction!(ietf_vrf_verify, m)?)?;
    m.add_function(wrap_pyfunction!(secret_from_seed, m)?)?;
    m.add_function(wrap_pyfunction!(public_from_secret, m)?)?;
    m.add_function(wrap_pyfunction!(generate_vrf_proof, m)?)?;
    m.add_class::<PyProof>()?;
    m.add_class::<RingContext>()?;
    Ok(())
}
