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
use std::sync::OnceLock;
use ark_vrf::ietf::{Proof};
use pyo3::exceptions::PyValueError;

/// Ring VRF context with an optional capacity independent of the member count.
#[pyclass]
struct RingContext {
    ring_ctx: RingProofParams,
    ring: Vec<Public>,
    commitment: RingCommitment,
    // Native preparation is immutable and shared by all signatures for this ring.
    // Verification-only contexts never allocate this additional proving state.
    prover_key: OnceLock<bandersnatch::RingProverKey>,
}

#[pymethods]
impl RingContext {
    #[new]
    #[pyo3(signature = (ring_data, ring_public_keys, *, ring_capacity = None))]
    fn new(
        py: Python<'_>,
        ring_data: &[u8],
        ring_public_keys: Vec<Vec<u8>>,
        ring_capacity: Option<usize>,
    ) -> PyResult<Self> {
        py.detach(move || Self::build(ring_data, ring_public_keys, ring_capacity))
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
        if prover_key_index >= self.ring.len() {
            return Err(PyValueError::new_err(
                "prover_key_index must refer to a supplied public key",
            ));
        }
        let sig = py.detach(|| {
            let secret = Secret::deserialize_compressed(&mut &secret_key[..]).map_err(|_| VrfError::DecodingError)?;
            let input = vrf_input_point(vrf_input_data);
            let output = secret.output(input);

            // Initialize only while detached: another signer may be preparing the
            // same ring, and waiting for it must not block Python's interpreter.
            let pkey = self.prover_key.get_or_init(|| {
                let pts: Vec<_> = self.ring.iter().map(|pk| pk.0).collect();
                self.ring_ctx.prover_key(&pts)
            });
            let prover = self.ring_ctx.prover(pkey.clone(), prover_key_index);

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

impl RingContext {
    fn build(
        ring_data: &[u8],
        ring_public_keys: Vec<Vec<u8>>,
        ring_capacity: Option<usize>,
    ) -> PyResult<Self> {
        let ring_capacity = ring_capacity.unwrap_or(ring_public_keys.len());
        if ring_capacity < ring_public_keys.len() {
            return Err(PyValueError::new_err(
                "ring_capacity must be at least the number of public keys",
            ));
        }
        let ring = vec_array_to_public(ring_public_keys);
        let pts: Vec<_> = ring.iter().map(|pk| pk.0).collect();
        // The native backend fills unused positions with its own padding point.
        // Keep only supplied members in `ring` so padding is never a signing index.
        let ring_ctx = ring_context(ring_data, ring_capacity)?;
        let verifier_key = ring_ctx.verifier_key(&pts);
        let commitment = verifier_key.commitment();
        Ok(Self { ring_ctx, ring, commitment, prover_key: OnceLock::new() })
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
fn ring_context(ring_data: &[u8], ring_capacity: usize) -> PyResult<RingProofParams> {
    use bandersnatch::PcsParams;
    use ark_vrf::ring::{max_ring_size_from_pcs_domain_size, pcs_domain_size};

    let pcs_params = PcsParams::deserialize_uncompressed_unchecked(&mut &ring_data[..])
        .map_err(|_| PyValueError::new_err("Invalid ring_data: cannot decode PCS parameters"))?;
    // Bound capacity before the upstream domain-size arithmetic, which is unchecked.
    // Check the minimum SRS size before using its inverse domain-size conversion.
    if pcs_params.powers_in_g1.len() < pcs_domain_size::<BandersnatchSha512Ell2>(0)
        || pcs_params.powers_in_g2.len() < 2
        || ring_capacity
            > max_ring_size_from_pcs_domain_size::<BandersnatchSha512Ell2>(
                pcs_params.powers_in_g1.len(),
            )
    {
        return Err(PyValueError::new_err(
            "ring_data does not support the requested ring_capacity",
        ));
    }
    RingProofParams::from_pcs_params(ring_capacity, pcs_params).map_err(|_| {
        PyValueError::new_err("ring_data does not support the requested ring_capacity")
    })
}

// Construct VRF Input Point from arbitrary data (section 1.2)
fn vrf_input_point(vrf_input_data: &[u8]) -> Input {
    Input::new(vrf_input_data).unwrap()
}

fn vrf_output_point(vrf_output_data: &[u8]) -> Output {
    let point =
        <BandersnatchSha512Ell2 as ark_vrf::Suite>::data_to_point(vrf_output_data)
            .unwrap();
    Output::from_affine(point)
}

type RingCommitment = ark_vrf::ring::RingCommitment<BandersnatchSha512Ell2>;

pub type PublicKey = [u8; 32];
pub type SecretKey = [u8; 32];

fn vec_array_to_public(ring_public_keys: Vec<Vec<u8>>) -> Vec<Public> {
    let fallback_public = Public::from_affine(RingProofParams::padding_point());

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
// Preserve the module's existing GIL requirement; free-threaded support needs
// its own audit and CI rather than an implicit safety declaration.
#[pymodule(gil_used = true)]
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
