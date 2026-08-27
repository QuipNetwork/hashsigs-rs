// Copyright (C) 2026 quip.network
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The PyO3 export layer, stamped out over one profile.
//!
//! [`python_profile_surface!`] emits a complete `#[pymodule]` that delegates to
//! [`hashsigs_rs::bindings`], the profile-generic core the WebAssembly surface
//! also uses. It exists for the same reason the wasm macro does: `#[pyfunction]`
//! cannot annotate a generic function, so a profile-generic surface has to be
//! monomorphized somewhere, and a macro does that without copying the logic.
//!
//! Each profile gets its own crate under `py/profiles/`, because one Cargo
//! package builds at most one `cdylib` and the wheel ships one extension per
//! profile. Those crates hold nothing but a macro invocation.
//!
//! # Why the exception class comes from Python
//!
//! Six extension modules each defining their own `HashSigsError` would give
//! six unrelated classes, so `except HashSigsError` caught from one profile
//! would not catch an error raised by another. Instead every module imports
//! the single class from `hashsigs._errors` on first use and raises that. One
//! wheel, one exception class, regardless of which profiles a caller touches.

use pyo3::exceptions::PyRuntimeError;
use pyo3::prelude::*;
use pyo3::sync::PyOnceLock;
use pyo3::types::PyType;

pub use hashsigs_rs;
pub use pyo3;

/// The shared `hashsigs._errors.HashSigsError` class, resolved once per
/// interpreter. Cached because every failing call needs it.
static HASHSIGS_ERROR: PyOnceLock<Py<PyType>> = PyOnceLock::new();

fn hashsigs_error(py: Python<'_>) -> PyResult<&Py<PyType>> {
    HASHSIGS_ERROR.get_or_try_init(py, || {
        py.import("hashsigs._errors")?
            .getattr("HashSigsError")?
            .cast_into::<PyType>()
            .map(Into::into)
            .map_err(|err| {
                PyRuntimeError::new_err(format!(
                    "hashsigs._errors.HashSigsError is not a class: {err}"
                ))
            })
    })
}

/// Convert a binding-core error into the shared Python exception, carrying the
/// machine-readable code as a `code` attribute.
///
/// The pure-Python package must be importable for this to work. That holds in
/// the built wheel, where the extensions live inside the `hashsigs` package
/// that defines the class. If the import fails, the original error is still
/// reported (as a `RuntimeError` naming both problems) rather than swallowed.
pub fn to_py_err(err: hashsigs_rs::bindings::BindingError) -> PyErr {
    Python::attach(|py| {
        let class = match hashsigs_error(py) {
            Ok(class) => class,
            Err(import_err) => {
                return PyRuntimeError::new_err(format!(
                    "[{}] {} (and hashsigs._errors could not be imported to \
                     raise it properly: {import_err})",
                    err.code, err.message
                ))
            }
        };
        match class.call1(py, (err.message.clone(),)) {
            Ok(instance) => {
                // A failure to attach the code must not hide the error itself,
                // so the code is folded into the message as a fallback.
                if instance.setattr(py, "code", err.code).is_err() {
                    return PyRuntimeError::new_err(format!("[{}] {}", err.code, err.message));
                }
                PyErr::from_value(instance.into_bound(py))
            }
            Err(construct_err) => PyRuntimeError::new_err(format!(
                "[{}] {} (constructing HashSigsError failed: {construct_err})",
                err.code, err.message
            )),
        }
    })
}

/// Emit the complete `#[pymodule]` surface for one profile.
///
/// `$module` is the extension module name, which MUST equal the `[lib] name`
/// of the crate invoking this and the stem of the installed `.so`. `$profile`
/// is the profile type; `$num_chains` and `$num_layers` are that profile's
/// `NUM_WOTS_CHAINS` and `NUM_HYPERTREE_LAYERS` as `usize` array widths.
///
/// Every function takes and returns plain `bytes`. The decomposed key objects
/// callers actually use are built on top in `hashsigs/_api.py`, exactly as
/// `ts/src/api.ts` does for the wasm surface, so the two languages agree on
/// the wire layouts by construction.
///
/// Nothing here mutates its arguments. `bytes` is immutable in Python, so the
/// stateful entry points return the advanced secret key instead of writing
/// through a buffer the way the wasm surface does.
#[macro_export]
macro_rules! python_profile_surface {
    ($module:ident, $profile:ty, $num_chains:expr, $num_layers:expr) => {
        use $crate::pyo3::prelude::*;

        // Bound once as named consts: a const generic argument must be a path,
        // a literal, or a braced block, and a named const is the readable one.
        const PROFILE_NUM_CHAINS: usize = $num_chains;
        const PROFILE_NUM_LAYERS: usize = $num_layers;

        /// The SHRINCS profile name this extension carries, read out of the
        /// compiled profile type rather than assumed from the module name.
        #[pyfunction]
        fn profile_name() -> &'static str {
            <$profile as $crate::hashsigs_rs::profile::Profile>::PROFILE_NAME
        }

        /// The `hashsigs-rs` version this extension was built from.
        #[pyfunction]
        fn version() -> &'static str {
            env!("CARGO_PKG_VERSION")
        }

        /// Derive a SPHINCS+C keypair from a 32-byte seed. Returns the
        /// 128-byte flat secret; the 64-byte public key is its trailing half.
        #[pyfunction]
        fn sphincs_plus_c_keygen(seed: &[u8]) -> PyResult<Vec<u8>> {
            $crate::hashsigs_rs::bindings::sphincs_plus_c_keygen::<$profile, PROFILE_NUM_LAYERS>(
                seed,
            )
            .map(|key| key.to_bytes().to_vec())
            .map_err($crate::to_py_err)
        }

        /// Sign a 32-byte message with a 128-byte SPHINCS+C secret key.
        #[pyfunction]
        fn sphincs_plus_c_sign(message: &[u8], secret_key: &[u8]) -> PyResult<Vec<u8>> {
            $crate::hashsigs_rs::bindings::sphincs_plus_c_sign::<$profile, PROFILE_NUM_LAYERS>(
                message, secret_key,
            )
            .map_err($crate::to_py_err)
        }

        /// Verify a SPHINCS+C signature against a 64-byte `pkSeed || root`
        /// public key. Never raises: bad input is simply `False`.
        #[pyfunction]
        fn sphincs_plus_c_verify(signature: &[u8], message: &[u8], public_key: &[u8]) -> bool {
            $crate::hashsigs_rs::bindings::sphincs_plus_c_verify::<$profile, PROFILE_NUM_CHAINS>(
                signature, message, public_key,
            )
        }

        /// Derive a SHRINCS keypair from a 32-byte seed and a stateful leaf
        /// budget. Returns `(secret_key, public_key, public_key_commitment)`.
        #[pyfunction]
        fn shrincs_keygen(
            seed: &[u8],
            max_signatures: u32,
        ) -> PyResult<(Vec<u8>, Vec<u8>, Vec<u8>)> {
            $crate::hashsigs_rs::bindings::shrincs_keygen::<
                $profile,
                PROFILE_NUM_CHAINS,
                PROFILE_NUM_LAYERS,
            >(seed, max_signatures)
            .map(|(signing_key, public_key)| {
                (
                    $crate::hashsigs_rs::bindings::serialize_shrincs_signing_key(&signing_key),
                    $crate::hashsigs_rs::bindings::encode_public_key_flat(&public_key),
                    public_key.public_key_commitment.clone(),
                )
            })
            .map_err($crate::to_py_err)
        }

        /// Revalidate a persisted 264-byte secret key against its own seeds.
        /// Returns `(secret_key, public_key, public_key_commitment)`.
        #[pyfunction]
        fn shrincs_import_signing_key(secret_key: &[u8]) -> PyResult<(Vec<u8>, Vec<u8>, Vec<u8>)> {
            $crate::hashsigs_rs::bindings::import_secret_key::<
                $profile,
                PROFILE_NUM_CHAINS,
                PROFILE_NUM_LAYERS,
            >(secret_key)
            .map(|(signing_key, public_key)| {
                (
                    $crate::hashsigs_rs::bindings::serialize_shrincs_signing_key(&signing_key),
                    $crate::hashsigs_rs::bindings::encode_public_key_flat(&public_key),
                    public_key.public_key_commitment.clone(),
                )
            })
            .map_err($crate::to_py_err)
        }

        /// Sign a 32-byte message with the next unused stateful leaf.
        ///
        /// Returns `(signature, advanced_secret_key)`. The caller MUST persist
        /// the returned secret key: signing again from the one passed in
        /// reuses a leaf, which breaks the one-time-signature guarantee the
        /// stateful path rests on. `bytes` is immutable, so unlike the wasm
        /// surface this cannot advance the caller's buffer in place.
        #[pyfunction]
        fn shrincs_sign(message: &[u8], secret_key: &[u8]) -> PyResult<(Vec<u8>, Vec<u8>)> {
            let mut advanced = secret_key.to_vec();
            let signature = $crate::hashsigs_rs::bindings::shrincs_sign::<
                $profile,
                PROFILE_NUM_CHAINS,
                PROFILE_NUM_LAYERS,
            >(message, &mut advanced)
            .map_err($crate::to_py_err)?;
            Ok((signature, advanced))
        }

        /// Sign a 32-byte message on the stateless recovery path. Consumes no
        /// leaf, so there is no advanced key to return.
        #[pyfunction]
        fn shrincs_sign_stateless(message: &[u8], secret_key: &[u8]) -> PyResult<Vec<u8>> {
            $crate::hashsigs_rs::bindings::shrincs_sign_stateless::<
                $profile,
                PROFILE_NUM_CHAINS,
                PROFILE_NUM_LAYERS,
            >(message, secret_key)
            .map_err($crate::to_py_err)
        }

        /// Verify a stateful signature against a 32-byte commitment. Never
        /// raises: a malformed envelope or a mismatch is simply `False`.
        #[pyfunction]
        fn shrincs_verify(signature: &[u8], message: &[u8], public_key_commitment: &[u8]) -> bool {
            $crate::hashsigs_rs::bindings::shrincs_verify::<$profile, PROFILE_NUM_CHAINS>(
                signature,
                message,
                public_key_commitment,
            )
        }

        /// Verify a stateless signature against the 64-byte stateless public
        /// key. A stateless SHRINCS signature is a SPHINCS+C signature, so
        /// this is `sphincs_plus_c_verify`.
        #[pyfunction]
        fn shrincs_verify_stateless(
            signature: &[u8],
            message: &[u8],
            stateless_public_key: &[u8],
        ) -> bool {
            sphincs_plus_c_verify(signature, message, stateless_public_key)
        }

        /// Start a fresh stateful chain from `new_seed`, leaving the stateless
        /// half and `max_signatures` untouched. Returns the new secret key.
        #[pyfunction]
        fn shrincs_reset(secret_key: &[u8], new_seed: &[u8]) -> PyResult<Vec<u8>> {
            let mut updated = secret_key.to_vec();
            $crate::hashsigs_rs::bindings::shrincs_reset::<
                $profile,
                PROFILE_NUM_CHAINS,
                PROFILE_NUM_LAYERS,
            >(&mut updated, new_seed)
            .map_err($crate::to_py_err)?;
            Ok(updated)
        }

        /// Recompute the 32-byte commitment a secret key currently implies.
        #[pyfunction]
        fn shrincs_compute_public_key_commitment(secret_key: &[u8]) -> PyResult<Vec<u8>> {
            $crate::hashsigs_rs::bindings::shrincs_compute_public_key_commitment::<
                $profile,
                PROFILE_NUM_CHAINS,
                PROFILE_NUM_LAYERS,
            >(secret_key)
            .map_err($crate::to_py_err)
        }

        /// Recover the 32-byte commitment a stateful signature implies, from
        /// the public key the envelope carries.
        #[pyfunction]
        fn shrincs_recover_public_key_commitment(signature: &[u8]) -> PyResult<Vec<u8>> {
            $crate::hashsigs_rs::bindings::shrincs_recover_public_key_commitment::<$profile>(
                signature,
            )
            .map_err($crate::to_py_err)
        }

        // The init function's name IS the module name PyO3 registers, and
        // CPython will only import an extension whose init symbol matches the
        // file stem. That is why `$module` must equal the crate's `[lib] name`.
        #[pymodule]
        fn $module(module: &Bound<'_, PyModule>) -> PyResult<()> {
            module.add_function(wrap_pyfunction!(profile_name, module)?)?;
            module.add_function(wrap_pyfunction!(version, module)?)?;
            module.add_function(wrap_pyfunction!(sphincs_plus_c_keygen, module)?)?;
            module.add_function(wrap_pyfunction!(sphincs_plus_c_sign, module)?)?;
            module.add_function(wrap_pyfunction!(sphincs_plus_c_verify, module)?)?;
            module.add_function(wrap_pyfunction!(shrincs_keygen, module)?)?;
            module.add_function(wrap_pyfunction!(shrincs_import_signing_key, module)?)?;
            module.add_function(wrap_pyfunction!(shrincs_sign, module)?)?;
            module.add_function(wrap_pyfunction!(shrincs_sign_stateless, module)?)?;
            module.add_function(wrap_pyfunction!(shrincs_verify, module)?)?;
            module.add_function(wrap_pyfunction!(shrincs_verify_stateless, module)?)?;
            module.add_function(wrap_pyfunction!(shrincs_reset, module)?)?;
            module.add_function(wrap_pyfunction!(
                shrincs_compute_public_key_commitment,
                module
            )?)?;
            module.add_function(wrap_pyfunction!(
                shrincs_recover_public_key_commitment,
                module
            )?)?;
            module.add(
                "MAX_STATEFUL_SIGNATURES",
                $crate::hashsigs_rs::bindings::MAX_STATEFUL_SIGNATURES_LIMIT,
            )?;
            Ok(())
        }
    };
}
