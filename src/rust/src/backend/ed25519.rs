// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use crate::backend::utils;
use crate::buf::CffiBuf;
use crate::error::{CryptographyError, CryptographyResult};
use crate::exceptions;

#[cfg(CRYPTOGRAPHY_OPENSSL_320_OR_GREATER)]
use foreign_types_shared::ForeignType;
#[cfg(CRYPTOGRAPHY_OPENSSL_320_OR_GREATER)]
use openssl_sys as ffi;
#[cfg(CRYPTOGRAPHY_OPENSSL_320_OR_GREATER)]
use std::ptr;

// RAII guard for EVP_MD_CTX to ensure cleanup in all code paths.
#[cfg(CRYPTOGRAPHY_OPENSSL_320_OR_GREATER)]
struct EvpMdCtxGuard(*mut ffi::EVP_MD_CTX);

#[cfg(CRYPTOGRAPHY_OPENSSL_320_OR_GREATER)]
impl Drop for EvpMdCtxGuard {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: self.0 is a valid EVP_MD_CTX pointer (null-checked above).
            // EVP_MD_CTX_free is safe to call on a valid context.
            unsafe {
                ffi::EVP_MD_CTX_free(self.0);
            }
        }
    }
}

// RAII guard for OSSL_PARAM_BLD to ensure cleanup in all code paths.
#[cfg(CRYPTOGRAPHY_OPENSSL_320_OR_GREATER)]
struct OsslParamBldGuard(*mut ffi::OSSL_PARAM_BLD);

#[cfg(CRYPTOGRAPHY_OPENSSL_320_OR_GREATER)]
impl Drop for OsslParamBldGuard {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: self.0 is a valid OSSL_PARAM_BLD pointer (null-checked above).
            // OSSL_PARAM_BLD_free is safe to call on a valid builder.
            unsafe {
                ffi::OSSL_PARAM_BLD_free(self.0);
            }
        }
    }
}

// RAII guard for OSSL_PARAM to ensure cleanup in all code paths.
#[cfg(CRYPTOGRAPHY_OPENSSL_320_OR_GREATER)]
struct OsslParamGuard(*mut ffi::OSSL_PARAM);

#[cfg(CRYPTOGRAPHY_OPENSSL_320_OR_GREATER)]
impl Drop for OsslParamGuard {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: self.0 is a valid OSSL_PARAM pointer (null-checked above).
            // OSSL_PARAM_free is safe to call on a valid param array.
            unsafe {
                ffi::OSSL_PARAM_free(self.0);
            }
        }
    }
}

#[pyo3::pyclass(frozen, module = "cryptography.hazmat.bindings._rust.openssl.ed25519")]
pub(crate) struct Ed25519PrivateKey {
    pkey: openssl::pkey::PKey<openssl::pkey::Private>,
}

#[pyo3::pyclass(frozen, module = "cryptography.hazmat.bindings._rust.openssl.ed25519")]
pub(crate) struct Ed25519PublicKey {
    pkey: openssl::pkey::PKey<openssl::pkey::Public>,
}

#[pyo3::pyfunction]
fn generate_key() -> CryptographyResult<Ed25519PrivateKey> {
    Ok(Ed25519PrivateKey {
        pkey: openssl::pkey::PKey::generate_ed25519()?,
    })
}

pub(crate) fn private_key_from_pkey(
    pkey: &openssl::pkey::PKeyRef<openssl::pkey::Private>,
) -> Ed25519PrivateKey {
    Ed25519PrivateKey {
        pkey: pkey.to_owned(),
    }
}

pub(crate) fn public_key_from_pkey(
    pkey: &openssl::pkey::PKeyRef<openssl::pkey::Public>,
) -> Ed25519PublicKey {
    Ed25519PublicKey {
        pkey: pkey.to_owned(),
    }
}

#[pyo3::pyfunction]
fn from_private_bytes(data: CffiBuf<'_>) -> pyo3::PyResult<Ed25519PrivateKey> {
    let pkey = openssl::pkey::PKey::private_key_from_raw_bytes(
        data.as_bytes(),
        openssl::pkey::Id::ED25519,
    )
    .map_err(|_| {
        pyo3::exceptions::PyValueError::new_err("An Ed25519 private key is 32 bytes long")
    })?;
    Ok(Ed25519PrivateKey { pkey })
}

#[pyo3::pyfunction]
fn from_public_bytes(data: &[u8]) -> pyo3::PyResult<Ed25519PublicKey> {
    let pkey = openssl::pkey::PKey::public_key_from_raw_bytes(data, openssl::pkey::Id::ED25519)
        .map_err(|_| {
            pyo3::exceptions::PyValueError::new_err("An Ed25519 public key is 32 bytes long")
        })?;
    Ok(Ed25519PublicKey { pkey })
}

/// Build OSSL_PARAM array for Ed25519ph with optional context string.
///
/// Returns RAII guards for both the builder and the built params. The caller
/// must keep both guards alive until the params are no longer needed.
#[cfg(CRYPTOGRAPHY_OPENSSL_320_OR_GREATER)]
fn build_ed25519ph_params(
    context: Option<&[u8]>,
) -> CryptographyResult<(OsslParamBldGuard, OsslParamGuard)> {
    // SAFETY: All FFI calls check return values. OSSL_PARAM_BLD and OSSL_PARAM
    // are wrapped in RAII guards for cleanup in all code paths.
    unsafe {
        let bld = ffi::OSSL_PARAM_BLD_new();
        if bld.is_null() {
            return Err(openssl::error::ErrorStack::get().into());
        }
        let bld_guard = OsslParamBldGuard(bld);

        // Set the instance to "Ed25519ph" (prehashed mode).
        if ffi::OSSL_PARAM_BLD_push_utf8_string(
            bld,
            b"instance\0".as_ptr().cast(),
            b"Ed25519ph\0".as_ptr().cast(),
            0,
        ) != 1
        {
            return Err(openssl::error::ErrorStack::get().into());
        }

        // Set the optional context string if provided.
        if let Some(ctx_bytes) = context {
            if ffi::OSSL_PARAM_BLD_push_octet_string(
                bld,
                b"context-string\0".as_ptr().cast(),
                ctx_bytes.as_ptr().cast(),
                ctx_bytes.len(),
            ) != 1
            {
                return Err(openssl::error::ErrorStack::get().into());
            }
        }

        let params = ffi::OSSL_PARAM_BLD_to_param(bld);
        if params.is_null() {
            return Err(openssl::error::ErrorStack::get().into());
        }
        let params_guard = OsslParamGuard(params);

        Ok((bld_guard, params_guard))
    }
}

#[pyo3::pymethods]
impl Ed25519PrivateKey {
    fn sign<'p>(
        &self,
        py: pyo3::Python<'p>,
        data: CffiBuf<'_>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        let mut signer = openssl::sign::Signer::new_without_digest(&self.pkey)?;
        let len = signer.len()?;
        Ok(pyo3::types::PyBytes::new_with(py, len, |b| {
            let n = signer
                .sign_oneshot(b, data.as_bytes())
                .map_err(CryptographyError::from)?;
            assert_eq!(n, b.len());
            Ok(())
        })?)
    }

    #[cfg(CRYPTOGRAPHY_OPENSSL_320_OR_GREATER)]
    #[pyo3(signature = (data, context=None))]
    fn sign_prehashed<'p>(
        &self,
        py: pyo3::Python<'p>,
        data: CffiBuf<'_>,
        context: Option<CffiBuf<'_>>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        let ctx_bytes = context.as_ref().map(|c| c.as_bytes());

        // RFC 8032 limits the context string to 255 bytes.
        if let Some(ctx) = ctx_bytes {
            if ctx.len() > 255 {
                return Err(CryptographyError::from(
                    pyo3::exceptions::PyValueError::new_err(
                        "Context must be at most 255 bytes long",
                    ),
                ));
            }
        }

        // SAFETY: md_ctx is valid (null-checked). pkey_ptr borrows self.pkey which
        // outlives this block. All FFI calls check return values. Resources are
        // protected by RAII guards (_md_ctx_guard, _bld_guard, params_guard).
        unsafe {
            // Create message digest context.
            let md_ctx = ffi::EVP_MD_CTX_new();
            if md_ctx.is_null() {
                return Err(openssl::error::ErrorStack::get().into());
            }
            let _md_ctx_guard = EvpMdCtxGuard(md_ctx);

            // Initialize the digest sign operation. For Ed25519, the digest
            // and engine are NULL since the algorithm handles its own hashing.
            let mut pctx: *mut ffi::EVP_PKEY_CTX = ptr::null_mut();
            let pkey_ptr = self.pkey.as_ptr();
            if ffi::EVP_DigestSignInit(
                md_ctx,
                &mut pctx,
                ptr::null(),
                ptr::null_mut(),
                pkey_ptr,
            ) != 1
            {
                return Err(openssl::error::ErrorStack::get().into());
            }

            // Build and set Ed25519ph parameters.
            let (_bld_guard, params_guard) = build_ed25519ph_params(ctx_bytes)?;
            if ffi::EVP_PKEY_CTX_set_params(pctx, params_guard.0) != 1 {
                return Err(openssl::error::ErrorStack::get().into());
            }

            // First call to determine the signature length.
            let data_bytes = data.as_bytes();
            let mut sig_len: usize = 0;
            if ffi::EVP_DigestSign(
                md_ctx,
                ptr::null_mut(),
                &mut sig_len,
                data_bytes.as_ptr(),
                data_bytes.len(),
            ) != 1
            {
                return Err(openssl::error::ErrorStack::get().into());
            }

            // Second call to produce the actual signature.
            Ok(pyo3::types::PyBytes::new_with(py, sig_len, |sig_buf| {
                let mut actual_len = sig_len;
                if ffi::EVP_DigestSign(
                    md_ctx,
                    sig_buf.as_mut_ptr(),
                    &mut actual_len,
                    data_bytes.as_ptr(),
                    data_bytes.len(),
                ) != 1
                {
                    return Err(CryptographyError::from(
                        openssl::error::ErrorStack::get(),
                    )
                    .into());
                }
                assert_eq!(actual_len, sig_buf.len());
                Ok(())
            })?)
        }
    }

    #[cfg(not(CRYPTOGRAPHY_OPENSSL_320_OR_GREATER))]
    #[pyo3(signature = (data, context=None))]
    #[allow(unused_variables)]
    fn sign_prehashed<'p>(
        &self,
        py: pyo3::Python<'p>,
        data: CffiBuf<'_>,
        context: Option<CffiBuf<'_>>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        Err(CryptographyError::from(
            exceptions::UnsupportedAlgorithm::new_err((
                "Ed25519ph requires OpenSSL 3.2+",
                exceptions::Reasons::UNSUPPORTED_PUBLIC_KEY_ALGORITHM,
            )),
        ))
    }

    fn public_key(&self) -> CryptographyResult<Ed25519PublicKey> {
        let raw_bytes = self.pkey.raw_public_key()?;
        Ok(Ed25519PublicKey {
            pkey: openssl::pkey::PKey::public_key_from_raw_bytes(
                &raw_bytes,
                openssl::pkey::Id::ED25519,
            )?,
        })
    }

    fn private_bytes_raw<'p>(
        &self,
        py: pyo3::Python<'p>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        let raw_bytes = self.pkey.raw_private_key()?;
        Ok(pyo3::types::PyBytes::new(py, &raw_bytes))
    }

    fn private_bytes<'p>(
        slf: &pyo3::Bound<'p, Self>,
        py: pyo3::Python<'p>,
        encoding: crate::serialization::Encoding,
        format: crate::serialization::PrivateFormat,
        encryption_algorithm: &pyo3::Bound<'p, pyo3::PyAny>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        utils::pkey_private_bytes(
            py,
            slf,
            &slf.borrow().pkey,
            encoding,
            format,
            encryption_algorithm,
            true,
            true,
        )
    }

    fn __copy__(slf: pyo3::PyRef<'_, Self>) -> pyo3::PyRef<'_, Self> {
        slf
    }

    fn __deepcopy__<'p>(
        slf: pyo3::PyRef<'p, Self>,
        _memo: &pyo3::Bound<'p, pyo3::PyAny>,
    ) -> pyo3::PyRef<'p, Self> {
        slf
    }
}

#[pyo3::pymethods]
impl Ed25519PublicKey {
    fn verify(&self, signature: CffiBuf<'_>, data: CffiBuf<'_>) -> CryptographyResult<()> {
        let valid = openssl::sign::Verifier::new_without_digest(&self.pkey)?
            .verify_oneshot(signature.as_bytes(), data.as_bytes())
            .unwrap_or(false);

        if !valid {
            return Err(CryptographyError::from(
                exceptions::InvalidSignature::new_err(()),
            ));
        }

        Ok(())
    }

    #[cfg(CRYPTOGRAPHY_OPENSSL_320_OR_GREATER)]
    #[pyo3(signature = (signature, data, context=None))]
    fn verify_prehashed(
        &self,
        signature: CffiBuf<'_>,
        data: CffiBuf<'_>,
        context: Option<CffiBuf<'_>>,
    ) -> CryptographyResult<()> {
        let ctx_bytes = context.as_ref().map(|c| c.as_bytes());

        // RFC 8032 limits the context string to 255 bytes.
        if let Some(ctx) = ctx_bytes {
            if ctx.len() > 255 {
                return Err(CryptographyError::from(
                    pyo3::exceptions::PyValueError::new_err(
                        "Context must be at most 255 bytes long",
                    ),
                ));
            }
        }

        // SAFETY: md_ctx is valid (null-checked). pkey_ptr borrows self.pkey which
        // outlives this block. All FFI calls check return values. Resources are
        // protected by RAII guards (_md_ctx_guard, _bld_guard, params_guard).
        unsafe {
            // Create message digest context.
            let md_ctx = ffi::EVP_MD_CTX_new();
            if md_ctx.is_null() {
                return Err(openssl::error::ErrorStack::get().into());
            }
            let _md_ctx_guard = EvpMdCtxGuard(md_ctx);

            // Initialize the digest verify operation. For Ed25519, the digest
            // and engine are NULL since the algorithm handles its own hashing.
            let mut pctx: *mut ffi::EVP_PKEY_CTX = ptr::null_mut();
            let pkey_ptr = self.pkey.as_ptr();
            if ffi::EVP_DigestVerifyInit(
                md_ctx,
                &mut pctx,
                ptr::null(),
                ptr::null_mut(),
                pkey_ptr,
            ) != 1
            {
                return Err(openssl::error::ErrorStack::get().into());
            }

            // Build and set Ed25519ph parameters.
            let (_bld_guard, params_guard) = build_ed25519ph_params(ctx_bytes)?;
            if ffi::EVP_PKEY_CTX_set_params(pctx, params_guard.0) != 1 {
                return Err(openssl::error::ErrorStack::get().into());
            }

            // Verify the signature.
            let sig_bytes = signature.as_bytes();
            let data_bytes = data.as_bytes();
            let rc = ffi::EVP_DigestVerify(
                md_ctx,
                sig_bytes.as_ptr(),
                sig_bytes.len(),
                data_bytes.as_ptr(),
                data_bytes.len(),
            );

            if rc != 1 {
                // Clear the OpenSSL error stack so it doesn't leak into
                // subsequent operations, then return our InvalidSignature.
                let _ = openssl::error::ErrorStack::get();
                return Err(CryptographyError::from(
                    exceptions::InvalidSignature::new_err(()),
                ));
            }
        }

        Ok(())
    }

    #[cfg(not(CRYPTOGRAPHY_OPENSSL_320_OR_GREATER))]
    #[pyo3(signature = (signature, data, context=None))]
    #[allow(unused_variables)]
    fn verify_prehashed(
        &self,
        signature: CffiBuf<'_>,
        data: CffiBuf<'_>,
        context: Option<CffiBuf<'_>>,
    ) -> CryptographyResult<()> {
        Err(CryptographyError::from(
            exceptions::UnsupportedAlgorithm::new_err((
                "Ed25519ph requires OpenSSL 3.2+",
                exceptions::Reasons::UNSUPPORTED_PUBLIC_KEY_ALGORITHM,
            )),
        ))
    }

    fn public_bytes_raw<'p>(
        &self,
        py: pyo3::Python<'p>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        let raw_bytes = self.pkey.raw_public_key()?;
        Ok(pyo3::types::PyBytes::new(py, &raw_bytes))
    }

    fn public_bytes<'p>(
        slf: &pyo3::Bound<'p, Self>,
        py: pyo3::Python<'p>,
        encoding: crate::serialization::Encoding,
        format: crate::serialization::PublicFormat,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        utils::pkey_public_bytes(py, slf, &slf.borrow().pkey, encoding, format, true, true)
    }

    fn __eq__(&self, other: pyo3::PyRef<'_, Self>) -> bool {
        self.pkey.public_eq(&other.pkey)
    }

    fn __copy__(slf: pyo3::PyRef<'_, Self>) -> pyo3::PyRef<'_, Self> {
        slf
    }

    fn __deepcopy__<'p>(
        slf: pyo3::PyRef<'p, Self>,
        _memo: &pyo3::Bound<'p, pyo3::PyAny>,
    ) -> pyo3::PyRef<'p, Self> {
        slf
    }
}

#[pyo3::pymodule(gil_used = false)]
pub(crate) mod ed25519 {
    #[pymodule_export]
    use super::{
        from_private_bytes, from_public_bytes, generate_key, Ed25519PrivateKey, Ed25519PublicKey,
    };
}
