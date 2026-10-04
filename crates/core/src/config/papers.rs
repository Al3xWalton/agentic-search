//! Loads trusted operator configuration and private credentials without source-bearing errors.
//! Paths resolve against the startup working directory; rotation requires a restart.

#![deny(missing_docs)]

use crate::api::v1::scholarly::{self, PaperProvider, PaperProviderError};
use serde::{Deserialize, Serialize};
use std::{
    fmt,
    fs::File,
    io::Read,
    path::{Path, PathBuf},
    sync::Arc,
};

/// Inclusive complete API configuration limit, in UTF-8 bytes.
const MAX_API_CONFIG_BYTES: usize = 1_048_576;
/// Inclusive OpenAlex credential limit after removing at most one terminal LF, in bytes.
const MAX_OPENALEX_KEY_BYTES: usize = 1_024;
/// Exact lowercase hexadecimal HTTP bearer length, in ASCII bytes.
const HTTP_BEARER_BYTES: usize = 64;

/// Closed startup selection; serialized configuration contains no credential material.
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum PaperProviderConfig {
    /// Queries the fixed OpenAlex works endpoint with an operator-owned credential.
    Openalex {
        /// Single-link, owned mode-0600 regular file; relative to startup working directory.
        api_key_file: PathBuf,
    },
    /// Queries an explicitly selected service implementing the scholar v1 wire protocol.
    Http {
        /// Complete HTTPS search URL, or literal-loopback HTTP URL, ending in /v1/search.
        endpoint: String,
        /// Owned mode-0600 file containing exactly 64 lowercase hexadecimal bytes, optional LF.
        bearer_token_file: PathBuf,
    },
}

impl fmt::Debug for PaperProviderConfig {
    // Neither configured destinations nor secret paths belong in diagnostics.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PaperProviderConfig { .. }")
    }
}

/// Startup credential with deliberately opaque formatting and no serialization or public getter.
pub(crate) struct Secret(String);

impl fmt::Debug for Secret {
    // Dependency formatting must not accidentally disclose authentication material.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret { .. }")
    }
}

impl fmt::Display for Secret {
    // Display follows the same closed diagnostic policy as Debug.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret { .. }")
    }
}

impl Secret {
    /// Builds one sensitive header, never a URL; errors discard the underlying bytes.
    pub(crate) fn header(&self) -> Result<reqwest::header::HeaderValue, PaperProviderError> {
        let mut value = reqwest::header::HeaderValue::from_str(&format!("Bearer {}", self.0))
            .map_err(|_| PaperProviderError::Configuration)?;
        value.set_sensitive(true);
        Ok(value)
    }
}

impl PaperProviderConfig {
    /// Loads a credential once and builds a network-idle provider.
    /// Returns only Configuration on invalid files, endpoints or client settings; never logs input.
    pub fn build(&self) -> Result<Arc<dyn PaperProvider>, PaperProviderError> {
        match self {
            Self::Openalex { api_key_file } => {
                let secret = load_secret(api_key_file, false)?;
                scholarly::build_openalex(secret)
            }
            Self::Http {
                endpoint,
                bearer_token_file,
            } => {
                let secret = load_secret(bearer_token_file, true)?;
                scholarly::build_http(endpoint, secret)
            }
        }
    }
}

/// Reads at most 1 MiB of regular-file API TOML, then validates local listener budgets.
/// Returns Configuration without paths, source excerpts or error chains on any failure.
pub fn read_api_config(path: &Path) -> Result<super::ApiConfig, PaperProviderError> {
    let file = regular_file(path, false)?;
    let bytes = read_bounded(file, MAX_API_CONFIG_BYTES)?;
    let text = std::str::from_utf8(&bytes).map_err(|_| PaperProviderError::Configuration)?;
    let config: super::ApiConfig =
        toml::from_str(text).map_err(|_| PaperProviderError::Configuration)?;
    config
        .v1
        .validate(&[config.host, config.prometheus_host, config.management_host])
        .map_err(|_| PaperProviderError::Configuration)?;
    Ok(config)
}

// Validate and read the same descriptor so a pathname replacement cannot change the credential.
fn load_secret(path: &Path, hex: bool) -> Result<Secret, PaperProviderError> {
    let cap = if hex {
        HTTP_BEARER_BYTES
    } else {
        MAX_OPENALEX_KEY_BYTES
    };
    let mut bytes = read_bounded(regular_file(path, true)?, cap + 1)?;
    if bytes.last() == Some(&b'\n') {
        bytes.pop();
    }
    if bytes.is_empty() || bytes.len() > cap || !bytes.iter().all(|b| (33..=126).contains(b)) {
        return Err(PaperProviderError::Configuration);
    }
    if hex
        && (bytes.len() != HTTP_BEARER_BYTES
            || !bytes
                .iter()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b)))
    {
        return Err(PaperProviderError::Configuration);
    }
    String::from_utf8(bytes)
        .map(Secret)
        .map_err(|_| PaperProviderError::Configuration)
}

// Nonblocking descriptor inspection refuses FIFOs and devices before attempting any read.
#[cfg(unix)]
fn regular_file(path: &Path, private: bool) -> Result<File, PaperProviderError> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let nofollow = if private { libc::O_NOFOLLOW } else { 0 };
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(nofollow | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| PaperProviderError::Configuration)?;
    let metadata = file
        .metadata()
        .map_err(|_| PaperProviderError::Configuration)?;
    // geteuid has no preconditions and returns the effective owner used for access checks.
    let owner = unsafe { libc::geteuid() };
    let uid = metadata.uid();
    #[cfg(test)]
    let uid = PAPER_OWNER.with(|injected| match injected.get() {
        Some(value) => value,
        None => uid,
    });
    if !metadata.is_file()
        || (private && (uid != owner || metadata.mode() & 0o7777 != 0o600 || metadata.nlink() != 1))
    {
        return Err(PaperProviderError::Configuration);
    }
    Ok(file)
}

// Platforms without these descriptor semantics cannot silently use a weaker credential loader.
#[cfg(not(unix))]
fn regular_file(_path: &Path, _private: bool) -> Result<File, PaperProviderError> {
    Err(PaperProviderError::Configuration)
}

// Read one extra byte to distinguish an exact cap from a hidden trailing payload.
fn read_bounded(file: File, cap: usize) -> Result<Vec<u8>, PaperProviderError> {
    let mut bytes = Vec::new();
    file.take((cap + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| PaperProviderError::Configuration)?;
    if bytes.len() > cap {
        return Err(PaperProviderError::Configuration);
    }
    Ok(bytes)
}

#[cfg(test)]
thread_local! {
    /// Injects only the observed descriptor UID before the ordinary validator.
    pub(crate) static PAPER_OWNER: std::cell::Cell<Option<u32>> = const {
        std::cell::Cell::new(None)
    };
}

/// Gives internal witnesses the actual secret wrapper without exporting credential access.
#[cfg(test)]
pub(crate) fn test_secret(path: &Path, http: bool) -> Result<Secret, PaperProviderError> {
    load_secret(path, http)
}
