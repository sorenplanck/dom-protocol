//! Atomic idempotency cache keyed by Kaystra effect/request nonce.

use std::{fs, io::Write, path::{Path, PathBuf}};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::wire::BuildSweepResponseV2;

#[derive(Debug, thiserror::Error)]
pub enum CacheError {
    #[error("cache unavailable")]
    Unavailable,
    #[error("request nonce replayed with different bytes")]
    Conflict,
    #[error("cache entry corrupt")]
    Corrupt,
}

#[derive(Serialize, Deserialize)]
struct Entry {
    request_hash: [u8; 32],
    response: BuildSweepResponseV2,
}

#[derive(Debug, Clone)]
pub struct SweepCache { directory: PathBuf }

impl SweepCache {
    pub fn open(directory: impl AsRef<Path>) -> Result<Self, CacheError> {
        fs::create_dir_all(directory.as_ref()).map_err(|_| CacheError::Unavailable)?;
        Ok(Self { directory: directory.as_ref().to_owned() })
    }

    pub fn request_hash(canonical_request: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"DOM-INTEROP/XMR-SIDECAR-REQUEST/V2\0");
        hasher.update((canonical_request.len() as u64).to_be_bytes());
        hasher.update(canonical_request);
        hasher.finalize().into()
    }

    pub fn load(
        &self,
        nonce: &[u8; 32],
        request_hash: &[u8; 32],
    ) -> Result<Option<BuildSweepResponseV2>, CacheError> {
        let path = self.path(nonce);
        let bytes = match fs::read(path) {
            Ok(value) => value,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(CacheError::Unavailable),
        };
        let entry: Entry = serde_json::from_slice(&bytes).map_err(|_| CacheError::Corrupt)?;
        if &entry.request_hash != request_hash { return Err(CacheError::Conflict); }
        if &entry.response.request_nonce != nonce || entry.response.raw_tx.is_empty() {
            return Err(CacheError::Corrupt);
        }
        Ok(Some(entry.response))
    }

    pub fn store(
        &self,
        nonce: &[u8; 32],
        request_hash: [u8; 32],
        response: &BuildSweepResponseV2,
    ) -> Result<(), CacheError> {
        if &response.request_nonce != nonce || response.raw_tx.is_empty() {
            return Err(CacheError::Corrupt);
        }
        let final_path = self.path(nonce);
        if final_path.exists() {
            return match self.load(nonce, &request_hash)? {
                Some(existing) if existing == *response => Ok(()),
                _ => Err(CacheError::Conflict),
            };
        }
        let entry = Entry { request_hash, response: response.clone() };
        let bytes = serde_json::to_vec(&entry).map_err(|_| CacheError::Corrupt)?;
        let temporary = final_path.with_extension(format!("tmp-{}", std::process::id()));
        {
            let mut file = fs::OpenOptions::new().write(true).create_new(true)
                .open(&temporary).map_err(|_| CacheError::Unavailable)?;
            file.write_all(&bytes).map_err(|_| CacheError::Unavailable)?;
            file.sync_all().map_err(|_| CacheError::Unavailable)?;
        }
        fs::rename(&temporary, &final_path).map_err(|_| CacheError::Unavailable)?;
        if let Ok(directory) = fs::File::open(&self.directory) { let _ = directory.sync_all(); }
        Ok(())
    }

    fn path(&self, nonce: &[u8; 32]) -> PathBuf {
        self.directory.join(format!("{}.json", hex::encode(nonce)))
    }
}
