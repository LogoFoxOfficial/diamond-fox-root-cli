use crate::model::{AssetLocation, PackageAsset, PackageManifest, SupportPackage};
use crate::package::{self, sha256_file};
use crate::state::AppDirs;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering, compiler_fence};

#[cfg(windows)]
use std::os::windows::fs::OpenOptionsExt;

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

pub struct GeneratedHostFile {
    pub name: &'static str,
    pub bytes: &'static [u8],
    pub sha256: &'static str,
}

pub struct GeneratedAsset {
    pub role: &'static str,
    pub ciphertext: &'static [u8],
    pub nonce: [u8; 16],
    pub tag: [u8; 32],
}

pub struct GeneratedPackage {
    pub manifest_json: &'static str,
    pub assets: Vec<GeneratedAsset>,
}

include!(concat!(env!("OUT_DIR"), "/builtins.rs"));

pub fn built_in_packages() -> Result<Vec<SupportPackage>, String> {
    generated_packages()
        .into_iter()
        .map(|generated| {
            let manifest: PackageManifest = serde_json::from_str(generated.manifest_json)
                .map_err(|error| format!("invalid embedded manifest: {error}"))?;
            package::validate_manifest(&manifest)?;
            let mut assets = Vec::with_capacity(manifest.assets.len());
            for spec in &manifest.assets {
                let embedded = generated
                    .assets
                    .iter()
                    .find(|asset| asset.role == spec.role)
                    .ok_or_else(|| format!("embedded asset missing: {}", spec.role))?;
                assets.push(PackageAsset {
                    spec: spec.clone(),
                    location: AssetLocation::Protected {
                        ciphertext: embedded.ciphertext,
                        nonce: embedded.nonce,
                        tag: embedded.tag,
                    },
                });
            }
            Ok(SupportPackage {
                manifest,
                assets,
                package_sha256: "EMBEDDED".into(),
            })
        })
        .collect()
}

pub fn available_packages(dirs: &AppDirs) -> Result<Vec<SupportPackage>, String> {
    let mut packages = built_in_packages()?;
    let built_in_ids: HashSet<_> = packages
        .iter()
        .map(|package| package.manifest.id.clone())
        .collect();
    for installed in package::list_installed(dirs) {
        let installed = installed?;
        if !built_in_ids.contains(&installed.manifest.id) {
            packages.push(installed);
        }
    }
    Ok(packages)
}

pub fn read_asset(asset: &PackageAsset) -> Result<Vec<u8>, String> {
    let bytes = match &asset.location {
        AssetLocation::File(path) => fs::read(path)
            .map_err(|error| format!("read registered asset {}: {error}", path.display()))?,
        AssetLocation::Protected {
            ciphertext,
            nonce,
            tag,
        } => {
            let mut key = embed_key();
            if !constant_time_eq(&auth_tag(&key, nonce, ciphertext), tag) {
                secure_clear(&mut key);
                return Err(format!(
                    "embedded {} authentication failed",
                    asset.spec.role
                ));
            }
            let plaintext = crypt(&key, nonce, ciphertext);
            secure_clear(&mut key);
            plaintext
        }
    };
    let actual = hex::encode_upper(Sha256::digest(&bytes));
    if !actual.eq_ignore_ascii_case(&asset.spec.sha256) {
        return Err(format!("{} asset hash mismatch", asset.spec.role));
    }
    Ok(bytes)
}

pub fn verify_embedded() -> Result<(), String> {
    for file in HOST_FILES {
        let actual = hex::encode_upper(Sha256::digest(file.bytes));
        if !actual.eq_ignore_ascii_case(file.sha256) {
            return Err(format!("embedded {} hash mismatch", file.name));
        }
    }
    for package in built_in_packages()? {
        for asset in &package.assets {
            let mut plaintext = read_asset(asset)?;
            secure_clear(&mut plaintext);
        }
    }
    Ok(())
}

pub fn ensure_embedded_adb(dirs: &AppDirs) -> Result<Option<PathBuf>, String> {
    if HOST_FILES.is_empty() {
        return Ok(None);
    }
    let directory = dirs.cache.join("platform-tools");
    fs::create_dir_all(&directory)
        .map_err(|error| format!("create {}: {error}", directory.display()))?;
    for file in HOST_FILES {
        let path = directory.join(file.name);
        if path.is_file() && sha256_file(&path)?.eq_ignore_ascii_case(file.sha256) {
            continue;
        }
        let temporary = path.with_extension(format!("tmp-{}", std::process::id()));
        fs::write(&temporary, file.bytes)
            .map_err(|error| format!("write {}: {error}", temporary.display()))?;
        if !sha256_file(&temporary)?.eq_ignore_ascii_case(file.sha256) {
            let _ = fs::remove_file(&temporary);
            return Err(format!("embedded {} write verification failed", file.name));
        }
        if path.exists() {
            fs::remove_file(&path)
                .map_err(|error| format!("replace {}: {error}", path.display()))?;
        }
        fs::rename(&temporary, &path)
            .map_err(|error| format!("commit {}: {error}", path.display()))?;
    }
    Ok(Some(directory.join("adb.exe")))
}

pub fn secure_clear(bytes: &mut [u8]) {
    for byte in bytes {
        unsafe { std::ptr::write_volatile(byte, 0) };
    }
    compiler_fence(Ordering::SeqCst);
}

pub struct TemporaryAsset {
    path: PathBuf,
}

impl TemporaryAsset {
    pub fn create(asset: &PackageAsset) -> Result<Self, String> {
        Self::create_from_bytes(read_asset(asset)?)
    }

    fn create_from_bytes(mut plaintext: Vec<u8>) -> Result<Self, String> {
        cleanup_stale_stage_files();
        let sequence = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "diamondfox-{}-{}-{sequence}.stage",
            std::process::id(),
            crate::state::now_unix()
        ));
        let mut options = OpenOptions::new();
        options.read(true).write(true).create_new(true);
        #[cfg(windows)]
        options.custom_flags(0x00000100);
        let mut handle = options
            .open(&path)
            .map_err(|error| format!("create temporary asset: {error}"))?;
        let write_result = handle
            .write_all(&plaintext)
            .and_then(|_| handle.sync_all())
            .map_err(|error| format!("write temporary asset: {error}"));
        secure_clear(&mut plaintext);
        drop(handle);
        if let Err(error) = write_result {
            let _ = fs::remove_file(&path);
            return Err(error);
        }
        Ok(Self { path })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TemporaryAsset {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

fn cleanup_stale_stage_files() {
    let Ok(entries) = fs::read_dir(std::env::temp_dir()) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if !name.starts_with("diamondfox-") || !name.ends_with(".stage") {
            continue;
        }
        let is_stale = entry
            .metadata()
            .and_then(|metadata| metadata.modified())
            .and_then(|modified| modified.elapsed().map_err(std::io::Error::other))
            .is_ok_and(|elapsed| elapsed > std::time::Duration::from_secs(3600));
        if is_stale {
            let _ = fs::remove_file(entry.path());
        }
    }
}

fn crypt(key: &[u8; 32], nonce: &[u8; 16], input: &[u8]) -> Vec<u8> {
    let mut output = Vec::with_capacity(input.len());
    for (counter, chunk) in input.chunks(32).enumerate() {
        let mut message = b"DiamondFox stream v1".to_vec();
        message.extend_from_slice(nonce);
        message.extend_from_slice(&(counter as u64).to_be_bytes());
        let block = hmac(key, &message);
        output.extend(
            chunk
                .iter()
                .zip(block.iter())
                .map(|(left, right)| left ^ right),
        );
    }
    output
}

fn embed_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    for index in 0..32 {
        key[index] = EMBED_KEY_MASK[index] ^ EMBED_KEY_MASKED[index];
    }
    key
}

fn auth_tag(key: &[u8; 32], nonce: &[u8; 16], ciphertext: &[u8]) -> [u8; 32] {
    let mut message = b"DiamondFox asset v1".to_vec();
    message.extend_from_slice(nonce);
    message.extend_from_slice(ciphertext);
    hmac(key, &message)
}

fn hmac(key: &[u8], message: &[u8]) -> [u8; 32] {
    let mut block = [0u8; 64];
    block[..key.len()].copy_from_slice(key);
    let mut inner = [0x36u8; 64];
    let mut outer = [0x5cu8; 64];
    for index in 0..64 {
        inner[index] ^= block[index];
        outer[index] ^= block[index];
    }
    let inner_hash = Sha256::digest([inner.as_slice(), message].concat());
    Sha256::digest([outer.as_slice(), inner_hash.as_slice()].concat())
        .as_slice()
        .try_into()
        .unwrap()
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0u8, |difference, (a, b)| difference | (a ^ b))
        == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protected_assets_authenticate_and_match_pinned_hashes() {
        verify_embedded().unwrap();
        let count = built_in_packages().unwrap().len();
        assert_eq!(count, if HOST_FILES.is_empty() { 0 } else { 3 });
    }

    #[test]
    fn temporary_asset_preserves_bytes_and_is_removed() {
        let expected = b"diamondfox\0binary\xffasset";
        let temporary = TemporaryAsset::create_from_bytes(expected.to_vec()).unwrap();
        let path = temporary.path().to_path_buf();
        assert_eq!(fs::read(&path).unwrap(), expected);
        drop(temporary);
        assert!(!path.exists());
    }
}
