use crate::model::{
    AssetLocation, AssetSpec, DFX_SCHEMA, PackageAsset, PackageManifest, SupportPackage, Workflow,
};
use crate::state::{AppDirs, now_unix};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Component, Path};
use zip::ZipArchive;

const MAX_MANIFEST: u64 = 128 * 1024;
const MAX_ASSET: u64 = 32 * 1024 * 1024;
const MAX_PACKAGE: u64 = 64 * 1024 * 1024;
const MAX_ASSETS: usize = 16;

pub struct VerifiedDfx {
    pub manifest: PackageManifest,
    pub package_sha256: String,
    assets: Vec<(AssetSpec, Vec<u8>)>,
}

pub fn sha256_file(path: &Path) -> Result<String, String> {
    let mut file = File::open(path).map_err(|error| format!("open {}: {error}", path.display()))?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|error| format!("read {}: {error}", path.display()))?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }
    Ok(hex::encode_upper(digest.finalize()))
}

fn sha256_bytes(data: &[u8]) -> String {
    hex::encode_upper(Sha256::digest(data))
}

fn safe_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 96
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn safe_relative(value: &str) -> bool {
    let path = Path::new(value);
    !value.is_empty()
        && !path.is_absolute()
        && path
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
}

pub fn validate_manifest(manifest: &PackageManifest) -> Result<(), String> {
    if manifest.schema != DFX_SCHEMA {
        return Err(format!("unsupported DFX schema: {}", manifest.schema));
    }
    if !safe_identifier(&manifest.id) || !safe_identifier(&manifest.version) {
        return Err("package ID or version contains unsupported characters".into());
    }
    if manifest.name.trim().is_empty() || manifest.name.len() > 120 {
        return Err("package name is empty or too long".into());
    }
    for (name, value) in [
        ("model", &manifest.gate.model),
        ("device", &manifest.gate.device),
        ("bootloader", &manifest.gate.bootloader),
        ("display", &manifest.gate.display),
        ("incremental", &manifest.gate.incremental),
        ("fingerprint", &manifest.gate.fingerprint),
        ("release", &manifest.gate.release),
        ("kernel", &manifest.gate.kernel),
    ] {
        if value.trim().is_empty() {
            return Err(format!("required gate is empty: {name}"));
        }
    }
    if manifest
        .gate
        .verified_boot
        .as_deref()
        .unwrap_or("")
        .is_empty()
        || manifest
            .gate
            .flash_locked
            .as_deref()
            .unwrap_or("")
            .is_empty()
    {
        return Err("verified_boot and flash_locked gates are required".into());
    }
    let remote = &manifest.settings.remote_dir;
    if !remote.starts_with("/data/local/tmp/diamondfox/")
        || remote.contains("..")
        || remote.contains(char::is_whitespace)
    {
        return Err("remote_dir must be a safe path below /data/local/tmp/diamondfox".into());
    }
    if !(30..=600).contains(&manifest.settings.attempt_timeout_seconds)
        || !(15..=300).contains(&manifest.settings.exploit_timeout_seconds)
        || !(15..=120).contains(&manifest.settings.p0_timeout_seconds)
    {
        return Err("package timeout is outside the accepted range".into());
    }
    if manifest.assets.is_empty() || manifest.assets.len() > MAX_ASSETS {
        return Err("invalid package asset count".into());
    }
    let mut roles = HashSet::new();
    let mut paths = HashSet::new();
    let mut remote_names = HashSet::new();
    for asset in &manifest.assets {
        if !matches!(asset.role.as_str(), "helper" | "payload" | "slide") {
            return Err(format!("unsupported asset role: {}", asset.role));
        }
        if !roles.insert(asset.role.as_str()) {
            return Err(format!("duplicate asset role: {}", asset.role));
        }
        if !safe_relative(&asset.path) || !asset.path.starts_with("payload/") {
            return Err(format!("unsafe asset path: {}", asset.path));
        }
        if !paths.insert(asset.path.as_str()) {
            return Err(format!("duplicate asset path: {}", asset.path));
        }
        if !safe_identifier(&asset.remote_name) || !remote_names.insert(asset.remote_name.as_str())
        {
            return Err(format!("invalid remote asset name: {}", asset.remote_name));
        }
        if !matches!(asset.mode.as_str(), "600" | "700") {
            return Err(format!("invalid mode for {}", asset.role));
        }
        if asset.sha256.len() != 64 || !asset.sha256.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(format!("invalid SHA-256 for {}", asset.role));
        }
    }
    if !roles.contains("helper") || !roles.contains("payload") {
        return Err("helper and payload assets are required".into());
    }
    match manifest.workflow {
        Workflow::SinglePayload if roles.contains("slide") => {
            return Err("single_payload must not contain a slide asset".into());
        }
        Workflow::TracefsF156 if !roles.contains("slide") => {
            return Err("tracefs_f156 requires a slide asset".into());
        }
        _ => {}
    }
    Ok(())
}

pub fn verify_dfx(path: &Path) -> Result<VerifiedDfx, String> {
    let metadata =
        fs::metadata(path).map_err(|error| format!("inspect {}: {error}", path.display()))?;
    if metadata.len() > MAX_PACKAGE {
        return Err("DFX package exceeds 64 MiB".into());
    }
    let package_sha256 = sha256_file(path)?;
    let file = File::open(path).map_err(|error| format!("open {}: {error}", path.display()))?;
    let mut archive = ZipArchive::new(file).map_err(|error| format!("invalid ZIP: {error}"))?;
    if archive.len() > MAX_ASSETS + 1 {
        return Err("DFX package has too many entries".into());
    }
    let manifest_data = {
        let mut entry = archive
            .by_name("manifest.json")
            .map_err(|_| "DFX package has no manifest.json")?;
        if entry.size() > MAX_MANIFEST {
            return Err("manifest.json exceeds 128 KiB".into());
        }
        let mut data = Vec::with_capacity(entry.size() as usize);
        entry
            .read_to_end(&mut data)
            .map_err(|error| format!("read manifest.json: {error}"))?;
        data
    };
    let manifest: PackageManifest = serde_json::from_slice(&manifest_data)
        .map_err(|error| format!("parse manifest.json: {error}"))?;
    validate_manifest(&manifest)?;

    let declared: HashMap<_, _> = manifest
        .assets
        .iter()
        .map(|asset| (asset.path.as_str(), asset))
        .collect();
    let mut seen = HashSet::new();
    let mut total = manifest_data.len() as u64;
    for index in 0..archive.len() {
        let entry = archive
            .by_index(index)
            .map_err(|error| format!("read ZIP entry: {error}"))?;
        let name = entry.name();
        if !seen.insert(name.to_string()) {
            return Err(format!("duplicate ZIP entry: {name}"));
        }
        if name == "manifest.json" {
            continue;
        }
        if entry.is_dir() || !declared.contains_key(name) {
            return Err(format!("undeclared ZIP entry: {name}"));
        }
        if entry.size() > MAX_ASSET {
            return Err(format!("asset exceeds 32 MiB: {name}"));
        }
        total = total.saturating_add(entry.size());
        if total > MAX_PACKAGE {
            return Err("uncompressed DFX data exceeds 64 MiB".into());
        }
    }
    let mut assets = Vec::with_capacity(manifest.assets.len());
    for spec in &manifest.assets {
        let mut entry = archive
            .by_name(&spec.path)
            .map_err(|_| format!("missing declared asset: {}", spec.path))?;
        let mut data = Vec::with_capacity(entry.size() as usize);
        entry
            .read_to_end(&mut data)
            .map_err(|error| format!("read {}: {error}", spec.path))?;
        if !sha256_bytes(&data).eq_ignore_ascii_case(&spec.sha256) {
            return Err(format!("asset hash mismatch: {}", spec.path));
        }
        assets.push((spec.clone(), data));
    }
    Ok(VerifiedDfx {
        manifest,
        package_sha256,
        assets,
    })
}

pub fn install_dfx(dirs: &AppDirs, path: &Path) -> Result<SupportPackage, String> {
    let verified = verify_dfx(path)?;
    let destination = dirs
        .packages
        .join(&verified.manifest.id)
        .join(&verified.manifest.version);
    if destination.exists() {
        let installed = load_installed(&destination)?;
        if installed.package_sha256 == verified.package_sha256 {
            return Ok(installed);
        }
        return Err(format!(
            "package version already exists with different content: {} {}",
            verified.manifest.id, verified.manifest.version
        ));
    }
    let temporary = dirs.packages.join(format!(
        ".install-{}-{}-{}",
        verified.manifest.id,
        std::process::id(),
        now_unix()
    ));
    fs::create_dir_all(&temporary)
        .map_err(|error| format!("create {}: {error}", temporary.display()))?;
    let result = (|| {
        let manifest_data = serde_json::to_vec_pretty(&verified.manifest)
            .map_err(|error| format!("serialize manifest: {error}"))?;
        fs::write(temporary.join("manifest.json"), manifest_data)
            .map_err(|error| format!("write manifest: {error}"))?;
        fs::write(
            temporary.join("package.sha256"),
            format!("{}\n", verified.package_sha256),
        )
        .map_err(|error| format!("write package hash: {error}"))?;
        for (spec, data) in &verified.assets {
            let output = temporary.join(&spec.path);
            let parent = output.parent().ok_or("invalid asset output path")?;
            fs::create_dir_all(parent)
                .map_err(|error| format!("create {}: {error}", parent.display()))?;
            let mut file = File::create(&output)
                .map_err(|error| format!("create {}: {error}", output.display()))?;
            file.write_all(data)
                .map_err(|error| format!("write {}: {error}", output.display()))?;
            file.sync_all()
                .map_err(|error| format!("flush {}: {error}", output.display()))?;
        }
        let parent = destination.parent().ok_or("invalid package destination")?;
        fs::create_dir_all(parent)
            .map_err(|error| format!("create {}: {error}", parent.display()))?;
        fs::rename(&temporary, &destination).map_err(|error| format!("commit package: {error}"))?;
        Ok::<(), String>(())
    })();
    if result.is_err() {
        let _ = fs::remove_dir_all(&temporary);
    }
    result?;
    load_installed(&destination)
}

pub fn load_installed(path: &Path) -> Result<SupportPackage, String> {
    let manifest_path = path.join("manifest.json");
    let data = fs::read(&manifest_path)
        .map_err(|error| format!("read {}: {error}", manifest_path.display()))?;
    if data.len() as u64 > MAX_MANIFEST {
        return Err(format!(
            "manifest is too large: {}",
            manifest_path.display()
        ));
    }
    let manifest: PackageManifest = serde_json::from_slice(&data)
        .map_err(|error| format!("parse {}: {error}", manifest_path.display()))?;
    validate_manifest(&manifest)?;
    let package_sha256 = fs::read_to_string(path.join("package.sha256"))
        .map_err(|error| format!("read package.sha256: {error}"))?
        .trim()
        .to_ascii_uppercase();
    if package_sha256.len() != 64 || !package_sha256.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("installed package has an invalid package hash".into());
    }
    let mut assets = Vec::with_capacity(manifest.assets.len());
    for spec in &manifest.assets {
        let asset_path = path.join(&spec.path);
        if !asset_path.is_file() {
            return Err(format!("installed asset is missing: {}", spec.path));
        }
        if !sha256_file(&asset_path)?.eq_ignore_ascii_case(&spec.sha256) {
            return Err(format!("installed asset hash mismatch: {}", spec.path));
        }
        assets.push(PackageAsset {
            spec: spec.clone(),
            location: AssetLocation::File(asset_path),
        });
    }
    Ok(SupportPackage {
        manifest,
        assets,
        package_sha256,
    })
}

pub fn list_installed(dirs: &AppDirs) -> Vec<Result<SupportPackage, String>> {
    let mut result = Vec::new();
    let Ok(ids) = fs::read_dir(&dirs.packages) else {
        return result;
    };
    for id in ids.flatten().filter(|entry| entry.path().is_dir()) {
        if id.file_name().to_string_lossy().starts_with('.') {
            continue;
        }
        let Ok(versions) = fs::read_dir(id.path()) else {
            continue;
        };
        for version in versions.flatten().filter(|entry| entry.path().is_dir()) {
            result.push(load_installed(&version.path()));
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{DeviceGate, PackageSettings};
    use std::io::Write;
    use zip::write::SimpleFileOptions;

    fn manifest() -> PackageManifest {
        PackageManifest {
            schema: 1,
            id: "s918b-test".into(),
            version: "1.0.0".into(),
            name: "S918B Test".into(),
            workflow: Workflow::SinglePayload,
            gate: DeviceGate {
                model: "SM-S918B".into(),
                device: "dm3q".into(),
                bootloader: "BL".into(),
                display: "DISPLAY".into(),
                incremental: "INC".into(),
                fingerprint: "FP".into(),
                release: "17".into(),
                kernel: "KERNEL".into(),
                verified_boot: Some("green".into()),
                flash_locked: Some("1".into()),
            },
            assets: vec![
                AssetSpec {
                    role: "helper".into(),
                    path: "payload/helper".into(),
                    remote_name: "helper".into(),
                    sha256: "0".repeat(64),
                    mode: "700".into(),
                },
                AssetSpec {
                    role: "payload".into(),
                    path: "payload/payload.so".into(),
                    remote_name: "payload.so".into(),
                    sha256: "1".repeat(64),
                    mode: "600".into(),
                },
            ],
            settings: PackageSettings {
                remote_dir: "/data/local/tmp/diamondfox/test".into(),
                attempt_timeout_seconds: 200,
                exploit_timeout_seconds: 120,
                p0_timeout_seconds: 45,
            },
        }
    }

    #[test]
    fn manifest_rejects_archive_escape() {
        let mut value = manifest();
        value.assets[0].path = "../helper".into();
        assert!(validate_manifest(&value).is_err());
    }

    #[test]
    fn manifest_rejects_command_like_remote_name() {
        let mut value = manifest();
        value.assets[0].remote_name = "helper;id".into();
        assert!(validate_manifest(&value).is_err());
    }

    #[test]
    fn package_round_trip_verifies_and_installs() {
        let base = std::env::temp_dir().join(format!(
            "diamond-fox-cli-package-{}-{}",
            std::process::id(),
            now_unix()
        ));
        fs::create_dir_all(&base).unwrap();
        let archive_path = base.join("support.dfx");
        let helper = b"test helper";
        let payload = b"test payload";
        let mut value = manifest();
        value.assets[0].sha256 = sha256_bytes(helper);
        value.assets[1].sha256 = sha256_bytes(payload);

        let archive_file = File::create(&archive_path).unwrap();
        let mut archive = zip::ZipWriter::new(archive_file);
        let options =
            SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);
        archive.start_file("manifest.json", options).unwrap();
        archive
            .write_all(&serde_json::to_vec_pretty(&value).unwrap())
            .unwrap();
        archive.start_file("payload/helper", options).unwrap();
        archive.write_all(helper).unwrap();
        archive.start_file("payload/payload.so", options).unwrap();
        archive.write_all(payload).unwrap();
        archive.finish().unwrap();

        let verified = verify_dfx(&archive_path).unwrap();
        assert_eq!(verified.manifest, value);
        assert_eq!(verified.assets.len(), 2);

        let dirs = AppDirs {
            packages: base.join("installed"),
            guards: base.join("guards"),
            cache: base.join("cache"),
        };
        for path in [&dirs.packages, &dirs.guards, &dirs.cache] {
            fs::create_dir_all(path).unwrap();
        }
        let installed = install_dfx(&dirs, &archive_path).unwrap();
        assert_eq!(installed.manifest, value);
        assert_eq!(installed.assets.len(), 2);
        assert_eq!(list_installed(&dirs).len(), 1);

        fs::remove_dir_all(base).unwrap();
    }
}
