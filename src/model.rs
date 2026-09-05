use serde::{Deserialize, Serialize};
use std::path::PathBuf;

pub const DFX_SCHEMA: u32 = 1;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Workflow {
    SinglePayload,
    TracefsF156,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DeviceGate {
    pub model: String,
    pub device: String,
    pub bootloader: String,
    pub display: String,
    pub incremental: String,
    pub fingerprint: String,
    pub release: String,
    pub kernel: String,
    #[serde(default)]
    pub verified_boot: Option<String>,
    #[serde(default)]
    pub flash_locked: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AssetSpec {
    pub role: String,
    pub path: String,
    pub remote_name: String,
    pub sha256: String,
    pub mode: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PackageSettings {
    pub remote_dir: String,
    pub attempt_timeout_seconds: u64,
    pub exploit_timeout_seconds: u64,
    pub p0_timeout_seconds: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PackageManifest {
    pub schema: u32,
    pub id: String,
    pub version: String,
    pub name: String,
    pub workflow: Workflow,
    pub gate: DeviceGate,
    pub assets: Vec<AssetSpec>,
    pub settings: PackageSettings,
}

#[derive(Clone, Debug)]
pub struct PackageAsset {
    pub spec: AssetSpec,
    pub location: AssetLocation,
}

#[derive(Clone, Debug)]
pub enum AssetLocation {
    File(PathBuf),
    Protected {
        ciphertext: &'static [u8],
        nonce: [u8; 16],
        tag: [u8; 32],
    },
}

#[derive(Clone, Debug)]
pub struct SupportPackage {
    pub manifest: PackageManifest,
    pub assets: Vec<PackageAsset>,
    pub package_sha256: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct AdbDevice {
    pub serial: String,
    pub state: String,
    pub model_hint: String,
    pub product_hint: String,
    pub device_hint: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct DeviceSnapshot {
    pub model: String,
    pub device: String,
    pub bootloader: String,
    pub display: String,
    pub incremental: String,
    pub fingerprint: String,
    pub release: String,
    pub kernel: String,
    pub boot_completed: String,
    pub verified_boot: String,
    pub flash_locked: String,
    pub boot_id: String,
    pub identity: String,
    pub context: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AttemptGuard {
    pub boot_id: String,
    pub state: String,
    pub package_id: String,
    pub unix_time: u64,
}

impl DeviceGate {
    pub fn mismatches(&self, actual: &DeviceSnapshot) -> Vec<String> {
        let fields = [
            ("model", self.model.as_str(), actual.model.as_str()),
            ("device", self.device.as_str(), actual.device.as_str()),
            (
                "bootloader",
                self.bootloader.as_str(),
                actual.bootloader.as_str(),
            ),
            ("display", self.display.as_str(), actual.display.as_str()),
            (
                "incremental",
                self.incremental.as_str(),
                actual.incremental.as_str(),
            ),
            ("release", self.release.as_str(), actual.release.as_str()),
            ("kernel", self.kernel.as_str(), actual.kernel.as_str()),
        ];
        let mut result = Vec::new();
        for (name, expected, actual) in fields {
            if expected != actual {
                result.push(format!("{name}: expected {expected}, got {actual}"));
            }
        }
        if !fingerprint_matches(&self.fingerprint, &actual.fingerprint) {
            result.push(format!(
                "fingerprint: expected {}, got {}",
                self.fingerprint, actual.fingerprint
            ));
        }
        if let Some(expected) = &self.verified_boot
            && expected != &actual.verified_boot
        {
            result.push(format!(
                "verified_boot: expected {expected}, got {}",
                actual.verified_boot
            ));
        }
        if let Some(expected) = &self.flash_locked
            && expected != &actual.flash_locked
        {
            result.push(format!(
                "flash_locked: expected {expected}, got {}",
                actual.flash_locked
            ));
        }
        result
    }

    pub fn warnings(&self, actual: &DeviceSnapshot) -> Vec<String> {
        if self.fingerprint == actual.fingerprint
            || !fingerprint_matches(&self.fingerprint, &actual.fingerprint)
        {
            return Vec::new();
        }
        let expected = fingerprint_product(&self.fingerprint).unwrap_or("unknown");
        let detected = fingerprint_product(&actual.fingerprint).unwrap_or("unknown");
        vec![format!(
            "Regional fingerprint product differs ({expected} -> {detected}); invariant build fields match"
        )]
    }
}

fn fingerprint_parts(value: &str) -> Option<(&str, &str, &str)> {
    let (brand, remainder) = value.split_once('/')?;
    let (product, invariant) = remainder.split_once('/')?;
    (!brand.is_empty() && !product.is_empty() && !invariant.is_empty())
        .then_some((brand, product, invariant))
}

fn fingerprint_product(value: &str) -> Option<&str> {
    fingerprint_parts(value).map(|(_, product, _)| product)
}

fn fingerprint_matches(expected: &str, actual: &str) -> bool {
    if expected == actual {
        return true;
    }
    match (fingerprint_parts(expected), fingerprint_parts(actual)) {
        (
            Some((expected_brand, _, expected_invariant)),
            Some((actual_brand, _, actual_invariant)),
        ) => expected_brand == actual_brand && expected_invariant == actual_invariant,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_gate_rejects_kernel_drift() {
        let snapshot = DeviceSnapshot {
            model: "SM-S918B".into(),
            device: "dm3q".into(),
            bootloader: "S918BXXSAFZG1".into(),
            display: "display".into(),
            incremental: "incremental".into(),
            fingerprint: "fingerprint".into(),
            release: "16".into(),
            kernel: "kernel-a".into(),
            ..Default::default()
        };
        let gate = DeviceGate {
            model: snapshot.model.clone(),
            device: snapshot.device.clone(),
            bootloader: snapshot.bootloader.clone(),
            display: snapshot.display.clone(),
            incremental: snapshot.incremental.clone(),
            fingerprint: snapshot.fingerprint.clone(),
            release: snapshot.release.clone(),
            kernel: "kernel-b".into(),
            verified_boot: None,
            flash_locked: None,
        };
        assert_eq!(gate.mismatches(&snapshot).len(), 1);
    }

    #[test]
    fn regional_fingerprint_product_is_warning_only() {
        let mut snapshot = DeviceSnapshot {
            model: "SM-S918B".into(),
            device: "dm3q".into(),
            bootloader: "S918BXXUAZZHL".into(),
            display: "CP2A.260605.016.S918BXXUAZZHL".into(),
            incremental: "S918BXXUAZZHL".into(),
            fingerprint:
                "samsung/dm3qother/dm3q:17/CP2A.260605.016/S918BXXUAZZHL:user/release-keys".into(),
            release: "17".into(),
            kernel: "kernel".into(),
            verified_boot: "green".into(),
            flash_locked: "1".into(),
            ..Default::default()
        };
        let gate = DeviceGate {
            model: snapshot.model.clone(),
            device: snapshot.device.clone(),
            bootloader: snapshot.bootloader.clone(),
            display: snapshot.display.clone(),
            incremental: snapshot.incremental.clone(),
            fingerprint: "samsung/dm3qxeea/dm3q:17/CP2A.260605.016/S918BXXUAZZHL:user/release-keys"
                .into(),
            release: snapshot.release.clone(),
            kernel: snapshot.kernel.clone(),
            verified_boot: Some(snapshot.verified_boot.clone()),
            flash_locked: Some(snapshot.flash_locked.clone()),
        };
        assert!(gate.mismatches(&snapshot).is_empty());
        assert_eq!(gate.warnings(&snapshot).len(), 1);
        snapshot.fingerprint =
            "samsung/dm3qother/dm3q:17/CP2A.260605.016/DIFFERENT:user/release-keys".into();
        assert_eq!(gate.mismatches(&snapshot).len(), 1);
        assert!(gate.warnings(&snapshot).is_empty());
    }
}
