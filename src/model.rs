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
            (
                "fingerprint",
                self.fingerprint.as_str(),
                actual.fingerprint.as_str(),
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
}
