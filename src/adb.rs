use crate::model::{AdbDevice, DeviceSnapshot};
use std::ffi::OsStr;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

#[cfg(windows)]
use std::os::windows::process::CommandExt;

#[derive(Clone, Debug)]
pub struct Adb {
    executable: PathBuf,
}

#[derive(Clone, Debug, Default)]
pub struct CommandResult {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
    pub timed_out: bool,
}

impl CommandResult {
    pub fn success(&self) -> bool {
        self.exit_code == 0 && !self.timed_out
    }

    pub fn combined(&self) -> String {
        match (self.stdout.trim(), self.stderr.trim()) {
            ("", "") => String::new(),
            (stdout, "") => stdout.into(),
            ("", stderr) => stderr.into(),
            (stdout, stderr) => format!("{stdout}\n{stderr}"),
        }
    }
}

impl Adb {
    pub fn discover(explicit: Option<PathBuf>) -> Self {
        let executable = explicit
            .or_else(|| std::env::var_os("DIAMONDFOX_ADB").map(PathBuf::from))
            .unwrap_or_else(|| PathBuf::from(if cfg!(windows) { "adb.exe" } else { "adb" }));
        Self { executable }
    }

    pub fn run<I, S>(&self, args: I, timeout: Duration) -> Result<CommandResult, String>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let mut command = Command::new(&self.executable);
        command
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        #[cfg(windows)]
        command.creation_flags(0x08000000);
        let mut child = command
            .spawn()
            .map_err(|error| format!("start {}: {error}", self.executable.display()))?;
        let mut stdout = child.stdout.take().ok_or("failed to capture adb stdout")?;
        let mut stderr = child.stderr.take().ok_or("failed to capture adb stderr")?;
        let stdout_thread = thread::spawn(move || {
            let mut data = Vec::new();
            let _ = stdout.read_to_end(&mut data);
            data
        });
        let stderr_thread = thread::spawn(move || {
            let mut data = Vec::new();
            let _ = stderr.read_to_end(&mut data);
            data
        });
        let started = Instant::now();
        let mut timed_out = false;
        let status = loop {
            if let Some(status) = child.try_wait().map_err(|error| error.to_string())? {
                break status;
            }
            if started.elapsed() >= timeout {
                timed_out = true;
                let _ = child.kill();
                break child.wait().map_err(|error| error.to_string())?;
            }
            thread::sleep(Duration::from_millis(40));
        };
        let stdout = stdout_thread.join().unwrap_or_default();
        let stderr = stderr_thread.join().unwrap_or_default();
        Ok(CommandResult {
            exit_code: status.code().unwrap_or(if timed_out { 124 } else { -1 }),
            stdout: String::from_utf8_lossy(&stdout).replace('\0', ""),
            stderr: String::from_utf8_lossy(&stderr).replace('\0', ""),
            timed_out,
        })
    }

    pub fn version(&self) -> Result<CommandResult, String> {
        self.run(["version"], Duration::from_secs(10))
    }

    pub fn list_supported(&self) -> Result<Vec<AdbDevice>, String> {
        let result = self.run(["devices", "-l"], Duration::from_secs(12))?;
        require_success(result, "adb devices")
            .map(|result| parse_devices(&result.stdout))
            .map(|devices| devices.into_iter().filter(is_supported_hint).collect())
    }

    pub fn select_supported(&self, serial: Option<&str>) -> Result<AdbDevice, String> {
        let online: Vec<_> = self
            .list_supported()?
            .into_iter()
            .filter(|device| device.state == "device")
            .collect();
        if let Some(serial) = serial {
            return online
                .into_iter()
                .find(|device| device.serial == serial)
                .ok_or_else(|| format!("supported online device not found: {serial}"));
        }
        match online.len() {
            0 => Err("no supported Samsung device is online".into()),
            1 => Ok(online.into_iter().next().unwrap()),
            _ => Err(format!(
                "multiple supported devices are online; use --serial with one of: {}",
                online
                    .iter()
                    .map(|device| device.serial.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            )),
        }
    }

    pub fn serial(
        &self,
        serial: &str,
        args: &[&str],
        timeout: Duration,
    ) -> Result<CommandResult, String> {
        let mut full = vec!["-s", serial];
        full.extend_from_slice(args);
        self.run(full, timeout)
    }

    pub fn shell(
        &self,
        serial: &str,
        command: &str,
        timeout: Duration,
    ) -> Result<CommandResult, String> {
        self.serial(serial, &["shell", command], timeout)
    }

    pub fn push_file(
        &self,
        serial: &str,
        local: &Path,
        remote: &str,
    ) -> Result<CommandResult, String> {
        let local = local.to_string_lossy().to_string();
        self.serial(serial, &["push", &local, remote], Duration::from_secs(60))
    }

    pub fn snapshot(&self, serial: &str) -> Result<DeviceSnapshot, String> {
        let command = concat!(
            "getprop ro.product.model; getprop ro.product.device; getprop ro.bootloader; ",
            "getprop ro.build.display.id; getprop ro.build.version.incremental; ",
            "getprop ro.build.fingerprint; getprop ro.build.version.release; uname -r; ",
            "getprop sys.boot_completed; getprop ro.boot.verifiedbootstate; ",
            "getprop ro.boot.flash.locked; cat /proc/sys/kernel/random/boot_id; ",
            "id; cat /proc/self/attr/current"
        );
        let result = require_success(
            self.shell(serial, command, Duration::from_secs(15))?,
            "device identity",
        )?;
        parse_snapshot(&result.stdout)
    }
}

pub fn require_success(result: CommandResult, label: &str) -> Result<CommandResult, String> {
    if result.success() {
        Ok(result)
    } else {
        Err(format!(
            "{label} failed (exit={}, timeout={}): {}",
            result.exit_code,
            result.timed_out,
            result.combined()
        ))
    }
}

fn is_supported_hint(device: &AdbDevice) -> bool {
    let normalized: String = device
        .model_hint
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .flat_map(char::to_uppercase)
        .collect();
    normalized == "SMS918B"
}

fn parse_devices(output: &str) -> Vec<AdbDevice> {
    output
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.is_empty() || line.starts_with("List of devices") || line.starts_with('*') {
                return None;
            }
            let mut fields = line.split_whitespace();
            let serial = fields.next()?.to_string();
            let state = fields.next()?.to_string();
            let mut device = AdbDevice {
                serial,
                state,
                ..Default::default()
            };
            for field in fields {
                if let Some(value) = field.strip_prefix("model:") {
                    device.model_hint = value.replace('_', "-");
                } else if let Some(value) = field.strip_prefix("product:") {
                    device.product_hint = value.into();
                } else if let Some(value) = field.strip_prefix("device:") {
                    device.device_hint = value.into();
                }
            }
            Some(device)
        })
        .collect()
}

fn parse_snapshot(output: &str) -> Result<DeviceSnapshot, String> {
    let normalized = output.replace('\r', "");
    let lines: Vec<_> = normalized.lines().map(str::trim).collect();
    if lines.len() < 14 {
        return Err(format!("incomplete device identity: {} lines", lines.len()));
    }
    Ok(DeviceSnapshot {
        model: lines[0].replace('_', "-"),
        device: lines[1].into(),
        bootloader: lines[2].into(),
        display: lines[3].into(),
        incremental: lines[4].into(),
        fingerprint: lines[5].into(),
        release: lines[6].into(),
        kernel: lines[7].into(),
        boot_completed: lines[8].into(),
        verified_boot: lines[9].into(),
        flash_locked: lines[10].into(),
        boot_id: lines[11].into(),
        identity: lines[12].into(),
        context: lines[13].into(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_parser_filters_non_samsung_models() {
        let data = "List of devices attached\nA device product:dm3q model:SM_S918B device:dm3q\nB device product:husky model:Pixel_8_Pro device:husky\n";
        let supported: Vec<_> = parse_devices(data)
            .into_iter()
            .filter(is_supported_hint)
            .collect();
        assert_eq!(supported.len(), 1);
        assert_eq!(supported[0].serial, "A");
    }

    #[test]
    fn snapshot_requires_all_exact_fields() {
        let data = "SM-S918B\ndm3q\nBL\nDISPLAY\nINC\nFP\n17\nKERNEL\n1\ngreen\n1\nboot-id\nuid=2000(shell)\nu:r:shell:s0\n";
        let snapshot = parse_snapshot(data).unwrap();
        assert_eq!(snapshot.model, "SM-S918B");
        assert_eq!(snapshot.boot_id, "boot-id");
    }
}
