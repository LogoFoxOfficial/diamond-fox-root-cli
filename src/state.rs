use crate::model::AttemptGuard;
use directories::ProjectDirs;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone, Debug)]
pub struct AppDirs {
    pub packages: PathBuf,
    pub guards: PathBuf,
    pub cache: PathBuf,
}

impl AppDirs {
    pub fn discover(override_path: Option<PathBuf>) -> Result<Self, String> {
        let base = override_path
            .or_else(|| std::env::var_os("DIAMONDFOX_HOME").map(PathBuf::from))
            .or_else(|| {
                ProjectDirs::from("com", "DiamondFox", "RootCli")
                    .map(|project| project.data_local_dir().to_path_buf())
            })
            .ok_or("LocalAppData is not available")?;
        let result = Self {
            packages: base.join("packages"),
            guards: base.join("guards"),
            cache: base.join("cache"),
        };
        for path in [&result.packages, &result.guards, &result.cache] {
            fs::create_dir_all(path)
                .map_err(|error| format!("create {}: {error}", path.display()))?;
        }
        Ok(result)
    }
}

pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn safe_name(value: &str) -> String {
    value
        .chars()
        .take(96)
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '-' | '_') {
                character
            } else {
                '_'
            }
        })
        .collect()
}

fn record_path(dirs: &AppDirs, serial: &str) -> PathBuf {
    dirs.guards
        .join(format!("attempt-{}.json", safe_name(serial)))
}

fn sentinel_path(dirs: &AppDirs, serial: &str, boot_id: &str) -> PathBuf {
    dirs.guards.join(format!(
        "used-{}-{}.guard",
        safe_name(serial),
        safe_name(boot_id)
    ))
}

pub fn guard_for_boot(dirs: &AppDirs, serial: &str, boot_id: &str) -> Option<AttemptGuard> {
    let record = fs::read(record_path(dirs, serial))
        .ok()
        .and_then(|data| serde_json::from_slice::<AttemptGuard>(&data).ok())
        .filter(|guard| guard.boot_id == boot_id);
    if record.is_some() {
        return record;
    }
    sentinel_path(dirs, serial, boot_id)
        .is_file()
        .then(|| AttemptGuard {
            boot_id: boot_id.into(),
            state: "ATTEMPTED".into(),
            package_id: "unknown".into(),
            unix_time: 0,
        })
}

pub fn mark_attempt(
    dirs: &AppDirs,
    serial: &str,
    boot_id: &str,
    package_id: &str,
) -> Result<(), String> {
    let sentinel = sentinel_path(dirs, serial, boot_id);
    let mut file = match OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&sentinel)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            return Err("a root attempt is already recorded for this Android boot".into());
        }
        Err(error) => return Err(format!("create {}: {error}", sentinel.display())),
    };
    writeln!(file, "boot_id={boot_id}\ncreated={}", now_unix())
        .map_err(|error| format!("write {}: {error}", sentinel.display()))?;
    file.sync_all()
        .map_err(|error| format!("flush {}: {error}", sentinel.display()))?;
    write_guard(dirs, serial, boot_id, package_id, "ATTEMPTED")
}

pub fn update_guard(
    dirs: &AppDirs,
    serial: &str,
    boot_id: &str,
    package_id: &str,
    state: &str,
) -> Result<(), String> {
    write_guard(dirs, serial, boot_id, package_id, state)
}

fn write_guard(
    dirs: &AppDirs,
    serial: &str,
    boot_id: &str,
    package_id: &str,
    state: &str,
) -> Result<(), String> {
    let guard = AttemptGuard {
        boot_id: boot_id.into(),
        state: state.into(),
        package_id: package_id.into(),
        unix_time: now_unix(),
    };
    let data = serde_json::to_vec_pretty(&guard).map_err(|error| error.to_string())?;
    let path = record_path(dirs, serial);
    let temporary = path.with_extension(format!("tmp-{}", std::process::id()));
    fs::write(&temporary, data)
        .map_err(|error| format!("write {}: {error}", temporary.display()))?;
    replace_file(&temporary, &path)
}

fn replace_file(source: &Path, destination: &Path) -> Result<(), String> {
    if destination.exists() {
        fs::remove_file(destination)
            .map_err(|error| format!("replace {}: {error}", destination.display()))?;
    }
    fs::rename(source, destination)
        .map_err(|error| format!("commit {}: {error}", destination.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sentinel_survives_status_record_loss() {
        let base = std::env::temp_dir().join(format!(
            "diamond-fox-cli-guard-{}-{}",
            std::process::id(),
            now_unix()
        ));
        let dirs = AppDirs {
            packages: base.join("packages"),
            guards: base.join("guards"),
            cache: base.join("cache"),
        };
        fs::create_dir_all(&dirs.guards).unwrap();
        mark_attempt(&dirs, "serial", "boot-id", "package").unwrap();
        fs::remove_file(record_path(&dirs, "serial")).unwrap();
        assert!(guard_for_boot(&dirs, "serial", "boot-id").is_some());
        assert!(mark_attempt(&dirs, "serial", "boot-id", "package").is_err());
        fs::remove_dir_all(base).unwrap();
    }
}
