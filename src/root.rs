use crate::adb::{Adb, CommandResult, require_success};
use crate::error::{ErrorCodeExt, coded};
use crate::model::{DeviceSnapshot, PackageAsset, SupportPackage, Workflow};
use crate::output::Reporter;
use crate::state::{self, AppDirs};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

pub struct RootOutcome {
    pub identity: String,
    pub shell_command: String,
}

pub fn select_package<'a>(
    packages: &'a [SupportPackage],
    snapshot: &DeviceSnapshot,
) -> Result<&'a SupportPackage, String> {
    let matches: Vec<_> = packages
        .iter()
        .filter(|package| package.manifest.gate.mismatches(snapshot).is_empty())
        .collect();
    match matches.len() {
        0 => {
            let closest = packages
                .iter()
                .map(|package| (package, package.manifest.gate.mismatches(snapshot)))
                .min_by_key(|(_, mismatches)| mismatches.len());
            let detail = closest
                .filter(|(_, mismatches)| !mismatches.is_empty())
                .map(|(package, mismatches)| {
                    format!(
                        "\nClosest profile: {}\nGate differences:\n  - {}",
                        package.manifest.name,
                        mismatches.join("\n  - ")
                    )
                })
                .unwrap_or_default();
            Err(coded(
                "GATE001",
                format!(
                    "no installed package matches {} / {} / {}{detail}",
                    snapshot.model, snapshot.bootloader, snapshot.kernel
                ),
            ))
        }
        1 => Ok(matches[0]),
        _ => {
            let exact: Vec<_> = matches
                .iter()
                .copied()
                .filter(|package| package.manifest.gate.fingerprint == snapshot.fingerprint)
                .collect();
            match exact.as_slice() {
                [package] => Ok(*package),
                _ => Err(coded(
                    "GATE002",
                    "more than one package matches this firmware",
                )),
            }
        }
    }
}

pub fn run(
    adb: &Adb,
    dirs: &AppDirs,
    packages: &[SupportPackage],
    serial: Option<&str>,
    assume_yes: bool,
    reporter: &Reporter,
) -> Result<Option<RootOutcome>, String> {
    reporter.step("Checking ADB");
    let version =
        require_success(adb.version().with_code("ADB001")?, "adb version").with_code("ADB002")?;
    reporter.ok(version.stdout.lines().next().unwrap_or("ADB is available"));

    let device = adb.select_supported(serial).with_code("ADB003")?;
    reporter.ok(format!("Device: {} ({})", device.model_hint, device.serial));
    let snapshot = adb.snapshot(&device.serial).with_code("ADB004")?;
    validate_snapshot(&snapshot)?;
    reporter.info(format!("Build: {}", snapshot.display));
    reporter.info(format!("Kernel: {}", snapshot.kernel));
    reporter.info(format!("Boot ID: {}", snapshot.boot_id));

    let package = select_package(packages, &snapshot)?;
    reporter.ok(format!("Root method: {}", package.manifest.name));
    for warning in package.manifest.gate.warnings(&snapshot) {
        reporter.warn(warning);
    }
    let helper = remote_asset(package, "helper")?;
    if let Some(identity) = root_identity(adb, &device.serial, std::slice::from_ref(&helper)) {
        reporter.ok("Temporary root is already active");
        return Ok(Some(outcome(&device.serial, &helper, identity)));
    }
    if let Some(guard) = state::guard_for_boot(dirs, &device.serial, &snapshot.boot_id) {
        return Err(coded(
            "GUARD001",
            format!(
                "this boot already has a root attempt recorded ({}) - reboot Android before trying again",
                guard.state
            ),
        ));
    }

    if !assume_yes {
        println!();
        reporter.warn("Do not close this terminal or disconnect USB while root is running.");
        reporter.info("If the process is interrupted, the phone may crash and reboot.");
        reporter.info("The root workflow can take several minutes. Wait for a final result.");
        println!();
        if !reporter.confirm("Continue")? {
            reporter.info("Cancelled");
            return Ok(None);
        }
    }

    reporter.step("Verifying and staging package assets");
    stage_package(adb, &device.serial, package, reporter).with_code("STAGE000")?;
    reporter.ok("Package assets match on the phone");
    if let Some(identity) = root_identity(adb, &device.serial, std::slice::from_ref(&helper)) {
        reporter.ok("Temporary root is already active");
        return Ok(Some(outcome(&device.serial, &helper, identity)));
    }

    state::mark_attempt(
        dirs,
        &device.serial,
        &snapshot.boot_id,
        &package.manifest.id,
    )
    .with_code("GUARD002")?;
    reporter.info("Persistent boot-attempt guard committed");
    let result = execute_attempt(adb, &device.serial, package, reporter);
    match result {
        Ok(identity) => {
            state::update_guard(
                dirs,
                &device.serial,
                &snapshot.boot_id,
                &package.manifest.id,
                "SUCCESS",
            )?;
            reporter.ok("Temporary kernel root verified");
            Ok(Some(outcome(&device.serial, &helper, identity)))
        }
        Err(error) => {
            let _ = state::update_guard(
                dirs,
                &device.serial,
                &snapshot.boot_id,
                &package.manifest.id,
                "FAILED",
            );
            Err(format!("{error}. Do not retry on this boot"))
        }
    }
}

fn validate_snapshot(snapshot: &DeviceSnapshot) -> Result<(), String> {
    if snapshot.model != "SM-S918B" || snapshot.device != "dm3q" {
        return Err(coded(
            "GATE003",
            format!(
                "unsupported device identity: {} / {}",
                snapshot.model, snapshot.device
            ),
        ));
    }
    if snapshot.boot_completed != "1" {
        return Err(coded("GATE004", "Android has not completed booting"));
    }
    if !snapshot.identity.starts_with("uid=2000(shell)") {
        return Err(coded(
            "GATE005",
            format!("unexpected ADB identity: {}", snapshot.identity),
        ));
    }
    if snapshot.context != "u:r:shell:s0" {
        return Err(coded(
            "GATE006",
            format!("unexpected SELinux context: {}", snapshot.context),
        ));
    }
    if snapshot.boot_id.is_empty() {
        return Err(coded("GATE007", "Android boot ID is empty"));
    }
    Ok(())
}

fn asset<'a>(package: &'a SupportPackage, role: &str) -> Result<&'a PackageAsset, String> {
    package
        .assets
        .iter()
        .find(|asset| asset.spec.role == role)
        .ok_or_else(|| format!("package has no {role} asset"))
}

fn remote_asset(package: &SupportPackage, role: &str) -> Result<String, String> {
    Ok(format!(
        "{}/{}",
        package.manifest.settings.remote_dir,
        asset(package, role)?.spec.remote_name
    ))
}

fn stage_package(
    adb: &Adb,
    serial: &str,
    package: &SupportPackage,
    reporter: &Reporter,
) -> Result<(), String> {
    let remote_dir = &package.manifest.settings.remote_dir;
    reporter.info(format!("Preparing remote workspace: {remote_dir}"));
    require_success(
        adb.shell(
            serial,
            &format!("mkdir -p {remote_dir}"),
            Duration::from_secs(15),
        )
        .with_code("STAGE001")?,
        "create remote directory",
    )
    .with_code("STAGE002")?;
    let mut expected = Vec::new();
    for item in &package.assets {
        let remote = format!("{remote_dir}/{}", item.spec.remote_name);
        reporter.info(format!("Authenticating local {} asset", item.spec.role));
        let temporary = crate::builtin::TemporaryAsset::create(item).with_code("STAGE003")?;
        reporter.info(format!("Uploading {} asset", item.spec.role));
        let push = adb.push_file(serial, temporary.path(), &remote);
        drop(temporary);
        require_success(push.with_code("STAGE004")?, "adb push").with_code("STAGE005")?;
        require_success(
            adb.shell(
                serial,
                &format!("chmod {} {remote}", item.spec.mode),
                Duration::from_secs(10),
            )
            .with_code("STAGE006")?,
            "chmod",
        )
        .with_code("STAGE007")?;
        reporter.ok(format!("Staged {} asset", item.spec.role));
        expected.push((remote, item.spec.sha256.to_ascii_lowercase()));
    }
    reporter.info("Verifying SHA-256 hashes on the device");
    let command = format!(
        "sha256sum {}",
        expected
            .iter()
            .map(|(remote, _)| remote.as_str())
            .collect::<Vec<_>>()
            .join(" ")
    );
    let result = require_success(
        adb.shell(serial, &command, Duration::from_secs(20))
            .with_code("STAGE008")?,
        "remote SHA-256",
    )
    .with_code("STAGE009")?;
    let output = result.stdout.to_ascii_lowercase();
    for (remote, hash) in expected {
        if !output
            .lines()
            .any(|line| line.contains(&hash) && line.contains(&remote))
        {
            return Err(coded(
                "STAGE010",
                format!("remote asset hash mismatch: {remote}"),
            ));
        }
    }
    reporter.ok("Remote asset integrity verified");
    Ok(())
}

fn execute_attempt(
    adb: &Adb,
    serial: &str,
    package: &SupportPackage,
    reporter: &Reporter,
) -> Result<String, String> {
    let helper = remote_asset(package, "helper")?;
    let payload = remote_asset(package, "payload")?;
    let remote_log = format!(
        "{}/root-{}.log",
        package.manifest.settings.remote_dir,
        state::now_unix()
    );
    let command = match package.manifest.workflow {
        Workflow::SinglePayload => format!(
            "EXPLOIT_ATTEMPTS=1 P0_ATTEMPT_TIMEOUT_SEC={} EXPLOIT_ATTEMPT_TIMEOUT_SEC={} {helper} --run-payload {payload} {helper} {remote_log}",
            package.manifest.settings.p0_timeout_seconds,
            package.manifest.settings.exploit_timeout_seconds,
        ),
        Workflow::TracefsF156 => {
            reporter.step("Resolving the current KASLR slide");
            let slide_asset = remote_asset(package, "slide")?;
            let slide_log = format!(
                "{}/slide-{}.log",
                package.manifest.settings.remote_dir,
                state::now_unix()
            );
            let slide_command = format!(
                "SLIDE_ONLY=1 EXPLOIT_ATTEMPTS=1 EXPLOIT_ATTEMPT_TIMEOUT_SEC=45 {helper} --run-payload {slide_asset} {helper} {slide_log}"
            );
            let result = require_success(
                adb.shell(serial, &slide_command, Duration::from_secs(90))
                    .with_code("ROOT100")?,
                "KASLR slide resolver",
            )
            .with_code("ROOT101")?;
            let slide = parse_tracefs_slide(&result.combined()).with_code("ROOT102")?;
            reporter.ok(format!("KASLR slide: 0x{slide:x}"));
            format!(
                "RMG_DURABLE_MILESTONES=1 APP_FOPS_USE_SIGRETURN=1 SLIDE_P0_OFFSET=0x{slide:x} EXPLOIT_ATTEMPTS=1 P0_ATTEMPT_TIMEOUT_SEC={} EXPLOIT_ATTEMPT_TIMEOUT_SEC={} {helper} --run-payload {payload} {helper} {remote_log}",
                package.manifest.settings.p0_timeout_seconds,
                package.manifest.settings.exploit_timeout_seconds,
            )
        }
    };
    reporter.step("Starting the root workflow");
    reporter.info(format!(
        "Maximum workflow window: {} seconds",
        package.manifest.settings.attempt_timeout_seconds
    ));
    reporter.info("The device may appear idle while the kernel workflow is active");
    run_and_poll_root(
        adb,
        serial,
        command,
        Duration::from_secs(package.manifest.settings.attempt_timeout_seconds),
        vec![helper],
        reporter,
    )
}

fn parse_tracefs_slide(text: &str) -> Result<u64, String> {
    let line = text
        .lines()
        .find(|line| line.contains("slide-kaslr-ok source=tracefs"))
        .ok_or("slide resolver returned no source=tracefs marker")?;
    let token: String = line
        .split("slide=")
        .nth(1)
        .ok_or("slide marker has no value")?
        .chars()
        .take_while(|character| character.is_ascii_hexdigit() || *character == 'x')
        .collect();
    let slide = u64::from_str_radix(token.trim_start_matches("0x"), 16)
        .map_err(|_| format!("invalid slide value: {token}"))?;
    if slide > 0x1f8000 || slide % 0x8000 != 0 || matches!(slide, 0x1a0000 | 0x1a8000) {
        return Err(format!("slide is outside the package policy: 0x{slide:x}"));
    }
    Ok(slide)
}

fn root_identity(adb: &Adb, serial: &str, helpers: &[String]) -> Option<String> {
    for helper in helpers {
        let command = format!("{helper} -c id");
        if let Ok(result) = adb.shell(serial, &command, Duration::from_secs(6)) {
            let identity = result.combined();
            if identity.contains("uid=0(root)") && identity.contains("u:r:kernel:s0") {
                return Some(identity);
            }
        }
    }
    None
}

fn run_and_poll_root(
    adb: &Adb,
    serial: &str,
    command: String,
    timeout: Duration,
    helpers: Vec<String>,
    reporter: &Reporter,
) -> Result<String, String> {
    let (sender, receiver) = mpsc::sync_channel(1);
    let worker_adb = adb.clone();
    let worker_serial = serial.to_string();
    thread::spawn(move || {
        let result = worker_adb.shell(&worker_serial, &command, timeout);
        let _ = sender.send(result);
    });
    let started = Instant::now();
    let mut completed: Option<CommandResult> = None;
    let mut completed_at: Option<Instant> = None;
    let mut last_probe = Instant::now() - Duration::from_secs(3);
    let mut last_status = Instant::now();
    loop {
        if last_probe.elapsed() >= Duration::from_secs(2) {
            if let Some(identity) = root_identity(adb, serial, &helpers) {
                return Ok(identity);
            }
            last_probe = Instant::now();
        }
        if last_status.elapsed() >= Duration::from_secs(10) {
            let elapsed = started.elapsed().as_secs();
            if completed.is_some() {
                reporter.info(format!(
                    "{elapsed}s elapsed; payload returned, waiting for root verification"
                ));
            } else {
                reporter.info(format!(
                    "{elapsed}s elapsed; root workflow active, verification probes continuing"
                ));
            }
            last_status = Instant::now();
        }
        if completed.is_none() {
            match receiver.recv_timeout(Duration::from_millis(250)) {
                Ok(Ok(result)) => {
                    completed = Some(result);
                    completed_at = Some(Instant::now());
                }
                Ok(Err(error)) => return Err(coded("ROOT201", error)),
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    return Err(coded("ROOT202", "root worker disconnected"));
                }
            }
        } else {
            thread::sleep(Duration::from_millis(250));
        }
        if completed_at.is_some_and(|finished| finished.elapsed() > Duration::from_secs(18))
            || (completed.is_none() && started.elapsed() > timeout + Duration::from_secs(10))
        {
            break;
        }
    }
    Err(coded(
        "ROOT203",
        match completed {
            Some(result) => format!(
                "root identity was not observed after exploit exit {}: {}",
                result.exit_code,
                result.combined()
            ),
            None => "root identity was not observed before the deadline".into(),
        },
    ))
}

fn outcome(serial: &str, helper: &str, identity: String) -> RootOutcome {
    RootOutcome {
        identity,
        shell_command: format!("adb -s {serial} shell -t \"{helper} -c /system/bin/sh -i\""),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tracefs_parser_requires_source_marker_and_policy() {
        assert_eq!(
            parse_tracefs_slide("slide-kaslr-ok source=tracefs slide=0x1d8000").unwrap(),
            0x1d8000
        );
        assert!(parse_tracefs_slide("slide-kaslr-ok source=app slide=0x1d8000").is_err());
        assert!(parse_tracefs_slide("slide-kaslr-ok source=tracefs slide=0x1a0000").is_err());
    }
}
