use crate::adb::Adb;
use crate::model::{DeviceSnapshot, SupportPackage};
use crate::output::Reporter;
use crate::package;
use crate::root;
use crate::state::{self, AppDirs};
use std::io::{self, Write};
use std::path::PathBuf;

pub fn run(adb: &Adb, dirs: &AppDirs, reporter: &Reporter) -> Result<(), String> {
    loop {
        reporter.clear();
        println!("DiamondFox Root");
        println!("===============");
        show_device_summary(adb, dirs, reporter);
        println!();
        println!("  1  Start temporary root");
        println!("  2  Device information");
        println!("  3  Install support package");
        println!("  4  Installed packages");
        println!("  5  Refresh");
        println!("  0  Exit");
        println!();

        match prompt("Select")?.as_str() {
            "1" => run_root(adb, dirs, reporter),
            "2" => show_device(adb, dirs, reporter),
            "3" => install_package(dirs, reporter),
            "4" => show_packages(dirs, reporter),
            "5" => continue,
            "0" | "q" | "quit" | "exit" => return Ok(()),
            _ => {
                reporter.error(crate::error::coded("UI001", "unknown selection"));
                pause();
            }
        }
    }
}

fn show_device_summary(adb: &Adb, dirs: &AppDirs, reporter: &Reporter) {
    let devices = match adb.list_supported() {
        Ok(devices) => devices
            .into_iter()
            .filter(|device| device.state == "device")
            .collect::<Vec<_>>(),
        Err(error) => {
            reporter.error(crate::error::coded(
                "ADB005",
                format!("ADB unavailable: {error}"),
            ));
            return;
        }
    };
    match devices.as_slice() {
        [] => reporter.info("Device: no supported Samsung phone connected"),
        [device] => match adb.snapshot(&device.serial) {
            Ok(snapshot) => {
                println!("Device       {} / {}", snapshot.model, snapshot.device);
                println!("Firmware     {}", snapshot.display);
                println!("Kernel       {}", snapshot.kernel);
                let packages = installed_packages(dirs).unwrap_or_default();
                match root::select_package(&packages, &snapshot) {
                    Ok(package) => {
                        println!("Root method  {}", package.manifest.name);
                        for warning in package.manifest.gate.warnings(&snapshot) {
                            reporter.warn(warning);
                        }
                    }
                    Err(_) => println!("Root method  Not available for this exact build"),
                }
                if let Some(guard) = state::guard_for_boot(dirs, &device.serial, &snapshot.boot_id)
                {
                    println!("Boot guard   {}", guard.state);
                } else {
                    println!("Boot guard   Ready");
                }
            }
            Err(error) => reporter.error(format!("Device inspection failed: {error}")),
        },
        _ => reporter.info(format!(
            "Device: {} supported phones connected",
            devices.len()
        )),
    }
}

fn run_root(adb: &Adb, dirs: &AppDirs, reporter: &Reporter) {
    let result = (|| {
        let serial = choose_device(adb)?;
        let packages = installed_packages(dirs)?;
        if packages.is_empty() {
            return Err(crate::error::coded(
                "PKG001",
                "no support package is installed",
            ));
        }
        root::run(adb, dirs, &packages, Some(&serial), false, reporter)
    })();
    match result {
        Ok(Some(outcome)) => {
            reporter.ok("Temporary root is ready");
            println!();
            println!("Root shell:");
            println!("{}", outcome.shell_command);
        }
        Ok(None) => {}
        Err(error) => reporter.error(error),
    }
    pause();
}

fn show_device(adb: &Adb, dirs: &AppDirs, reporter: &Reporter) {
    let result = choose_device(adb).and_then(|serial| {
        let snapshot = adb.snapshot(&serial)?;
        print_snapshot(&serial, &snapshot, dirs);
        Ok(())
    });
    if let Err(error) = result {
        reporter.error(error);
    }
    pause();
}

fn print_snapshot(serial: &str, snapshot: &DeviceSnapshot, dirs: &AppDirs) {
    println!();
    println!("Serial         {serial}");
    println!("Model          {}", snapshot.model);
    println!("Device         {}", snapshot.device);
    println!("Build          {}", snapshot.display);
    println!("Bootloader     {}", snapshot.bootloader);
    println!("Android        {}", snapshot.release);
    println!("Kernel         {}", snapshot.kernel);
    println!("Verified Boot  {}", snapshot.verified_boot);
    println!("Flash locked   {}", snapshot.flash_locked);
    println!("Boot complete  {}", snapshot.boot_completed);
    if let Some(guard) = state::guard_for_boot(dirs, serial, &snapshot.boot_id) {
        println!("Boot guard     {}", guard.state);
    } else {
        println!("Boot guard     Ready");
    }
}

fn install_package(dirs: &AppDirs, reporter: &Reporter) {
    let result = (|| {
        let input = prompt("Path to .dfx package")?;
        let path = PathBuf::from(input.trim_matches('"'));
        let verified = package::verify_dfx(&path)?;
        println!();
        println!("Package       {}", verified.manifest.name);
        println!("Version       {}", verified.manifest.version);
        println!("Model         {}", verified.manifest.gate.model);
        println!("Bootloader    {}", verified.manifest.gate.bootloader);
        println!("SHA-256       {}", verified.package_sha256);
        reporter.warn("Publisher authentication is not available for schema 1 packages");
        if !reporter.confirm("Install this unsigned package")? {
            return Ok(None);
        }
        package::install_dfx(dirs, &path).map(Some)
    })();
    match result {
        Ok(Some(installed)) => reporter.ok(format!(
            "Installed {} {}",
            installed.manifest.name, installed.manifest.version
        )),
        Ok(None) => reporter.info("Installation cancelled"),
        Err(error) => reporter.error(error),
    }
    pause();
}

fn show_packages(dirs: &AppDirs, reporter: &Reporter) {
    match installed_packages(dirs) {
        Ok(packages) if packages.is_empty() => reporter.info("No support packages installed"),
        Ok(packages) => {
            println!();
            for package in packages {
                println!(
                    "{} {}  {}  {}",
                    package.manifest.name,
                    package.manifest.version,
                    package.manifest.gate.model,
                    package.manifest.gate.bootloader
                );
            }
        }
        Err(error) => reporter.error(error),
    }
    pause();
}

fn choose_device(adb: &Adb) -> Result<String, String> {
    let devices = adb
        .list_supported()?
        .into_iter()
        .filter(|device| device.state == "device")
        .collect::<Vec<_>>();
    match devices.as_slice() {
        [] => Err(crate::error::coded(
            "ADB006",
            "no supported Samsung device is online",
        )),
        [device] => Ok(device.serial.clone()),
        _ => {
            println!();
            println!("Supported devices:");
            for (index, device) in devices.iter().enumerate() {
                println!("  {}  {}  {}", index + 1, device.model_hint, device.serial);
            }
            let selection = prompt("Select device")?
                .parse::<usize>()
                .map_err(|_| crate::error::coded("UI002", "invalid device selection"))?;
            devices
                .get(selection.saturating_sub(1))
                .map(|device| device.serial.clone())
                .ok_or_else(|| crate::error::coded("UI002", "invalid device selection"))
        }
    }
}

fn installed_packages(dirs: &AppDirs) -> Result<Vec<SupportPackage>, String> {
    crate::builtin::available_packages(dirs)
}

fn prompt(label: &str) -> Result<String, String> {
    print!("{label}: ");
    io::stdout().flush().map_err(|error| error.to_string())?;
    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .map_err(|error| error.to_string())?;
    Ok(input.trim().to_string())
}

fn pause() {
    let _ = prompt("Press Enter to continue");
}
