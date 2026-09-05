mod adb;
mod builtin;
mod cli;
mod interactive;
mod model;
mod output;
mod package;
mod root;
mod state;

use clap::Parser;
use cli::{Cli, Command, PackageCommand};
use model::SupportPackage;
use output::Reporter;
use state::AppDirs;

fn main() {
    let cli = Cli::parse();
    let reporter = Reporter::new(cli.no_color);
    if let Err(error) = run(cli, &reporter) {
        reporter.fail(error);
        std::process::exit(1);
    }
}

fn run(cli: Cli, reporter: &Reporter) -> Result<(), String> {
    let data_dir = cli.data_dir.clone();
    let dirs = AppDirs::discover(data_dir)?;
    builtin::verify_embedded()?;
    let embedded_adb = if cli.adb.is_none() && std::env::var_os("DIAMONDFOX_ADB").is_none() {
        builtin::ensure_embedded_adb(&dirs)?
    } else {
        None
    };
    let adb = adb::Adb::discover(cli.adb.or(embedded_adb));
    match cli.command {
        None => {
            interactive::run(&adb, &dirs, reporter)?;
        }
        Some(Command::Devices { json }) => {
            let devices = adb.list_supported()?;
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&devices).map_err(|error| error.to_string())?
                );
            } else if devices.is_empty() {
                reporter.info("No supported Samsung device detected");
            } else {
                for device in devices {
                    reporter.ok(format!(
                        "{}  {}  {}",
                        device.serial, device.state, device.model_hint
                    ));
                }
            }
        }
        Some(Command::Inspect { serial, json }) => {
            let device = adb.select_supported(serial.as_deref())?;
            let snapshot = adb.snapshot(&device.serial)?;
            let packages = installed_packages(&dirs)?;
            let selected = root::select_package(&packages, &snapshot).ok();
            let guard = state::guard_for_boot(&dirs, &device.serial, &snapshot.boot_id);
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "serial": device.serial,
                        "device": snapshot,
                        "package": selected.map(|package| serde_json::json!({
                            "id": package.manifest.id,
                            "version": package.manifest.version,
                            "name": package.manifest.name,
                            "workflow": package.manifest.workflow,
                        })),
                        "boot_guard": guard,
                    }))
                    .map_err(|error| error.to_string())?
                );
            } else {
                reporter.ok(format!("Model: {} / {}", snapshot.model, snapshot.device));
                reporter.info(format!("Build: {}", snapshot.display));
                reporter.info(format!("Bootloader: {}", snapshot.bootloader));
                reporter.info(format!("Kernel: {}", snapshot.kernel));
                reporter.info(format!("Verified Boot: {}", snapshot.verified_boot));
                reporter.info(format!("Flash locked: {}", snapshot.flash_locked));
                reporter.info(format!("Boot ID: {}", snapshot.boot_id));
                if let Some(package) = selected {
                    reporter.ok(format!("Root method available: {}", package.manifest.name));
                } else {
                    reporter.fail("No installed root package matches this exact firmware");
                }
                if let Some(guard) = guard {
                    reporter.fail(format!("Boot attempt guard: {}", guard.state));
                }
            }
        }
        Some(Command::Package { command }) => match command {
            PackageCommand::Install {
                path,
                accept_unsigned,
            } => {
                if !accept_unsigned {
                    return Err(
                        "schema 1 packages are unsigned; inspect the source and repeat with --accept-unsigned"
                            .into(),
                    );
                }
                let installed = package::install_dfx(&dirs, &path)?;
                reporter.ok(format!(
                    "Installed {} {}",
                    installed.manifest.name, installed.manifest.version
                ));
                reporter.info(format!("Package SHA-256: {}", installed.package_sha256));
            }
            PackageCommand::Verify { path } => {
                let verified = package::verify_dfx(&path)?;
                reporter.ok(format!(
                    "Valid DFX structure: {} {}",
                    verified.manifest.name, verified.manifest.version
                ));
                reporter.info(format!("Package SHA-256: {}", verified.package_sha256));
                reporter.info("Publisher authenticity: not available in schema 1");
            }
            PackageCommand::List { json } => {
                let packages = installed_packages(&dirs)?;
                if json {
                    let values: Vec<_> = packages
                        .iter()
                        .map(|package| {
                            serde_json::json!({
                                "id": package.manifest.id,
                                "version": package.manifest.version,
                                "name": package.manifest.name,
                                "workflow": package.manifest.workflow,
                                "model": package.manifest.gate.model,
                                "bootloader": package.manifest.gate.bootloader,
                                "package_sha256": package.package_sha256,
                            })
                        })
                        .collect();
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&values).map_err(|error| error.to_string())?
                    );
                } else if packages.is_empty() {
                    reporter.info(format!(
                        "No support packages installed in {}",
                        dirs.packages.display()
                    ));
                } else {
                    for package in packages {
                        reporter.ok(format!(
                            "{} {}  {}  {}",
                            package.manifest.id,
                            package.manifest.version,
                            package.manifest.gate.model,
                            package.manifest.gate.bootloader
                        ));
                    }
                }
            }
        },
        Some(Command::Root { serial, yes }) => {
            let packages = installed_packages(&dirs)?;
            if packages.is_empty() {
                return Err(format!(
                    "no support packages installed; use 'package install <file>.dfx --accept-unsigned' first\npackage directory: {}",
                    dirs.packages.display()
                ));
            }
            if let Some(outcome) =
                root::run(&adb, &dirs, &packages, serial.as_deref(), yes, reporter)?
            {
                reporter.info(format!("Identity: {}", outcome.identity.trim()));
                println!();
                println!("Root shell:");
                println!("{}", outcome.shell_command);
            }
        }
    }
    Ok(())
}

fn installed_packages(dirs: &AppDirs) -> Result<Vec<SupportPackage>, String> {
    builtin::available_packages(dirs)
}
