use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "diamond-fox-root")]
#[command(version)]
#[command(about = "Temporary root manager for supported Samsung devices")]
pub struct Cli {
    #[arg(
        long,
        global = true,
        value_name = "PATH",
        help = "Path to adb.exe. Overrides DIAMONDFOX_ADB and PATH"
    )]
    pub adb: Option<PathBuf>,

    #[arg(
        long,
        global = true,
        value_name = "PATH",
        help = "Directory for installed packages and persistent boot guards"
    )]
    pub data_dir: Option<PathBuf>,

    #[arg(long, global = true, help = "Disable ANSI colors")]
    pub no_color: bool,

    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Subcommand)]
pub enum Command {
    #[command(about = "List connected supported Samsung devices")]
    Devices {
        #[arg(long, help = "Print machine-readable JSON")]
        json: bool,
    },
    #[command(about = "Show the exact device identity, package match, and boot guard")]
    Inspect {
        #[arg(
            long,
            help = "Select one ADB serial when multiple supported devices are online"
        )]
        serial: Option<String>,
        #[arg(long, help = "Print machine-readable JSON")]
        json: bool,
    },
    #[command(about = "Verify, install, or list DFX support packages")]
    Package {
        #[command(subcommand)]
        command: PackageCommand,
    },
    #[command(about = "Start one temporary-root attempt on the current Android boot")]
    Root {
        #[arg(
            long,
            help = "Select one ADB serial when multiple supported devices are online"
        )]
        serial: Option<String>,
        #[arg(long, help = "Skip the interactive interruption warning")]
        yes: bool,
    },
}

#[derive(Subcommand)]
pub enum PackageCommand {
    #[command(about = "Verify and install a DFX package")]
    Install {
        #[arg(help = "DFX package to install")]
        path: PathBuf,
        #[arg(long, help = "Accept schema 1 without publisher authentication")]
        accept_unsigned: bool,
    },
    #[command(about = "Validate a DFX package without installing it")]
    Verify {
        #[arg(help = "DFX package to verify")]
        path: PathBuf,
    },
    #[command(about = "List installed support packages")]
    List {
        #[arg(long, help = "Print machine-readable JSON")]
        json: bool,
    },
}
