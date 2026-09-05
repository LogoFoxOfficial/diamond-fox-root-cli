use std::io::{self, IsTerminal, Write};

pub struct Reporter {
    color: bool,
}

impl Reporter {
    pub fn new(no_color: bool) -> Self {
        let terminal = io::stdout().is_terminal();
        #[cfg(windows)]
        let supported = enable_windows_virtual_terminal();
        #[cfg(not(windows))]
        let supported = true;
        Self {
            color: !no_color && terminal && supported,
        }
    }

    pub fn info(&self, message: impl AsRef<str>) {
        self.line("[i]", message.as_ref(), "\x1b[90m");
    }

    pub fn step(&self, message: impl AsRef<str>) {
        self.line("[>]", message.as_ref(), "\x1b[36m");
    }

    pub fn ok(&self, message: impl AsRef<str>) {
        self.line("[+]", message.as_ref(), "\x1b[32m");
    }

    pub fn warn(&self, message: impl AsRef<str>) {
        self.line("[!]", message.as_ref(), "\x1b[33m");
    }

    pub fn fail(&self, message: impl AsRef<str>) {
        self.line("[x]", message.as_ref(), "\x1b[31m");
    }

    pub fn error(&self, message: impl std::fmt::Display) {
        self.fail(crate::error::normalized(message));
    }

    pub fn clear(&self) {
        if io::stdout().is_terminal() {
            print!("\x1b[2J\x1b[H");
            let _ = io::stdout().flush();
        }
    }

    fn line(&self, marker: &str, message: &str, color: &str) {
        if self.color {
            println!("{color}{marker}\x1b[0m {message}");
        } else {
            println!("{marker} {message}");
        }
    }

    pub fn confirm(&self, prompt: &str) -> Result<bool, String> {
        print!("{prompt} [y/N]: ");
        io::stdout().flush().map_err(|error| error.to_string())?;
        let mut answer = String::new();
        io::stdin()
            .read_line(&mut answer)
            .map_err(|error| error.to_string())?;
        Ok(matches!(
            answer.trim().to_ascii_lowercase().as_str(),
            "y" | "yes"
        ))
    }
}

#[cfg(windows)]
fn enable_windows_virtual_terminal() -> bool {
    use std::ffi::c_void;

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetStdHandle(handle: u32) -> *mut c_void;
        fn GetConsoleMode(handle: *mut c_void, mode: *mut u32) -> i32;
        fn SetConsoleMode(handle: *mut c_void, mode: u32) -> i32;
    }

    let mut mode = 0u32;
    unsafe {
        let handle = GetStdHandle((-11i32) as u32);
        !handle.is_null()
            && GetConsoleMode(handle, &mut mode) != 0
            && SetConsoleMode(handle, mode | 0x0004) != 0
    }
}
