use std::io::{self, IsTerminal, Write};

pub struct Reporter {
    color: bool,
}

impl Reporter {
    pub fn new(no_color: bool) -> Self {
        Self {
            color: !no_color && io::stdout().is_terminal(),
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

    pub fn fail(&self, message: impl AsRef<str>) {
        self.line("[x]", message.as_ref(), "\x1b[31m");
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
