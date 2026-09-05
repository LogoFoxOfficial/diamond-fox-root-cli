use std::fmt::Display;

pub fn coded(code: &str, message: impl Display) -> String {
    format!("[DF-{code}] {message}")
}

pub fn normalized(message: impl Display) -> String {
    let message = message.to_string();
    if message.starts_with("[DF-") {
        message
    } else {
        coded("E000", message)
    }
}

pub trait ErrorCodeExt<T> {
    fn with_code(self, code: &str) -> Result<T, String>;
}

impl<T, E: Display> ErrorCodeExt<T> for Result<T, E> {
    fn with_code(self, code: &str) -> Result<T, String> {
        self.map_err(|error| {
            let message = error.to_string();
            if message.starts_with("[DF-") {
                message
            } else {
                coded(code, message)
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalization_preserves_existing_codes() {
        assert_eq!(normalized("failure"), "[DF-E000] failure");
        assert_eq!(normalized("[DF-ADB001] failure"), "[DF-ADB001] failure");
        let result: Result<(), &str> = Err("failure");
        assert_eq!(
            result.with_code("TEST001").unwrap_err(),
            "[DF-TEST001] failure"
        );
        let result: Result<(), &str> = Err("[DF-TEST001] failure");
        assert_eq!(
            result.with_code("OTHER").unwrap_err(),
            "[DF-TEST001] failure"
        );
    }
}
