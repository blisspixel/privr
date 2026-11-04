//! Absolute user roots for Unix storage. Invalid overrides use the home default.

use std::ffi::OsString;
use std::path::PathBuf;

pub(crate) fn absolute(value: Option<OsString>) -> Option<PathBuf> {
    value.map(PathBuf::from).filter(|path| path.is_absolute())
}

pub(crate) fn home_dir() -> Option<PathBuf> {
    absolute(std::env::var_os("HOME"))
}

pub(crate) fn resolve(
    value: Option<OsString>,
    home: Option<OsString>,
    default: &str,
) -> Option<PathBuf> {
    absolute(value).or_else(|| absolute(home).map(|root| root.join(default)))
}

pub(crate) fn user_root(variable: &str, default: &str) -> Option<PathBuf> {
    resolve(
        std::env::var_os(variable),
        std::env::var_os("HOME"),
        default,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn overrides_and_home_defaults_must_be_absolute() {
        for default in [".cache", ".config", ".local/share"] {
            for invalid in [None, Some(""), Some("relative/root")] {
                assert_eq!(
                    resolve(
                        invalid.map(Into::into),
                        Some("/home/fixture".into()),
                        default
                    ),
                    Some(PathBuf::from("/home/fixture").join(default))
                );
                for home in [None, Some(""), Some("relative/home")] {
                    assert_eq!(
                        resolve(invalid.map(Into::into), home.map(Into::into), default),
                        None
                    );
                }
            }
            for home in [None, Some(""), Some("relative/home"), Some("/home/fixture")] {
                assert_eq!(
                    resolve(
                        Some("/absolute/override".into()),
                        home.map(Into::into),
                        default
                    ),
                    Some(PathBuf::from("/absolute/override"))
                );
            }
        }
    }
}
