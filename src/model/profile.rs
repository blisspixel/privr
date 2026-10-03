//! Built-in profiles and profile ordering.
//!
//! Profiles form an escalating ladder:
//! Baseline <= Strict <= Restrictive
//!
//! Each profile tier is a strict superset of the one before it.

use std::fmt;
use std::str::FromStr;

use clap::ValueEnum;
use serde::{Deserialize, Serialize};

/// Built-in profiles, ordered. Each is a strict superset of the one before it.
///
/// No profile in this ladder contains a control that reduces security. Security
/// tradeoffs are selected deliberately and acknowledged per control.
#[derive(
    Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd, ValueEnum, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum Profile {
    /// Disable passive collection while retaining features and security protections.
    #[default]
    Baseline,
    /// Add controls with real, disclosed functionality tradeoffs.
    Strict,
    /// Add controls with substantial convenience or functionality cost.
    Restrictive,
}

impl Profile {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Baseline => "baseline",
            Self::Strict => "strict",
            Self::Restrictive => "restrictive",
        }
    }

    pub fn parse(s: &str) -> Result<Self, String> {
        s.parse()
    }
}

impl fmt::Display for Profile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Profile {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "baseline" => Ok(Self::Baseline),
            "strict" => Ok(Self::Strict),
            "restrictive" => Ok(Self::Restrictive),
            other => Err(format!(
                "unknown profile '{other}', expected 'baseline', 'strict', or 'restrictive'"
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_ordering_is_monotonic_ladder() {
        assert!(Profile::Baseline < Profile::Strict);
        assert!(Profile::Strict < Profile::Restrictive);
        assert!(Profile::Baseline < Profile::Restrictive);
    }

    #[test]
    fn profile_parsing_and_display() {
        assert_eq!("baseline".parse::<Profile>().unwrap(), Profile::Baseline);
        assert_eq!("strict".parse::<Profile>().unwrap(), Profile::Strict);
        assert_eq!(
            "restrictive".parse::<Profile>().unwrap(),
            Profile::Restrictive
        );
        assert!("unknown".parse::<Profile>().is_err());
        assert_eq!(Profile::parse("baseline").unwrap(), Profile::Baseline);
        assert_eq!(Profile::Baseline.to_string(), "baseline");
    }
}
