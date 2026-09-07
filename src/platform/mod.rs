//! Platform adapters.
//!
//! Each platform module owns its own probing and its own effective-state
//! resolution, because precedence is platform-specific and control-specific.
//! The engine never learns any of it.
//!
//! Modules are gated by target rather than selected at runtime, so code for a
//! platform is not merely unreachable elsewhere, it is not compiled.

#[cfg(windows)]
pub mod windows;

use crate::model::host::HostFacts;

/// Discover the facts this host presents.
///
/// On a platform whose adapters are not implemented, every fact is unknown.
/// That is the honest answer: it leaves every control undetermined rather than
/// reporting a machine as compliant that was never examined.
pub fn discover() -> HostFacts {
    #[cfg(windows)]
    {
        windows::discovery::discover()
    }
    #[cfg(not(windows))]
    {
        HostFacts::unknown(crate::model::host::Platform::current())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::host::Platform;

    #[test]
    fn discovery_reports_the_running_platform() {
        assert_eq!(discover().platform, Platform::current());
    }

    #[cfg(not(windows))]
    #[test]
    fn an_unimplemented_platform_admits_it_knows_nothing() {
        // The property that keeps an unported platform honest: no fact is
        // guessed, so no control can evaluate to a pass.
        let host = discover();
        assert!(host.version.is_unknown());
        assert!(host.edition.is_unknown());
        assert!(host.elevated.is_unknown());
    }
}
