//! Typed raw observations for tests of the real compiled Linux catalogue.

use std::collections::BTreeMap;

use crate::catalog::Context;
use crate::model::evidence::{Evidence, RawValue, ValueKind};
use crate::model::host::{Fact, HostFacts, ManagementSource, Platform};
use crate::platform::linux::evidence::{Reader, Target};
use crate::platform::linux::systemd::{
    ConfigurationEvidence, ConfigurationFamily, ConfigurationFile, ConfigurationRoot,
    DirectoryListing, RootEvidence,
};

pub fn host(distribution: &str, desktop: &str) -> HostFacts {
    let mut host = HostFacts::unknown(Platform::Linux);
    host.distribution = Fact::Known(distribution.to_owned());
    host.session.desktop = Fact::Known(desktop.to_owned());
    host.session.live_session = Fact::Known(true);
    host
}

pub fn text(bytes: &[u8]) -> Evidence {
    Evidence::Present {
        source: ManagementSource::Unknown,
        value: RawValue::new(ValueKind::String, bytes.to_vec()),
    }
}

pub fn absent() -> Evidence {
    Evidence::Absent {
        source: ManagementSource::Unknown,
    }
}

pub fn present_flag() -> Evidence {
    Evidence::Present {
        source: ManagementSource::Unknown,
        value: RawValue::new(ValueKind::Bool, vec![1]),
    }
}

const FSTRIM_UNIT: &[u8] = b"[Timer]\nOnCalendar=weekly\n";

/// Record the fstrim unit search path and the three wants symlinks.
///
/// `loaded` is one unit path whose bytes are present. Every other unit path
/// is absent. `wants_present` are the wants symlinks that exist.
pub fn fstrim(
    loaded: Option<(Target, &[u8])>,
    wants_present: &[Target],
) -> Vec<(Target, Evidence)> {
    let units = [
        Target::FstrimUnitEtc,
        Target::FstrimUnitRun,
        Target::FstrimUnitLocal,
        Target::FstrimUnitUsr,
        Target::FstrimUnitLib,
    ];
    let wants = [Target::FstrimAdmin, Target::FstrimLib, Target::FstrimVendor];
    let mut entries = Vec::with_capacity(units.len() + wants.len());
    for target in units {
        let evidence = match loaded {
            Some((chosen, bytes)) if chosen == target => text(bytes),
            _ => absent(),
        };
        entries.push((target, evidence));
    }
    for target in wants {
        let evidence = if wants_present.contains(&target) {
            present_flag()
        } else {
            absent()
        };
        entries.push((target, evidence));
    }
    entries
}

/// Vendor wants symlink, with a non-empty unit file and no mask above it.
pub fn fstrim_enabled() -> Vec<(Target, Evidence)> {
    fstrim(
        Some((Target::FstrimUnitUsr, FSTRIM_UNIT)),
        &[Target::FstrimVendor],
    )
}

/// A loadable unit with no wants symlink.
pub fn fstrim_disabled() -> Vec<(Target, Evidence)> {
    fstrim(Some((Target::FstrimUnitUsr, FSTRIM_UNIT)), &[])
}

/// Admin unit file empty, which masks the timer, while a vendor wants
/// symlink and a lower unit file are also recorded.
pub fn fstrim_masked() -> Vec<(Target, Evidence)> {
    let mut entries = fstrim(
        Some((
            Target::FstrimUnitUsr,
            b"[Timer]\nOnCalendar=weekly\n# /home/secret-user\n",
        )),
        &[Target::FstrimVendor],
    );
    for (target, evidence) in &mut entries {
        if *target == Target::FstrimUnitEtc {
            *evidence = text(b"");
        }
    }
    entries
}

pub fn reader(entries: impl IntoIterator<Item = (Target, Evidence)>) -> Reader {
    Reader::recorded(entries.into_iter().collect::<BTreeMap<_, _>>())
}

pub fn configuration(bytes: &[u8]) -> ConfigurationEvidence {
    let mut evidence = ConfigurationEvidence::default();
    for root in [
        ConfigurationRoot::Etc,
        ConfigurationRoot::Run,
        ConfigurationRoot::UsrLocalLib,
        ConfigurationRoot::UsrLib,
    ] {
        evidence.roots.insert(
            root,
            RootEvidence {
                main: if root == ConfigurationRoot::Etc {
                    ConfigurationFile::Regular(RawValue::new(ValueKind::String, bytes.to_vec()))
                } else {
                    ConfigurationFile::Absent
                },
                before: DirectoryListing::Absent,
                after: DirectoryListing::Absent,
                files: BTreeMap::new(),
            },
        );
    }
    evidence
}

pub fn configuration_reader(family: ConfigurationFamily, bytes: &[u8]) -> Reader {
    Reader::recorded_with_configurations(
        BTreeMap::new(),
        BTreeMap::from([(family, configuration(bytes))]),
    )
}

pub fn reader_with_exposure(
    entries: impl IntoIterator<Item = (Target, Evidence)>,
    exposure: crate::platform::linux::exposure::ExposureRecords,
) -> Reader {
    Reader::recorded_with_exposure(entries.into_iter().collect(), BTreeMap::new(), exposure)
}

pub fn context<'a>(host: &'a HostFacts, reader: &'a Reader) -> Context<'a> {
    Context {
        host,
        linux: reader,
    }
}
