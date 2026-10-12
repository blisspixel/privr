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

pub fn context<'a>(host: &'a HostFacts, reader: &'a Reader) -> Context<'a> {
    Context {
        host,
        linux: reader,
    }
}
