//! Bounded reads of the Linux catalogue's existing compiled file targets.

use std::collections::BTreeMap;
use std::io::Read;
use std::path::PathBuf;

use super::exposure::{
    self, AvahiFiles, ExposureRecords, NmFiles, ResolvedRecord, ThumbnailRecord,
};
use super::systemd::{self, ConfigurationEvidence, ConfigurationFamily};
use crate::engine::evaluate::Uncertainty;
use crate::model::evidence::{DenialReason, Evidence, RawValue, UndeterminedReason, ValueKind};
use crate::model::host::ManagementSource;

pub const MAX_FILE_BYTES: usize = 64 * 1024;

/// No caller-supplied path or command can become a probe target.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Target {
    DebianPopcon,
    FedoraAbrt,
    UbuntuInsights,
    UbuntuReport,
    KdeFeedback,
    FstrimAdmin,
    FstrimLib,
    FstrimVendor,
}

impl Target {
    fn path(self) -> Option<PathBuf> {
        Some(match self {
            Self::DebianPopcon => "/etc/popularity-contest.conf".into(),
            Self::FedoraAbrt => "/etc/abrt/abrt-action-save-package-data.conf".into(),
            Self::UbuntuInsights => "/etc/ubuntu-insights/opt-in".into(),
            Self::UbuntuReport => {
                PathBuf::from(std::env::var_os("HOME")?).join(".cache/ubuntu-report/metrics.json")
            }
            Self::KdeFeedback => {
                PathBuf::from(std::env::var_os("HOME")?).join(".config/KDE/UserFeedback.conf")
            }
            Self::FstrimAdmin => "/etc/systemd/system/timers.target.wants/fstrim.timer".into(),
            Self::FstrimLib => "/lib/systemd/system/timers.target.wants/fstrim.timer".into(),
            Self::FstrimVendor => "/usr/lib/systemd/system/timers.target.wants/fstrim.timer".into(),
        })
    }

    fn presence_only(self) -> bool {
        matches!(
            self,
            Self::UbuntuInsights
                | Self::UbuntuReport
                | Self::FstrimAdmin
                | Self::FstrimLib
                | Self::FstrimVendor
        )
    }
}

#[derive(Debug)]
pub struct Recording {
    entries: BTreeMap<Target, Evidence>,
    configurations: BTreeMap<ConfigurationFamily, ConfigurationEvidence>,
    exposure: Box<ExposureRecords>,
    #[cfg(test)]
    requested: std::sync::Mutex<Vec<Target>>,
    #[cfg(test)]
    requested_configurations: std::sync::Mutex<Vec<ConfigurationFamily>>,
}

#[derive(Debug, Default)]
pub enum Reader {
    #[default]
    Live,
    Recorded(Recording),
}

impl Reader {
    pub fn recorded(entries: BTreeMap<Target, Evidence>) -> Self {
        Self::recorded_with_configurations(entries, BTreeMap::new())
    }

    pub fn recorded_with_configurations(
        entries: BTreeMap<Target, Evidence>,
        configurations: BTreeMap<ConfigurationFamily, ConfigurationEvidence>,
    ) -> Self {
        Self::recorded_with_exposure(entries, configurations, ExposureRecords::default())
    }

    pub fn recorded_with_exposure(
        entries: BTreeMap<Target, Evidence>,
        configurations: BTreeMap<ConfigurationFamily, ConfigurationEvidence>,
        exposure: ExposureRecords,
    ) -> Self {
        Self::Recorded(Recording {
            entries,
            configurations,
            exposure: Box::new(exposure),
            #[cfg(test)]
            requested: std::sync::Mutex::default(),
            #[cfg(test)]
            requested_configurations: std::sync::Mutex::default(),
        })
    }

    pub fn network_manager(&self) -> Option<NmFiles> {
        match self {
            Self::Live => exposure::read_live_network_manager(),
            Self::Recorded(recording) => recording.exposure.network_manager.clone(),
        }
    }

    pub fn avahi(&self) -> Option<AvahiFiles> {
        match self {
            Self::Live => exposure::read_live_avahi(),
            Self::Recorded(recording) => recording.exposure.avahi.clone(),
        }
    }

    pub fn resolved(&self) -> Option<ResolvedRecord> {
        match self {
            Self::Live => exposure::read_live_resolved(),
            Self::Recorded(recording) => recording.exposure.resolved.clone(),
        }
    }

    pub fn thumbnails(&self) -> Option<ThumbnailRecord> {
        match self {
            Self::Live => exposure::read_live_thumbnails(),
            Self::Recorded(recording) => recording.exposure.thumbnails.clone(),
        }
    }

    pub fn configuration(
        &self,
        family: ConfigurationFamily,
    ) -> crate::engine::evaluate::Resolution {
        match self {
            Self::Live => systemd::resolve(family, &systemd::read_live(family)),
            Self::Recorded(recording) => {
                #[cfg(test)]
                recording
                    .requested_configurations
                    .lock()
                    .expect("recorded trace lock")
                    .push(family);
                systemd::resolve(
                    family,
                    recording
                        .configurations
                        .get(&family)
                        .unwrap_or(&ConfigurationEvidence::default()),
                )
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn requested_configurations(&self) -> Vec<ConfigurationFamily> {
        match self {
            Self::Recorded(recording) => recording
                .requested_configurations
                .lock()
                .expect("recorded trace lock")
                .clone(),
            Self::Live => panic!("recorded read trace requires a recording"),
        }
    }

    #[cfg(test)]
    pub(crate) fn requested(&self) -> Vec<Target> {
        match self {
            Self::Recorded(recording) => recording
                .requested
                .lock()
                .expect("recorded trace lock")
                .clone(),
            Self::Live => panic!("recorded read trace requires a recording"),
        }
    }

    fn read(&self, target: Target) -> Evidence {
        match self {
            Self::Live => read_live(target),
            Self::Recorded(recording) => {
                #[cfg(test)]
                recording
                    .requested
                    .lock()
                    .expect("recorded trace lock")
                    .push(target);
                recording
                    .entries
                    .get(&target)
                    .cloned()
                    .unwrap_or(Evidence::Undetermined {
                        source: ManagementSource::Unknown,
                        reason: UndeterminedReason::NoResult,
                    })
            }
        }
    }

    pub fn text(&self, target: Target) -> Result<Option<String>, Uncertainty> {
        match self.read(target) {
            Evidence::Absent { .. } => Ok(None),
            Evidence::Present { value, .. } if value.kind == ValueKind::String => {
                if value.bytes.len() > MAX_FILE_BYTES {
                    return Err(Uncertainty::Undetermined);
                }
                String::from_utf8(value.bytes)
                    .map(Some)
                    .map_err(|_| Uncertainty::Malformed)
            }
            other => Err(uncertainty(&other)),
        }
    }

    pub fn exists(&self, target: Target) -> Result<bool, Uncertainty> {
        match self.read(target) {
            Evidence::Absent { .. } => Ok(false),
            Evidence::Present { value, .. }
                if value.kind == ValueKind::Bool && value.bytes == [1] =>
            {
                Ok(true)
            }
            other => Err(uncertainty(&other)),
        }
    }
}

fn uncertainty(evidence: &Evidence) -> Uncertainty {
    match evidence {
        Evidence::Denied { .. } => Uncertainty::Denied,
        Evidence::Present { .. } | Evidence::Malformed { .. } => Uncertainty::Malformed,
        Evidence::Unsupported { .. } | Evidence::Undetermined { .. } | Evidence::Absent { .. } => {
            Uncertainty::Undetermined
        }
    }
}

fn read_live(target: Target) -> Evidence {
    let source = ManagementSource::Unknown;
    let Some(path) = target.path() else {
        return Evidence::Undetermined {
            source,
            reason: UndeterminedReason::HostFactUnknown,
        };
    };
    let read = if target.presence_only() {
        std::fs::metadata(path).map(|_| RawValue::new(ValueKind::Bool, vec![1]))
    } else {
        std::fs::File::open(path).and_then(|file| {
            let mut bytes = Vec::new();
            file.take(MAX_FILE_BYTES as u64 + 1)
                .read_to_end(&mut bytes)?;
            Ok(RawValue::new(ValueKind::String, bytes))
        })
    };
    match read {
        Ok(value) => Evidence::Present { source, value },
        Err(error) => match error.kind() {
            std::io::ErrorKind::NotFound => Evidence::Absent { source },
            std::io::ErrorKind::PermissionDenied => Evidence::Denied {
                source,
                reason: DenialReason::Permission,
            },
            _ => Evidence::Undetermined {
                source,
                reason: UndeterminedReason::ProbeFailed,
            },
        },
    }
}
