//! Shared CLI/MCP cleanup execution with durable intent and cooperative stopping.

use std::io;
use std::path::Path;

use crate::journal::{JOURNAL_SCHEMA, TransactionJournal};
use crate::model::residue::{
    CleanupJournal, CleanupStatus, CleanupTarget, PurgeMode, PurgeReport, ResiduePurgeItem,
    ResidueSpec, TrimStatus,
};
use crate::platform::cancellation::{Cancellation, SignalGuard};

pub(crate) fn execute(
    mode: PurgeMode,
    targets: &[ResidueSpec],
    trim: bool,
    journal_dir: &Path,
) -> Result<PurgeReport, String> {
    let (_signals, cancellation) = SignalGuard::begin()?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let journal = TransactionJournal {
        schema: JOURNAL_SCHEMA,
        transaction_id: format!(
            "clean-{}-{}-{}",
            now.as_secs(),
            now.subsec_nanos(),
            std::process::id()
        ),
        timestamp: crate::report::format_rfc3339_utc(std::time::SystemTime::now()),
        platform: crate::model::host::Platform::current().as_str().to_owned(),
        profile: format!("clean:{}", mode.as_str()),
        operations: Vec::new(),
        cleanup: Some(CleanupJournal {
            status: CleanupStatus::Running,
            targets: targets
                .iter()
                .map(|spec| CleanupTarget {
                    id: spec.id.clone(),
                    status: CleanupStatus::Pending,
                    files_removed: 0,
                    bytes_removed: 0,
                    files_retained: 0,
                    files_denied: 0,
                })
                .collect(),
            trim: trim.then_some(CleanupStatus::Pending),
        }),
    };
    run_with(
        journal,
        mode,
        targets,
        &cancellation,
        |journal| crate::journal::save_transaction_in(journal_dir, journal).map(|_| ()),
        crate::platform::purge_residue_target,
        crate::platform::execute_volume_trim,
    )
}

fn progress(journal: &mut TransactionJournal) -> &mut CleanupJournal {
    journal.cleanup.as_mut().expect("cleanup transaction")
}

fn checkpoint(
    journal: &mut TransactionJournal,
    save: &mut impl FnMut(&TransactionJournal) -> io::Result<()>,
    error: &mut Option<String>,
) -> bool {
    if save(journal).is_ok() {
        true
    } else {
        progress(journal).status = CleanupStatus::Failed;
        *error = Some("Could not persist cleanup progress; the on-disk record may be incomplete. No further cleanup was attempted.".to_owned());
        false
    }
}

fn run_with(
    mut journal: TransactionJournal,
    mode: PurgeMode,
    targets: &[ResidueSpec],
    cancellation: &Cancellation,
    mut save: impl FnMut(&TransactionJournal) -> io::Result<()>,
    mut purge: impl FnMut(&ResidueSpec, &Cancellation) -> ResiduePurgeItem,
    mut trim: impl FnMut() -> TrimStatus,
) -> Result<PurgeReport, String> {
    save(&journal).map_err(|error| {
        format!(
            "Cannot prepare cleanup journal ({:?}); nothing was cleaned",
            error.kind()
        )
    })?;
    let mut items = Vec::new();
    let mut journal_error = None;
    for (index, spec) in targets.iter().enumerate() {
        if cancellation.requested() {
            progress(&mut journal).status = CleanupStatus::Interrupted;
            break;
        }
        progress(&mut journal).targets[index].status = CleanupStatus::Running;
        if !checkpoint(&mut journal, &mut save, &mut journal_error) {
            break;
        }
        let item = purge(spec, cancellation);
        let status = if cancellation.requested() {
            CleanupStatus::Interrupted
        } else if item.error.is_some() || item.files_retained > 0 || item.files_denied > 0 {
            CleanupStatus::Failed
        } else {
            CleanupStatus::Completed
        };
        progress(&mut journal).targets[index] = CleanupTarget {
            id: spec.id.clone(),
            status,
            files_removed: item.files_removed,
            bytes_removed: item.bytes_reclaimed,
            files_retained: item.files_retained,
            files_denied: item.files_denied,
        };
        items.push(item);
        if status != CleanupStatus::Completed {
            progress(&mut journal).status = status;
        }
        if !checkpoint(&mut journal, &mut save, &mut journal_error)
            || status != CleanupStatus::Completed
        {
            break;
        }
    }
    let mut trim_result = None;
    if cancellation.requested() && progress(&mut journal).status == CleanupStatus::Running {
        progress(&mut journal).status = CleanupStatus::Interrupted;
    }
    if progress(&mut journal).status == CleanupStatus::Running
        && progress(&mut journal).trim.is_some()
    {
        progress(&mut journal).trim = Some(CleanupStatus::Running);
        if checkpoint(&mut journal, &mut save, &mut journal_error) {
            let result = trim();
            let status = if result.executed {
                CleanupStatus::Completed
            } else {
                CleanupStatus::Failed
            };
            progress(&mut journal).trim = Some(status);
            if cancellation.requested() {
                progress(&mut journal).status = CleanupStatus::Interrupted;
            } else if status == CleanupStatus::Failed {
                progress(&mut journal).status = status;
            }
            trim_result = Some(result);
        }
    }
    if progress(&mut journal).status == CleanupStatus::Running {
        progress(&mut journal).status = CleanupStatus::Completed;
    }
    // A failed checkpoint already establishes an unwritable journal. Preserve
    // its unfinished state and the in-memory partial report, without retrying.
    if journal_error.is_none() {
        checkpoint(&mut journal, &mut save, &mut journal_error);
    }
    Ok(PurgeReport {
        schema: 1,
        mode,
        dry_run: false,
        status: Some(progress(&mut journal).status),
        transaction_id: Some(journal.transaction_id),
        journal_error,
        total_files_affected: items.iter().map(|item| item.files_removed).sum(),
        total_bytes_affected: items.iter().map(|item| item.bytes_reclaimed).sum(),
        items,
        trim: trim_result,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::residue::ResidueCategory;
    use std::cell::Cell;

    fn fixtures(trim: bool) -> (Vec<ResidueSpec>, TransactionJournal) {
        let targets: Vec<_> = ["first", "second"]
            .into_iter()
            .map(|id| ResidueSpec {
                id: id.to_owned(),
                title: id.to_owned(),
                category: ResidueCategory::AppCache,
                description: "fixture".to_owned(),
                trade_off: "fixture".to_owned(),
                polite_retained: false,
                requires_risk_ack: false,
            })
            .collect();
        let journal = TransactionJournal {
            schema: JOURNAL_SCHEMA,
            transaction_id: "clean-fixture".to_owned(),
            timestamp: "1.000".to_owned(),
            platform: "linux".to_owned(),
            profile: "clean:aggressive".to_owned(),
            operations: Vec::new(),
            cleanup: Some(CleanupJournal {
                status: CleanupStatus::Running,
                targets: targets
                    .iter()
                    .map(|spec| CleanupTarget {
                        id: spec.id.clone(),
                        status: CleanupStatus::Pending,
                        files_removed: 0,
                        bytes_removed: 0,
                        files_retained: 0,
                        files_denied: 0,
                    })
                    .collect(),
                trim: trim.then_some(CleanupStatus::Pending),
            }),
        };
        (targets, journal)
    }

    fn removed(spec: &ResidueSpec, _: &Cancellation) -> ResiduePurgeItem {
        ResiduePurgeItem {
            id: spec.id.clone(),
            title: spec.title.clone(),
            category: spec.category,
            trade_off: spec.trade_off.clone(),
            files_removed: 2,
            bytes_reclaimed: 20,
            files_retained: 0,
            files_denied: 0,
            error: None,
        }
    }

    fn no_trim() -> TrimStatus {
        panic!("TRIM must not execute")
    }

    #[test]
    fn each_target_is_journaled_before_execution_and_completion_is_explicit() {
        let (targets, journal) = fixtures(false);
        let next = Cell::new(0);
        let mut saved = Vec::new();
        let report = run_with(
            journal,
            PurgeMode::Aggressive,
            &targets,
            &Cancellation::default(),
            |journal| {
                let state = journal.cleanup.as_ref().expect("progress");
                if state
                    .targets
                    .iter()
                    .any(|target| target.status == CleanupStatus::Running)
                {
                    next.set(next.get() + 1);
                }
                saved.push(state.clone());
                Ok(())
            },
            |spec, cancellation| {
                assert_eq!(next.get(), if spec.id == "first" { 1 } else { 2 });
                removed(spec, cancellation)
            },
            no_trim,
        )
        .expect("run");
        assert_eq!(report.status, Some(CleanupStatus::Completed));
        assert_eq!(report.total_files_affected, 4);
        assert_eq!(report.total_bytes_affected, 40);
        assert_eq!(
            saved.first().expect("intent").status,
            CleanupStatus::Running
        );
        let last = saved.last().expect("final checkpoint");
        assert_eq!(last.status, CleanupStatus::Completed);
        assert!(
            last.targets.iter().all(
                |target| target.status == CleanupStatus::Completed && target.files_removed == 2
            )
        );
    }

    #[test]
    fn cancellation_saves_partial_totals_and_never_starts_next_target_or_trim() {
        let (targets, journal) = fixtures(true);
        let cancellation = Cancellation::default();
        let mut saved = Vec::new();
        let report = run_with(
            journal,
            PurgeMode::Aggressive,
            &targets,
            &cancellation,
            |journal| {
                saved.push(journal.clone());
                Ok(())
            },
            |spec, cancellation| {
                assert_eq!(spec.id, "first");
                cancellation.cancel();
                removed(spec, cancellation)
            },
            no_trim,
        )
        .expect("partial report");
        assert_eq!(report.status, Some(CleanupStatus::Interrupted));
        assert_eq!(report.total_files_affected, 2);
        let last = saved.last().unwrap().cleanup.as_ref().unwrap();
        assert_eq!(last.status, CleanupStatus::Interrupted);
        assert_eq!(last.targets[0].status, CleanupStatus::Interrupted);
        assert_eq!(last.targets[0].bytes_removed, 20);
        assert_eq!(last.targets[1].status, CleanupStatus::Pending);
        assert_eq!(last.trim, Some(CleanupStatus::Pending));
    }

    #[test]
    fn cancellation_before_execution_keeps_every_target_pending() {
        let (targets, journal) = fixtures(false);
        let cancellation = Cancellation::default();
        cancellation.cancel();
        let mut last = None;
        let report = run_with(
            journal,
            PurgeMode::Aggressive,
            &targets,
            &cancellation,
            |journal| {
                last = journal.cleanup.clone();
                Ok(())
            },
            |_, _| panic!("cancelled cleanup must not execute"),
            no_trim,
        )
        .unwrap();
        assert_eq!(report.status, Some(CleanupStatus::Interrupted));
        assert!(report.items.is_empty());
        assert!(
            last.unwrap()
                .targets
                .iter()
                .all(|target| target.status == CleanupStatus::Pending)
        );
    }

    #[test]
    fn any_journal_failure_stops_subsequent_mutation_and_keeps_partial_report() {
        // Initial intent, first pre-write, first result, second pre-write,
        // second result, and final completion are all independent failure gates.
        for fail_at in 1..=6 {
            let (targets, journal) = fixtures(false);
            let saves = Cell::new(0);
            let calls = Cell::new(0);
            let mut persisted = None;
            let result = run_with(
                journal,
                PurgeMode::Aggressive,
                &targets,
                &Cancellation::default(),
                |journal| {
                    saves.set(saves.get() + 1);
                    if saves.get() == fail_at {
                        return Err(io::ErrorKind::StorageFull.into());
                    }
                    persisted = journal.cleanup.clone();
                    Ok(())
                },
                |spec, cancellation| {
                    calls.set(calls.get() + 1);
                    removed(spec, cancellation)
                },
                no_trim,
            );
            assert_eq!(
                calls.get(),
                match fail_at {
                    1 | 2 => 0,
                    3 | 4 => 1,
                    _ => 2,
                }
            );
            if fail_at == 1 {
                assert!(result.is_err());
                assert!(persisted.is_none());
            } else {
                let report = result.unwrap();
                assert_eq!(report.status, Some(CleanupStatus::Failed));
                assert_eq!(report.total_files_affected, calls.get() * 2);
                assert!(report.journal_error.is_some());
                assert_eq!(persisted.unwrap().status, CleanupStatus::Running);
            }
        }
    }

    #[test]
    fn retained_files_fail_the_run_and_stop_later_targets() {
        let (targets, journal) = fixtures(false);
        let report = run_with(
            journal,
            PurgeMode::Aggressive,
            &targets,
            &Cancellation::default(),
            |_| Ok(()),
            |spec, cancellation| {
                assert_eq!(spec.id, "first");
                let mut item = removed(spec, cancellation);
                item.files_retained = 1;
                item
            },
            no_trim,
        )
        .unwrap();
        assert_eq!(report.status, Some(CleanupStatus::Failed));
        assert_eq!(report.items.len(), 1);
    }

    #[test]
    fn permission_denied_files_fail_the_run_and_stop_later_targets() {
        let (targets, journal) = fixtures(false);
        let report = run_with(
            journal,
            PurgeMode::Aggressive,
            &targets,
            &Cancellation::default(),
            |_| Ok(()),
            |spec, cancellation| {
                assert_eq!(spec.id, "first");
                let mut item = removed(spec, cancellation);
                item.files_denied = 1;
                item
            },
            no_trim,
        )
        .unwrap();
        assert_eq!(report.status, Some(CleanupStatus::Failed));
        assert_eq!(report.items.len(), 1);
        assert_eq!(report.items[0].files_denied, 1);
    }

    #[test]
    fn trim_is_journaled_before_execution_and_cannot_fail_silently() {
        for success in [true, false] {
            let (_, mut journal) = fixtures(true);
            journal.cleanup.as_mut().unwrap().targets.clear();
            let prepared = Cell::new(false);
            let mut last = None;
            let report = run_with(
                journal,
                PurgeMode::Aggressive,
                &[],
                &Cancellation::default(),
                |journal| {
                    let state = journal.cleanup.as_ref().unwrap();
                    prepared.set(state.trim == Some(CleanupStatus::Running));
                    last = Some(state.clone());
                    Ok(())
                },
                |_, _| panic!("no file targets"),
                || {
                    assert!(prepared.get());
                    TrimStatus {
                        volume: "/".to_owned(),
                        media_type: "fixture".to_owned(),
                        supported: true,
                        executed: success,
                        message: "fixture".to_owned(),
                    }
                },
            )
            .unwrap();
            let expected = if success {
                CleanupStatus::Completed
            } else {
                CleanupStatus::Failed
            };
            assert_eq!(report.status, Some(expected));
            assert_eq!(last.unwrap().trim, Some(expected));
        }
    }
}
