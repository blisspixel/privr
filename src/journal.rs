//! Transaction journal for verified mutation and rollback.
//!
//! Stores applied operations durably by transaction ID. Every operation records
//! its exact preimage (prior state, type, and raw bytes) and postimage, so that
//! rollback can verify no external changes occurred before restoring prior state.

use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::model::evidence::RawValue;

/// Schema version for transaction records.
pub const JOURNAL_SCHEMA: u8 = 1;

/// One journaled operation within a transaction.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct OperationJournal {
    pub control_id: String,
    pub target_key: String,
    pub preimage: Option<RawValue>,
    pub postimage: RawValue,
    pub verified: bool,
}

/// A completed mutation transaction.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct TransactionJournal {
    pub schema: u8,
    pub transaction_id: String,
    pub timestamp: String,
    pub platform: String,
    pub profile: String,
    pub operations: Vec<OperationJournal>,
}

/// Validate that a transaction ID contains only allowed characters and no path navigation.
pub fn is_valid_transaction_id(id: &str) -> bool {
    if id.is_empty() || id.len() > 128 {
        return false;
    }
    id.chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

/// The base directory where transaction journals are stored.
pub fn transactions_dir() -> PathBuf {
    #[cfg(windows)]
    {
        if let Ok(appdata) = std::env::var("LOCALAPPDATA") {
            PathBuf::from(appdata)
                .join("privr")
                .join("state")
                .join("transactions")
        } else if let Ok(profile) = std::env::var("USERPROFILE") {
            PathBuf::from(profile)
                .join("AppData")
                .join("Local")
                .join("privr")
                .join("state")
                .join("transactions")
        } else {
            PathBuf::from(r"C:\ProgramData\privr\state\transactions")
        }
    }
    #[cfg(not(windows))]
    {
        if let Ok(xdg) = std::env::var("XDG_DATA_HOME") {
            PathBuf::from(xdg)
                .join("privr")
                .join("state")
                .join("transactions")
        } else if let Ok(home) = std::env::var("HOME") {
            PathBuf::from(home)
                .join(".local")
                .join("share")
                .join("privr")
                .join("state")
                .join("transactions")
        } else {
            std::env::temp_dir()
                .join("privr")
                .join("state")
                .join("transactions")
        }
    }
}

/// Write a transaction to disk atomically.
pub fn save_transaction(tx: &TransactionJournal) -> Result<PathBuf, std::io::Error> {
    save_transaction_in(&transactions_dir(), tx)
}

pub(crate) fn save_transaction_in(
    dir: &Path,
    tx: &TransactionJournal,
) -> Result<PathBuf, std::io::Error> {
    if !is_valid_transaction_id(&tx.transaction_id) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Invalid transaction identifier",
        ));
    }
    fs::create_dir_all(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(metadata) = fs::metadata(dir) {
            let mut perms = metadata.permissions();
            perms.set_mode(0o700);
            let _ = fs::set_permissions(dir, perms);
        }
    }
    let final_path = dir.join(format!("{}.json", tx.transaction_id));
    if final_path.is_symlink() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "Symlinks are not permitted for transaction journals",
        ));
    }
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let tmp_path = dir.join(format!(
        "{}.tmp.{}.{}",
        tx.transaction_id,
        std::process::id(),
        nanos
    ));
    let content = serde_json::to_string_pretty(tx)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    fs::write(&tmp_path, content)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(metadata) = fs::metadata(&tmp_path) {
            let mut perms = metadata.permissions();
            perms.set_mode(0o600);
            let _ = fs::set_permissions(&tmp_path, perms);
        }
    }
    if let Err(e) = fs::rename(&tmp_path, &final_path) {
        let _ = fs::remove_file(&tmp_path);
        return Err(e);
    }
    Ok(final_path)
}

/// Read a transaction from disk by ID.
pub fn load_transaction(id: &str) -> Result<TransactionJournal, std::io::Error> {
    load_transaction_in(&transactions_dir(), id)
}

pub(crate) fn load_transaction_in(
    dir: &Path,
    id: &str,
) -> Result<TransactionJournal, std::io::Error> {
    if !is_valid_transaction_id(id) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Invalid transaction identifier",
        ));
    }
    let path = dir.join(format!("{id}.json"));
    if path.is_symlink() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "Symlinks are not permitted for transaction journals",
        ));
    }
    if !path.exists() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("Transaction record '{id}' not found"),
        ));
    }
    let content = fs::read_to_string(&path)?;
    serde_json::from_str(&content)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
}

/// List all saved transactions in chronological order.
pub fn list_transactions() -> Vec<TransactionJournal> {
    list_transactions_in(&transactions_dir())
}

pub(crate) fn list_transactions_in(dir: &Path) -> Vec<TransactionJournal> {
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return Vec::new(),
    };
    let mut txs = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_file()
            && path.extension().is_some_and(|ext| ext == "json")
            && let Some(stem) = path.file_stem().and_then(|s| s.to_str())
            && let Ok(tx) = load_transaction_in(dir, stem)
        {
            txs.push(tx);
        }
    }
    txs.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));
    txs
}

/// Retrieve the most recent transaction recorded on disk.
pub fn latest_transaction() -> Option<TransactionJournal> {
    list_transactions().pop()
}

/// A private, empty journal directory for each test, without environment changes.
#[cfg(test)]
pub(crate) struct TestDirectory(pub PathBuf);

#[cfg(test)]
impl TestDirectory {
    pub fn new() -> Self {
        static SEQUENCE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let sequence = SEQUENCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "privr-journal-test-{}-{nanos}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&path).expect("isolated test directory");
        Self(path)
    }
}

#[cfg(test)]
impl Drop for TestDirectory {
    fn drop(&mut self) {
        for entry in fs::read_dir(&self.0).expect("test directory").flatten() {
            fs::remove_file(entry.path()).expect("remove test journal");
        }
        fs::remove_dir(&self.0).expect("remove empty test directory");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::evidence::ValueKind;

    #[test]
    fn transactions_round_trip_through_json() {
        let tx = TransactionJournal {
            schema: JOURNAL_SCHEMA,
            transaction_id: "tx-test-123".to_owned(),
            timestamp: "2026-09-21T10:00:00Z".to_owned(),
            platform: "windows".to_owned(),
            profile: "baseline".to_owned(),
            operations: vec![OperationJournal {
                control_id: "windows.advertising.id".to_owned(),
                target_key: "HKCU|Software\\Test|Val#native".to_owned(),
                preimage: Some(RawValue::new(ValueKind::U32, vec![1, 0, 0, 0])),
                postimage: RawValue::new(ValueKind::U32, vec![0, 0, 0, 0]),
                verified: true,
            }],
        };

        let json = serde_json::to_string(&tx).expect("serialize");
        let parsed: TransactionJournal = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed, tx);
    }

    #[test]
    fn invalid_transaction_ids_are_refused() {
        assert!(!is_valid_transaction_id(""));
        assert!(!is_valid_transaction_id("../escape"));
        assert!(!is_valid_transaction_id("..\\escape"));
        assert!(!is_valid_transaction_id("tx/slash"));
        assert!(!is_valid_transaction_id("tx\\backslash"));
        assert!(!is_valid_transaction_id("tx:colon"));
        assert!(!is_valid_transaction_id("tx*star"));
        assert!(is_valid_transaction_id("tx-1234567890"));
        assert!(is_valid_transaction_id("tx_2026_09_21"));
        assert!(is_valid_transaction_id("a1B2-c3D4"));
    }

    #[test]
    fn save_and_load_transaction_round_trips() {
        let directory = TestDirectory::new();
        let tx = TransactionJournal {
            schema: JOURNAL_SCHEMA,
            transaction_id: "tx-test-roundtrip-42".to_owned(),
            timestamp: "2026-10-02T12:00:00Z".to_owned(),
            platform: "windows".to_owned(),
            profile: "baseline".to_owned(),
            operations: vec![OperationJournal {
                control_id: "windows.advertising.id".to_owned(),
                target_key: "HKCU|Software\\Test|Val#native".to_owned(),
                preimage: Some(RawValue::new(ValueKind::U32, vec![1, 0, 0, 0])),
                postimage: RawValue::new(ValueKind::U32, vec![0, 0, 0, 0]),
                verified: true,
            }],
        };

        let path = save_transaction_in(&directory.0, &tx).expect("save transaction");
        assert!(path.exists());

        let loaded =
            load_transaction_in(&directory.0, &tx.transaction_id).expect("load transaction");
        assert_eq!(loaded, tx);

        let _ = fs::remove_file(path);
    }

    #[test]
    fn load_nonexistent_transaction_returns_not_found() {
        let directory = TestDirectory::new();
        let err = load_transaction_in(&directory.0, "tx-nonexistent-id-999").unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
    }

    #[test]
    fn load_invalid_transaction_id_returns_invalid_input() {
        let directory = TestDirectory::new();
        let err = load_transaction_in(&directory.0, "../escape").unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    }

    #[test]
    fn list_and_latest_transactions_return_saved_entries() {
        let directory = TestDirectory::new();
        let tx1 = TransactionJournal {
            schema: JOURNAL_SCHEMA,
            transaction_id: "tx-test-list-1".to_owned(),
            timestamp: "2026-10-02T10:00:00Z".to_owned(),
            platform: "windows".to_owned(),
            profile: "baseline".to_owned(),
            operations: Vec::new(),
        };
        let tx2 = TransactionJournal {
            schema: JOURNAL_SCHEMA,
            transaction_id: "tx-test-list-2".to_owned(),
            timestamp: "2026-10-02T11:00:00Z".to_owned(),
            platform: "windows".to_owned(),
            profile: "baseline".to_owned(),
            operations: Vec::new(),
        };
        let p1 = save_transaction_in(&directory.0, &tx1).expect("save tx1");
        let p2 = save_transaction_in(&directory.0, &tx2).expect("save tx2");

        let txs = list_transactions_in(&directory.0);
        assert_eq!(txs, vec![tx1, tx2.clone()]);

        let latest = list_transactions_in(&directory.0).pop();
        assert_eq!(latest, Some(tx2));

        let _ = fs::remove_file(p1);
        let _ = fs::remove_file(p2);
    }
}
