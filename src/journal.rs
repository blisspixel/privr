//! Transaction journal for verified mutation and rollback.
//!
//! Stores applied operations durably by transaction ID. Every operation records
//! its exact preimage (prior state, type, and raw bytes) and postimage, so that
//! rollback can verify no external changes occurred before restoring prior state.

use std::fs;
use std::path::PathBuf;

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
    if !is_valid_transaction_id(&tx.transaction_id) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Invalid transaction identifier",
        ));
    }
    let dir = transactions_dir();
    fs::create_dir_all(&dir)?;
    let final_path = dir.join(format!("{}.json", tx.transaction_id));
    let tmp_path = dir.join(format!("{}.tmp.{}", tx.transaction_id, std::process::id()));
    let content = serde_json::to_string_pretty(tx)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    fs::write(&tmp_path, content)?;
    if let Err(e) = fs::rename(&tmp_path, &final_path) {
        let _ = fs::remove_file(&tmp_path);
        return Err(e);
    }
    Ok(final_path)
}

/// Read a transaction from disk by ID.
pub fn load_transaction(id: &str) -> Result<TransactionJournal, std::io::Error> {
    if !is_valid_transaction_id(id) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Invalid transaction identifier",
        ));
    }
    let path = transactions_dir().join(format!("{id}.json"));
    let content = fs::read_to_string(&path)?;
    serde_json::from_str(&content)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
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
}
