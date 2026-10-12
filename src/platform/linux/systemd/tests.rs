use super::*;

fn regular(text: impl AsRef<[u8]>) -> ConfigurationFile {
    ConfigurationFile::Regular(RawValue::new(ValueKind::String, text.as_ref().to_vec()))
}

fn empty() -> ConfigurationEvidence {
    let mut evidence = crate::test_context::configuration(b"");
    evidence
        .roots
        .get_mut(&ConfigurationRoot::Etc)
        .unwrap()
        .main = ConfigurationFile::Absent;
    evidence
}

fn drop_in(
    evidence: &mut ConfigurationEvidence,
    root: ConfigurationRoot,
    name: &[u8],
    file: ConfigurationFile,
) {
    let entry = evidence.roots.get_mut(&root).unwrap();
    let mut names = match &entry.before {
        DirectoryListing::Complete(names) => names.clone(),
        _ => Vec::new(),
    };
    names.push(name.to_vec());
    entry.before = DirectoryListing::Complete(names);
    entry.after = entry.before.clone();
    entry.files.insert(name.to_vec(), file);
}

fn cases() -> [(
    ConfigurationFamily,
    &'static str,
    &'static str,
    ConfiguredStorage,
); 2] {
    [
        (
            ConfigurationFamily::Coredump,
            "[Coredump]\nStorage=none\n",
            "[Coredump]\nStorage=external\n",
            ConfiguredStorage::External,
        ),
        (
            ConfigurationFamily::Journald,
            "[Journal]\nStorage=volatile\n",
            "[Journal]\nStorage=persistent\n",
            ConfiguredStorage::Persistent,
        ),
    ]
}

#[test]
fn issue18_main_priority_selects_first_present_without_reading_shadowed_content() {
    for (family, desired, _, _) in cases() {
        for (index, root) in ROOTS.into_iter().enumerate() {
            let mut evidence = empty();
            evidence.roots.get_mut(&root).unwrap().main = regular(desired);
            for lower in &ROOTS[index + 1..] {
                evidence.roots.get_mut(lower).unwrap().main =
                    ConfigurationFile::Uncertain(Uncertainty::Denied);
            }
            assert_eq!(
                configured_storage(family, &evidence),
                Ok(if family == ConfigurationFamily::Coredump {
                    ConfiguredStorage::None
                } else {
                    ConfiguredStorage::Volatile
                })
            );
            assert_eq!(resolve(family, &evidence).state, None);
            evidence.roots.get_mut(&root).unwrap().main = ConfigurationFile::Mask;
            assert_eq!(
                configured_storage(family, &evidence),
                Ok(ConfiguredStorage::Unspecified)
            );
        }
    }
}

#[test]
fn issue18_dropin_only_and_later_adverse_assignment_reach_actual_compiled_controls() {
    for (family, desired, adverse, expected) in cases() {
        for main in [ConfigurationFile::Absent, regular(desired)] {
            let mut evidence = empty();
            evidence
                .roots
                .get_mut(&ConfigurationRoot::Etc)
                .unwrap()
                .main = main;
            drop_in(
                &mut evidence,
                ConfigurationRoot::UsrLib,
                b"90-retention.conf",
                regular(adverse),
            );
            assert_eq!(configured_storage(family, &evidence), Ok(expected));
            let reader = super::super::evidence::Reader::recorded_with_configurations(
                BTreeMap::new(),
                BTreeMap::from([(family, evidence)]),
            );
            let host = crate::test_context::host("arch", "hyprland");
            let context = crate::test_context::context(&host, &reader);
            let selector = if family == ConfigurationFamily::Coredump {
                "systemd.coredump"
            } else {
                "systemd.journald"
            };
            let report = crate::report::Report::build_with_context(
                &context,
                Some("baseline"),
                None,
                &[selector.to_owned()],
                &[],
            );
            assert_eq!(
                report.results[0].outcome,
                crate::model::outcome::Outcome::Unknown
            );
            assert_eq!(report.exit_code(), 3);
            assert!(
                report.results[0]
                    .note
                    .as_ref()
                    .unwrap()
                    .contains(expected.label())
            );
        }
        let mut desired_only = empty();
        drop_in(
            &mut desired_only,
            ConfigurationRoot::Run,
            b"50-local.conf",
            regular(desired),
        );
        assert!(resolve(family, &desired_only).note.unwrap().contains(
            if family == ConfigurationFamily::Coredump {
                "Storage=none"
            } else {
                "Storage=volatile"
            }
        ));
    }
}

#[test]
fn issue18_duplicate_basename_priority_precedes_global_lexical_order() {
    for (family, desired, adverse, expected) in cases() {
        let mut evidence = empty();
        drop_in(
            &mut evidence,
            ConfigurationRoot::UsrLib,
            b"10-common.conf",
            regular(adverse),
        );
        drop_in(
            &mut evidence,
            ConfigurationRoot::Etc,
            b"10-common.conf",
            regular(desired),
        );
        drop_in(
            &mut evidence,
            ConfigurationRoot::UsrLib,
            b"90-vendor.conf",
            regular(adverse),
        );
        assert_eq!(configured_storage(family, &evidence), Ok(expected));
        evidence
            .roots
            .get_mut(&ConfigurationRoot::UsrLib)
            .unwrap()
            .files
            .insert(
                b"10-common.conf".to_vec(),
                ConfigurationFile::Uncertain(Uncertainty::Denied),
            );
        evidence
            .roots
            .get_mut(&ConfigurationRoot::Etc)
            .unwrap()
            .files
            .insert(b"10-common.conf".to_vec(), ConfigurationFile::Mask);
        assert_eq!(configured_storage(family, &evidence), Ok(expected));
        evidence
            .roots
            .get_mut(&ConfigurationRoot::UsrLib)
            .unwrap()
            .files
            .insert(b"90-vendor.conf".to_vec(), ConfigurationFile::Mask);
        assert_eq!(
            configured_storage(family, &evidence),
            Ok(ConfiguredStorage::Unspecified)
        );
        evidence
            .roots
            .get_mut(&ConfigurationRoot::Etc)
            .unwrap()
            .files
            .insert(b"10-common.conf".to_vec(), regular(b""));
        assert_eq!(
            configured_storage(family, &evidence),
            Ok(ConfiguredStorage::Unspecified)
        );
    }
}

#[test]
fn issue18_parser_respects_sections_comments_crlf_and_last_scalar() {
    for (family, _, adverse, expected) in cases() {
        let text = format!(
            "Storage=none\n[Unrelated]\nStorage=none\n# comment\n; comment\n[{}]\r\n Storage = none \r\nOther=anything\n{}",
            family.section(),
            adverse
        );
        let mut evidence = crate::test_context::configuration(text.as_bytes());
        assert_eq!(configured_storage(family, &evidence), Ok(expected));
        drop_in(
            &mut evidence,
            ConfigurationRoot::Etc,
            b"99-no-section.conf",
            regular("Storage=none\n"),
        );
        assert_eq!(configured_storage(family, &evidence), Ok(expected));
    }
    for (value, expected) in [
        ("auto", ConfiguredStorage::Auto),
        ("none", ConfiguredStorage::None),
        ("volatile", ConfiguredStorage::Volatile),
    ] {
        assert_eq!(
            configured_storage(
                ConfigurationFamily::Journald,
                &crate::test_context::configuration(
                    format!("[Journal]\nStorage={value}\n").as_bytes()
                )
            ),
            Ok(expected)
        );
    }
    assert_eq!(
        configured_storage(
            ConfigurationFamily::Coredump,
            &crate::test_context::configuration(b"[Coredump]\nStorage=journal\n")
        ),
        Ok(ConfiguredStorage::Journal)
    );
}

#[test]
fn issue18_invalid_relevant_syntax_cannot_be_erased_by_later_valid_values() {
    for (family, desired, _, _) in cases() {
        for invalid in [
            "Storage=",
            "Storage=INVALID",
            "Storage='none'",
            "Storage=\"none\"",
            "storage=none",
            "Storage=NONE",
            "Storage",
            "Storage none",
            "Storage=none # inline",
            "[broken",
            "[[]]",
            "Storage=none\\",
            "Other=one\\\nStorage=none",
            "Storage=none\rExtra",
        ] {
            let bytes = format!("[{}]\n{invalid}\n{desired}", family.section());
            let evidence = crate::test_context::configuration(bytes.as_bytes());
            assert_eq!(
                configured_storage(family, &evidence),
                Err(Uncertainty::Malformed),
                "{invalid:?}"
            );
        }
        for invalid in [vec![0xff], b"\0".to_vec(), vec![1]] {
            let evidence = crate::test_context::configuration(&invalid);
            assert_eq!(
                configured_storage(family, &evidence),
                Err(Uncertainty::Malformed)
            );
        }
        for wrong in [
            ValueKind::Bool,
            ValueKind::Binary,
            ValueKind::StringList,
            ValueKind::Other(9),
        ] {
            let mut evidence = empty();
            evidence
                .roots
                .get_mut(&ConfigurationRoot::Etc)
                .unwrap()
                .main =
                ConfigurationFile::Regular(RawValue::new(wrong, desired.as_bytes().to_vec()));
            assert_eq!(
                configured_storage(family, &evidence),
                Err(Uncertainty::Malformed)
            );
        }
    }
}

#[test]
fn issue18_all_missing_denied_and_raced_observations_remain_unknown() {
    for (family, desired, _, _) in cases() {
        assert_eq!(
            configured_storage(family, &ConfigurationEvidence::default()),
            Err(Uncertainty::Undetermined)
        );
        for root in ROOTS {
            let mut evidence = crate::test_context::configuration(desired.as_bytes());
            evidence.roots.remove(&root);
            assert_eq!(
                configured_storage(family, &evidence),
                Err(Uncertainty::Undetermined)
            );
            for reason in [
                Uncertainty::Denied,
                Uncertainty::Undetermined,
                Uncertainty::Unsupported,
                Uncertainty::Malformed,
            ] {
                let mut evidence = crate::test_context::configuration(desired.as_bytes());
                let entry = evidence.roots.get_mut(&root).unwrap();
                entry.before = DirectoryListing::Uncertain(reason);
                entry.after = entry.before.clone();
                assert_eq!(configured_storage(family, &evidence), Err(reason));
            }
            let mut evidence = empty();
            evidence.roots.get_mut(&root).unwrap().after = DirectoryListing::Complete(vec![]);
            assert_eq!(
                configured_storage(family, &evidence),
                Err(Uncertainty::Undetermined)
            );
        }
        for file in [
            ConfigurationFile::Absent,
            ConfigurationFile::Uncertain(Uncertainty::Denied),
        ] {
            let mut evidence = empty();
            drop_in(
                &mut evidence,
                ConfigurationRoot::Etc,
                b"10-observed.conf",
                file,
            );
            assert!(configured_storage(family, &evidence).is_err());
            evidence
                .roots
                .get_mut(&ConfigurationRoot::Etc)
                .unwrap()
                .files
                .clear();
            assert_eq!(
                configured_storage(family, &evidence),
                Err(Uncertainty::Undetermined)
            );
        }
        let evidence = empty();
        assert_eq!(
            configured_storage(family, &evidence),
            Ok(ConfiguredStorage::Unspecified)
        );
        assert_eq!(resolve(family, &evidence).state, None);
    }
}

#[test]
fn issue18_boundaries_refuse_overflow_without_truncation_or_identifier_leaks() {
    for bytes in [
        vec![b'#'; MAX_LINE_BYTES + 1],
        vec![b'\n'; MAX_FILE_BYTES + 1],
    ] {
        assert_eq!(
            configured_storage(
                ConfigurationFamily::Journald,
                &crate::test_context::configuration(&bytes)
            ),
            Err(Uncertainty::Undetermined)
        );
    }
    for name in [
        b"../private.conf".to_vec(),
        b"bad\\name.conf".to_vec(),
        b"bad\0.conf".to_vec(),
        b"bad\n.conf".to_vec(),
        vec![0xff, b'.', b'c', b'o', b'n', b'f'],
        vec![b'x'; MAX_NAME_BYTES + 1],
        b".".to_vec(),
        b"..".to_vec(),
        vec![],
        b"no-extension".to_vec(),
    ] {
        let mut evidence = empty();
        drop_in(&mut evidence, ConfigurationRoot::Etc, &name, regular(b""));
        assert_eq!(
            configured_storage(ConfigurationFamily::Journald, &evidence),
            Err(Uncertainty::Malformed)
        );
        let note = resolve(ConfigurationFamily::Journald, &evidence)
            .note
            .unwrap();
        assert!(!note.contains("private"));
        assert!(!note.contains("bad"));
    }
    let mut evidence = empty();
    for i in 0..MAX_ENTRIES {
        drop_in(
            &mut evidence,
            ConfigurationRoot::Etc,
            format!("{i:03}.conf").as_bytes(),
            regular(b""),
        );
    }
    assert_eq!(
        configured_storage(ConfigurationFamily::Journald, &evidence),
        Ok(ConfiguredStorage::Unspecified)
    );
    drop_in(
        &mut evidence,
        ConfigurationRoot::Run,
        b"extra.conf",
        regular(b""),
    );
    assert_eq!(
        configured_storage(ConfigurationFamily::Journald, &evidence),
        Err(Uncertainty::Undetermined)
    );
    let mut evidence = empty();
    drop_in(
        &mut evidence,
        ConfigurationRoot::Etc,
        b"duplicate.conf",
        regular(b""),
    );
    drop_in(
        &mut evidence,
        ConfigurationRoot::Etc,
        b"duplicate.conf",
        regular(b""),
    );
    assert_eq!(
        configured_storage(ConfigurationFamily::Journald, &evidence),
        Err(Uncertainty::Malformed)
    );
    let mut evidence = empty();
    for i in 0..8 {
        drop_in(
            &mut evidence,
            ConfigurationRoot::UsrLib,
            format!("{i}.conf").as_bytes(),
            regular(vec![b'\n'; MAX_FILE_BYTES]),
        );
    }
    assert_eq!(
        configured_storage(ConfigurationFamily::Journald, &evidence),
        Ok(ConfiguredStorage::Unspecified)
    );
    drop_in(
        &mut evidence,
        ConfigurationRoot::Etc,
        b"extra.conf",
        regular(b"\n"),
    );
    assert_eq!(
        configured_storage(ConfigurationFamily::Journald, &evidence),
        Err(Uncertainty::Undetermined)
    );
}

#[test]
fn issue18_recorded_omission_never_falls_back_to_live_or_attests_a_runtime_version() {
    let reader = super::super::evidence::Reader::recorded(BTreeMap::new());
    for family in [ConfigurationFamily::Coredump, ConfigurationFamily::Journald] {
        let resolution = reader.configuration(family);
        assert_eq!(resolution.state, None);
        assert_eq!(resolution.uncertainty, Some(Uncertainty::Undetermined));
        assert!(resolution.note.unwrap().contains("component version/build"));
        // Even an older-layout main file and a desired value provide no
        // loaded-generation, command-line, credential or namespace evidence.
        let evidence = crate::test_context::configuration(
            format!("[{}]\nStorage=none\n", family.section()).as_bytes(),
        );
        assert!(
            resolve(family, &evidence)
                .note
                .unwrap()
                .contains("systemd v262 standard paths")
        );
    }
    assert!(reader.requested().is_empty());
    assert_eq!(
        reader.requested_configurations(),
        vec![ConfigurationFamily::Coredump, ConfigurationFamily::Journald]
    );
}

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        use std::sync::atomic::{AtomicU64, Ordering};
        static SEQUENCE: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "privr-systemd-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}

#[test]
fn issue18_live_adapter_private_files_masks_links_types_limits_and_observed_changes() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let fixture = Fixture::new();
    let path = fixture.0.join("config");
    assert!(matches!(read_file(&path), ConfigurationFile::Absent));
    std::fs::write(&path, b"[Journal]\nStorage=volatile\n").unwrap();
    assert!(matches!(read_file(&path), ConfigurationFile::Regular(_)));
    assert!(matches!(
        read_file_with(&path, MAX_FILE_BYTES, || std::fs::write(&path, b"changed")
            .unwrap()),
        ConfigurationFile::Uncertain(_)
    ));
    assert!(matches!(
        read_file_with(&path, MAX_FILE_BYTES, || std::fs::remove_file(&path)
            .unwrap()),
        ConfigurationFile::Uncertain(_)
    ));
    for target in [
        "/dev/null",
        "/dev/null/",
        "/dev/null/.",
        "/dev//null",
        "//dev/null",
        "/dev/./null",
        "missing",
        "config-other",
    ] {
        symlink(target, &path).unwrap();
        let file = read_file(&path);
        if target == "/dev/null" {
            assert!(matches!(file, ConfigurationFile::Mask));
        } else {
            assert!(matches!(file, ConfigurationFile::Uncertain(_)));
        }
        std::fs::remove_file(&path).unwrap();
    }
    std::fs::create_dir(&path).unwrap();
    assert!(matches!(read_file(&path), ConfigurationFile::Uncertain(_)));
    std::fs::remove_dir(&path).unwrap();
    std::fs::write(&path, vec![b'\n'; MAX_FILE_BYTES + 1]).unwrap();
    assert!(matches!(read_file(&path), ConfigurationFile::Uncertain(_)));
    std::fs::write(&path, b"value").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o0)).unwrap();
    assert!(matches!(
        read_file(&path),
        ConfigurationFile::Uncertain(Uncertainty::Denied)
    ));
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let parent_link = fixture.0.join("linked");
    symlink(&fixture.0, &parent_link).unwrap();
    assert!(matches!(
        read_file(&parent_link.join("config")),
        ConfigurationFile::Uncertain(_)
    ));
    assert_eq!(
        io_uncertainty(&std::io::Error::from(std::io::ErrorKind::Other)),
        Uncertainty::Undetermined
    );
}

#[test]
fn issue18_live_collector_uses_only_private_roots_and_winning_files() {
    use std::os::unix::fs::symlink;
    let fixture = Fixture::new();
    let paths: [PathBuf; 4] = std::array::from_fn(|i| fixture.0.join(i.to_string()));
    for path in &paths {
        std::fs::create_dir(path).unwrap();
    }
    for family in [ConfigurationFamily::Coredump, ConfigurationFamily::Journald] {
        let main = paths[1].join(family.filename());
        std::fs::write(&main, format!("[{}]\nStorage=none\n", family.section())).unwrap();
        symlink("not-admitted", paths[2].join(family.filename())).unwrap();
        for path in &paths {
            std::fs::create_dir(path.join(format!("{}.d", family.filename()))).unwrap();
        }
        let vendor = paths[3]
            .join(format!("{}.d", family.filename()))
            .join("50-common.conf");
        symlink("not-admitted", vendor).unwrap();
        let admin = paths[0]
            .join(format!("{}.d", family.filename()))
            .join("50-common.conf");
        std::fs::write(&admin, b"").unwrap();
        let evidence = collect(family, paths.clone());
        assert_eq!(
            configured_storage(family, &evidence),
            Ok(ConfiguredStorage::None)
        );
        assert!(evidence.roots[&ConfigurationRoot::UsrLib].files.is_empty());
        assert!(matches!(
            evidence.roots[&ConfigurationRoot::UsrLocalLib].main,
            ConfigurationFile::Uncertain(_)
        ));
    }
}

#[test]
fn issue18_live_directory_listing_is_complete_safe_and_bounded() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let fixture = Fixture::new();
    let dir = fixture.0.join("dropins");
    assert_eq!(list_directory(&dir), DirectoryListing::Absent);
    std::fs::write(&dir, b"").unwrap();
    assert!(matches!(
        list_directory(&dir),
        DirectoryListing::Uncertain(_)
    ));
    std::fs::remove_file(&dir).unwrap();
    symlink("missing", &dir).unwrap();
    assert!(matches!(
        list_directory(&dir),
        DirectoryListing::Uncertain(_)
    ));
    std::fs::remove_file(&dir).unwrap();
    std::fs::create_dir(&dir).unwrap();
    std::fs::write(dir.join("ignore.txt"), b"").unwrap();
    std::fs::write(dir.join("bad\n.conf"), b"").unwrap();
    assert_eq!(
        list_directory(&dir),
        DirectoryListing::Uncertain(Uncertainty::Malformed)
    );
    std::fs::remove_file(dir.join("bad\n.conf")).unwrap();
    for i in 0..MAX_ENTRIES {
        std::fs::write(dir.join(format!("{i:03}.conf")), b"").unwrap();
    }
    assert!(
        matches!(list_directory(&dir), DirectoryListing::Complete(names) if names.len() == MAX_ENTRIES)
    );
    std::fs::write(dir.join("extra.conf"), b"").unwrap();
    assert_eq!(
        list_directory(&dir),
        DirectoryListing::Uncertain(Uncertainty::Undetermined)
    );
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o0)).unwrap();
    assert_eq!(
        list_directory(&dir),
        DirectoryListing::Uncertain(Uncertainty::Denied)
    );
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
}

#[test]
fn issue18_live_metadata_recheck_detects_directory_change_and_special_file() {
    let fixture = Fixture::new();
    let dir = fixture.0.join("dropins");
    std::fs::create_dir(&dir).unwrap();
    let changed = list_directory_with(&dir, || std::fs::write(dir.join("new.conf"), b"").unwrap());
    assert_eq!(
        changed,
        DirectoryListing::Uncertain(Uncertainty::Undetermined)
    );
    let socket = fixture.0.join("socket");
    // Linux limits socket path bytes. An open private directory supplies a
    // short alias without changing the process working directory.
    use std::os::fd::AsRawFd;
    let directory = File::open(&fixture.0).unwrap();
    let alias = PathBuf::from(format!("/proc/self/fd/{}/socket", directory.as_raw_fd()));
    let _listener = std::os::unix::net::UnixListener::bind(alias).unwrap();
    assert!(matches!(
        read_file(&socket),
        ConfigurationFile::Uncertain(_)
    ));
}

#[test]
fn issue18_duplicate_shadow_priority_covers_all_four_roots() {
    for (index, root) in ROOTS.into_iter().enumerate() {
        let mut evidence = empty();
        drop_in(
            &mut evidence,
            root,
            b"50-local.conf",
            regular(b"[Journal]\nStorage=volatile\n"),
        );
        for lower in &ROOTS[index + 1..] {
            drop_in(
                &mut evidence,
                *lower,
                b"50-local.conf",
                ConfigurationFile::Uncertain(Uncertainty::Denied),
            );
        }
        assert_eq!(
            configured_storage(ConfigurationFamily::Journald, &evidence),
            Ok(ConfiguredStorage::Volatile)
        );
    }
    let mut evidence = empty();
    let name = format!("{}.conf", "x".repeat(MAX_NAME_BYTES - 5));
    drop_in(
        &mut evidence,
        ConfigurationRoot::Etc,
        name.as_bytes(),
        regular(vec![b'#'; MAX_LINE_BYTES]),
    );
    assert_eq!(
        configured_storage(ConfigurationFamily::Journald, &evidence),
        Ok(ConfiguredStorage::Unspecified)
    );
}
