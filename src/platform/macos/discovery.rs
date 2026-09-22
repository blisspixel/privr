//! macOS host discovery.
//!
//! Establishes facts about the macOS host: version, build, architecture,
//! container environment, and privilege level.

use std::fs;

use crate::model::host::{
    Architecture, ContainerKind, Fact, HostFacts, OsVersion, Platform, SessionFacts, WriteModel,
};

const SYSTEM_VERSION_PLIST: &str = "/System/Library/CoreServices/SystemVersion.plist";

/// Extract string value between XML tags `<key>KeyName</key><string>Value</string>`.
fn extract_plist_string(content: &str, key: &str) -> Option<String> {
    let tag = format!("<key>{key}</key>");
    let key_pos = content.find(&tag)?;
    let rest = &content[key_pos + tag.len()..];
    let string_open = "<string>";
    let string_close = "</string>";
    let open_pos = rest.find(string_open)?;
    let val_start = open_pos + string_open.len();
    let close_pos = rest[val_start..].find(string_close)?;
    Some(rest[val_start..val_start + close_pos].trim().to_string())
}

fn version() -> Fact<OsVersion> {
    let Ok(content) = fs::read_to_string(SYSTEM_VERSION_PLIST) else {
        return Fact::Unknown;
    };

    let ver_str = extract_plist_string(&content, "ProductUserInterfaceVersion")
        .or_else(|| extract_plist_string(&content, "ProductVersion"));

    let build_str = extract_plist_string(&content, "ProductBuildVersion");

    let Some(ver) = ver_str else {
        return Fact::Unknown;
    };

    let components: Vec<u32> = ver
        .split('.')
        .filter_map(|c| c.parse::<u32>().ok())
        .collect();

    if components.is_empty() {
        return Fact::Unknown;
    }

    let display = match build_str {
        Some(build) => format!("{ver} ({build})"),
        None => ver,
    };

    Fact::Known(OsVersion::new(components, display))
}

fn architecture() -> Fact<Architecture> {
    match std::env::consts::ARCH {
        "aarch64" => Fact::Known(Architecture::Aarch64),
        "x86_64" => Fact::Known(Architecture::X86_64),
        _ => Fact::Known(Architecture::Other),
    }
}

fn elevated() -> Fact<bool> {
    if std::env::var("USER").as_deref() == Ok("root") {
        return Fact::Known(true);
    }
    Fact::Unknown
}

/// Discover facts for the current macOS host.
pub fn discover() -> HostFacts {
    HostFacts {
        platform: Platform::Macos,
        version: version(),
        architecture: architecture(),
        edition: Fact::NotPresent,
        distribution: Fact::NotPresent,
        managed: Fact::Unknown,
        write_model: Fact::Known(WriteModel::Mutable),
        container: Fact::Known(ContainerKind::None),
        session: SessionFacts::not_present(),
        elevated: elevated(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_plist_string_finds_nested_values() {
        let plist = r#"
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>ProductBuildVersion</key>
    <string>24A335</string>
    <key>ProductCopyright</key>
    <string>1983-2026 Apple Inc.</string>
    <key>ProductName</key>
    <string>macOS</string>
    <key>ProductUserInterfaceVersion</key>
    <string>15.0</string>
    <key>ProductVersion</key>
    <string>15.0</string>
</dict>
</plist>
"#;
        assert_eq!(
            extract_plist_string(plist, "ProductVersion").as_deref(),
            Some("15.0")
        );
        assert_eq!(
            extract_plist_string(plist, "ProductBuildVersion").as_deref(),
            Some("24A335")
        );
        assert_eq!(extract_plist_string(plist, "NonExistentKey"), None);
    }
}
