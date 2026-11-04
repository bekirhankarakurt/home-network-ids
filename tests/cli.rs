//! Tests of the `hnids` binary.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn hnids(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_hnids"))
        .args(args)
        .output()
        .unwrap()
}

fn fixture(name: &str) -> String {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
        .display()
        .to_string()
}

fn temp(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!("hnids-cli-{}-{name}", std::process::id()))
}

#[test]
fn replay_prints_json_lines_and_summary() {
    let inv = temp("inv1.json");
    let out = hnids(&[
        "replay",
        &fixture("portscan.pcap"),
        "--inventory",
        inv.to_str().unwrap(),
    ]);
    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    let kinds: Vec<String> = stdout
        .lines()
        .map(|l| {
            serde_json::from_str::<serde_json::Value>(l).unwrap()["kind"]
                .as_str()
                .unwrap()
                .to_owned()
        })
        .collect();
    assert!(kinds.contains(&"syn_scan".to_owned()));
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(stderr.contains("129 packets, 0 parse errors"), "{stderr}");

    let listed = hnids(&["inventory", "--inventory", inv.to_str().unwrap()]);
    let table = String::from_utf8(listed.stdout).unwrap();
    assert!(
        table.contains("Raspberry Pi") && table.contains("5 device(s)"),
        "{table}"
    );
    let json = hnids(&["inventory", "--inventory", inv.to_str().unwrap(), "--json"]);
    let v: serde_json::Value = serde_json::from_slice(&json.stdout).unwrap();
    assert_eq!(v["devices"].as_object().unwrap().len(), 5);
    std::fs::remove_file(inv).unwrap();
}

#[test]
fn min_severity_file_output_and_exit_code() {
    let inv = temp("inv2.json");
    let alerts = temp("alerts.jsonl");
    let out = hnids(&[
        "replay",
        &fixture("mixed.pcapng"),
        "--inventory",
        inv.to_str().unwrap(),
        "--min-severity",
        "high",
        "-o",
        alerts.to_str().unwrap(),
        "--fail-on-alert",
        "--quiet",
    ]);
    assert_eq!(out.status.code(), Some(2));
    assert!(out.stdout.is_empty() && out.stderr.is_empty());
    let text = std::fs::read_to_string(&alerts).unwrap();
    assert!(text.lines().count() >= 5);
    assert!(text
        .lines()
        .all(|l| l.contains("\"severity\":\"high\"") || l.contains("\"severity\":\"critical\"")));
    std::fs::remove_file(inv).unwrap();
    std::fs::remove_file(alerts).unwrap();
}

#[test]
fn config_commands() {
    let out = hnids(&["config", "default"]);
    assert!(out.status.success());
    let path = temp("cfg.toml");
    std::fs::write(&path, &out.stdout).unwrap();
    let check = hnids(&["config", "check", path.to_str().unwrap()]);
    assert!(check.status.success());
    std::fs::write(&path, "[portscan]\nwindow = 3\n").unwrap();
    let bad = hnids(&["config", "check", path.to_str().unwrap()]);
    assert_eq!(bad.status.code(), Some(1));
    assert!(String::from_utf8(bad.stderr)
        .unwrap()
        .contains("unknown field"));
    std::fs::remove_file(path).unwrap();
}

#[test]
fn bad_inputs_fail_cleanly() {
    let junk = temp("junk.pcap");
    std::fs::write(&junk, b"definitely not a capture file").unwrap();
    let out = hnids(&["replay", junk.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8(out.stderr)
        .unwrap()
        .contains("unrecognised capture format"));
    std::fs::remove_file(junk).unwrap();

    let missing = hnids(&["replay", "/nonexistent/file.pcap"]);
    assert_eq!(missing.status.code(), Some(1));
    let speed = hnids(&["replay", &fixture("portscan.pcap"), "--speed", "0"]);
    assert_eq!(speed.status.code(), Some(1));
    let live = hnids(&["live", "-i", "hnids-missing0"]);
    assert_eq!(live.status.code(), Some(1));
    assert!(String::from_utf8(live.stderr)
        .unwrap()
        .contains("CAP_NET_RAW"));
}
