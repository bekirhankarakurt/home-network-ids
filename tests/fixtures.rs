//! End-to-end tests: committed pcap fixtures through the full pipeline.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use home_network_ids::alert::Alert;
use home_network_ids::capture;
use home_network_ids::config::Config;
use home_network_ids::detect::Engine;
use home_network_ids::oui::OuiTable;
use home_network_ids::pipeline::{Options, Pipeline, Report};
use home_network_ids::sink::Collector;
use home_network_ids::synth;

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

fn temp(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!("hnids-it-{}-{name}", std::process::id()))
}

fn replay(name: &str, mut config: Config) -> (Vec<Alert>, Report) {
    let inventory = temp(&format!("{name}.json"));
    config.inventory.path.clone_from(&inventory);
    let source = capture::open_file(&fixture(name)).unwrap();
    let engine = Engine::from_config(&config, Arc::new(OuiTable::builtin())).unwrap();
    let alerts = Collector::default();
    let opts = Options {
        capacity: 4,
        ..Options::default()
    };
    let report = Pipeline::start(
        source,
        engine,
        vec![Box::new(alerts.clone())],
        opts,
        Arc::new(AtomicBool::new(false)),
    )
    .unwrap()
    .join()
    .unwrap();
    let _ = std::fs::remove_file(inventory);
    (alerts.alerts(), report)
}

fn kinds(alerts: &[Alert]) -> BTreeSet<&'static str> {
    alerts.iter().map(|a| a.kind).collect()
}

#[test]
fn fixtures_match_generator() {
    for (name, generate) in synth::FIXTURES {
        let expected = synth::encode(name, &generate()).unwrap();
        let actual = std::fs::read(fixture(name)).unwrap();
        assert!(
            expected == actual,
            "{name} is stale; run `cargo run --example gen_fixtures`"
        );
    }
}

#[test]
fn portscan_fixture() {
    let (alerts, report) = replay("portscan.pcap", Config::default());
    assert_eq!(report.counters.captured, 129);
    assert_eq!(report.counters.parse_errors, 0);
    let k = kinds(&alerts);
    for expected in [
        "syn_scan",
        "xmas_scan",
        "null_scan",
        "fin_scan",
        "host_sweep",
    ] {
        assert!(k.contains(expected), "missing {expected}: {k:?}");
    }
    let scan = alerts.iter().find(|a| a.kind == "syn_scan").unwrap();
    assert_eq!(scan.src_ip.unwrap().to_string(), "192.168.1.66");
}

#[test]
fn arp_spoof_fixture() {
    let (alerts, _) = replay("arp_spoof.pcap", Config::default());
    let k = kinds(&alerts);
    for expected in [
        "arp_binding_change",
        "gratuitous_arp_flood",
        "arp_sender_mismatch",
    ] {
        assert!(k.contains(expected), "missing {expected}: {k:?}");
    }
    let change = alerts
        .iter()
        .find(|a| a.kind == "arp_binding_change")
        .unwrap();
    assert_eq!(change.details["old_mac"], "38:10:d5:aa:00:01");
    assert_eq!(change.details["new_mac"], "de:ad:be:ef:00:66");
}

#[test]
fn arp_static_binding_is_critical() {
    let config =
        Config::from_toml("[arp.static_bindings]\n\"192.168.1.1\" = \"38:10:d5:aa:00:01\"\n")
            .unwrap();
    let (alerts, _) = replay("arp_spoof.pcap", config);
    assert!(alerts.iter().any(|a| a.kind == "arp_static_mismatch"
        && a.severity == home_network_ids::alert::Severity::Critical));
}

#[test]
fn new_device_fixture_with_allowlist() {
    let (alerts, _) = replay("new_device.pcap", Config::default());
    let iot = alerts
        .iter()
        .find(|a| a.message.contains("24:0a:c4:9a:bc:de"))
        .unwrap();
    assert_eq!(iot.kind, "new_device");
    assert!(iot.message.contains("Espressif"));

    let config = Config::from_toml(
        "[inventory]\nalert_on_new = false\nallowlist = [\"a4:5e:60:11:22:33\", \"38:10:d5:aa:00:01\", \"b0:a7:37:10:20:30\"]\n",
    )
    .unwrap();
    let (alerts, _) = replay("new_device.pcap", config);
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].kind, "rogue_device");
}

#[test]
fn dns_fixture() {
    let (alerts, _) = replay("dns_anomaly.pcap", Config::default());
    let k = kinds(&alerts);
    for expected in ["dns_long_name", "dns_high_entropy", "dns_nxdomain_burst"] {
        assert!(k.contains(expected), "missing {expected}: {k:?}");
    }
}

#[test]
fn mixed_pcapng_covers_every_detector() {
    let (alerts, report) = replay("mixed.pcapng", Config::default());
    assert_eq!(report.counters.parse_errors, 0);
    let detectors: BTreeSet<_> = alerts.iter().map(|a| a.detector).collect();
    assert_eq!(
        detectors,
        BTreeSet::from(["arp", "dns", "inventory", "portscan"])
    );
}

#[test]
fn disabled_detectors_stay_quiet() {
    let config = Config::from_toml(
        "[portscan]\nenabled = false\n[arp]\nenabled = false\n[inventory]\nenabled = false\n[dns]\nenabled = false\n",
    )
    .unwrap();
    let (alerts, report) = replay("mixed.pcapng", config);
    assert!(alerts.is_empty());
    assert_eq!(report.counters.parsed, report.counters.captured);
}
