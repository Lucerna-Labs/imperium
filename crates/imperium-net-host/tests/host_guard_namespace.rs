//! Kernel acceptance test for the opt-in host guard.
//!
//! Run only through the documented `unshare -Urn` command after setting up an
//! isolated dummy interface. `nft` is an independent observer in this test;
//! production host enforcement uses libnftables in process.

use std::fs;
use std::net::UdpSocket;
use std::os::unix::fs::MetadataExt;
use std::process::Command;
use std::time::Duration;

use imperium_net_host::{HostGuardError, HostGuardMode, HostKillSwitch};

fn assert_isolated_namespace() {
    assert_eq!(
        std::env::var("IMPERIUM_HOST_GUARD_NS_TEST").as_deref(),
        Ok("1"),
        "set the explicit isolated-namespace test marker"
    );
    let current = fs::metadata("/proc/self/ns/net").expect("current net namespace");
    let init = fs::metadata("/proc/1/ns/net").expect("init net namespace");
    assert_ne!(
        current.ino(),
        init.ino(),
        "refusing to touch the current host network namespace"
    );
}

fn nft(args: &[&str]) -> std::process::Output {
    Command::new("nft")
        .args(args)
        .output()
        .expect("run nft observer")
}

fn dropped_output_packets(table: &str) -> u64 {
    let output = nft(&["list", "chain", "inet", table, "output"]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = String::from_utf8(output.stdout).expect("UTF-8 nft output");
    let line = text
        .lines()
        .find(|line| line.contains("counter packets") && line.contains("drop"))
        .expect("terminal drop counter");
    let fields: Vec<&str> = line.split_whitespace().collect();
    let count = fields
        .iter()
        .position(|field| *field == "packets")
        .expect("packets field");
    fields[count + 1].parse().expect("numeric packet count")
}

fn send_udp(bind: &str, destination: &str) {
    let socket = UdpSocket::bind(bind).expect("bind probe socket");
    let _ = socket.send_to(b"guard test", destination);
}

#[test]
#[ignore = "run only in unshare -Urn with dummy0 IPv4 and IPv6 test routes"]
fn explicit_engage_blocks_host_ipv4_ipv6_and_dns_then_cleans_up() {
    assert_isolated_namespace();

    let mut guard = HostKillSwitch::install().expect("install kernel guard");
    assert_eq!(guard.mode(), HostGuardMode::Armed);
    let table = guard.table_name().to_string();

    // Merely arming must not block the host or count a dropped packet.
    send_udp("0.0.0.0:0", "198.51.100.2:53");
    assert_eq!(dropped_output_packets(&table), 0);

    guard
        .set_mode(HostGuardMode::Engaged)
        .expect("engage kernel guard");
    let arp = nft(&["list", "chain", "arp", &table, "output"]);
    assert!(
        arp.status.success(),
        "{}",
        String::from_utf8_lossy(&arp.stderr)
    );
    let arp_rules = String::from_utf8(arp.stdout).expect("UTF-8 nft output");
    assert!(arp_rules.contains("policy drop"));
    assert!(
        !arp_rules.contains("accept"),
        "ARP must have no egress exception"
    );
    send_udp("0.0.0.0:0", "198.51.100.2:53"); // IPv4 DNS
    send_udp("0.0.0.0:0", "198.51.100.2:443"); // ordinary host UDP
    send_udp("[::]:0", "[2001:db8:100::2]:53"); // IPv6 DNS
    assert!(
        dropped_output_packets(&table) >= 3,
        "all three non-loopback probes must reach the kernel drop rule"
    );

    // Local application control remains usable while engaged.
    let receiver = UdpSocket::bind("127.0.0.1:0").expect("loopback receiver");
    receiver
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    let sender = UdpSocket::bind("127.0.0.1:0").expect("loopback sender");
    sender
        .send_to(b"local", receiver.local_addr().unwrap())
        .unwrap();
    let mut buffer = [0u8; 16];
    let (read, _) = receiver.recv_from(&mut buffer).expect("loopback allowed");
    assert_eq!(&buffer[..read], b"local");

    guard
        .set_mode(HostGuardMode::Disarmed)
        .expect("disarm kernel guard");
    send_udp("0.0.0.0:0", "198.51.100.2:53");
    assert_eq!(dropped_output_packets(&table), 0);

    guard.remove().expect("remove owned table");
    assert!(!nft(&["list", "table", "inet", &table]).status.success());
    assert!(!nft(&["list", "table", "arp", &table]).status.success());
}

#[test]
#[ignore = "run only in unshare -Urn after dropping CAP_NET_ADMIN with setpriv"]
fn startup_refuses_when_cap_net_admin_is_unavailable() {
    assert_isolated_namespace();
    let error = match HostKillSwitch::install() {
        Ok(_) => panic!("guard must refuse startup without CAP_NET_ADMIN"),
        Err(error) => error,
    };
    assert!(matches!(error, HostGuardError::Kernel(_)), "{error}");
}
