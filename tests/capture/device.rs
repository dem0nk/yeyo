use pcap::{ConnectionStatus, Device, DeviceFlags, IfFlags};
use yeyo::capture::{self, Interface};
use yeyo::error::YeyoError;

fn dev(name: &str, if_flags: IfFlags, status: ConnectionStatus) -> Device {
    Device {
        name: name.to_string(),
        desc: None,
        addresses: Vec::new(),
        flags: DeviceFlags {
            if_flags,
            connection_status: status,
        },
    }
}

fn up() -> IfFlags {
    IfFlags::UP | IfFlags::RUNNING
}

fn pick(devices: Vec<Device>) -> Result<String, YeyoError> {
    capture::first_connected(devices).map(|d| d.name)
}

fn names_and_defaults(list: &[Interface]) -> Vec<(&str, bool)> {
    list.iter().map(|i| (i.name.as_str(), i.default)).collect()
}

#[test]
fn test_first_connected_skips_disconnected_ok() {
    let devices = vec![
        dev("ap1", up(), ConnectionStatus::Disconnected),
        dev("en0", up(), ConnectionStatus::Connected),
    ];
    assert_eq!(pick(devices), Ok("en0".to_string()));
}

#[test]
fn test_first_connected_keeps_list_order_ok() {
    let devices = vec![
        dev("en0", up(), ConnectionStatus::Connected),
        dev("en1", up(), ConnectionStatus::Connected),
    ];
    assert_eq!(pick(devices), Ok("en0".to_string()));
}

#[test]
fn test_first_connected_skips_loopback_ok() {
    let devices = vec![
        dev("lo0", up() | IfFlags::LOOPBACK, ConnectionStatus::Connected),
        dev("en0", up(), ConnectionStatus::Connected),
    ];
    assert_eq!(pick(devices), Ok("en0".to_string()));
}

#[test]
fn test_first_connected_skips_down_ok() {
    let devices = vec![
        dev("en0", IfFlags::RUNNING, ConnectionStatus::Connected),
        dev("en1", up(), ConnectionStatus::Connected),
    ];
    assert_eq!(pick(devices), Ok("en1".to_string()));
}

#[test]
fn test_first_connected_skips_not_running_ok() {
    let devices = vec![
        dev("en0", IfFlags::UP, ConnectionStatus::Connected),
        dev("en1", up(), ConnectionStatus::Connected),
    ];
    assert_eq!(pick(devices), Ok("en1".to_string()));
}

#[test]
fn test_first_connected_skips_unknown_status_ok() {
    let devices = vec![
        dev("utun0", up(), ConnectionStatus::Unknown),
        dev("en0", up(), ConnectionStatus::Connected),
    ];
    assert_eq!(pick(devices), Ok("en0".to_string()));
}

#[test]
fn test_first_connected_empty_list_err() {
    assert_eq!(pick(Vec::new()), Err(YeyoError::NoDevice));
}

#[test]
fn test_first_connected_none_usable_err() {
    let devices = vec![
        dev("ap1", up(), ConnectionStatus::Disconnected),
        dev(
            "lo0",
            up() | IfFlags::LOOPBACK,
            ConnectionStatus::NotApplicable,
        ),
    ];
    assert_eq!(pick(devices), Err(YeyoError::NoDevice));
}

#[test]
fn test_device_explicit_name_ok() -> Result<(), YeyoError> {
    let device = capture::device(Some("nope"))?;
    assert_eq!(device.name, "nope");
    Ok(())
}

#[test]
fn test_describe_marks_first_usable_as_default_ok() {
    let list = capture::describe(vec![
        dev(
            "ap1",
            up() | IfFlags::WIRELESS,
            ConnectionStatus::Disconnected,
        ),
        dev("en0", up() | IfFlags::WIRELESS, ConnectionStatus::Connected),
        dev("en1", up(), ConnectionStatus::Connected),
    ]);
    assert_eq!(
        names_and_defaults(&list),
        vec![("ap1", false), ("en0", true), ("en1", false)]
    );
}

#[test]
fn test_describe_no_usable_has_no_default_ok() {
    let list = capture::describe(vec![
        dev("ap1", up(), ConnectionStatus::Disconnected),
        dev(
            "lo0",
            up() | IfFlags::LOOPBACK,
            ConnectionStatus::NotApplicable,
        ),
    ]);
    assert!(list.iter().all(|i| !i.default));
}

#[test]
fn test_describe_empty_ok() {
    assert!(capture::describe(Vec::new()).is_empty());
}

#[test]
fn test_labels_wireless_ok() {
    let list = capture::describe(vec![
        dev("en0", up() | IfFlags::WIRELESS, ConnectionStatus::Connected),
        dev(
            "ap1",
            up() | IfFlags::WIRELESS,
            ConnectionStatus::Disconnected,
        ),
    ]);
    assert_eq!(
        list[0].labels,
        vec!["Up", "Running", "Wireless", "Associated"]
    );
    assert_eq!(
        list[1].labels,
        vec!["Up", "Running", "Wireless", "Not associated"]
    );
}

#[test]
fn test_labels_wired_and_loopback_ok() {
    let list = capture::describe(vec![
        dev("eth0", up(), ConnectionStatus::Connected),
        dev("eth1", up(), ConnectionStatus::Disconnected),
        dev(
            "lo0",
            up() | IfFlags::LOOPBACK,
            ConnectionStatus::NotApplicable,
        ),
        dev("utun0", up(), ConnectionStatus::Unknown),
        dev("down0", IfFlags::empty(), ConnectionStatus::Unknown),
    ]);
    assert_eq!(list[0].labels, vec!["Up", "Running", "Connected"]);
    assert_eq!(list[1].labels, vec!["Up", "Running", "Disconnected"]);
    assert_eq!(list[2].labels, vec!["Up", "Running", "Loopback"]);
    assert_eq!(list[3].labels, vec!["Up", "Running"]);
    assert!(list[4].labels.is_empty());
}

#[test]
fn test_interface_display_full_ok() {
    let mut d = dev("any", up(), ConnectionStatus::Connected);
    d.desc = Some(String::from(
        "Pseudo-device that captures on all interfaces",
    ));
    let list = capture::describe(vec![d]);
    assert_eq!(
        list[0].to_string(),
        "any (Pseudo-device that captures on all interfaces) [Up, Running, Connected] (default)"
    );
}

#[test]
fn test_interface_display_bare_ok() {
    let list = capture::describe(vec![dev(
        "down0",
        IfFlags::empty(),
        ConnectionStatus::Unknown,
    )]);
    assert_eq!(list[0].to_string(), "down0");
}
