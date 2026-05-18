//! macOS IOKit Statistics collector.
//!
//! Each `IOBlockStorageDriver` node in the I/O Registry carries a
//! `Statistics` dict with split read/write byte and operation counters
//! plus cumulative `Total Time` per direction. We extract those plus
//! the BSD name (`disk0`, `disk2`, …) from the immediate IOMedia child.
//!
//! Why parse `ioreg` text instead of going FFI: Apple's plist
//! serializer (`ioreg -a`) strips most IOMedia properties when the
//! query starts from `IOBlockStorageDriver`, so we'd need to run two
//! separate ioreg queries and rejoin by entry ID. The text output with
//! `-l -w 0` carries every property inline in a stable format.
//!
//! Latency is reported as **avg per-op µs** (`Total Time / Operations`).
//! True p50/p99 latencies require IOReport subscription or eBPF, both
//! deferred.

use std::collections::HashMap;
use std::process::Command;

#[derive(Debug, Default, Clone)]
pub struct IokitDeviceStats {
    /// Kept for symmetry with the HashMap key — useful if a caller
    /// holds onto a single `IokitDeviceStats` after lookup.
    #[allow(dead_code)]
    pub bsd_name: String,
    pub bytes_read: u64,
    pub bytes_written: u64,
    pub ops_read: u64,
    pub ops_written: u64,
    /// Nanoseconds cumulative — the kernel's per-op service time summed
    /// across every read since boot.
    pub total_time_read_ns: u64,
    pub total_time_write_ns: u64,
}

pub fn collect() -> HashMap<String, IokitDeviceStats> {
    let Ok(out) = Command::new("ioreg")
        .args(["-c", "IOBlockStorageDriver", "-r", "-l", "-w", "0"])
        .output()
    else {
        return HashMap::new();
    };
    if !out.status.success() {
        return HashMap::new();
    }
    let text = String::from_utf8_lossy(&out.stdout);
    parse_ioreg(&text)
}

/// Pure parser, exposed for tests on any platform.
pub(crate) fn parse_ioreg(text: &str) -> HashMap<String, IokitDeviceStats> {
    let mut out = HashMap::new();
    let mut pending_stats: Option<Stats> = None;

    let mut lines = text.lines().peekable();
    while let Some(line) = lines.next() {
        if line_is_node(line, "IOBlockStorageDriver") {
            // Property block for this driver follows; pull Statistics
            // out of it.
            pending_stats = read_property_block(&mut lines).and_then(|props| {
                props
                    .iter()
                    .find(|(k, _)| k == "Statistics")
                    .map(|(_, v)| parse_statistics(v))
            });
            continue;
        }
        if line_is_node(line, "IOMedia") {
            let Some(props) = read_property_block(&mut lines) else {
                continue;
            };
            let bsd = props
                .iter()
                .find(|(k, _)| k == "BSD Name")
                .map(|(_, v)| strip_quotes(v).to_string());
            let whole = props
                .iter()
                .find(|(k, _)| k == "Whole")
                .map(|(_, v)| v == "Yes")
                .unwrap_or(false);
            // The first IOMedia under each driver is the whole-disk
            // media. Partition IOMedia entries (Whole=No) appear later
            // under partition schemes — we want to skip those.
            if let (Some(name), true, Some(s)) = (bsd, whole, pending_stats.take()) {
                out.insert(
                    name.clone(),
                    IokitDeviceStats {
                        bsd_name: name,
                        bytes_read: s.bytes_read,
                        bytes_written: s.bytes_written,
                        ops_read: s.ops_read,
                        ops_written: s.ops_written,
                        total_time_read_ns: s.total_time_read_ns,
                        total_time_write_ns: s.total_time_write_ns,
                    },
                );
            }
        }
    }
    out
}

#[derive(Default, Clone, Copy)]
struct Stats {
    bytes_read: u64,
    bytes_written: u64,
    ops_read: u64,
    ops_written: u64,
    total_time_read_ns: u64,
    total_time_write_ns: u64,
}

fn line_is_node(line: &str, class_name: &str) -> bool {
    let trimmed = line.trim_start();
    trimmed.starts_with("+-o ") && trimmed.contains(&format!("<class {}", class_name))
}

/// Reads a `{ ... }` property block that immediately follows a `+-o`
/// node line. ioreg indents each property with a leading `|` plus
/// whitespace. Returns the `(key, raw_value)` pairs in order.
fn read_property_block<'a>(
    lines: &mut std::iter::Peekable<impl Iterator<Item = &'a str>>,
) -> Option<Vec<(String, String)>> {
    // Skip until we find the opening `{`.
    loop {
        let peek = lines.peek()?;
        let trimmed = peek.trim();
        if trimmed.ends_with('{') || trimmed == "{" {
            lines.next();
            break;
        }
        // If another node header arrives before a property block, the
        // current node had no properties.
        if trimmed.starts_with("+-o ") {
            return None;
        }
        lines.next();
    }

    let mut out = Vec::new();
    for line in lines.by_ref() {
        let trimmed = line.trim().trim_start_matches('|').trim();
        if trimmed == "}" {
            break;
        }
        if let Some((k, v)) = parse_property(trimmed) {
            out.push((k, v));
        }
    }
    Some(out)
}

/// Parses one line of the form `"Key" = value`. Quotes around the key
/// are stripped; the value is returned verbatim (may itself be a dict
/// in `{a=b,c=d}` form).
fn parse_property(line: &str) -> Option<(String, String)> {
    let eq = line.find(" = ")?;
    let key_raw = line[..eq].trim();
    let val_raw = line[eq + 3..].trim();
    Some((strip_quotes(key_raw).to_string(), val_raw.to_string()))
}

fn strip_quotes(s: &str) -> &str {
    let t = s.trim();
    if t.len() >= 2 && t.starts_with('"') && t.ends_with('"') {
        &t[1..t.len() - 1]
    } else {
        t
    }
}

/// Parses the inline Statistics dict, e.g.
/// `{"Operations (Write)"=13964680,"Bytes (Read)"=368261685248,...}`
fn parse_statistics(raw: &str) -> Stats {
    let mut s = Stats::default();
    let inner = raw.trim_start_matches('{').trim_end_matches('}');
    for pair in inner.split(',') {
        let Some(eq) = pair.find('=') else { continue };
        let k = strip_quotes(pair[..eq].trim());
        let v: u64 = pair[eq + 1..].trim().parse().unwrap_or(0);
        match k {
            "Bytes (Read)" => s.bytes_read = v,
            "Bytes (Write)" => s.bytes_written = v,
            "Operations (Read)" => s.ops_read = v,
            "Operations (Write)" => s.ops_written = v,
            "Total Time (Read)" => s.total_time_read_ns = v,
            "Total Time (Write)" => s.total_time_write_ns = v,
            _ => {}
        }
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Truncated but structurally faithful sample of `ioreg -c
    /// IOBlockStorageDriver -r -l -w 0` from an Apple Silicon Mac.
    const SAMPLE: &str = r#"+-o IOBlockStorageDriver  <class IOBlockStorageDriver, id 0x100000663, registered, matched, active, busy 0 (117 ms), retain 8>
  | {
  |   "IOClass" = "IOBlockStorageDriver"
  |   "Statistics" = {"Operations (Write)"=13964680,"Latency Time (Write)"=0,"Bytes (Read)"=368261685248,"Errors (Write)"=0,"Total Time (Read)"=3698579261481,"Latency Time (Read)"=0,"Retries (Read)"=0,"Errors (Read)"=0,"Total Time (Write)"=1213255816800,"Bytes (Write)"=222826323968,"Operations (Read)"=12975224,"Retries (Write)"=0}
  | }
  |
  +-o APPLE SSD AP1024Z Media  <class IOMedia, id 0x100000791, registered, matched, active, busy 0 (117 ms), retain 12>
    | {
    |   "Content" = "GUID_partition_scheme"
    |   "Whole" = Yes
    |   "BSD Name" = "disk0"
    |   "Size" = 1000555581440
    | }
    |
    +-o IOMediaBSDClient  <class IOMediaBSDClient, id 0x1000007ca, registered, matched, active, busy 0 (0 ms), retain 6>
"#;

    #[test]
    fn parses_one_driver_with_media() {
        let m = parse_ioreg(SAMPLE);
        let stats = m.get("disk0").expect("disk0 should be present");
        assert_eq!(stats.bytes_read, 368_261_685_248);
        assert_eq!(stats.bytes_written, 222_826_323_968);
        assert_eq!(stats.ops_read, 12_975_224);
        assert_eq!(stats.ops_written, 13_964_680);
        assert_eq!(stats.total_time_read_ns, 3_698_579_261_481);
        assert_eq!(stats.total_time_write_ns, 1_213_255_816_800);
    }

    #[test]
    fn skips_partition_media() {
        // Whole=No → partition. Should not produce an entry.
        let text = r#"+-o IOBlockStorageDriver  <class IOBlockStorageDriver, id 0x1, ...>
  | {
  |   "Statistics" = {"Bytes (Read)"=10,"Bytes (Write)"=20,"Operations (Read)"=1,"Operations (Write)"=2,"Total Time (Read)"=0,"Total Time (Write)"=0}
  | }
  +-o foo Media  <class IOMedia, id 0x2, ...>
    | {
    |   "Whole" = No
    |   "BSD Name" = "disk0s1"
    | }
"#;
        let m = parse_ioreg(text);
        assert!(m.is_empty());
    }
}
