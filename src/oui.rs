//! MAC vendor lookup from an embedded OUI table plus an optional user file.

use std::collections::HashMap;
use std::path::Path;

use crate::packet::MacAddr;

const BUILTIN: &str = include_str!("../data/oui.csv");

/// Maps 24-bit OUIs to vendor names.
#[derive(Debug, Clone, Default)]
pub struct OuiTable {
    map: HashMap<u32, String>,
}

impl OuiTable {
    /// Table with only the embedded entries.
    pub fn builtin() -> Self {
        let mut t = Self::default();
        t.extend_from_csv(BUILTIN);
        t
    }

    /// Embedded entries extended (and overridden) by a CSV file.
    ///
    /// # Errors
    ///
    /// Returns the I/O error if the file cannot be read.
    pub fn with_file(path: &Path) -> std::io::Result<Self> {
        let mut t = Self::builtin();
        t.extend_from_csv(&std::fs::read_to_string(path)?);
        Ok(t)
    }

    /// Adds entries from CSV text; accepts both `PREFIX,Vendor` and the IEEE
    /// `Registry,Assignment,Organization Name,...` layout. Lines that do not
    /// contain a 6-digit hex prefix are ignored. Returns the number added.
    pub fn extend_from_csv(&mut self, text: &str) -> usize {
        let mut added = 0;
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let fields = split_csv(line);
            let (prefix, vendor) = match fields.as_slice() {
                [reg, prefix, vendor, ..] if reg.starts_with("MA-") => (prefix, vendor),
                [prefix, vendor, ..] => (prefix, vendor),
                _ => continue,
            };
            let hex: String = prefix.chars().filter(char::is_ascii_hexdigit).collect();
            let Ok(oui) = u32::from_str_radix(&hex, 16) else {
                continue;
            };
            if hex.len() != 6 || vendor.is_empty() {
                continue;
            }
            self.map.insert(oui, vendor.trim().to_owned());
            added += 1;
        }
        added
    }

    /// Vendor for `mac`, if its OUI is known.
    pub fn lookup(&self, mac: MacAddr) -> Option<&str> {
        self.map.get(&mac.oui()).map(String::as_str)
    }

    /// Number of entries.
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// True if the table has no entries.
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}

/// Splits one CSV line, honouring double-quoted fields with `""` escapes.
fn split_csv(line: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut cur = String::new();
    let mut quoted = false;
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        match (c, quoted) {
            ('"', true) if chars.peek() == Some(&'"') => {
                cur.push('"');
                chars.next();
            }
            ('"', _) => quoted = !quoted,
            (',', false) => fields.push(std::mem::take(&mut cur)),
            _ => cur.push(c),
        }
    }
    fields.push(cur);
    fields
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_lookup() {
        let t = OuiTable::builtin();
        assert!(t.len() > 50);
        assert_eq!(
            t.lookup("b8:27:eb:12:34:56".parse().unwrap()),
            Some("Raspberry Pi")
        );
        assert_eq!(t.lookup("02:00:00:00:00:01".parse().unwrap()), None);
    }

    #[test]
    fn ieee_format_with_quotes() {
        let mut t = OuiTable::default();
        let n = t.extend_from_csv(
            "Registry,Assignment,Organization Name,Organization Address\n\
             MA-L,AABBCC,\"Acme, Inc.\",\"1 Road\"\n\
             MA-L,XYZ,Bad,\n\
             DDEEFF,Plain Vendor\n",
        );
        assert_eq!(n, 2);
        assert_eq!(
            t.lookup("aa:bb:cc:00:00:00".parse().unwrap()),
            Some("Acme, Inc.")
        );
        assert_eq!(
            t.lookup("dd:ee:ff:00:00:00".parse().unwrap()),
            Some("Plain Vendor")
        );
    }

    #[test]
    fn csv_escapes() {
        assert_eq!(
            split_csv(r#"a,"b ""q"", c",d"#),
            vec!["a", "b \"q\", c", "d"]
        );
    }
}
