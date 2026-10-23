//! Export of stored history as JSON Lines or CSV.

use std::io::{self, Write};

use crate::metrics::{FIELDS, Record};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Jsonl,
    Csv,
}

impl Format {
    pub fn parse(s: &str) -> Option<Format> {
        match s.to_ascii_lowercase().as_str() {
            "jsonl" | "json" | "ndjson" => Some(Format::Jsonl),
            "csv" => Some(Format::Csv),
            _ => None,
        }
    }
}

pub fn write(records: &[Record], format: Format, out: &mut impl Write) -> io::Result<()> {
    match format {
        Format::Jsonl => {
            for r in records {
                serde_json::to_writer(&mut *out, r).map_err(io::Error::other)?;
                out.write_all(b"\n")?;
            }
        }
        Format::Csv => {
            // Only columns that have at least one value, to keep files small.
            let cols: Vec<&str> = FIELDS
                .iter()
                .map(|f| f.key)
                .filter(|k| records.iter().any(|r| r.get(k).is_some()))
                .collect();
            write!(out, "time_unix,time_utc")?;
            for c in &cols {
                write!(out, ",{c}")?;
            }
            writeln!(out)?;
            for r in records {
                let (y, mo, d, h, mi, s) = crate::util::civil_from_unix(r.t);
                write!(out, "{},{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}Z", r.t)?;
                for c in &cols {
                    match r.get(c) {
                        Some(v) => write!(out, ",{v}")?,
                        None => write!(out, ",")?,
                    }
                }
                writeln!(out)?;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn recs() -> Vec<Record> {
        vec![
            Record {
                t: 1_709_210_096,
                cpu: Some(12.5),
                ..Default::default()
            },
            Record {
                t: 1_709_210_106,
                cpu: Some(13.0),
                net_rx: Some(100.0),
                ..Default::default()
            },
        ]
    }

    #[test]
    fn csv_has_only_present_columns() {
        let mut buf = Vec::new();
        write(&recs(), Format::Csv, &mut buf).unwrap();
        let s = String::from_utf8(buf).unwrap();
        let lines: Vec<&str> = s.lines().collect();
        assert_eq!(lines[0], "time_unix,time_utc,cpu,net_rx");
        assert_eq!(lines[1], "1709210096,2024-02-29T12:34:56Z,12.5,");
        assert_eq!(lines[2], "1709210106,2024-02-29T12:35:06Z,13,100");
    }

    #[test]
    fn jsonl_one_line_per_record() {
        let mut buf = Vec::new();
        write(&recs(), Format::Jsonl, &mut buf).unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert_eq!(s.lines().count(), 2);
        assert!(s.starts_with(r#"{"t":1709210096,"cpu":12.5}"#));
    }

    #[test]
    fn format_names() {
        assert_eq!(Format::parse("CSV"), Some(Format::Csv));
        assert_eq!(Format::parse("jsonl"), Some(Format::Jsonl));
        assert_eq!(Format::parse("xml"), None);
    }
}
