// SPDX-License-Identifier: MIT

use anyhow::{bail, Context, Result};
use std::io::BufRead;
use std::path::Path;
use std::time::Duration;

use crate::{
    print_input_report_data, print_input_report_description, Backend, BpfOption, EventNode,
    ReportDescriptor,
};

// FIXME: add a enum to differ between hid events and bpf events

struct HidRecorderEvent {
    usecs: u64,
    bytes: Vec<u8>,
}

pub struct HidRecorderBackend {
    name: String,
    bustype: u16,
    vid: u16,
    pid: u16,
    rdesc: Vec<u8>,
    events: Vec<HidRecorderEvent>,
}

impl HidRecorderBackend {}

/// Decode a length-prefixed string of bytes, e.g.
/// 4 00 01 02 03 04
/// ^ ^------------^
/// |      |
/// |      + bytes in hex
/// +-- length in bytes, decimal
fn decode_length_prefixed_data(str: &str) -> Result<(usize, Vec<u8>)> {
    let Some((length, rest)) = str.split_once(' ') else {
        bail!("Invalid format, expected <length> [byte, byte, ...]");
    };
    let length = length.parse::<usize>()?;
    let bytes = hex::decode(rest.replace(' ', ""))?;

    if length != bytes.len() {
        bail!("Invalid data length: {} expected {}", bytes.len(), length);
    }

    Ok((length, bytes))
}

impl TryFrom<&Path> for HidRecorderBackend {
    type Error = anyhow::Error;

    fn try_from(path: &Path) -> Result<Self> {
        let f = std::fs::File::open(path)?;
        let lines = std::io::BufReader::new(f)
            .lines()
            .map_while(Result::ok)
            .map(|l| String::from(l.trim()));

        let mut name = None;
        let mut bustype: Option<u16> = None;
        let mut vid: Option<u16> = None;
        let mut pid: Option<u16> = None;
        let mut rdesc: Option<Vec<u8>> = None;
        let mut events: Vec<HidRecorderEvent> = Vec::new();

        for line in lines {
            if line.is_empty() || line.starts_with("#") {
                continue;
            }
            match line.split_once(' ') {
                Some(("N:", rest)) => name = Some(String::from(rest)),
                Some(("I:", rest)) => {
                    let v = rest
                        .split(' ')
                        .map(|s| u16::from_str_radix(s, 16))
                        .collect::<Result<Vec<u16>, _>>()?;
                    bustype = Some(*v.first().context("Missing bustype")?);
                    vid = Some(*v.get(1).context("Missing vid")?);
                    pid = Some(*v.get(2).context("Missing pid")?);
                }
                Some(("R:", rest)) => {
                    rdesc = Some(
                        decode_length_prefixed_data(rest)
                            .context("Invalid report descriptor")?
                            .1,
                    );
                }
                Some(("E:", rest)) => {
                    let (timestamp, rest) = rest.split_once(' ').context("Missing timestamp")?;
                    let (secs, usecs) = timestamp
                        .split_once('.')
                        .context("Invalid timestamp format")?;
                    let secs = secs
                        .parse::<u64>()
                        .context(format!("Invalid timestamp string {secs}"))?;
                    let usecs = usecs
                        .parse::<u64>()
                        .context(format!("Invalid timestamp string {usecs}"))?;
                    let bytes = decode_length_prefixed_data(rest)
                        .context("Invalid bytes")?
                        .1;
                    events.push(HidRecorderEvent {
                        usecs: secs * 1_000_000 + usecs,
                        bytes,
                    })
                }
                // ignore unknown prefixes
                _ => {}
            };
        }

        Ok(HidRecorderBackend {
            name: name.context("Missing name")?,
            bustype: bustype.context("Missing bustype")?,
            vid: vid.context("Missing vid")?,
            pid: pid.context("Missing pid")?,
            rdesc: rdesc.context("Missing rdesc")?,
            events,
        })
    }
}

impl Backend for HidRecorderBackend {
    fn name(&self) -> &str {
        &self.name
    }

    fn bustype(&self) -> u32 {
        self.bustype as u32
    }

    fn vid(&self) -> u32 {
        self.vid as u32
    }

    fn pid(&self) -> u32 {
        self.pid as u32
    }

    fn rdesc(&self) -> &[u8] {
        &self.rdesc
    }

    fn event_nodes(&self) -> &[EventNode] {
        &[]
    }

    fn read_events(&self, _use_bpf: BpfOption, rdesc: &ReportDescriptor) -> Result<()> {
        for e in self.events.iter() {
            let elapsed = Duration::from_micros(e.usecs);
            print_input_report_description(&e.bytes, rdesc)?;
            print_input_report_data(&e.bytes, rdesc, &elapsed)?;
        }

        Ok(())
    }
}
