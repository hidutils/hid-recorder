// SPDX-License-Identifier: MIT
//

use anyhow::{bail, Context, Result};
use std::io::Read;
use std::path::Path;
use std::time::Duration;
use yaml_rust2::{Yaml, YamlLoader};

use crate::{
    print_input_report_data, print_input_report_description, Backend, BpfOption, ReportDescriptor,
};

#[derive(Debug)]
struct HidrawEvent {
    usecs: u64,
    bytes: Vec<u8>,
}

#[derive(Debug)]
pub struct LibinputRecordingBackend {
    name: String,
    bustype: u32,
    vid: u32,
    pid: u32,
    rdesc: Vec<u8>,
    events: Vec<HidrawEvent>,
}

impl TryFrom<&Path> for LibinputRecordingBackend {
    type Error = anyhow::Error;

    fn try_from(path: &Path) -> Result<Self> {
        let mut file = std::fs::File::open(path)?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;

        let yml = YamlLoader::load_from_str(&contents)?;
        let yml = &yml[0]; // we don't know any multi-document yaml sources
        let root = yml.as_hash().context("Not a libinput recording")?;
        if !root.contains_key(&Yaml::String("libinput".into())) {
            bail!("Not a libinput recording");
        }
        let devices = root
            .get(&Yaml::String("devices".into()))
            .context("Malformed libinput recording - missing devices")?;
        // We quietly pick the first device only
        let device = devices
            .as_vec()
            .context("Malformed libinput recording - devices isn't a list")?
            .first()
            .context("Malformed libinput recording - no devices")?
            .as_hash()
            .context("Malformed libinput recording - device not an object")?;
        let hid: &Vec<Yaml> = device
            .get(&Yaml::String("hid".into()))
            .context("Not a libinput recording - hid element missing")?
            .as_vec()
            .context("Malformed libinput recording - hid not an array")?;
        let bytes = hid
            .iter()
            .map(|entry| {
                entry
                    .as_i64()
                    .and_then(|i| u8::try_from(i).ok())
                    .context("Malformed libinput recording - not a i8")
            })
            .collect::<Result<Vec<u8>, anyhow::Error>>()?;

        let evdev = device
            .get(&Yaml::String("evdev".into()))
            .context("Malformed libinput recording - evdev is missing")?
            .as_hash()
            .context("Malformed libinput recording - evdev is not an object")?;
        let name = evdev
            .get(&Yaml::String("name".into()))
            .context("Malformed libinput recording - name is missing")?
            .as_str()
            .context("Malformed libinput recording - name is not a string")?;
        let ids = evdev
            .get(&Yaml::String("id".into()))
            .context("Malformed libinput recording - ids missing")?
            .as_vec()
            .context("Malformed libinput recording - ids not an array")?
            .iter()
            .map(|id| {
                id.as_i64()
                    .and_then(|i| u32::try_from(i).ok())
                    .context("Malformed libinput recording - ids not u16")
            })
            .collect::<Result<Vec<u32>, anyhow::Error>>()?;

        let bustype = *ids
            .first()
            .context("Malformed libinput recording - missing bustype")?;
        let vid = *ids
            .get(1)
            .context("Malformed libinput recording - missing vid")?;
        let pid = *ids
            .get(2)
            .context("Malformed libinput recording - missing pid")?;

        let evlist = device
            .get(&Yaml::String("events".into()))
            .context("Not a libinput recording - events element missing")?
            .as_vec()
            .context("Malformed libinput recording - events not an array")?;

        // The key isn't fixed, might be hidraw1, hidraw2, ...
        // We only care about the first one found and only search
        // for that one in the rest of the recording.
        // A recording that alternates hidraw events is so niche we don't
        // need to care about it.
        let hidraw_node = evlist
            .iter()
            .filter_map(|event| event.as_hash())
            .filter_map(|event| event.get(&Yaml::String("hid".into()))?.as_hash())
            .find_map(|hid| {
                hid.keys()
                    .find(|key| key.as_str().filter(|k| k.starts_with("hidraw")).is_some())
            });

        let events: Vec<HidrawEvent> = if let Some(hidraw_node) = hidraw_node {
            evlist
                .iter()
                .filter_map(|event| event.as_hash())
                .filter_map(|event| event.get(&Yaml::String("hid".into()))?.as_hash())
                .filter_map(|hid| {
                    let ts = hid.get(&Yaml::String("time".into()))?.as_vec()?;
                    let secs = ts.first()?.as_i64()? as u64;
                    let usecs = ts.get(1)?.as_i64()? as u64;
                    let bytes = hid
                        .get(hidraw_node)?
                        .as_vec()?
                        .iter()
                        .map(|id| {
                            id.as_i64()
                                .and_then(|i| u8::try_from(i).ok())
                                .context("Malformed libinput recording - hidraw bytes not u8")
                        })
                        .collect::<Result<Vec<u8>, anyhow::Error>>()
                        .ok()?;
                    Some((secs * 1_000_000u64 + usecs, bytes))
                })
                .map(|(usecs, bytes)| HidrawEvent { usecs, bytes })
                .collect::<Vec<HidrawEvent>>()
        } else {
            Vec::new()
        };

        Ok(LibinputRecordingBackend {
            name: String::from(name),
            bustype,
            vid,
            pid,
            rdesc: bytes,
            events,
        })
    }
}

impl Backend for LibinputRecordingBackend {
    fn name(&self) -> &str {
        &self.name
    }

    fn bustype(&self) -> u32 {
        self.bustype
    }

    fn vid(&self) -> u32 {
        self.vid
    }

    fn pid(&self) -> u32 {
        self.pid
    }

    fn rdesc(&self) -> &[u8] {
        &self.rdesc
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
