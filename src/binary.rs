// SPDX-License-Identifier: MIT
//

use anyhow::Result;
use std::path::Path;

use crate::{Backend, BpfOption, EventNode, ReportDescriptor};

#[derive(Debug)]
pub struct BinaryBackend {
    name: String,
    bustype: u32,
    vid: u32,
    pid: u32,
    rdesc: Vec<u8>,
}

impl TryFrom<&Path> for BinaryBackend {
    type Error = anyhow::Error;

    fn try_from(path: &Path) -> Result<Self> {
        let rdesc = std::fs::read(path)?;

        Ok(BinaryBackend {
            name: String::from("No Name"),
            bustype: 0x0,
            vid: 0x0,
            pid: 0x0,
            rdesc,
        })
    }
}

impl Backend for BinaryBackend {
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

    fn event_nodes(&self) -> &[EventNode] {
        &[]
    }

    fn read_events(&self, _use_bpf: BpfOption, _rdesc: &ReportDescriptor) -> Result<()> {
        Ok(())
    }
}
