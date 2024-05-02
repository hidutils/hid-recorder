// SPDX-License-Identifier: MIT
//
use anyhow::{bail, Context, Result};
use clap::Parser;
use std::io::BufRead;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, Instant};
use uhid_virt::{Bus, UHIDDevice};

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Cli {
    /// Print debugging information
    #[arg(long, default_value_t = false)]
    verbose: bool,

    /// Path to the hid-recorder recording
    recording: PathBuf,
}

struct Event {
    usecs: u64,
    bytes: Vec<u8>,
}

struct Recording {
    name: String,
    ids: (u16, u16, u16),
    rdesc: Vec<u8>,
    events: Vec<Event>,
}

/// Decode a length-prefixed string of bytes, e.g.
/// 4 00 01 02 03 04
/// ^ ^------------^
/// |      |
/// |      + bytes in hex
/// +-- length in bytes, decimal
fn data_decode(str: &str) -> Result<(usize, Vec<u8>)> {
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

fn parse(path: &Path) -> Result<Recording> {
    let f = std::fs::File::open(path)?;
    let lines = std::io::BufReader::new(f).lines();
    let mut name: Option<String> = None;
    let mut ids: Option<[u16; 3]> = None;
    let mut rdesc: Option<Vec<u8>> = None;
    let mut events: Vec<Event> = vec![];
    for line in lines
        .map_while(Result::ok)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| String::from(l.trim()))
    {
        match line.split_once(' ') {
            Some(("N:", rest)) => name = Some(String::from(rest)),
            Some(("I:", rest)) => {
                ids = Some(
                    rest.split(' ')
                        .map(|s| u16::from_str_radix(s, 16).unwrap())
                        .collect::<Vec<u16>>()
                        .try_into()
                        .unwrap(),
                )
            }
            Some(("R:", rest)) => {
                rdesc = Some(data_decode(rest).context("Invalid report descriptor")?.1)
            }
            Some(("E:", rest)) => {
                let Some((timestamp, rest)) = rest.split_once(' ') else {
                    bail!("Invalid event format, expected <timestamp> <length>, ...")
                };
                let Some((secs, usecs)) = timestamp.split_once('.') else {
                    bail!("Invalid timestamp format")
                };
                let secs = secs
                    .parse::<u64>()
                    .context(format!("Invalid timestamp string {secs}"))?;
                let usecs = usecs
                    .parse::<u64>()
                    .context(format!("Invalid timestamp string {usecs}"))?;
                let bytes = data_decode(rest).context("Invalid event format")?.1;
                events.push(Event {
                    usecs: secs * 1_000_000 + usecs,
                    bytes,
                });
            }
            _ => bail!("Invalid or unknown line: {line}"),
        }
    }

    Ok(Recording {
        name: name.unwrap(),
        ids: ids.unwrap().into(),
        rdesc: rdesc.unwrap(),
        events,
    })
}

fn hid_replay() -> Result<()> {
    let cli = Cli::parse();

    let recording = parse(&cli.recording)?;

    let bus = match recording.ids.0 {
        1 => Bus::PCI,
        2 => Bus::ISAPNP,
        3 => Bus::USB,
        4 => Bus::HIL,
        5 => Bus::BLUETOOTH,
        6 => Bus::VIRTUAL,
        16 => Bus::ISA,
        17 => Bus::I8042,
        18 => Bus::XTKBD,
        19 => Bus::RS232,
        20 => Bus::GAMEPORT,
        21 => Bus::PARPORT,
        22 => Bus::AMIGA,
        23 => Bus::ADB,
        24 => Bus::I2C,
        25 => Bus::HOST,
        26 => Bus::GSC,
        27 => Bus::ATARI,
        28 => Bus::SPI,
        29 => Bus::RMI,
        30 => Bus::CEC,
        31 => Bus::INTEL_ISHTP,
        _ => bail!("Unknown bus type: {}", recording.ids.0),
    };

    let create_params = uhid_virt::CreateParams {
        name: recording.name,
        phys: "".to_string(),
        uniq: "".to_string(),
        bus,
        vendor: recording.ids.1 as u32,
        product: recording.ids.2 as u32,
        version: 0,
        country: 0,
        rd_data: recording.rdesc,
    };

    let mut uhid_device = UHIDDevice::create(create_params)?;

    loop {
        print!("Hit enter to start replaying the events");
        std::io::stdout().flush().unwrap();
        let mut buffer = String::new();
        std::io::stdin().read_line(&mut buffer)?;
        // we need some loop condition, otherwise rust detects the
        // loop can never enter and throws away our uhid device. weird.
        if buffer.trim() == "quit" {
            break;
        }
        let start_time = Instant::now();
        for e in &recording.events {
            let current_time = Instant::now();
            // actual time passed since we started
            let elapsed = current_time.duration_since(start_time);
            // what our recording said
            let target_time = Duration::from_micros(e.usecs);
            if target_time > elapsed {
                std::thread::sleep(target_time - elapsed);
            }
            uhid_device.write(&e.bytes)?;
        }
    }

    Ok(())
}

fn main() -> ExitCode {
    let rc = hid_replay();
    match rc {
        Ok(_) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("Error: {e:#}");
            ExitCode::FAILURE
        }
    }
}
