// SPDX-License-Identifier: MIT
//
use anyhow::{bail, Context, Result};
use clap::Parser;
use std::io::BufRead;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, Instant};
use uhid_virt::{Bus, OutputEvent, StreamError, UHIDDevice};

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Cli {
    /// Print debugging information
    #[arg(long, default_value_t = false)]
    verbose: bool,

    /// Replay events starting at this timestamp (in milliseconds)
    #[arg(long, default_value_t = 0)]
    start_time: u64,

    /// Replay events stopping at this timestamp (in milliseconds)
    #[arg(long, default_value_t = 0)]
    stop_time: u64,

    /// Path to the hid-recorder recording
    recording: PathBuf,
}

#[derive(Debug)]
struct Event {
    usecs: u64,
    bytes: Vec<u8>,
}

#[derive(Debug)]
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

    let mut recording = parse(&cli.recording)?;

    println!(
        "Device {:04X}:{:04X}:{:04X} - {}",
        recording.ids.0, recording.ids.1, recording.ids.2, recording.name
    );

    if cli.start_time > 0 || cli.stop_time > 0 {
        recording.events = recording
            .events
            .into_iter()
            .skip_while(|e| e.usecs < cli.start_time * 1000)
            .take_while(|e| cli.stop_time == 0 || e.usecs < cli.stop_time * 1000)
            .collect();
    }

    let recording = recording;
    if let Some(last_event) = recording.events.last() {
        let secs = (last_event.usecs - cli.start_time * 1000) / 1_000_000;
        println!(
            "Recording is {secs}s long ({} HID reports).",
            recording.events.len()
        );
    } else {
        println!("This recording has no events!");
    }

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
        name: format!("hid-replay {}", recording.name),
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

    let uhid_sysfs = PathBuf::from("/sys/devices/virtual/misc/uhid/");
    // Devices use bus/vid/pid like this: 0003:056A:0357.0049 with the last component
    // being an incremental (and thus not predictable) number
    let globname = format!(
        "{:04X}:{:04X}:{:04X}.*",
        recording.ids.0, recording.ids.1, recording.ids.2
    );
    let globstr = uhid_sysfs.join(globname);
    let globstr = globstr.to_string_lossy();

    loop {
        // We might have a GetFeature request waiting which we'll just
        // reply to with EIO, that's good enough for what we do here.
        // uhid_virt doesn't expose the fd though so we can only
        // try to read, fail, and continue, no polling.
        match uhid_device.read() {
            Ok(OutputEvent::GetReport { id, .. }) => {
                uhid_device.write_get_report_reply(id, nix::errno::Errno::EIO as u16, vec![])?;
            }
            Ok(OutputEvent::SetReport { id, .. }) => {
                uhid_device.write_set_report_reply(id, nix::errno::Errno::EIO as u16)?;
            }
            Ok(_) => {}
            Err(StreamError::Io(e)) => match e.kind() {
                std::io::ErrorKind::WouldBlock => {}
                _ => bail!(e),
            },
            Err(StreamError::UnknownEventType(e)) => bail!("Unknown error {e}"),
        }

        // Check if there's a `hidraw` directory inside our just-created
        // uhid sysfs path. If not we have the uhid device but not yet
        // the hidraw device. This means the kernel is still sending us
        // GetReports that we have to process.
        //
        // We may have multiple devices with the same bus/vid/pid so we check
        // for all of them to have a hidraw directory. In the worst case we may
        // have to wait for a different device to initialize but let's consider
        // that a bit niche.
        let mut have_elements = false;
        if glob::glob(&globstr)
            .context("Failed to read glob pattern")?
            .all(|e| {
                have_elements = true;
                e.is_ok() && e.unwrap().join("hidraw").exists()
            })
            && have_elements
        {
            break;
        };
        std::thread::sleep(Duration::from_millis(10));
    }

    let mut pos = 0i8;
    let mut direction = 1i8;
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
                let interval = target_time - elapsed;
                if interval > Duration::from_secs(2) {
                    let note = format!("***** Sleeping for {}s *****", interval.as_secs());
                    print!("\r{:^50}", note);
                    std::io::stdout().flush().unwrap();
                }
                std::thread::sleep(interval);
            }
            print!("\r{1:0$}*{1:2$}", pos as usize, " ", 50 - pos as usize);
            std::io::stdout().flush().unwrap();
            uhid_device.write(&e.bytes)?;
            pos += direction;
            if pos % 49 == 0 {
                direction *= -1;
            }
        }
        print!("\r{:50}\r", " ");
        std::io::stdout().flush().unwrap();
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
