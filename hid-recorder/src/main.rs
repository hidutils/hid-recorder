// SPDX-License-Identifier: MIT

use anyhow::{bail, Context, Result};
use clap::Parser;
use libc;
use nix::poll::{poll, PollFd, PollFlags, PollTimeout};
use std::fs::OpenOptions;
use std::io::Read;
use std::os::fd::AsFd;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Instant;

use hidreport::hid::{
    CollectionItem, GlobalItem, Item, ItemType, LocalItem, MainDataItem, MainItem,
    ReportDescriptorItems,
};
use hidreport::hut;
use hidreport::*;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Cli {
    /// Print debugging information
    #[arg(short, long, default_value_t = false)]
    debug: bool,

    /// Path to the hidraw device node
    path: PathBuf,
}

fn fmt_main_item(item: &MainItem) -> String {
    match item {
        MainItem::Input(i) => {
            format!(
                "Input ({},{},{}{}{}{}{}{})",
                if i.is_constant() { "Cnst" } else { "Data" },
                if i.is_variable() { "Var" } else { "Arr" },
                if i.is_relative() { "Rel" } else { "Abs" },
                if i.wraps() { ",Wrap" } else { "" },
                if i.is_nonlinear() { ",NonLin" } else { "" },
                if i.has_no_preferred_state() {
                    ",NoPref"
                } else {
                    ""
                },
                if i.has_null_state() { ",Null" } else { "" },
                if i.is_buffered_bytes() { ",Buff" } else { "" }
            )
        }
        MainItem::Output(i) => {
            format!(
                "Output ({},{},{}{}{}{}{}{}{})",
                if i.is_constant() { "Cnst" } else { "Data" },
                if i.is_variable() { "Var" } else { "Arr" },
                if i.is_relative() { "Rel" } else { "Abs" },
                if i.wraps() { ",Wrap" } else { "" },
                if i.is_nonlinear() { ",NonLin" } else { "" },
                if i.has_no_preferred_state() {
                    ",NoPref"
                } else {
                    ""
                },
                if i.has_null_state() { ",Null" } else { "" },
                if i.is_volatile() { ",Vol" } else { "" },
                if i.is_buffered_bytes() { ",Buff" } else { "" }
            )
        }
        MainItem::Feature(i) => {
            format!(
                "Feature ({},{},{}{}{}{}{}{}{})",
                if i.is_constant() { "Cnst" } else { "Data" },
                if i.is_variable() { "Var" } else { "Arr" },
                if i.is_relative() { "Rel" } else { "Abs" },
                if i.wraps() { ",Wrap" } else { "" },
                if i.is_nonlinear() { ",NonLin" } else { "" },
                if i.has_no_preferred_state() {
                    ",NoPref"
                } else {
                    ""
                },
                if i.has_null_state() { ",Null" } else { "" },
                if i.is_volatile() { ",Vol" } else { "" },
                if i.is_buffered_bytes() { ",Buff" } else { "" }
            )
        }
        MainItem::Collection(c) => format!(
            "Collection ({})",
            match c {
                CollectionItem::Physical => "Physical",
                CollectionItem::Application => "Application",
                CollectionItem::Logical => "Logical",
                CollectionItem::Report => "Report",
                CollectionItem::NamedArray => "NamedArray",
                CollectionItem::UsageSwitch => "UsageSwitch",
                CollectionItem::UsageModifier => "UsageModifier",
                CollectionItem::Reserved { .. } => "Reserved",
                CollectionItem::VendorDefined { .. } => "VendorDefined",
            },
        ),
        MainItem::EndCollection => "EndCollection".into(),
    }
}

fn fmt_global_item(item: &GlobalItem) -> String {
    match item {
        GlobalItem::UsagePage { usage_page } => {
            let up = hut::UsagePage::try_from(usage_page);
            let str = match up {
                Ok(up) => format!("{up}"),
                Err(_) => format!("{usage_page}"),
            };

            format!("Usage Page ({str})")
        }
        GlobalItem::LogicalMinimum { minimum } => format!("Logical Minimum ({minimum})"),
        GlobalItem::LogicalMaximum { maximum } => format!("Logical Maximum ({maximum})"),
        GlobalItem::PhysicalMinimum { minimum } => format!("Physical Maximum ({minimum})"),
        GlobalItem::PhysicalMaximum { maximum } => format!("Physical Minimum ({maximum})"),
        GlobalItem::UnitExponent { exponent } => format!("Exponent ({exponent})"),
        GlobalItem::Unit { unit } => format!("Unit ({unit})"),
        GlobalItem::ReportSize { size } => format!("Report Size ({size})"),
        GlobalItem::ReportId { id } => format!("Report ID ({id})"),
        GlobalItem::ReportCount { count } => format!("Report Count ({count})"),
        GlobalItem::Push => "Push".into(),
        GlobalItem::Pop => "Pop".into(),
        GlobalItem::Reserved => "Reserved".into(),
    }
}

fn fmt_local_item(item: &LocalItem, global_usage_page: &UsagePage) -> String {
    match item {
        LocalItem::Usage {
            usage_page,
            usage_id,
        } => {
            let up: &UsagePage = match usage_page {
                Some(up) => up,
                None => global_usage_page,
            };
            let hut = hut::UsagePage::try_from(up);
            let str = match hut {
                Ok(hut) => {
                    let u = hut.to_usage(usage_id);
                    match u {
                        Ok(u) => format!("{u}"),
                        Err(_) => format!("{usage_id}"),
                    }
                }
                Err(_) => format!("{usage_id}"),
            };
            format!("Usage ({str})")
        }
        LocalItem::UsageMinimum { minimum } => format!("UsageMinimum ({minimum})"),
        LocalItem::UsageMaximum { maximum } => format!("UsageMaximum ({maximum})"),
        LocalItem::DesignatorIndex { index } => format!("DesignatorIndex ({index})"),
        LocalItem::DesignatorMinimum { minimum } => format!("DesignatorMinimum ({minimum})"),
        LocalItem::DesignatorMaximum { maximum } => format!("DesignatorMaximum ({maximum})"),
        LocalItem::StringIndex { index } => format!("StringIndex ({index})"),
        LocalItem::StringMinimum { minimum } => format!("StringMinimum ({minimum})"),
        LocalItem::StringMaximum { maximum } => format!("StringMaximum ({maximum})"),
        LocalItem::Delimiter { delimiter } => format!("Delimiter ({delimiter})"),
        LocalItem::Reserved { value } => format!("Reserved ({value})"),
    }
}

fn fmt_item(item: &impl Item, usage_page: &UsagePage) -> String {
    match item.item_type() {
        ItemType::Main(mi) => fmt_main_item(&mi),
        ItemType::Global(gi) => fmt_global_item(&gi),
        ItemType::Local(li) => fmt_local_item(&li, usage_page),
        i => format!("{:?}", i),
    }
}

fn parse_rdesc(bytes: &[u8]) -> Result<()> {
    let rdesc_items = ReportDescriptorItems::try_from(bytes)?;
    let mut indent = 0;
    let mut current_usage_page = UsagePage::from(0u16); // Undefined

    // Print the device description
    for rdesc_item in rdesc_items.iter() {
        let item = rdesc_item.item();
        let offset = rdesc_item.offset();
        let bytes = item
            .bytes()
            .iter()
            .map(|b| format!("{b:02x}, "))
            .collect::<Vec<String>>()
            .join("");

        match item.item_type() {
            ItemType::Main(MainItem::EndCollection) => indent -= 2,
            _ => {}
        }

        let indented = format!("{:indent$}{}", "", fmt_item(item, &current_usage_page));
        println!("# {bytes:30} // {indented:40} {offset}");
        match item.item_type() {
            ItemType::Main(MainItem::Collection(_)) => indent += 2,
            ItemType::Global(GlobalItem::UsagePage { usage_page }) => {
                current_usage_page = usage_page;
            }
            _ => {}
        }
    }

    Ok(())
}

// This would be easier with udev but let's keep the dependencies relatively minimal.
fn find_sysfs_path(path: &Path) -> Result<PathBuf> {
    let sysfs = if path.starts_with("/dev/") {
        PathBuf::from("/sys/class/hidraw/")
            .join(path.file_name().unwrap())
            .join("device")
    } else if path.starts_with("/sys") {
        let path = path.canonicalize()?;
        let path = if !path.is_dir() {
            path.parent().unwrap()
        } else {
            &path
        };
        // We're now somewhere in one of
        // in /sys/devices/pci0000:00/0000:00:14.0/usb1/1-9/1-9:1.2/0003:046D:C52B.0003/hidraw/hidraw0
        // Go up the HID device root
        path.components()
            .take_while(|c| !c.as_os_str().to_string_lossy().starts_with("hidraw"))
            .collect()
    } else {
        bail!("Don't know how to handle {path:?}");
    };

    Ok(sysfs)
}

/// Print the parsed reports as an outline of how they look like
fn print_report(r: &impl Report) {
    if r.report_id().is_some() {
        println!("# Report ID: {}", r.report_id().unwrap());
    }
    println!("#    Report size: {} bits", r.size_in_bits());
    for field in r.fields().iter() {
        print!(
            "#  |   Bits: {:3} -> {:3} | ",
            field.bits().start(),
            field.bits().end()
        );
        match field {
            Field::Constant(_c) => {
                print!("{:60} |", "######### Padding");
            }
            Field::Variable(v) => {
                let hutstr: String = match hut::Usage::try_from(&v.usage) {
                    Err(_) => "<unknown>".into(),
                    Ok(u) => format!("{} / {}", hut::UsagePage::from(&u), u),
                };
                print!(
                    "Usage: {:04x}/{:04x}: {:42} | ",
                    u16::from(v.usage.usage_page),
                    u16::from(v.usage.usage_id),
                    hutstr
                );
                print!(
                    "Logical Range: {:5}->{:5} | ",
                    i32::from(v.logical_minimum),
                    i32::from(v.logical_maximum)
                );
                if let (Some(min), Some(max)) = (v.physical_minimum, v.physical_maximum) {
                    print!(
                        "Physical Range: {:5}->{:5} | ",
                        i32::from(min),
                        i32::from(max)
                    );
                };
                if let Some(u) = v.unit {
                    match u.units() {
                        Some(units) => print!("Unit: {:?}: {:?}", u.system(), units),
                        None => {}
                    }
                }
            }
            Field::Array(a) => {
                print!("Usages:");
                a.usages().iter().for_each(|u| {
                    let hutstr: String = match hut::Usage::try_from(u) {
                        Err(_) => "<unknown>".into(),
                        Ok(u) => format!("{} / {}", hut::UsagePage::from(&u), u),
                    };
                    print!(
                        "\n#                              {:04x}/{:04x}: {:43}",
                        u16::from(u.usage_page),
                        u16::from(u.usage_id),
                        hutstr
                    );
                });
                print!(
                    "| Logical Range: {:5}->{:5} | ",
                    i32::from(a.logical_minimum),
                    i32::from(a.logical_maximum)
                );
                if let (Some(min), Some(max)) = (a.physical_minimum, a.physical_maximum) {
                    print!(
                        "Physical Range: {:5}->{:5} | ",
                        i32::from(min),
                        i32::from(max)
                    );
                };
                if let Some(u) = a.unit {
                    match u.units() {
                        Some(units) => print!("Unit: {:?}: {:?}", u.system(), units),
                        None => {}
                    }
                }
            }
        }
        println!();
    }
}

fn parse(path: &Path) -> Result<ReportDescriptor> {
    let sysfs = find_sysfs_path(path)?;
    let rdesc_path = sysfs.join("report_descriptor");
    if !rdesc_path.exists() {
        bail!("Unable to find report descriptor at {rdesc_path:?}");
    }

    let bytes = std::fs::read(rdesc_path)?;
    parse_rdesc(&bytes)?;

    // Print the readable fields
    let bytestr = bytes
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<String>>()
        .join(" ");
    println!("R: {bytestr}");

    // uevent should contain
    // HID_NAME=foo bar
    // HID_ID=00003:0002135:0000123513
    let uevent_path = sysfs.join("uevent");
    let uevent = std::fs::read_to_string(uevent_path)?;

    let name = uevent
        .lines()
        .find(|l| l.starts_with("HID_NAME"))
        .context("Unable to find HID_NAME in uevent")?;
    let (_, name) = name
        .split_once("=")
        .context("Unexpected HID_NAME= format")?;
    println!("N: {name}");

    let id = uevent
        .lines()
        .find(|l| l.starts_with("HID_ID"))
        .context("Unable to find HID_ID in uevent")?;
    let (_, id) = id.split_once("=").context("Unexpected HID_ID= format")?;
    let ids: Vec<u32> = id
        .split(":")
        .map(|s| u32::from_str_radix(s, 16).context("Failed to parse {s} to int"))
        .collect::<Result<Vec<u32>>>()
        .context("Unable to parse HID_ID")?;
    let (bustype, vid, pid) = (ids[0], ids[1], ids[2]);

    println!("I: {bustype:x} {vid:x} {pid:x}");

    let rdesc = ReportDescriptor::try_from(&bytes as &[u8])?;
    println!("# Report descriptor:");
    let input_reports = rdesc.input_reports();
    if !input_reports.is_empty() {
        println!("# Input reports:");
        for r in rdesc.input_reports() {
            println!("# ------- Input Report ------- ");
            print_report(r);
        }
    }
    let output_reports = rdesc.output_reports();
    if !output_reports.is_empty() {
        println!("# Output reports:");
        for r in rdesc.output_reports() {
            println!("# ------- Output Report ------- ");
            print_report(r);
        }
    }
    let feature_reports = rdesc.feature_reports();
    if !feature_reports.is_empty() {
        println!("# Feature reports:");
        for r in rdesc.feature_reports() {
            println!("# ------- Feature Report ------- ");
            print_report(r);
        }
    }

    Ok(rdesc)
}

fn parse_report(bytes: &[u8], rdesc: &ReportDescriptor, start_time: &Instant) -> Result<()> {
    let Some(report) = rdesc.find_input_report(bytes) else {
        bail!("Unable to find matching report");
    };

    if let Some(id) = report.report_id() {
        println!("# Report ID: {id} / ");
    }

    let mut current_collection: Option<&Collection> = None;

    /// Check for a logical collections in the slice and compare it to the current one,
    /// returning either the current one (if unchanged) or the new one (if changed).
    /// If no logical collection is present, None is returned.
    fn compare_collections<'a>(
        collections: &'a [Collection],
        current: Option<&'a Collection>,
    ) -> (bool, Option<&'a Collection>) {
        let c = collections
            .iter()
            .find(|&c| matches!(c.collection_type(), CollectionType::Logical));
        let (changed, newc) = match c {
            // true only on the first call
            Some(c) if current.is_none() => (true, Some(c)),
            Some(c) => {
                if c != current.unwrap() {
                    (true, Some(c))
                } else {
                    (false, current)
                }
            }
            None => (false, current),
        };
        (changed, newc)
    }

    for field in report.fields() {
        match field {
            Field::Constant(_) => {
                print!(
                    "#  |             <{} bits padding>",
                    field.bits().clone().count()
                );
                println!("");
            }
            Field::Variable(var) => {
                let changed: bool;
                (changed, current_collection) =
                    compare_collections(&var.collections, current_collection);
                if changed {
                    println!("#  +------------------------------");
                }
                let v = var.extract_i32(bytes).unwrap();
                let u = var.usage;
                let hut = hut::Usage::try_from(&u);
                let hutstr = if let Ok(hut) = hut {
                    format!("{hut}")
                } else {
                    format!(
                        "{:04x}/{:04x}",
                        u16::from(u.usage_page),
                        u16::from(u.usage_id)
                    )
                };
                print!("#  |             ");
                println!("{:20}: {:5} |", hutstr, i32::from(v));
            }
            Field::Array(arr) => {
                let changed: bool;
                (changed, current_collection) =
                    compare_collections(&arr.collections, current_collection);
                if changed {
                    println!("#  +------------------------------");
                }

                let usage_range = arr.usage_range();

                // The values in the array are usage values between usage min/max
                let vs = arr.extract_u32(bytes).unwrap();
                vs.iter().for_each(|v| {
                    // Does the value have a usage page?
                    let usage = if (v & 0xffff0000) != 0 {
                        Usage::from(*v)
                    } else {
                        Usage::from_page_and_id(
                            usage_range.minimum().usage_page(),
                            UsageId::from(*v as u16),
                        )
                    };
                    // Usage within range?
                    if let Some(usage) = usage_range.lookup_usage(&usage) {
                        let hutstr = if let Ok(hut) = hut::Usage::try_from(usage) {
                            format!("{hut}")
                        } else {
                            format!(
                                "{:04x}/{:04x}",
                                u16::from(usage.usage_page),
                                u16::from(usage.usage_id)
                            )
                        };
                        print!("#                ");
                        println!("{:20}: {:5} |", hutstr, v);
                    }
                });
            }
        }
    }

    let elapsed = start_time.elapsed();

    print!(
        "E: {:06}.{:06} {} ",
        elapsed.as_secs(),
        elapsed.as_micros() % 1000000,
        report.size_in_bytes()
    );
    bytes[..report.size_in_bytes()]
        .iter()
        .for_each(|b| print!("{b:02x} "));
    println!("");

    Ok(())
}

fn read_events(path: &Path, rdesc: &ReportDescriptor) -> Result<()> {
    let mut f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(path)?;

    let timeout = PollTimeout::try_from(-1).unwrap();
    let mut now: Option<Instant> = None;
    let mut data = [0; 1024];
    loop {
        let mut pollfds = [PollFd::new(f.as_fd(), PollFlags::POLLIN)];
        if poll(&mut pollfds, timeout)? > 0 {
            match f.read(&mut data) {
                Ok(_nbytes) => {
                    now = if now.is_none() {
                        Some(Instant::now())
                    } else {
                        now
                    };
                    parse_report(&data, rdesc, &now.unwrap())?;
                }
                Err(e) => {
                    if e.kind() != std::io::ErrorKind::WouldBlock {
                        bail!(e);
                    }
                }
            };
        }
    }

    Ok(())
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    let rc = parse(&cli.path);
    if let Err(e) = rc {
        eprintln!("Error: {e:#}");
        return ExitCode::FAILURE;
    }
    let rc = if cli.path.starts_with("/dev") {
        let rdesc = rc.unwrap();
        read_events(&cli.path, &rdesc)
    } else {
        Ok(())
    };

    match rc {
        Ok(_) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("Error: {e:#}");
            ExitCode::FAILURE
        }
    }
}
