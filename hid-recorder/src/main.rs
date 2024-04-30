// SPDX-License-Identifier: MIT

use anyhow::{bail, Context, Result};
use clap::{Parser, ValueEnum};
use nix::poll::{poll, PollFd, PollFlags, PollTimeout};
use owo_colors::{OwoColorize, Stream::Stdout, Style};
use std::collections::HashSet;
use std::fs::OpenOptions;
use std::io::{Read, Write};
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

enum Styles {
    None,
    InputItem,
    OutputItem,
    FeatureItem,
    Data,
}

impl Styles {
    fn style(&self) -> Style {
        match self {
            Styles::None => Style::new(),
            Styles::Data => Style::new().red(),
            Styles::InputItem => Style::new().green().bold(),
            Styles::OutputItem => Style::new().yellow().bold(),
            Styles::FeatureItem => Style::new().blue().bold(),
        }
    }
}

// Usage: cprintln!(Sytles::Data, <normal println args>)
macro_rules! cprintln {
    ($stream:ident) => { writeln!($stream).unwrap(); };
    ($stream:ident, $style:expr, $($arg:tt)*) => {{
        writeln!($stream, "{}", format!($($arg)*).if_supports_color(Stdout, |text| text.style($style.style()))).unwrap();
    }};
}

macro_rules! cprint {
    ($stream:ident) => { write!($stream).unwrap(); };
    ($stream:ident, $style:expr, $($arg:tt)*) => {{
        write!($stream, "{}", format!($($arg)*).if_supports_color(Stdout, |text| text.style($style.style()))).unwrap();
    }};
}

#[derive(ValueEnum, Clone, Debug)]
enum ClapColorArg {
    Auto,
    Never,
    Always,
}

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Cli {
    /// Print debugging information
    #[arg(short, long, default_value_t = false)]
    debug: bool,

    #[arg(long, value_enum, default_value_t = ClapColorArg::Auto)]
    color: ClapColorArg,

    #[arg(long, default_value_t = ("-").to_string())]
    output_file: String,

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

fn parse_rdesc(stream: &mut impl Write, bytes: &[u8]) -> Result<()> {
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

        if let ItemType::Main(MainItem::EndCollection) = item.item_type() {
            indent -= 2;
        }

        let indented = format!("{:indent$}{}", "", fmt_item(item, &current_usage_page));
        let style = match item.item_type() {
            ItemType::Main(MainItem::Input(..)) => Styles::InputItem,
            ItemType::Main(MainItem::Output(..)) => Styles::OutputItem,
            ItemType::Main(MainItem::Feature(..)) => Styles::FeatureItem,
            _ => Styles::None,
        };
        cprintln!(stream, style, "# {bytes:30} // {indented:40} {offset}");

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
fn print_report(stream: &mut impl Write, r: &impl Report) {
    if r.report_id().is_some() {
        cprintln!(
            stream,
            Styles::None,
            "# Report ID: {}",
            r.report_id().unwrap()
        );
    }
    cprintln!(
        stream,
        Styles::None,
        "#    Report size: {} bits",
        r.size_in_bits()
    );
    for field in r.fields().iter() {
        cprint!(
            stream,
            Styles::None,
            "#  |   Bits: {:3} -> {:3} | ",
            field.bits().start(),
            field.bits().end()
        );
        match field {
            Field::Constant(_c) => {
                cprint!(stream, Styles::None, "{:60} |", "######### Padding");
            }
            Field::Variable(v) => {
                let hutstr: String = match hut::Usage::try_from(&v.usage) {
                    Err(_) => "<unknown>".into(),
                    Ok(u) => format!("{} / {}", hut::UsagePage::from(&u), u),
                };
                cprint!(
                    stream,
                    Styles::None,
                    "Usage: {:04x}/{:04x}: {:42} | ",
                    u16::from(v.usage.usage_page),
                    u16::from(v.usage.usage_id),
                    hutstr
                );
                cprint!(
                    stream,
                    Styles::None,
                    "Logical Range: {:5}->{:5} | ",
                    i32::from(v.logical_minimum),
                    i32::from(v.logical_maximum)
                );
                if let (Some(min), Some(max)) = (v.physical_minimum, v.physical_maximum) {
                    cprint!(
                        stream,
                        Styles::None,
                        "Physical Range: {:5}->{:5} | ",
                        i32::from(min),
                        i32::from(max)
                    );
                };
                if let Some(u) = v.unit {
                    if let Some(units) = u.units() {
                        cprint!(stream, Styles::None, "Unit: {:?}: {:?}", u.system(), units);
                    }
                }
            }
            Field::Array(a) => {
                cprint!(stream, Styles::None, "Usages:");
                a.usages().iter().for_each(|u| {
                    let hutstr: String = match hut::Usage::try_from(u) {
                        Err(_) => "<unknown>".into(),
                        Ok(u) => format!("{} / {}", hut::UsagePage::from(&u), u),
                    };
                    cprint!(
                        stream,
                        Styles::None,
                        "\n#                              {:04x}/{:04x}: {:43}",
                        u16::from(u.usage_page),
                        u16::from(u.usage_id),
                        hutstr
                    );
                });
                cprint!(
                    stream,
                    Styles::None,
                    "| Logical Range: {:5}->{:5} | ",
                    i32::from(a.logical_minimum),
                    i32::from(a.logical_maximum)
                );
                if let (Some(min), Some(max)) = (a.physical_minimum, a.physical_maximum) {
                    cprint!(
                        stream,
                        Styles::None,
                        "Physical Range: {:5}->{:5} | ",
                        i32::from(min),
                        i32::from(max)
                    );
                };
                if let Some(u) = a.unit {
                    if let Some(units) = u.units() {
                        cprint!(stream, Styles::None, "Unit: {:?}: {:?}", u.system(), units);
                    }
                }
            }
        }
        cprintln!(stream);
    }
}

fn parse_uevent(sysfs: &Path) -> Result<(String, (u32, u32, u32))> {
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
        .split_once('=')
        .context("Unexpected HID_NAME= format")?;

    let id = uevent
        .lines()
        .find(|l| l.starts_with("HID_ID"))
        .context("Unable to find HID_ID in uevent")?;
    let (_, id) = id.split_once('=').context("Unexpected HID_ID= format")?;
    let ids: Vec<u32> = id
        .split(':')
        .map(|s| u32::from_str_radix(s, 16).context("Failed to parse {s} to int"))
        .collect::<Result<Vec<u32>>>()
        .context("Unable to parse HID_ID")?;
    let (bustype, vid, pid) = (ids[0], ids[1], ids[2]);

    Ok((name.to_string(), (bustype, vid, pid)))
}

fn parse(stream: &mut impl Write, path: &Path) -> Result<ReportDescriptor> {
    let sysfs = find_sysfs_path(path)?;
    let rdesc_path = sysfs.join("report_descriptor");
    if !rdesc_path.exists() {
        bail!("Unable to find report descriptor at {rdesc_path:?}");
    }

    let (name, ids) = parse_uevent(&sysfs)?;
    let (bustype, vid, pid) = ids;

    cprintln!(stream, Styles::None, "# {name}");
    let bytes = std::fs::read(rdesc_path)?;
    parse_rdesc(stream, &bytes)?;

    // Print the readable fields
    let bytestr = bytes
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<String>>()
        .join(" ");
    cprintln!(stream, Styles::Data, "R: {bytestr}");
    cprintln!(stream, Styles::Data, "N: {name}");
    cprintln!(stream, Styles::Data, "I: {bustype:x} {vid:x} {pid:x}");

    let rdesc = ReportDescriptor::try_from(&bytes as &[u8])?;
    cprintln!(stream, Styles::None, "# Report descriptor:");
    let input_reports = rdesc.input_reports();
    if !input_reports.is_empty() {
        for r in rdesc.input_reports() {
            cprintln!(stream, Styles::InputItem, "# ------- Input Report ------- ");
            print_report(stream, r);
        }
    }
    let output_reports = rdesc.output_reports();
    if !output_reports.is_empty() {
        for r in rdesc.output_reports() {
            cprintln!(
                stream,
                Styles::OutputItem,
                "# ------- Output Report ------- "
            );
            print_report(stream, r);
        }
    }
    let feature_reports = rdesc.feature_reports();
    if !feature_reports.is_empty() {
        for r in rdesc.feature_reports() {
            cprintln!(
                stream,
                Styles::FeatureItem,
                "# ------- Feature Report ------- "
            );
            print_report(stream, r);
        }
    }

    Ok(rdesc)
}

fn print_field_values(stream: &mut impl Write, bytes: &[u8], field: &Field) {
    match field {
        Field::Constant(_) => {
            cprint!(
                stream,
                Styles::None,
                "<{} bits padding> | ",
                field.bits().clone().count()
            );
        }
        Field::Variable(var) => {
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
            cprint!(stream, Styles::None, "{}: {:5} | ", hutstr, v);
        }
        Field::Array(arr) => {
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
                    cprint!(stream, Styles::None, "{}: {:5} | ", hutstr, v);
                }
            });
        }
    }
}

fn parse_report(
    stream: &mut impl Write,
    bytes: &[u8],
    rdesc: &ReportDescriptor,
    start_time: &Instant,
) -> Result<()> {
    let Some(report) = rdesc.find_input_report(bytes) else {
        bail!("Unable to find matching report");
    };

    if let Some(id) = report.report_id() {
        cprintln!(stream, Styles::None, "# Report ID: {id} / ");
    }

    let collections: HashSet<&Collection> = report
        .fields()
        .iter()
        .flat_map(|f| f.collections())
        .filter(|c| matches!(c.collection_type(), CollectionType::Logical))
        .collect();
    if collections.is_empty() {
        cprint!(stream, Styles::None, "#                ");
        for field in report.fields() {
            print_field_values(stream, bytes, field);
        }
        cprintln!(stream);
    } else {
        let mut collections: Vec<&Collection> = collections.into_iter().collect();
        collections.sort_by(|a, b| a.id().partial_cmp(b.id()).unwrap());

        for collection in collections {
            cprint!(stream, Styles::None, "#                ");
            for field in report.fields().iter().filter(|f| {
                // logical collections may be nested, so we only group those items together
                // where the deepest logical collection matches
                f.collections()
                    .iter()
                    .rev()
                    .find(|c| matches!(c.collection_type(), CollectionType::Logical))
                    .map(|c| c == collection)
                    .unwrap_or(false)
            }) {
                print_field_values(stream, bytes, field);
            }
            cprintln!(stream);
        }
    }

    let elapsed = start_time.elapsed();

    cprintln!(
        stream,
        Styles::Data,
        "E: {:06}.{:06} {} {}",
        elapsed.as_secs(),
        elapsed.as_micros() % 1000000,
        report.size_in_bytes(),
        bytes[..report.size_in_bytes()]
            .iter()
            .fold("".to_string(), |acc, b| format!("{acc}{b:02x} "))
    );

    Ok(())
}

fn read_events(stream: &mut impl Write, path: &Path, rdesc: &ReportDescriptor) -> Result<()> {
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
                    parse_report(stream, &data, rdesc, &now.unwrap())?;
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

    let mut stream: Box<dyn Write> = if cli.output_file == "-" {
        // Bit lame but easier to just set the env for owo_colors to figure out the rest
        match cli.color {
            ClapColorArg::Never => std::env::set_var("NO_COLOR", "1"),
            ClapColorArg::Auto => {}
            ClapColorArg::Always => std::env::set_var("FORCE_COLOR", "1"),
        }

        Box::new(std::io::stdout())
    } else {
        std::env::set_var("NO_COLOR", "1");
        Box::new(std::fs::File::create(cli.output_file).unwrap())
    };

    let rc = parse(&mut stream, &cli.path);
    if let Err(e) = rc {
        eprintln!("Error: {e:#}");
        return ExitCode::FAILURE;
    }
    let rc = if cli.path.starts_with("/dev") {
        let rdesc = rc.unwrap();
        read_events(&mut stream, &cli.path, &rdesc)
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
