// SPDX-License-Identifier: MIT

use anyhow::{bail, Context, Result};
use clap::{ColorChoice, Parser};
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
use hidreport::*;

#[derive(Default)]
enum Styles {
    #[default]
    None,
    InputItem,
    OutputItem,
    FeatureItem,
    ReportId,
    Data,
    Separator,
    Timestamp,
    Note,
}

impl Styles {
    fn style(&self) -> Style {
        match self {
            Styles::None => Style::new(),
            Styles::Data => Style::new().red(),
            Styles::Note => Style::new().red().bold(),
            Styles::InputItem => Style::new().green().bold(),
            Styles::OutputItem => Style::new().yellow().bold(),
            Styles::FeatureItem => Style::new().blue().bold(),
            Styles::ReportId => Style::new().magenta().bold(),
            Styles::Separator => Style::new().magenta(),
            Styles::Timestamp => Style::new().purple(),
        }
    }
}

const MAX_USAGES_DISPLAYED: usize = 5;

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

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Cli {
    /// Print debugging information
    #[arg(short, long, default_value_t = false)]
    debug: bool,

    /// Do not shorten the output.
    #[arg(short, long, default_value_t = false)]
    full: bool,

    #[arg(long, value_enum, default_value_t = ColorChoice::Auto)]
    color: ColorChoice,

    #[arg(long, default_value_t = ("-").to_string())]
    output_file: String,

    /// Path to the hidraw or event device node, or a binary
    /// hid descriptor file
    path: Option<PathBuf>,
}

struct Options {
    full: bool,
}

struct RDescFile {
    path: PathBuf,
    name: Option<String>,
    bustype: u32,
    vid: u32,
    pid: u32,
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
        MainItem::EndCollection => "End Collection".into(),
    }
}

fn fmt_global_item(item: &GlobalItem) -> String {
    match item {
        GlobalItem::UsagePage { usage_page } => {
            let upval = u16::from(usage_page);
            let up = hut::UsagePage::try_from(upval);
            let str = match up {
                Ok(up) => format!("{up}"),
                Err(_) => format!("Usage Page (0x{upval:04X})"),
            };

            format!("Usage Page ({str})")
        }
        GlobalItem::LogicalMinimum { minimum } => format!("Logical Minimum ({minimum})"),
        GlobalItem::LogicalMaximum { maximum } => {
            // Special case -1 as maximum. It's common enough and never means -1 but
            // we can only know this is we check the minimum for signed-ness.
            let maximum: i32 = maximum.into();
            if maximum == -1 {
                format!("Logical Maximum ({})", maximum as u32)
            } else {
                format!("Logical Maximum ({maximum})")
            }
        }
        GlobalItem::PhysicalMinimum { minimum } => format!("Physical Minimum ({minimum})"),
        GlobalItem::PhysicalMaximum { maximum } => format!("Physical Maximum ({maximum})"),
        GlobalItem::UnitExponent { exponent } => format!("Unit Exponent ({})", exponent.exponent()),
        GlobalItem::Unit { unit } => format!(
            "Unit ({:?}{}{unit})",
            unit.system(),
            match unit.system() {
                UnitSystem::None => "",
                _ => ": ",
            }
        ),
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
            let hut = hut::UsagePage::try_from(u16::from(up));
            let str = match hut {
                Ok(hut) => {
                    let uidval = u16::from(usage_id);
                    let u = hut.to_usage(uidval);
                    match u {
                        Ok(u) => format!("{u}"),
                        Err(_) => format!("0x{uidval:04X}"),
                    }
                }
                Err(_) => format!("0x{:04x}", u16::from(usage_id)),
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

fn print_rdesc_items(stream: &mut impl Write, bytes: &[u8]) -> Result<()> {
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
            .map(|b| format!("0x{b:02x}, "))
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
            ItemType::Global(GlobalItem::ReportId { .. }) => Styles::ReportId,
            _ => Styles::None,
        };
        cprintln!(stream, style, "# {bytes:30} // {indented:41} {offset}");

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
    let pathstr = path.to_string_lossy();
    let sysfs: PathBuf;
    if pathstr.starts_with("/dev/hidraw") {
        sysfs = PathBuf::from("/sys/class/hidraw/")
            .join(path.file_name().unwrap())
            .join("device");
    } else if pathstr.starts_with("/dev/input/event") {
        // /sys/class/input/event0/device/device/hidraw/hidraw4/device/
        let parent = PathBuf::from("/sys/class/input/")
            .join(path.file_name().unwrap())
            .join("device")
            .join("device")
            .join("hidraw");
        if !parent.exists() {
            bail!("Couldn't find a  hidraw device for this event node, please use /dev/hidraw* instead");
        }
        let hidraws: Vec<String> = std::fs::read_dir(&parent)?
            .flatten()
            .flat_map(|f| f.file_name().into_string())
            .filter(|name| name.starts_with("hidraw"))
            .collect();
        if hidraws.is_empty() {
            bail!("Couldn't find a  hidraw device for this event node, please use /dev/hidraw* instead");
        } else if hidraws.len() > 1 {
            bail!(
                "More than one hidraw device for this event node, please use /dev/hidraw* instead"
            );
        }
        sysfs = parent.join(hidraws.first().unwrap()).join("device");
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
        sysfs = path
            .components()
            .take_while(|c| !c.as_os_str().to_string_lossy().starts_with("hidraw"))
            .collect();
    } else {
        bail!("Don't know how to handle {path:?}");
    };

    Ok(sysfs)
}

fn usage_to_str(u: &Usage) -> String {
    let hutstr: String =
        match hut::Usage::new_from_page_and_id(u16::from(u.usage_page), u16::from(u.usage_id)) {
            Err(_) => "<unknown>".into(),
            Ok(u) => format!("{} / {}", hut::UsagePage::from(&u), u),
        };

    format!(
        "{:04x}/{:04x}: {:43}",
        u16::from(u.usage_page),
        u16::from(u.usage_id),
        hutstr
    )
}

fn logical_range_to_str(
    logical_minimum: &LogicalMinimum,
    logical_maximum: &LogicalMaximum,
) -> String {
    let max = match i32::from(logical_maximum) {
        m @ -1 => format!("0x{m:x}"),
        m @ 0x7fffffff => format!("0x{m:x}"),
        m => format!("{m}"),
    };
    format!(
        "Logical Range: {:5}..={:<5}",
        i32::from(logical_minimum),
        max
    )
}

fn physical_range_to_str(
    physical_minimum: &Option<PhysicalMinimum>,
    physical_maximum: &Option<PhysicalMaximum>,
) -> Option<String> {
    if let (Some(min), Some(max)) = (physical_minimum, physical_maximum) {
        Some(format!(
            "Physical Range: {:5}..={:<5}",
            i32::from(min),
            i32::from(max)
        ))
    } else {
        None
    }
}

fn unit_to_str(unit: &Option<Unit>) -> Option<String> {
    if let Some(u) = unit {
        if let Some(units) = u.units() {
            Some(format!(
                "Unit: {:?}{}{}",
                u.system(),
                match u.system() {
                    UnitSystem::None => "",
                    _ => ": ",
                },
                units
                    .iter()
                    .map(|u| format!("{u}"))
                    .collect::<Vec<String>>()
                    .join("")
            ))
        } else {
            None
        }
    } else {
        None
    }
}

fn bits_to_str(bits: &std::ops::Range<usize>) -> String {
    if bits.len() > 1 {
        format!("Bits: {:3}..={:<3}", bits.start, bits.end - 1)
    } else {
        format!("Bit:  {:3}      ", bits.start,)
    }
}

#[derive(Default)]
struct PrintableColumn {
    string: String,
    style: Styles,
}

impl From<&str> for PrintableColumn {
    fn from(s: &str) -> PrintableColumn {
        PrintableColumn {
            string: s.to_string(),
            style: Styles::None,
        }
    }
}

impl From<String> for PrintableColumn {
    fn from(s: String) -> PrintableColumn {
        PrintableColumn {
            string: s,
            style: Styles::None,
        }
    }
}

impl From<Option<String>> for PrintableColumn {
    fn from(s: Option<String>) -> PrintableColumn {
        match s {
            None => PrintableColumn::default(),
            Some(s) => PrintableColumn {
                string: s,
                style: Styles::None,
            },
        }
    }
}

#[derive(Default)]
struct PrintableRow {
    bits: PrintableColumn,
    usage: PrintableColumn,
    logical_range: PrintableColumn,
    physical_range: PrintableColumn,
    unit: PrintableColumn,
}

impl PrintableRow {
    fn columns<'a>(&'a self) -> impl Iterator<Item = &'a PrintableColumn> {
        vec![
            &self.bits,
            &self.usage,
            &self.logical_range,
            &self.physical_range,
            &self.unit,
        ]
        .into_iter()
        .filter(move |x| !x.string.is_empty())
    }
}

#[derive(Default)]
struct PrintableTable {
    rows: Vec<PrintableRow>,
    colwidths: [usize; 5],
}

impl PrintableTable {
    fn add(&mut self, row: PrintableRow) {
        self.colwidths[0] = std::cmp::max(row.bits.string.len(), self.colwidths[0]);
        self.colwidths[1] = std::cmp::max(row.usage.string.len(), self.colwidths[1]);
        self.colwidths[2] = std::cmp::max(row.logical_range.string.len(), self.colwidths[2]);
        self.colwidths[3] = std::cmp::max(row.physical_range.string.len(), self.colwidths[3]);
        self.colwidths[4] = std::cmp::max(row.unit.string.len(), self.colwidths[4]);
        self.rows.push(row);
    }
}

/// Print the parsed reports as an outline of how they look like
fn print_report_summary(stream: &mut impl Write, r: &impl Report, opts: &Options) {
    if r.report_id().is_some() {
        cprintln!(
            stream,
            Styles::ReportId,
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

    let mut table = PrintableTable::default();
    for field in r.fields() {
        let mut row = PrintableRow::default();
        row.bits = PrintableColumn::from(bits_to_str(&field.bits()));
        match field {
            Field::Constant(_c) => {
                row.usage = "######### Padding".into();
            }
            Field::Variable(v) => {
                row.usage = format!("Usage: {}", usage_to_str(&v.usage)).into();
                row.logical_range =
                    logical_range_to_str(&v.logical_minimum, &v.logical_maximum).into();
                row.physical_range =
                    physical_range_to_str(&v.physical_minimum, &v.physical_maximum).into();
                row.unit = unit_to_str(&v.unit).into();
            }
            Field::Array(a) => {
                row.usage = "Usages:".into();
                row.logical_range =
                    logical_range_to_str(&a.logical_minimum, &a.logical_maximum).into();
                row.physical_range =
                    physical_range_to_str(&a.physical_minimum, &a.physical_maximum).into();
                row.unit = unit_to_str(&a.unit).into();
                table.add(row);
                row = PrintableRow::default();
                let usages = a.usages().iter();
                let usages = if opts.full {
                    usages.take(0xffffffff)
                } else {
                    usages.take(MAX_USAGES_DISPLAYED)
                };
                usages.for_each(|u| {
                    let row = PrintableRow {
                        bits: PrintableColumn::from(" "),
                        usage: PrintableColumn::from(usage_to_str(&u)),
                        ..Default::default()
                    };
                    table.add(row);
                });
                if !opts.full && a.usages().len() > MAX_USAGES_DISPLAYED {
                    let row = PrintableRow {
                        bits: PrintableColumn::from(" "),
                        usage: PrintableColumn {
                            string: "... use --full to see all usages".into(),
                            style: Styles::Note,
                        },
                        ..Default::default()
                    };
                    table.add(row);
                }
            }
        }
        table.add(row);
    }

    for row in table.rows {
        cprint!(stream, Styles::None, "#  ");
        for (idx, col) in row.columns().enumerate() {
            cprint!(
                stream,
                col.style,
                "| {:w$} ",
                col.string,
                w = table.colwidths[idx]
            );
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

fn find_rdesc(path: &Path) -> Result<RDescFile> {
    if vec!["/dev", "/sys"]
        .iter()
        .any(|prefix| path.starts_with(prefix))
    {
        let sysfs = find_sysfs_path(path)?;
        let rdesc_path = sysfs.join("report_descriptor");
        if !rdesc_path.exists() {
            bail!("Unable to find report descriptor at {rdesc_path:?}");
        }

        let (name, ids) = parse_uevent(&sysfs)?;
        let (bustype, vid, pid) = ids;

        Ok(RDescFile {
            path: rdesc_path,
            name: Some(name),
            bustype,
            vid,
            pid,
        })
    } else {
        // If it's a file, let's assume it's a binary rdesc file like
        // the report_descriptor file.
        Ok(RDescFile {
            path: path.into(),
            name: None,
            bustype: 0,
            vid: 0,
            pid: 0,
        })
    }
}

fn parse(stream: &mut impl Write, rdesc: &RDescFile, opts: &Options) -> Result<ReportDescriptor> {
    let bytes = std::fs::read(&rdesc.path)?;
    if bytes.is_empty() {
        bail!("Empty report descriptor");
    }
    let name = if let Some(name) = &rdesc.name {
        name.clone()
    } else {
        String::from("unknown")
    };
    let (bustype, vid, pid) = (rdesc.bustype, rdesc.vid, rdesc.pid);

    cprintln!(stream, Styles::None, "# {name}");
    cprintln!(
        stream,
        Styles::None,
        "# Report descriptor length: {} bytes",
        bytes.len()
    );
    print_rdesc_items(stream, &bytes)?;

    // Print the readable fields
    let bytestr = bytes
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<String>>()
        .join(" ");
    cprintln!(stream, Styles::Data, "R: {} {bytestr}", bytes.len());
    cprintln!(stream, Styles::Data, "N: {name}");
    cprintln!(stream, Styles::Data, "I: {bustype:x} {vid:x} {pid:x}");

    let rdesc = ReportDescriptor::try_from(&bytes as &[u8])?;
    cprintln!(stream, Styles::None, "# Report descriptor:");
    let input_reports = rdesc.input_reports();
    if !input_reports.is_empty() {
        for r in rdesc.input_reports() {
            cprintln!(stream, Styles::InputItem, "# ------- Input Report ------- ");
            print_report_summary(stream, r, opts);
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
            print_report_summary(stream, r, opts);
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
            print_report_summary(stream, r, opts);
        }
    }

    Ok(rdesc)
}

fn get_hut_str(usage: &Usage) -> String {
    let up: u16 = usage.usage_page.into();
    let uid: u16 = usage.usage_id.into();
    if let Ok(hut) = hut::Usage::new_from_page_and_id(up, uid) {
        format!("{hut}")
    } else {
        format!(
            "{:04x}/{:04x}",
            u16::from(usage.usage_page),
            u16::from(usage.usage_id)
        )
    }
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
            let hutstr = get_hut_str(&var.usage);
            if var.bits.len() <= 32 {
                if var.is_signed() {
                    let v = var.extract_i32(bytes).unwrap();
                    cprint!(stream, Styles::None, "{}: {:5} | ", hutstr, v);
                } else {
                    let v = var.extract_u32(bytes).unwrap();
                    cprint!(stream, Styles::None, "{}: {:5} | ", hutstr, v);
                }
            } else {
                // FIXME: output is not correct if start/end doesn't align with byte
                // boundaries
                let data = &bytes[var.bits.start / 8..var.bits.end / 8];
                cprint!(
                    stream,
                    Styles::None,
                    "{}: {} | ",
                    hutstr,
                    data.iter()
                        .map(|v| format!("{v:02x}"))
                        .collect::<Vec<String>>()
                        .join(" ")
                );
            }
        }
        Field::Array(arr) => {
            // The values in the array are usage values between usage min/max
            let vs = arr.extract_u32(bytes).unwrap();
            if arr.usages().len() > 1 {
                let usage_range = arr.usage_range();

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
                        let hutstr = get_hut_str(usage);
                        cprint!(stream, Styles::None, "{}: {:5} | ", hutstr, v);
                    } else {
                        // Let's just print the value as-is
                        cprint!(stream, Styles::None, "{v:02x} | ");
                    }
                });
            } else {
                let hutstr = match arr.usages().first() {
                    Some(usage) => get_hut_str(usage),
                    None => "<unknown>".to_string(),
                };
                cprint!(
                    stream,
                    Styles::None,
                    "{hutstr}: {} |",
                    vs.iter()
                        .fold("".to_string(), |acc, b| format!("{acc}{b:02x} "))
                );
            }
        }
    }
}

fn parse_input_report(
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
    cprintln!(
        stream,
        Styles::Separator,
        "##############################################################################"
    );
    cprintln!(stream, Styles::None, "# Recorded events below in format:");
    cprintln!(
        stream,
        Styles::None,
        "# E: <seconds>.<microseconds> <length-in-bytes> [bytes ...]",
    );
    cprintln!(stream, Styles::None, "#");

    cprintln!(
        stream,
        Styles::Timestamp,
        "# Current time: {}",
        chrono::prelude::Local::now().format("%H:%M:%S").to_string()
    );

    let mut f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(path)?;

    let timeout = PollTimeout::try_from(-1).unwrap();
    let mut start_time: Option<Instant> = None;
    let mut last_timestamp: Option<Instant> = None;
    let mut data = [0; 1024];
    loop {
        let mut pollfds = [PollFd::new(f.as_fd(), PollFlags::POLLIN)];
        if poll(&mut pollfds, timeout)? > 0 {
            match f.read(&mut data) {
                Ok(_nbytes) => {
                    start_time = if start_time.is_none() {
                        Some(Instant::now())
                    } else {
                        start_time
                    };

                    let elapsed = last_timestamp.or(start_time).unwrap().elapsed();
                    if elapsed.as_secs() > 5 {
                        cprintln!(
                            stream,
                            Styles::Timestamp,
                            "# Current time: {}",
                            chrono::prelude::Local::now().format("%H:%M:%S").to_string()
                        );
                        last_timestamp = Some(Instant::now());
                    }

                    parse_input_report(stream, &data, rdesc, &start_time.unwrap())?;
                }
                Err(e) => {
                    if e.kind() != std::io::ErrorKind::WouldBlock {
                        bail!(e);
                    }
                }
            };
        }
    }
}

fn find_device() -> Result<PathBuf> {
    eprintln!("# Available devices:");
    let mut hidraws: Vec<String> = std::fs::read_dir("/dev/")?
        .flatten()
        .flat_map(|f| f.file_name().into_string())
        .filter(|name| name.starts_with("hidraw"))
        .collect();

    hidraws.sort_by(|a, b| human_sort::compare(a, b));

    for file in hidraws {
        let uevent_path = PathBuf::from(format!("/sys/class/hidraw/{}/device/", file));
        let (name, _) = parse_uevent(&uevent_path)?;
        let devnode = format!("/dev/{file}:");
        eprintln!("# {devnode:14}    {name}");
    }

    eprint!("# Select the device event number [0-9]: ");
    std::io::stdout().flush().unwrap();
    let mut buffer = String::new();
    std::io::stdin().read_line(&mut buffer)?;

    let path = PathBuf::from(format!("/dev/hidraw{}", buffer.trim()));
    if !path.exists() {
        bail!("Invalid device");
    }

    Ok(path)
}

fn hid_recorder() -> Result<()> {
    let cli = Cli::parse();

    let mut stream: Box<dyn Write> = if cli.output_file == "-" {
        // Bit lame but easier to just set the env for owo_colors to figure out the rest
        match cli.color {
            ColorChoice::Never => std::env::set_var("NO_COLOR", "1"),
            ColorChoice::Auto => {}
            ColorChoice::Always => std::env::set_var("FORCE_COLOR", "1"),
        }

        Box::new(std::io::stdout())
    } else {
        std::env::set_var("NO_COLOR", "1");
        Box::new(std::fs::File::create(cli.output_file).unwrap())
    };

    let path = match cli.path {
        Some(path) => path,
        None => find_device()?,
    };

    let rdesc_file = find_rdesc(&path)?;
    let opts = Options { full: cli.full };

    let rdesc = parse(&mut stream, &rdesc_file, &opts)?;
    if path.starts_with("/dev") {
        read_events(&mut stream, &path, &rdesc)?
    }
    Ok(())
}

fn main() -> ExitCode {
    let rc = hid_recorder();
    match rc {
        Ok(_) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("Error: {e:#}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_hidraw() {
        let hidraws: Vec<String> = std::fs::read_dir("/dev/")
            .unwrap()
            .flatten()
            .flat_map(|f| f.file_name().into_string())
            .filter(|name| name.starts_with("hidraw"))
            .collect();
        for hidraw in hidraws.iter().map(|h| PathBuf::from("/dev/").join(h)) {
            let result = find_rdesc(&hidraw);
            assert!(result.is_ok());
        }
    }

    #[test]
    fn test_find_event_node() {
        // We can't assume any local event nodes, and even where we have them
        // they're not backed by HID devices.
        if std::env::var("CI").is_ok() {
            return;
        }
        let evdevs: Vec<String> = std::fs::read_dir("/dev/input")
            .unwrap()
            .flatten()
            .flat_map(|f| f.file_name().into_string())
            .filter(|name| name.starts_with("event"))
            .collect();
        if !evdevs.is_empty() {
            assert!(evdevs
                .iter()
                .map(|n| PathBuf::from("/dev/input").join(n))
                .any(|evdev| find_rdesc(&evdev).is_ok()));
        }
    }

    // Make sure we can always parse the devices currently plugged into
    // this machine.
    #[test]
    fn test_parse_local_hid_reports() {
        let hidraws: Vec<String> = std::fs::read_dir("/dev/")
            .unwrap()
            .flatten()
            .flat_map(|f| f.file_name().into_string())
            .filter(|name| name.starts_with("hidraw"))
            .collect();
        for rdesc_file in hidraws
            .iter()
            .map(|h| PathBuf::from("/dev/").join(h))
            .map(|path| find_rdesc(&path).unwrap())
        {
            let mut buf = std::io::BufWriter::new(Vec::new());
            let opts = Options { full: true };
            parse(&mut buf, &rdesc_file, &opts)
                .expect(&format!("Failed to parse {:?}", rdesc_file.path));
        }
    }
}
