// SPDX-License-Identifier: MIT

use anyhow::{bail, Context, Result};
use clap::{ColorChoice, Parser, ValueEnum};
use owo_colors::{OwoColorize, Rgb, Stream::Stdout, Style};
use std::collections::HashSet;
use std::io::Write;
use std::ops::Deref;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

// we reuse ColorChoice for your `--bpf` argument
use clap::ColorChoice as BpfOption;

use hidreport::hid::{
    CollectionItem, GlobalItem, Item, ItemType, LocalItem, MainDataItem, MainItem,
    ReportDescriptorItems,
};
use hidreport::*;

static mut OUTFILE: OnceLock<
    std::sync::Mutex<std::cell::RefCell<std::io::LineWriter<std::fs::File>>>,
> = OnceLock::new();

pub enum Prefix {
    Name,
    Id,
    ReportDescriptor,
    Event,
    Bpf,
}

impl std::fmt::Display for Prefix {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Prefix::Name => "N",
            Prefix::Id => "I",
            Prefix::ReportDescriptor => "R",
            Prefix::Event => "E",
            Prefix::Bpf => "B",
        };
        write!(f, "{s}:")
    }
}

pub enum Outfile {
    Stdout,
    File(&'static mut std::sync::Mutex<std::cell::RefCell<std::io::LineWriter<std::fs::File>>>),
}

impl Default for Outfile {
    fn default() -> Self {
        Self::new()
    }
}

impl Outfile {
    pub fn new() -> Self {
        unsafe {
            #[allow(static_mut_refs)]
            match OUTFILE.get_mut() {
                None => Outfile::Stdout,
                Some(o) => Outfile::File(o),
            }
        }
    }

    fn init(cli: &Cli) -> Result<()> {
        // Bit lame but easier to just set the env for owo_colors to figure out the rest
        match cli.color {
            ColorChoice::Never => std::env::set_var("NO_COLOR", "1"),
            ColorChoice::Auto => {}
            ColorChoice::Always => std::env::set_var("FORCE_COLOR", "1"),
        }
        if cli.output_file != "-" {
            let out = std::fs::File::create(cli.output_file.clone()).unwrap();
            let _ = unsafe {
                #[allow(static_mut_refs)]
                OUTFILE.set(std::sync::Mutex::new(std::cell::RefCell::new(
                    std::io::LineWriter::new(out),
                )))
            };
        }
        Ok(())
    }

    fn write(&mut self, style: &Styles, msg: &str) {
        write!(
            self,
            "{}",
            msg.if_supports_color(Stdout, |text| text.style(style.into()))
        )
        .unwrap();
    }

    fn writeln(&mut self, style: &Styles, msg: &str) {
        writeln!(
            self,
            "{}",
            msg.if_supports_color(Stdout, |text| text.style(style.into()))
        )
        .unwrap();
    }

    /// Write a generic unstyled comment
    pub fn write_comment(&mut self, msg: &str) {
        self.writeln(&Styles::None, format!("# {msg}").as_ref());
    }

    /// Write a generic comment with styling
    pub fn write_comment_styled(&mut self, style: Styles, msg: &str) {
        self.writeln(&style, format!("# {msg}").as_ref());
    }

    /// Write the item information as a comment (typically at the top of the file)
    pub fn write_item_comment(
        &mut self,
        item_type: ItemType,
        item: &str,
        bytes: &[u8],
        indent: usize,
        offset: usize,
    ) {
        let bytes = bytes
            .iter()
            .map(|b| format!("0x{b:02x}, "))
            .collect::<Vec<String>>()
            .join("");

        let style = match item_type {
            ItemType::Main(MainItem::Input(..)) => Styles::InputItem,
            ItemType::Main(MainItem::Output(..)) => Styles::OutputItem,
            ItemType::Main(MainItem::Feature(..)) => Styles::FeatureItem,
            ItemType::Global(GlobalItem::ReportId { .. }) => Styles::ReportId,
            ItemType::Global(GlobalItem::UsagePage { .. }) => Styles::UsagePage,
            ItemType::Local(LocalItem::Usage { .. }) => Styles::Usage,
            ItemType::Local(LocalItem::UsageId { .. }) => Styles::Usage,
            ItemType::Local(LocalItem::UsageMinimum { .. }) => Styles::Usage,
            ItemType::Local(LocalItem::UsageMaximum { .. }) => Styles::Usage,
            _ => Styles::None,
        };

        let indented = format!("{:indent$}{}", "", item);
        let prefix = style.as_str();
        self.writeln(
            &style,
            format!("# {prefix} {bytes:30} // {indented:41} {offset}").as_ref(),
        );
    }

    /// Print a separator line for logical separation between sections
    pub fn separator(&mut self) {
        self.writeln(
            &Styles::Separator,
            "##############################################################################",
        );
    }

    /// Write the (colored) prefix for the given report, if any
    pub fn report_comment_prefix(&mut self, report_id: &Option<ReportId>) {
        let report_style = if let Some(report_id) = report_id {
            Styles::Report {
                report_id: *report_id,
            }
        } else {
            Styles::None
        };
        self.write(&Styles::None, "# ");
        self.write(&report_style, report_style.as_str());
        self.write(&Styles::None, " ");
    }

    /// Print a comment related to some report, prefixed with a colored
    /// version of the report id
    pub fn report_comment(&mut self, report_id: &Option<ReportId>, msg: &str) {
        self.report_comment_prefix(report_id);
        self.writeln(&Styles::None, msg);
    }

    /// Print a comment related to some report, the comment message contains
    /// of several individually styled components
    pub fn report_comment_components(
        &mut self,
        report_id: &Option<ReportId>,
        components: &[(Styles, String)],
    ) {
        self.report_comment_prefix(report_id);
        for (style, msg) in components {
            Outfile::new().write(style, msg.to_string().as_ref());
        }
        self.writeln(&Styles::None, "");
    }

    /// Write an actual data entry (unlike a comment)
    pub fn write_data(&mut self, prefix: Prefix, datastr: &str) {
        self.writeln(&Styles::Data, format!("{prefix} {datastr}").as_str());
    }

    pub fn write_name(&mut self, name: &str) {
        self.write_data(Prefix::Name, name.to_string().as_str());
    }
    pub fn write_id(&mut self, bustype: u32, vid: u32, pid: u32) {
        self.write_data(Prefix::Id, format!("{bustype:x} {vid:x} {pid:x}").as_str());
    }

    pub fn write_report_descriptor(&mut self, bytes: &[u8]) {
        let bytestr = bytes
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<String>>()
            .join(" ");
        self.write_data(
            Prefix::ReportDescriptor,
            format!("{} {bytestr}", bytes.len()).as_str(),
        );
    }

    /// Write a timestamp comment
    pub fn write_timestamp(&mut self) {
        self.writeln(
            &Styles::Timestamp,
            format!(
                "# Current time: {}",
                chrono::prelude::Local::now().format("%H:%M:%S")
            )
            .as_ref(),
        )
    }
}

impl Write for Outfile {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            Outfile::Stdout => std::io::stdout().write(buf),
            Outfile::File(o) => o.get_mut().unwrap().deref().borrow_mut().write(buf),
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Outfile::Stdout => std::io::stdout().flush(),
            Outfile::File(o) => o.get_mut().unwrap().deref().borrow_mut().flush(),
        }
    }
    fn write_all(&mut self, buf: &[u8]) -> std::io::Result<()> {
        match self {
            Outfile::Stdout => std::io::stdout().write_all(buf),
            Outfile::File(o) => o.get_mut().unwrap().deref().borrow_mut().write_all(buf),
        }
    }
    fn write_fmt(&mut self, args: std::fmt::Arguments<'_>) -> std::io::Result<()> {
        match self {
            Outfile::Stdout => std::io::stdout().write_fmt(args),
            Outfile::File(o) => o.get_mut().unwrap().deref().borrow_mut().write_fmt(args),
        }
    }
}

trait Backend {
    fn name(&self) -> &str;
    fn bustype(&self) -> u32;
    fn vid(&self) -> u32;
    fn pid(&self) -> u32;
    fn rdesc(&self) -> &[u8];
    fn read_events(&self, use_bpf: BpfOption, rdesc: &ReportDescriptor) -> Result<()>;
}

#[derive(Default, Clone)]
pub enum Styles {
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
    Report {
        report_id: ReportId,
    },
    Bpf,
    Usage,
    UsagePage,
}

impl From<&Styles> for Style {
    fn from(styles: &Styles) -> Style {
        match styles {
            Styles::None => Style::new(),
            Styles::Bpf => Style::new().blue(),
            Styles::Data => Style::new().red(),
            Styles::Note => Style::new().red().bold(),
            Styles::InputItem => Style::new().green().bold(),
            Styles::OutputItem => Style::new().yellow().bold(),
            Styles::FeatureItem => Style::new().blue().bold(),
            Styles::ReportId => Style::new().magenta().bold(),
            Styles::Separator => Style::new().magenta(),
            Styles::Timestamp => Style::new().purple(),
            Styles::Report { report_id } => Style::new().on_color(match u8::from(report_id) % 7 {
                1 => Rgb(0xfc, 0x8d, 0x62),
                2 => Rgb(0x8d, 0xa0, 0xcb),
                3 => Rgb(0xe7, 0x8a, 0xc3),
                4 => Rgb(0xa6, 0xd8, 0x54),
                5 => Rgb(0xff, 0xd9, 0x2f),
                6 => Rgb(0xe5, 0xc4, 0x94),
                _ => Rgb(0x66, 0xc2, 0xa5),
            }),
            Styles::Usage => Style::new().bold(),
            Styles::UsagePage => Style::new().bold(),
        }
    }
}

impl Styles {
    fn as_str(&self) -> &str {
        match self {
            Styles::None => " ",
            Styles::Bpf => "",
            Styles::Data => "",
            Styles::Note => " ",
            Styles::InputItem => "┇",
            Styles::OutputItem => "┊",
            Styles::FeatureItem => "║",
            Styles::ReportId => "┅",
            Styles::Separator => "",
            Styles::Timestamp => "",
            Styles::Report { report_id } => match u8::from(report_id) % 7 {
                1 => "░",
                2 => "▒",
                3 => "▓",
                4 => "▚",
                5 => "▞",
                6 => "▃",
                _ => "▘",
            },
            Styles::Usage => "🭬",
            Styles::UsagePage => "🮥",
        }
    }
}

const MAX_USAGES_DISPLAYED: usize = 5;

mod hidraw;
mod hidrecording;
mod libinput;

#[derive(ValueEnum, Clone, Debug)]
enum InputFormat {
    Auto,
    Hidraw,
    LibinputRecording,
    HidRecording,
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

    // Explicitly specify the input format (usually auto is enough)
    #[arg(long, value_enum, default_value_t = InputFormat::Auto)]
    input_format: InputFormat,

    /// Only describe the device, do not wait for events
    #[arg(long, default_value_t = false)]
    only_describe: bool,

    /// Also grab the events from the device through HID-BPF
    /// (default to enable the output if a HID-BPF program
    /// is detected on the target device).
    #[arg(long, default_value_t = BpfOption::Auto)]
    bpf: BpfOption,

    /// Path to the hidraw or event device node, or a binary
    /// hid descriptor file
    path: Option<PathBuf>,
}

#[derive(Default)]
struct Options {
    full: bool,
    only_describe: bool,
    bpf: ColorChoice,
}

fn fmt_main_item(item: &MainItem) -> String {
    let (prefix, details) = match item {
        MainItem::Input(i) => {
            let details = vec![
                if i.is_constant() { "Cnst" } else { "Data" },
                if i.is_variable() { "Var" } else { "Arr" },
                if i.is_relative() { "Rel" } else { "Abs" },
                if i.wraps() { ",Wrap" } else { "" },
                if i.is_nonlinear() { ",NonLin" } else { "" },
                if i.has_no_preferred_state() {
                    "NoPref"
                } else {
                    ""
                },
                if i.has_null_state() { "Null" } else { "" },
                if i.is_buffered_bytes() { "Buff" } else { "" },
            ];
            ("Input", details)
        }
        MainItem::Output(i) => {
            let details = vec![
                if i.is_constant() { "Cnst" } else { "Data" },
                if i.is_variable() { "Var" } else { "Arr" },
                if i.is_relative() { "Rel" } else { "Abs" },
                if i.wraps() { ",Wrap" } else { "" },
                if i.is_nonlinear() { ",NonLin" } else { "" },
                if i.has_no_preferred_state() {
                    "NoPref"
                } else {
                    ""
                },
                if i.has_null_state() { "Null" } else { "" },
                if i.is_volatile() { "Vol" } else { "" },
                if i.is_buffered_bytes() { "Buff" } else { "" },
            ];
            ("Output", details)
        }
        MainItem::Feature(i) => {
            let details = vec![
                if i.is_constant() { "Cnst" } else { "Data" },
                if i.is_variable() { "Var" } else { "Arr" },
                if i.is_relative() { "Rel" } else { "Abs" },
                if i.wraps() { "Wrap" } else { "" },
                if i.is_nonlinear() { "NonLin" } else { "" },
                if i.has_no_preferred_state() {
                    "NoPref"
                } else {
                    ""
                },
                if i.has_null_state() { "Null" } else { "" },
                if i.is_volatile() { "Vol" } else { "" },
                if i.is_buffered_bytes() { "Buff" } else { "" },
            ];
            ("Feature", details)
        }
        MainItem::Collection(c) => {
            let details = vec![match c {
                CollectionItem::Physical => "Physical",
                CollectionItem::Application => "Application",
                CollectionItem::Logical => "Logical",
                CollectionItem::Report => "Report",
                CollectionItem::NamedArray => "NamedArray",
                CollectionItem::UsageSwitch => "UsageSwitch",
                CollectionItem::UsageModifier => "UsageModifier",
                CollectionItem::Reserved { .. } => "Reserved",
                CollectionItem::VendorDefined { .. } => "VendorDefined",
            }];
            ("Collection", details)
        }
        MainItem::EndCollection => return String::from("End Collection"),
    };

    let details = details
        .into_iter()
        .filter(|s| !s.is_empty())
        .map(String::from)
        .collect::<Vec<String>>()
        .join(",");
    format!("{prefix} ({details})")
}

fn fmt_global_item(item: &GlobalItem) -> String {
    match item {
        GlobalItem::UsagePage(usage_page) => {
            let upval = u16::from(usage_page);
            let up = hut::UsagePage::try_from(upval);
            let str = match up {
                Ok(up) => format!("{up}"),
                Err(_) => format!("Usage Page (0x{upval:04X})"),
            };

            format!("Usage Page ({str})")
        }
        GlobalItem::LogicalMinimum(minimum) => format!("Logical Minimum ({minimum})"),
        GlobalItem::LogicalMaximum(maximum) => {
            // Special case -1 as maximum. It's common enough and never means -1 but
            // we can only know this is we check the minimum for signed-ness.
            let maximum: i32 = maximum.into();
            if maximum == -1 {
                format!("Logical Maximum ({})", maximum as u32)
            } else {
                format!("Logical Maximum ({maximum})")
            }
        }
        GlobalItem::PhysicalMinimum(minimum) => format!("Physical Minimum ({minimum})"),
        GlobalItem::PhysicalMaximum(maximum) => format!("Physical Maximum ({maximum})"),
        GlobalItem::UnitExponent(exponent) => format!("Unit Exponent ({})", exponent.exponent()),
        GlobalItem::Unit(unit) => format!(
            "Unit ({:?}{}{unit})",
            unit.system(),
            match unit.system() {
                UnitSystem::None => "",
                _ => ": ",
            }
        ),
        GlobalItem::ReportSize(size) => format!("Report Size ({size})"),
        GlobalItem::ReportId(id) => format!("Report ID ({id})"),
        GlobalItem::ReportCount(count) => format!("Report Count ({count})"),
        GlobalItem::Push => "Push".into(),
        GlobalItem::Pop => "Pop".into(),
        GlobalItem::Reserved => "Reserved".into(),
    }
}

fn fmt_local_item(item: &LocalItem, global_usage_page: &UsagePage) -> String {
    match item {
        LocalItem::Usage(usage_page, usage_id) => {
            let hut = hut::UsagePage::try_from(u16::from(usage_page));
            let str = match hut {
                Ok(hut) => {
                    let uidval = u16::from(usage_id);
                    let u = hut.to_usage_from_value(uidval);
                    match u {
                        Ok(u) => format!("{u}"),
                        Err(_) => format!("0x{uidval:04X}"),
                    }
                }
                Err(_) => format!("0x{:04x}", u16::from(usage_id)),
            };
            format!("Usage ({str})")
        }
        LocalItem::UsageId(usage_id) => {
            let hut = hut::UsagePage::try_from(u16::from(global_usage_page));
            let str = match hut {
                Ok(hut) => {
                    let uidval = u16::from(usage_id);
                    let u = hut.to_usage_from_value(uidval);
                    match u {
                        Ok(u) => format!("{u}"),
                        Err(_) => format!("0x{uidval:04X}"),
                    }
                }
                Err(_) => format!("0x{:04x}", u16::from(usage_id)),
            };
            format!("Usage ({str})")
        }
        LocalItem::UsageMinimum(minimum) => format!("UsageMinimum ({minimum})"),
        LocalItem::UsageMaximum(maximum) => format!("UsageMaximum ({maximum})"),
        LocalItem::DesignatorIndex(index) => format!("DesignatorIndex ({index})"),
        LocalItem::DesignatorMinimum(minimum) => format!("DesignatorMinimum ({minimum})"),
        LocalItem::DesignatorMaximum(maximum) => format!("DesignatorMaximum ({maximum})"),
        LocalItem::StringIndex(index) => format!("StringIndex ({index})"),
        LocalItem::StringMinimum(minimum) => format!("StringMinimum ({minimum})"),
        LocalItem::StringMaximum(maximum) => format!("StringMaximum ({maximum})"),
        LocalItem::Delimiter(delimiter) => format!("Delimiter ({delimiter})"),
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

fn print_rdesc_items(bytes: &[u8]) -> Result<()> {
    let rdesc_items = ReportDescriptorItems::try_from(bytes)?;
    let mut indent = 0;
    let mut current_usage_page = UsagePage::from(0u16); // Undefined

    // Print the device description
    for rdesc_item in rdesc_items.iter() {
        let item = rdesc_item.item();
        let offset = rdesc_item.offset();
        match item.item_type() {
            ItemType::Main(MainItem::EndCollection) | ItemType::Global(GlobalItem::Pop) => {
                indent -= 2;
            }
            _ => {}
        }
        Outfile::new().write_item_comment(
            item.item_type(),
            fmt_item(item, &current_usage_page).as_ref(),
            item.bytes(),
            indent,
            offset,
        );

        match item.item_type() {
            ItemType::Main(MainItem::Collection(_)) => indent += 2,
            ItemType::Global(GlobalItem::Push) => {
                indent += 2;
            }
            ItemType::Global(GlobalItem::UsagePage(usage_page)) => {
                current_usage_page = usage_page;
            }
            _ => {}
        }
    }

    Ok(())
}

// This would be easier with udev but let's keep the dependencies relatively minimal.
pub fn find_sysfs_path(path: &Path) -> Result<PathBuf> {
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
            Ok(hut::Usage::VendorDefinedPage { vendor_page, usage }) => {
                format!(
                    "Vendor Defined Usage {:04x} / {:04x}",
                    u16::from(vendor_page),
                    u16::from(&usage)
                )
            }
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
        u.units().map(|units| {
            format!(
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
            )
        })
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
    style: Styles, // FIXME
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
    fn columns(&self) -> impl Iterator<Item = &'_ PrintableColumn> {
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

fn is_vendor_or_reserved_field(field: &Field) -> bool {
    match field {
        Field::Constant(_) => false,
        Field::Array(_) => false,
        Field::Variable(v) => {
            let up: u16 = v.usage.usage_page.into();
            match hut::UsagePage::try_from(up) {
                Err(_) => false,
                Ok(hut::UsagePage::VendorDefinedPage { .. }) => true,
                Ok(hut::UsagePage::ReservedUsagePage { .. }) => true,
                Ok(_) => false,
            }
        }
    }
}

fn vendor_report_filler(count: usize) -> PrintableRow {
    PrintableRow {
        bits: PrintableColumn::from("  "),
        usage: PrintableColumn {
            string: format!("Total of {count} vendor usages, use --full to see all"),
            style: Styles::Note,
        },
        ..Default::default()
    }
}

fn repeat_usage_filler(count: usize) -> PrintableRow {
    PrintableRow {
        bits: PrintableColumn::from("  "),
        usage: PrintableColumn {
            string: format!(
                "Total of {} repeated usages, use --full to see all",
                count + 1
            ),
            style: Styles::Note,
        },
        ..Default::default()
    }
}

/// Print the parsed reports as an outline of how they look like
fn print_report_summary(r: &impl Report, opts: &Options) {
    if let Some(report_id) = r.report_id() {
        Outfile::new().report_comment(r.report_id(), format!("Report ID: {}", report_id).as_str());
    }
    Outfile::new().report_comment(
        r.report_id(),
        format!(" | Report size: {} bits", r.size_in_bits()).as_str(),
    );

    const REPEAT_LIMIT: usize = 3;

    let mut last_usage: Usage = Usage::from(0);
    let mut repeat_usage_count = 0;
    let mut vendor_report_count = 0;
    let mut table = PrintableTable::default();
    for field in r.fields() {
        let mut row = PrintableRow {
            bits: PrintableColumn::from(bits_to_str(field.bits())),
            ..Default::default()
        };
        if !opts.full && is_vendor_or_reserved_field(field) {
            vendor_report_count += 1;
        } else {
            if vendor_report_count > REPEAT_LIMIT {
                table.add(vendor_report_filler(vendor_report_count));
            }
            vendor_report_count = 0;
        }
        let row = match field {
            Field::Constant(_c) => {
                if repeat_usage_count > REPEAT_LIMIT {
                    table.add(repeat_usage_filler(repeat_usage_count));
                }
                row.usage = "######### Padding".into();
                Some(row)
            }
            Field::Variable(v) => {
                if vendor_report_count <= REPEAT_LIMIT && repeat_usage_count <= REPEAT_LIMIT {
                    row.usage = format!("Usage: {}", usage_to_str(&v.usage)).into();
                    row.logical_range =
                        logical_range_to_str(&v.logical_minimum, &v.logical_maximum).into();
                    row.physical_range =
                        physical_range_to_str(&v.physical_minimum, &v.physical_maximum).into();
                    row.unit = unit_to_str(&v.unit).into();
                }
                if !opts.full && last_usage == v.usage {
                    repeat_usage_count += 1;
                } else {
                    if repeat_usage_count > REPEAT_LIMIT {
                        table.add(repeat_usage_filler(repeat_usage_count));
                    }
                    repeat_usage_count = 0;
                }
                last_usage = v.usage;
                Some(row)
            }
            Field::Array(a) => {
                if repeat_usage_count > REPEAT_LIMIT {
                    table.add(repeat_usage_filler(repeat_usage_count));
                }
                row.usage = "Usages:".into();
                row.logical_range =
                    logical_range_to_str(&a.logical_minimum, &a.logical_maximum).into();
                row.physical_range =
                    physical_range_to_str(&a.physical_minimum, &a.physical_maximum).into();
                row.unit = unit_to_str(&a.unit).into();
                table.add(row);
                let usages = a.usages().iter();
                let usages = if opts.full {
                    usages.take(0xffffffff)
                } else {
                    usages.take(MAX_USAGES_DISPLAYED)
                };
                usages.for_each(|u| {
                    let row = PrintableRow {
                        bits: PrintableColumn::from(" "),
                        usage: PrintableColumn::from(usage_to_str(u)),
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
                None
            }
        };
        if vendor_report_count <= REPEAT_LIMIT && repeat_usage_count <= REPEAT_LIMIT {
            if let Some(row) = row {
                table.add(row);
            }
        }
    }

    if vendor_report_count > REPEAT_LIMIT {
        table.add(vendor_report_filler(vendor_report_count));
    } else if repeat_usage_count > REPEAT_LIMIT {
        table.add(repeat_usage_filler(repeat_usage_count));
    }
    for row in table.rows {
        let components = row
            .columns()
            .enumerate()
            .map(|(idx, col)| {
                (
                    col.style.clone(),
                    format!("{:w$} ", col.string, w = table.colwidths[idx]),
                )
            })
            .collect::<Vec<(Styles, String)>>();
        Outfile::new().report_comment_components(r.report_id(), components.as_slice());
    }
}

pub fn parse_uevent(sysfs: &Path) -> Result<(String, (u32, u32, u32))> {
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

fn parse_report_descriptor(backend: &impl Backend, opts: &Options) -> Result<ReportDescriptor> {
    let name = backend.name();
    let (bustype, vid, pid) = (backend.bustype(), backend.vid(), backend.pid());
    let bytes = backend.rdesc();

    Outfile::new().write_comment(name.to_string().as_str());
    Outfile::new()
        .write_comment(format!("Report descriptor length: {} bytes", bytes.len()).as_str());
    print_rdesc_items(bytes)?;

    // Print the readable fields
    Outfile::new().write_report_descriptor(bytes);
    Outfile::new().write_name(name);
    Outfile::new().write_id(bustype, vid, pid);

    let rdesc = ReportDescriptor::try_from(bytes as &[u8])?;
    Outfile::new().write_comment("Report descriptor:");
    let input_reports = rdesc.input_reports();
    if !input_reports.is_empty() {
        for r in rdesc.input_reports() {
            Outfile::new().write_comment_styled(Styles::InputItem, "------- Input Report ------- ");
            print_report_summary(r, opts);
        }
    }
    let output_reports = rdesc.output_reports();
    if !output_reports.is_empty() {
        for r in rdesc.output_reports() {
            Outfile::new()
                .write_comment_styled(Styles::OutputItem, "------- Output Report ------- ");
            print_report_summary(r, opts);
        }
    }
    let feature_reports = rdesc.feature_reports();
    if !feature_reports.is_empty() {
        for r in rdesc.feature_reports() {
            Outfile::new()
                .write_comment_styled(Styles::FeatureItem, "------- Feature Report ------- ");
            print_report_summary(r, opts);
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

fn print_field_values(bytes: &[u8], field: &Field) -> String {
    match field {
        Field::Constant(_) => {
            format!("<{} bits padding>", field.bits().clone().count())
        }
        Field::Variable(var) => {
            let hutstr = get_hut_str(&var.usage);
            if var.bits.len() <= 32 {
                if var.is_signed() {
                    let v: i32 = var.extract(bytes).unwrap().into();
                    format!("{}: {:5}", hutstr, v)
                } else {
                    let v: u32 = var.extract(bytes).unwrap().into();
                    format!("{}: {:5}", hutstr, v)
                }
            } else {
                // FIXME: output is not correct if start/end doesn't align with byte
                // boundaries
                let data = &bytes[var.bits.start / 8..var.bits.end / 8];
                format!(
                    "{}: {}",
                    hutstr,
                    data.iter()
                        .map(|v| format!("{v:02x}"))
                        .collect::<Vec<String>>()
                        .join(" ")
                )
            }
        }
        Field::Array(arr) => {
            // The values in the array are usage values between usage min/max
            let vs: Vec<u32> = arr.extract(bytes).unwrap().iter().map(u32::from).collect();
            if arr.usages().len() > 1 {
                let usage_range = arr.usage_range();

                vs.iter()
                    .map(|v| {
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
                            format!("{}: {:5}", hutstr, v)
                        } else {
                            // Let's just print the value as-is
                            format!("{v:02x}")
                        }
                    })
                    .collect::<Vec<String>>()
                    .join("| ")
            } else {
                let hutstr = match arr.usages().first() {
                    Some(usage) => get_hut_str(usage),
                    None => "<unknown>".to_string(),
                };
                format!(
                    "{hutstr}: {}",
                    vs.iter()
                        .fold("".to_string(), |acc, b| format!("{acc}{b:02x} "))
                )
            }
        }
    }
}

pub fn print_input_report_description(bytes: &[u8], rdesc: &ReportDescriptor) -> Result<()> {
    let Some(report) = rdesc.find_input_report(bytes) else {
        bail!("Unable to find matching report");
    };

    if let Some(id) = report.report_id() {
        Outfile::new().report_comment(report.report_id(), format!(" Report ID: {id} / ").as_ref());
    };

    let collections: HashSet<&Collection> = report
        .fields()
        .iter()
        .flat_map(|f| f.collections())
        .filter(|c| matches!(c.collection_type(), CollectionType::Logical))
        .collect();
    if collections.is_empty() {
        let msg = report
            .fields()
            .iter()
            .map(|f| print_field_values(bytes, f))
            .collect::<Vec<String>>()
            .join(" |");
        Outfile::new().report_comment(report.report_id(), format!("              {msg}").as_str());
    } else {
        let mut collections: Vec<&Collection> = collections.into_iter().collect();
        collections.sort_by(|a, b| a.id().partial_cmp(b.id()).unwrap());

        for collection in collections {
            let msg = report
                .fields()
                .iter()
                .filter(|f| {
                    // logical collections may be nested, so we only group those items together
                    // where the deepest logical collection matches
                    f.collections()
                        .iter()
                        .rev()
                        .find(|c| matches!(c.collection_type(), CollectionType::Logical))
                        .map(|c| c == collection)
                        .unwrap_or(false)
                })
                .map(|f| print_field_values(bytes, f))
                .collect::<Vec<String>>()
                .join(" |");
            Outfile::new()
                .report_comment(report.report_id(), format!("              {msg}").as_str());
        }
    }

    Ok(())
}

pub fn print_input_report_data(
    bytes: &[u8],
    rdesc: &ReportDescriptor,
    elapsed: &Duration,
) -> Result<()> {
    let Some(report) = rdesc.find_input_report(bytes) else {
        bail!("Unable to find matching report");
    };

    Outfile::new().write_data(
        Prefix::Event,
        format!(
            "{:06}.{:06} {} {}",
            elapsed.as_secs(),
            elapsed.as_micros() % 1000000,
            report.size_in_bytes(),
            bytes[..report.size_in_bytes()]
                .iter()
                .fold("".to_string(), |acc, b| format!("{acc}{b:02x} "))
        )
        .as_ref(),
    );

    Ok(())
}

pub fn print_bpf_input_report_data(bytes: &[u8], elapsed: &Duration) {
    let bytes = bytes
        .iter()
        .fold("".to_string(), |acc, b| format!("{acc}{b:02x} "));
    Outfile::new().write_data(
        Prefix::Bpf,
        format!(
            "{:06}.{:06} {} {}",
            elapsed.as_secs(),
            elapsed.as_micros() % 1000000,
            bytes.len(),
            bytes,
        )
        .as_ref(),
    );
}

pub fn print_current_time(last_timestamp: Option<Instant>) -> Option<Instant> {
    let prev_timestamp = last_timestamp.unwrap_or(Instant::now());
    let elapsed = prev_timestamp.elapsed().as_secs();
    let now = chrono::prelude::Local::now();
    if last_timestamp.is_none() || (elapsed > 1 && now.timestamp() % 5 == 0) {
        Outfile::new().write_timestamp();
        Some(Instant::now())
    } else {
        last_timestamp
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

fn process(backend: impl Backend, opts: &Options) -> Result<()> {
    let rdesc = parse_report_descriptor(&backend, opts)?;
    if !opts.only_describe {
        Outfile::new().separator();
        Outfile::new().write_comment("Recorded events below in format:");
        Outfile::new().write_comment("E: <seconds>.<microseconds> <length-in-bytes> [bytes ...]");
        Outfile::new().write_comment("");
        backend.read_events(opts.bpf, &rdesc)?;
    }
    Ok(())
}

fn hid_recorder() -> Result<()> {
    let cli = Cli::parse();

    let _ = Outfile::init(&cli);

    let path = match cli.path {
        Some(path) => path,
        None => find_device()?,
    };
    let path = path.as_path();
    let input_format = if path.starts_with("/sys") || path.starts_with("/dev") {
        InputFormat::Hidraw
    } else {
        cli.input_format
    };

    let opts = Options {
        full: cli.full,
        only_describe: cli.only_describe,
        bpf: cli.bpf,
    };
    match input_format {
        InputFormat::Hidraw => {
            let backend = hidraw::HidrawBackend::try_from(path)?;
            process(backend, &opts)
        }
        InputFormat::LibinputRecording => {
            let backend = libinput::LibinputRecordingBackend::try_from(path)?;
            process(backend, &opts)
        }
        InputFormat::HidRecording => {
            let backend = hidrecording::HidRecorderBackend::try_from(path)?;
            process(backend, &opts)
        }
        InputFormat::Auto => {
            if let Ok(backend) = hidraw::HidrawBackend::try_from(path) {
                process(backend, &opts)
            } else if let Ok(backend) = libinput::LibinputRecordingBackend::try_from(path) {
                process(backend, &opts)
            } else if let Ok(backend) = hidrecording::HidRecorderBackend::try_from(path) {
                process(backend, &opts)
            } else {
                bail!("Unrecognized file format");
            }
        }
    }
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
            let result = hidraw::HidrawBackend::try_from(hidraw.as_path());
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
                .any(|evdev| hidraw::HidrawBackend::try_from(evdev.as_path()).is_ok()));
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
        for (path, backend) in hidraws
            .iter()
            .map(|h| PathBuf::from("/dev/").join(h))
            .map(|path| {
                (
                    path.clone(),
                    hidraw::HidrawBackend::try_from(path.as_path()).unwrap(),
                )
            })
        {
            let opts = Options {
                full: true,
                ..Default::default()
            };
            parse_report_descriptor(&backend, &opts)
                .unwrap_or_else(|_| panic!("Failed to parse {:?}", path));
        }
    }
}
