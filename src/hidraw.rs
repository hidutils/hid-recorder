// SPDX-License-Identifier: MIT

use anyhow::{bail, Context, Result};
use nix::poll::{poll, PollFd, PollFlags, PollTimeout};
use std::cell::OnceCell;
use std::fs::OpenOptions;
use std::io::Read;
use std::os::fd::{AsFd, AsRawFd};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::time::Instant;

use crate::{
    find_sysfs_path, parse_uevent, print_bpf_input_report_data, print_current_time,
    print_input_report_data, print_input_report_description, Backend, BpfOption, EventNode,
    Outfile, ReportDescriptor, Styles,
};

use libbpf_rs::libbpf_sys;
use libbpf_rs::skel::OpenSkel as _;
use libbpf_rs::skel::SkelBuilder as _;

mod hidrecord {
    include!(env!("SKELFILE"));
}
mod hidrecord_tracing {
    include!(env!("SKELFILE_TRACING"));
}

use hidrecord::*;
use hidrecord_tracing::*;

const PACKET_SIZE: usize = 64;

// A Rust version of hid_recorder_event in hidrecord.bpf.c
// struct hid_recorder_event {
// 	__u8 length;
// 	__u8 data[64];
// };
#[allow(non_camel_case_types)]
#[repr(C)]
struct hid_recorder_event {
    packet_count: u8,
    packet_number: u8,
    length: u8,
    data: [u8; PACKET_SIZE],
}

// A Rust version of attach_prog_args in hidrecord_tracing.bpf.c
// struct attach_prog_args {
// 	int prog_fd;
// 	unsigned int hid;
// 	int retval;
// };
#[allow(non_camel_case_types)]
#[repr(C)]
struct attach_prog_args {
    prog_fd: i32,
    hid: u32,
    retval: i32,
}

#[derive(Debug)]
pub enum BpfError {
    LibBPFError { error: libbpf_rs::Error },
    OsError { errno: u32 },
}

impl std::error::Error for BpfError {}

impl std::fmt::Display for BpfError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BpfError::LibBPFError { error } => write!(f, "{error}"),
            BpfError::OsError { errno } => {
                write!(f, "{}", libbpf_rs::Error::from_raw_os_error(*errno as i32))
            }
        }
    }
}

impl From<libbpf_rs::Error> for BpfError {
    fn from(e: libbpf_rs::Error) -> BpfError {
        BpfError::LibBPFError { error: e }
    }
}

pub struct HidrawBackend {
    name: String,
    bustype: u32,
    vid: u32,
    pid: u32,
    rdesc: Vec<u8>,
    device_path: Option<PathBuf>,
    event_nodes: Vec<EventNode>,
}

impl HidrawBackend {
    fn read_events_loop(
        &self,
        path: &Path,
        rdesc: &ReportDescriptor,
        map_ringbuf: Option<&libbpf_rs::Map>,
    ) -> Result<()> {
        let mut f = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(path)?;

        let timeout = PollTimeout::try_from(-1).unwrap();
        let start_time: OnceCell<Instant> = OnceCell::new();
        let mut last_timestamp: Option<Instant> = None;
        let mut data = [0; 1024];
        let mut bpf_vec = Vec::new();

        let ringbuf = map_ringbuf.map(|map_ringbuf| {
            let mut builder = libbpf_rs::RingBufferBuilder::new();
            builder
                .add(map_ringbuf, |data| {
                    bpf_event_handler(data, &mut bpf_vec, &start_time)
                })
                .unwrap();
            builder.build().unwrap()
        });

        loop {
            let mut pollfds = vec![PollFd::new(f.as_fd(), PollFlags::POLLIN)];
            if let Some(ref ringbuf) = ringbuf {
                let ringbuf_fd = unsafe {
                    std::os::fd::BorrowedFd::borrow_raw(ringbuf.epoll_fd() as std::os::fd::RawFd)
                };
                pollfds.push(PollFd::new(ringbuf_fd, PollFlags::POLLIN));
            }

            if poll(&mut pollfds, timeout)? > 0 {
                let has_events: Vec<bool> = pollfds
                    .iter()
                    .map(|fd| fd.revents())
                    .map(|revents| revents.is_some_and(|flag| flag.intersects(PollFlags::POLLIN)))
                    .collect();

                if has_events[0] {
                    match f.read(&mut data) {
                        Ok(_nbytes) => {
                            last_timestamp = print_current_time(last_timestamp);
                            let _ = start_time.get_or_init(|| last_timestamp.unwrap());
                            print_input_report_description(&data, rdesc)?;

                            let elapsed = start_time.get().unwrap().elapsed();
                            // This prints the B: 123 00 01 02 ... data line via the callback
                            if let Some(ref ringbuf) = ringbuf {
                                let _ = ringbuf.consume();
                            }

                            print_input_report_data(&data, rdesc, &elapsed)?;
                        }
                        Err(e) => {
                            if e.kind() != std::io::ErrorKind::WouldBlock {
                                bail!(e);
                            }
                        }
                    };
                }
                if *has_events.get(1).unwrap_or(&false) {
                    if let Some(ref ringbuf) = ringbuf {
                        last_timestamp = print_current_time(last_timestamp);
                        let _ = start_time.get_or_init(|| last_timestamp.unwrap());
                        let _ = ringbuf.consume();
                    }
                }
            }
        }
    }
}

impl TryFrom<&Path> for HidrawBackend {
    type Error = anyhow::Error;

    fn try_from(path: &Path) -> Result<Self> {
        if ["/dev", "/sys"]
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

            let bytes = std::fs::read(&rdesc_path)?;
            if bytes.is_empty() {
                bail!("Empty report descriptor");
            }

            let pathstr = path.to_string_lossy();
            let device_path = if pathstr.starts_with("/dev/hidraw") {
                Some(PathBuf::from(path))
            } else if pathstr.starts_with("/dev/input/event") {
                // uevent should contain
                // DEVNAME=hidraw0
                let uevent_path = sysfs.parent().unwrap().join("uevent");
                let uevent = std::fs::read_to_string(uevent_path)?;
                let name = uevent
                    .lines()
                    .find(|l| l.starts_with("DEVNAME"))
                    .context("Unable to find DEVNAME in uevent")?;
                let (_, name) = name.split_once('=').context("Unexpected DEVNAME= format")?;
                Some(PathBuf::from("/dev/").join(name))
            } else {
                None
            };

            let mut event_nodes: Vec<EventNode> = Vec::new();
            if let Some(path) = &device_path {
                let hidraw = path.file_name().unwrap().to_string_lossy().to_string();
                let sysfs: PathBuf = PathBuf::from("/sys/class/hidraw/")
                    .join(hidraw)
                    .join("device/input");

                if let Ok(readdir) = std::fs::read_dir(sysfs) {
                    for dir in readdir
                        .filter_map(|entry| entry.ok())
                        .filter(|entry| entry.file_name().to_string_lossy().starts_with("input"))
                    {
                        let name =
                            std::fs::read_to_string(dir.path().join("name")).unwrap_or("".into());
                        let name = name.trim_end();

                        if let Ok(readdir) = std::fs::read_dir(dir.path()) {
                            for event in readdir.filter_map(|entry| entry.ok()).filter(|entry| {
                                entry.file_name().to_string_lossy().starts_with("event")
                            }) {
                                event_nodes.push(EventNode {
                                    name: name.into(),
                                    path: PathBuf::from("/dev/input").join(event.file_name()),
                                });
                            }
                        }
                    }
                }
            };

            Ok(HidrawBackend {
                name,
                bustype,
                vid,
                pid,
                rdesc: bytes,
                device_path,
                event_nodes,
            })
        } else {
            bail!("Not a syfs file or hidraw node");
        }
    }
}

impl Backend for HidrawBackend {
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
        &self.event_nodes
    }

    fn read_events(&self, use_bpf: BpfOption, rdesc: &ReportDescriptor) -> Result<()> {
        if self.device_path.is_none() {
            return Ok(());
        }
        let path = self.device_path.as_ref().unwrap();
        match preload_bpf_tracer(use_bpf, path)? {
            HidBpfSkel::None => self.read_events_loop(path, rdesc, None)?,
            HidBpfSkel::StructOps(skel) => {
                let maps = skel.maps();
                // We need to keep _link around or the program gets immediately removed
                let _link = maps.hid_record().attach_struct_ops()?;
                self.read_events_loop(path, rdesc, Some(maps.events()))?
            }
            HidBpfSkel::Tracing(skel, hid_id) => {
                let attach_args = attach_prog_args {
                    prog_fd: skel.progs().hid_record_event().as_fd().as_raw_fd(),
                    hid: hid_id,
                    retval: -1,
                };

                let _link =
                    run_syscall_prog_attach(skel.progs().attach_prog(), attach_args).unwrap();
                self.read_events_loop(path, rdesc, Some(skel.maps().events()))?
            }
        }
        Ok(())
    }
}

fn bpf_event_handler(
    data: &[u8],
    buffer: &mut Vec<u8>,
    start_time: &OnceCell<Instant>,
) -> ::std::os::raw::c_int {
    if data.len() != std::mem::size_of::<hid_recorder_event>() {
        eprintln!(
            "Invalid size {} != {}",
            data.len(),
            std::mem::size_of::<hid_recorder_event>()
        );
        return 1;
    }

    let event = unsafe { &*(data.as_ptr() as *const hid_recorder_event) };

    if event.length == 0 {
        return 1;
    }

    let elapsed = start_time.get().unwrap().elapsed();

    let size = if event.packet_number == event.packet_count - 1 {
        event.length as usize - event.packet_number as usize * PACKET_SIZE
    } else {
        PACKET_SIZE
    };

    if event.packet_number == 0 {
        buffer.clear();
    }

    buffer.extend_from_slice(&event.data[..size]);

    if event.packet_number == event.packet_count - 1 {
        print_bpf_input_report_data(buffer, &elapsed);
    }
    0
}

enum HidBpfSkel {
    None,
    StructOps(Box<HidrecordSkel<'static>>),
    Tracing(Box<HidrecordTracingSkel<'static>>, u32),
}

fn print_to_log(level: libbpf_rs::PrintLevel, msg: String) {
    /* we strip out the 3 following lines that happen when the kernel
     * doesn't support HID-BPF struct_ops
     */
    let ignore_msgs = [
        "struct bpf_struct_ops_hid_bpf_ops is not found in kernel BTF",
        "failed to load object 'hidrecord_bpf'",
        "failed to load BPF skeleton 'hidrecord_bpf': -2",
    ];
    if ignore_msgs.iter().any(|ignore| msg.contains(ignore)) {
        return;
    }
    match level {
        libbpf_rs::PrintLevel::Info => {
            Outfile::new().writeln(&Styles::Bpf, format!("# {}", msg.trim()).as_str())
        }
        libbpf_rs::PrintLevel::Warn => {
            Outfile::new().writeln(&Styles::Note, format!("# {}", msg.trim()).as_str())
        }
        _ => (),
    }
}

fn preload_bpf_tracer(use_bpf: BpfOption, path: &Path) -> Result<HidBpfSkel> {
    let sysfs = find_sysfs_path(path)?.canonicalize()?;
    let hid_id = u32::from_str_radix(
        sysfs
            .extension()
            .unwrap()
            .to_str()
            .expect("not a hex value"),
        16,
    )
    .unwrap();

    let sysfs_name = sysfs
        .file_name()
        .unwrap()
        .to_str()
        .unwrap()
        .replace([':', '.'], "_");

    let bpffs = PathBuf::from("/sys/fs/bpf/hid/").join(sysfs_name);

    let enable_bpf = match use_bpf {
        BpfOption::Never => false,
        BpfOption::Always => true,
        BpfOption::Auto => bpffs.exists(),
    };

    if bpffs.exists() {
        if let Ok(readdir) = std::fs::read_dir(bpffs) {
            let bpfs = readdir
                .flatten()
                .map(|e| String::from(e.file_name().to_string_lossy()))
                .collect::<Vec<String>>();
            Outfile::new().writeln(
                &Styles::None,
                &format!("# BPF programs active: {}", bpfs.join(", ")),
            );
        }
    }

    if !enable_bpf {
        return Ok(HidBpfSkel::None);
    }

    libbpf_rs::set_print(Some((libbpf_rs::PrintLevel::Info, print_to_log)));

    let skel_builder = HidrecordSkelBuilder::default();
    let mut open_skel = skel_builder.open().unwrap();
    let hid_record_update = open_skel.struct_ops.hid_record_mut();
    hid_record_update.hid_id = hid_id as i32;

    if let Ok(skel) = open_skel.load() {
        return Ok(HidBpfSkel::StructOps(Box::new(skel)));
    }

    let skel_builder = HidrecordTracingSkelBuilder::default();
    let skel = skel_builder.open()?.load()?;
    Ok(HidBpfSkel::Tracing(Box::new(skel), hid_id))
}

fn run_syscall_prog_generic<T>(prog: &libbpf_rs::Program, data: T) -> Result<T, BpfError> {
    let fd = prog.as_fd().as_raw_fd();
    let data_ptr: *const libc::c_void = &data as *const _ as *const libc::c_void;
    let mut run_opts = libbpf_sys::bpf_test_run_opts {
        sz: std::mem::size_of::<libbpf_sys::bpf_test_run_opts>()
            .try_into()
            .unwrap(),
        ctx_in: data_ptr,
        ctx_size_in: std::mem::size_of::<T>() as u32,
        ..Default::default()
    };

    let run_opts_ptr: *mut libbpf_sys::bpf_test_run_opts = &mut run_opts;

    match unsafe { libbpf_sys::bpf_prog_test_run_opts(fd, run_opts_ptr) } {
        0 => Ok(data),
        e => Err(BpfError::OsError { errno: -e as u32 }),
    }
}

fn run_syscall_prog_attach(
    prog: &libbpf_rs::Program,
    attach_args: attach_prog_args,
) -> Result<i32, BpfError> {
    let args = run_syscall_prog_generic(prog, attach_args)?;
    if args.retval < 0 {
        Err(BpfError::OsError {
            errno: -args.retval as u32,
        })
    } else {
        Ok(args.retval)
    }
}
