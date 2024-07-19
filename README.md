# hid-recorder

HID Recorder is a utility to record HID data from a `/dev/hidraw` device and print both
the HID Report Descriptor and the HID Reports in a human and machine-readable format.
This output can be used for analysis and/or replaying devices and their events.

This is a Rust reimplementation of hid-recorder from
[hid-tools](https://gitlab.freedesktop.org/libevdev/hid-tools/)

# Installation

A pre-built binary is available for our
[releases](https://github.com/hidutils/hid-recorder/releases). Simply download the
`hid-recorder.zip`, unpack it and you are good to go:
```
$ unzip hid-recorder.zip
$ chmod +x hid-recorder
$ sudo ./hid-recorder
```

## Installation with `cargo`

The easiest is to install with cargo:

```
$ cargo install hid-recorder
$ hid-recorder
```

This installs in `$CARGO_HOME` (usually `$HOME/.cargo`) and is sufficient for
use-cases where you only neeed to analyze the HID Report Descriptor (not
events from the device)

For use-cases where you need to record events (HID Reports) hid-recorder
needs read access to the respective `/dev/hidraw` device. Typically this
means you need to run as root. The easiest way is to run through `pkexec`
which will ask for your user's password:

```
$ pkexec hid-recorder
```

Alternatively you can install hid-recorder so you can access it via
sudo:

## Sudo-compatible Installation

### Install as user in $CARGO_HOME

This is the default `cargo` installation but requires that you add the
path manually when running hid-recorder:

```
$ cargo install hid-recorder
$ sudo $HOME/.cargo/bin/hid-recorder
```

### Install as root in /usr/local

Install hid-recorder in `/usr/local/` which is typically part of the
default `$PATH`.

```
$ sudo CARGO_INSTALL_ROOT=/usr/local cargo install hid-recorder
$ sudo hid-recorder
```

### Allow access to the device to non-root users

This is the least safe option as once read access is granted, any
process can read events from the device. If the device is a keyboard
this allows for key loggers to read all events.

```
$ cargo install hid-recorder
$ sudo chmod o+r /dev/hidraw0
$ hid-recorder
```
It is recommended to remove these permissions once the recording is
complete:

```
$ sudo chmod o-r /dev/hidraw0
```

# Recording a device

The typical use is a request for "attach a hid recording" in an issue.
To do this, run hid-recorder with no arguments and pick the device
in question, e.g.

```
$ sudo hid-recorder
# Available devices:
# /dev/hidraw0:     Microsoft Microsoft® 2.4GHz Transceiver v9.0
# /dev/hidraw1:     Microsoft Microsoft® 2.4GHz Transceiver v9.0
# /dev/hidraw2:     Microsoft Microsoft® 2.4GHz Transceiver v9.0
# /dev/hidraw3:     Logitech USB Receiver
# /dev/hidraw4:     HUION Huion Tablet_H641P
# /dev/hidraw5:     HUION Huion Tablet_H641P
# /dev/hidraw6:     HUION Huion Tablet_H641P
# /dev/hidraw7:     Yubico YubiKey OTP+FIDO+CCID
# /dev/hidraw8:     Logitech ERGO K860
# /dev/hidraw9:     Yubico YubiKey OTP+FIDO+CCID
# Select the device event number [0-9]:
```

Alternatively provide the `/dev/hidraw` path directly:
```
$ sudo hid-recorder /dev/hidraw0
```

Use the `--help` option to see more options.
