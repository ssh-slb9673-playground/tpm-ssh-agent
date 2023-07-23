use crate::tpm::{Tpm, TpmAccess};
use i2cdev::linux::{LinuxI2CDevice, LinuxI2CError};
use std::convert::From;
use std::fmt;

pub mod driver;
pub mod tpm;

pub type TpmResult<T> = Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    LinuxI2CError(LinuxI2CError),
    Unknown,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match &self {
            Error::LinuxI2CError(e) => write!(f, "{}", e),
            Error::Unknown => write!(f, "Unknown"),
        }
    }
}

impl std::error::Error for Error {}

impl From<i2cdev::linux::LinuxI2CError> for Error {
    fn from(err: i2cdev::linux::LinuxI2CError) -> Error {
        Error::LinuxI2CError(err)
    }
}

fn print_info(tpm: &mut Tpm) -> TpmResult<()> {
    let caps = &tpm.read_capabilities()?;
    println!("### TPM Information ###");
    let (tpm_vendor_id, tpm_device_id, tpm_revision_id) = &tpm.read_identifiers()?;

    println!("* Vendor ID: {:04x}", tpm_vendor_id);
    println!("* Device ID: {:04x}", tpm_device_id);
    println!("* Revision ID: {:04x}", tpm_revision_id);

    print!("* Interface Type: ");
    if caps.interface_type() == 0b0010 {
        println!("FIFO over I2C");
    } else {
        println!("Unknown({})", caps.interface_type());
    }

    print!("* Interface Version: ");
    if caps.interface_version() == 0b000 {
        println!("TCG I2C Interface 1.0");
    } else {
        println!("Unknown({})", caps.interface_version());
    }

    print!("* TPM Family: ");
    match caps.tpm_family() {
        0b00 => println!("TPM 1.2"),
        0b01 => println!("TPM 2.0"),
        x => println!("Unknown({})", x),
    }

    println!("* Guard time: {} usec", caps.guard_time_usec());
    println!("* Need Guard time?");
    println!("  - Write after Write: {}", caps.need_guard_write_write());
    println!("  - Write after Read: {}", caps.need_guard_write_read());
    println!("  - Read after Write: {}", caps.need_guard_read_write());
    println!("  - Read after Read: {}", caps.need_guard_read_read());
    println!(
        "  - ACK/NACK to repeated START: {}",
        caps.guard_time_repeated_start()
    );

    let sup_bool = |x: bool| if x { "Supported" } else { "Unsupported" };
    println!("* I2C Bus Speed Capabilities");
    println!("  - Standard Mode: {}", sup_bool(caps.sm_support()));
    println!("  - Fast Mode: {}", sup_bool(caps.fm_support()));
    println!("  - Fast Mode Plus: {}", sup_bool(caps.fmplus_support()));
    println!("  - High-Speed Mode: {}", sup_bool(caps.hsmode_support()));

    print!("* Supported locality: ");

    match caps.cap_locality() {
        0b00 => println!("[0]"),
        0b01 => println!("[0, 1, 2, 3, 4]"),
        0b10 => println!("[0, 1, 2, ..., 255]"),
        x => println!("Unknown({})", x),
    }

    print!("* Changing I2C Address: ");
    match caps.device_address_change() {
        0b00 => println!("Unupported"),
        0b01 => println!("Supported (by vendor specific mechanism)"),
        0b10 => println!("Reserved (bug?)"),
        0b11 => println!("Supported (by TCG-defined mechanism)"),
        _ => println!("Invalid"),
    }

    println!(
        "* Burst count: {}",
        if caps.burst_count_static() {
            "Static"
        } else {
            "Dynamic"
        }
    );

    Ok(())
}

fn main() -> TpmResult<()> {
    let mut tpm = Tpm::new(Box::new(LinuxI2CDevice::new("/dev/i2c-9", 0x2e)?));

    let (tpm_vendor_id, tpm_device_id, tpm_revision_id) = &tpm.read_identifiers()?;
    // For Infineon SLB9673 only
    assert_eq!(tpm_vendor_id, &0x15d1);
    assert_eq!(tpm_device_id, &0x001c);
    assert_eq!(tpm_revision_id, &0x16);
    print_info(&mut tpm)?;
    if !&tpm.read_access()?.active_locality() {
        let _ = &tpm.write_access(&TpmAccess::new().with_request_use(true))?;
        let ac = &tpm.read_access()?;
        if !ac.active_locality() {
            println!("[+] Can't get locality control");
            return Ok(());
        }
    }
    let sts = &tpm.read_status()?;
    println!("{sts:?}");

    Ok(())
}
