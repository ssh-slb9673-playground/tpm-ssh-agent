extern crate i2cdev;

use i2cdev::core::*;
use i2cdev::linux::LinuxI2CDevice;
use std::convert::From;
use std::fmt;

#[derive(Debug)]
pub enum Error {
    LinuxI2CError(i2cdev::linux::LinuxI2CError),
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
pub type TPMResult<T> = Result<T, Error>;

impl From<i2cdev::linux::LinuxI2CError> for Error {
    fn from(err: i2cdev::linux::LinuxI2CError) -> Error {
        Error::LinuxI2CError(err)
    }
}

fn tpm_read_identifiers(device: &mut LinuxI2CDevice) -> Result<(u16, u16, u8), Error> {
    let mut read_vid_and_did_buf = [0u8; 4];
    let mut read_rid_buf = [0u8; 1];

    device.write(&[0x48])?;
    device.read(&mut read_vid_and_did_buf)?;
    device.write(&[0x4c])?;
    device.read(&mut read_rid_buf)?;

    let (tpm_vendor_id, tpm_device_id) = {
        (
            read_vid_and_did_buf[1] as u16 * 256 + read_vid_and_did_buf[0] as u16,
            read_vid_and_did_buf[3] as u16 * 256 + read_vid_and_did_buf[2] as u16,
        )
    };

    let tpm_revision_id = read_rid_buf[0];

    Ok((tpm_vendor_id, tpm_device_id, tpm_revision_id))
}

fn main() -> Result<(), Error> {
    let mut dev = LinuxI2CDevice::new("/dev/i2c-9", 0x2e)?;

    let (tpm_vendor_id, tpm_device_id, tpm_revision_id) = tpm_read_identifiers(&mut dev)?;
    assert_eq!(tpm_vendor_id, 0x15d1);
    assert_eq!(tpm_device_id, 0x001c);
    assert_eq!(tpm_revision_id, 0x16);
    println!("[+] Vendor ID: {:04x}", tpm_vendor_id);
    println!("[+] Device ID: {:04x}", tpm_device_id);
    println!("[+] Revision ID: {:01x}", tpm_revision_id);

    /*
    let mut cap_read_buf: [u8; 4] = [0; 4];
    let cap_write_buf: [u8; 1] = [0x30];
    dev.write_read_address(0x2e, &cap_write_buf, &mut cap_read_buf)?;
    println!(
        "[+] capabilities = {:02x} {:02x} {:02x} {:02x}",
        cap_read_buf[3], cap_read_buf[2], cap_read_buf[1], cap_read_buf[0]
    );
    */

    Ok(())
}
