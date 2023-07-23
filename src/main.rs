extern crate i2cdev;

use crate::tpm::{I2CTPMAccessor, TPM};
use i2cdev::core::*;
use i2cdev::linux::LinuxI2CDevice;
use std::convert::From;
use std::fmt;

mod tpm;

#[macro_export]
macro_rules! bit {
    ($x:expr, $i:expr) => {
        (($x >> $i) & 1)
    };
    ($x:expr, $i:expr, bool) => {
        (($x >> $i) & 1) == 1
    };
    ($x:expr, $i:expr, $type:ty) => {
        (($x >> $i) & 1) as $type
    };
}

impl I2CTPMAccessor for LinuxI2CDevice {
    fn i2c_read(&mut self, read_buf: &mut [u8]) -> TPMResult<()> {
        self.read(read_buf)?;
        Ok(())
    }

    fn i2c_write(&mut self, write_buf: &[u8]) -> TPMResult<()> {
        self.write(write_buf)?;
        Ok(())
    }
}

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

fn main() -> TPMResult<()> {
    let mut tpm = TPM::new(Box::new(LinuxI2CDevice::new("/dev/i2c-9", 0x2e)?));

    let (tpm_vendor_id, tpm_device_id, tpm_revision_id) = &tpm.read_identifiers()?;
    // For Infineon SLB9673 only
    assert_eq!(tpm_vendor_id, &0x15d1);
    assert_eq!(tpm_device_id, &0x001c);
    assert_eq!(tpm_revision_id, &0x16);

    {
        let locality = &tpm.read_locality()?;
        println!("{}", locality);
    }
    let _ = &tpm.write_locality(3)?;
    {
        let locality = &tpm.read_locality()?;
        println!("{}", locality);
    }
    {
        let access = &tpm.read_access()?;
        println!("{:?}", access);
    }
    let stat = &tpm.read_status()?;
    dbg!(stat);
    let _ = &tpm.write_locality(0)?;
    {
        let locality = &tpm.read_locality()?;
        println!("{}", locality);
    }
    Ok(())
}
