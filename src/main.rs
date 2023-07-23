use crate::tpm::TPM;
use i2cdev::linux::{LinuxI2CDevice, LinuxI2CError};
use std::convert::From;
use std::fmt;

mod driver;
mod tpm;

pub type TPMResult<T> = Result<T, Error>;

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
    ($x:expr, $i:expr, $j:expr, $type:ty) => {
        assert!($j > 0);
        (($x >> $i) & ((1 << $j) - 1)) as $type
    };
}

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
