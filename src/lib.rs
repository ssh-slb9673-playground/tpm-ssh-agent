#[macro_use]
extern crate num_derive;

mod driver;
pub mod tpm;
mod util;

pub type TpmResult<T> = Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    LinuxI2CError(i2cdev::linux::LinuxI2CError),
    HidApiError(hidapi::HidError),
    TpmError(tpm::command::TpmResponseCode),
    Unknown,
    TpmBusy,
    TpmParse,
    Hardware,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match &self {
            Error::LinuxI2CError(e) => write!(f, "{}", e),
            Error::HidApiError(e) => write!(f, "{}", e),
            Error::TpmError(e) => write!(f, "TpmError: RC = {:?}", e),
            Error::Unknown => write!(f, "Unknown"),
            Error::TpmBusy => write!(f, "Busy"),
            Error::TpmParse => write!(f, "Parse"),
            Error::Hardware => write!(f, "Hardware"),
        }
    }
}

impl std::error::Error for Error {}
