pub mod tpm;
mod util;

pub type TpmResult<T> = Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    DriverError(Box<dyn std::error::Error>),
    TpmError(tpm::TpmError),
    Hardware,
    Unknown,
}

macro_rules! driver_error {
    ($et:ty) => {
        impl std::convert::From<$et> for Error {
            fn from(err: $et) -> Self {
                Error::DriverError(Box::new(err))
            }
        }
    };
}

driver_error!(i2cdev::linux::LinuxI2CError);
driver_error!(hidapi::HidError);

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match &self {
            Error::DriverError(e) => write!(f, "{}", e),
            Error::TpmError(e) => write!(f, "{}", e),
            Error::Hardware => write!(f, "Hardware"),
            Error::Unknown => write!(f, "Unknown"),
        }
    }
}

impl std::error::Error for Error {}
