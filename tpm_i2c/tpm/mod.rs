use crate::{Error, TpmResult};

use structure::{Tpm2Command, TpmResponseCode, TpmStartupType, TpmiYesNo};

pub mod commands;
mod i2c;
pub mod structure;

#[derive(Debug)]
pub enum TpmError {
    UnsuccessfulResponse(structure::TpmResponseCode),
    Parse,
    Busy,
    Unreadable,
    LocalityReq(u8),
}

impl std::fmt::Display for TpmError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match &self {
            TpmError::UnsuccessfulResponse(rc) => write!(f, "Unsuccessful Result: RC = {:?}", rc),
            TpmError::Parse => write!(f, "TPM Parse"),
            TpmError::Busy => write!(f, "TPM Busy"),
            TpmError::Unreadable => write!(f, "TPM Unreadable"),
            TpmError::LocalityReq(n) => write!(f, "Can't get control of locality {}", n),
        }
    }
}

impl std::error::Error for TpmError {}

impl std::convert::From<TpmError> for Error {
    fn from(err: TpmError) -> Error {
        Error::TpmError(err)
    }
}

pub trait TpmData {
    fn to_tpm(&self) -> Vec<u8>;
    fn from_tpm(v: &[u8]) -> TpmResult<(Self, &[u8])>
    where
        Self: Sized;
}

pub trait I2CTpmAccessor {
    fn initialize(&mut self) -> TpmResult<()>;
    fn i2c_read(&mut self, read_buf: &mut [u8]) -> TpmResult<()>;
    fn i2c_write(&mut self, write_buf: &[u8]) -> TpmResult<()>;
}

pub struct Tpm {
    device: Box<dyn I2CTpmAccessor>,
    current_locality: u8,
}

impl Tpm {
    pub fn new(mut device: Box<dyn I2CTpmAccessor>) -> TpmResult<Tpm> {
        let mut read_buf = [0u8; 1];
        device.initialize()?;
        device.i2c_write(&[0x00])?;
        device.i2c_read(&mut read_buf)?;
        Ok(Tpm {
            device,
            current_locality: read_buf[0],
        })
    }

    pub(in crate::tpm) fn execute(
        &mut self,
        cmd: &Tpm2Command,
    ) -> TpmResult<structure::Tpm2Response> {
        use std::thread::sleep;
        use std::time::Duration;
        self.request_locality(0)?;
        self.write_fifo(cmd.to_tpm().as_slice())?;
        sleep(Duration::from_millis(5));
        self.write_status(&i2c::TpmStatus::new().with_tpm_go(true))?;
        structure::Tpm2Response::from_tpm(self.read_fifo()?.as_slice())
    }

    pub fn init(&mut self) -> TpmResult<()> {
        let (tpm_vendor_id, tpm_device_id, tpm_revision_id) = self.read_identifiers()?;
        // For Infineon SLB9673 only
        assert_eq!(tpm_vendor_id, 0x15d1);
        assert_eq!(tpm_device_id, 0x001c);
        assert_eq!(tpm_revision_id, 0x16);
        if !self.request_locality(0)? {
            return Err(TpmError::LocalityReq(0).into());
        }
        let res = self.startup(TpmStartupType::Clear);
        if let Err(Error::TpmError(TpmError::UnsuccessfulResponse(TpmResponseCode::Initialize))) =
            res
        {
            println!("[*] TPM was already initialied");
        } else if res.is_err() {
            return res;
        } else {
            self.selftest(TpmiYesNo::No)?;
        }
        self.release_locality()?;
        Ok(())
    }
}
