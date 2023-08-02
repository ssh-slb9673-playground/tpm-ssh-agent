use crate::{Error, TpmResult};
use std::backtrace::Backtrace;

use structure::{Tpm2Command, TpmResponseCode, TpmResponseCodeFormat0, TpmiYesNo};

pub mod commands;
mod i2c;
pub mod structure;

#[derive(Debug)]
pub enum TpmError {
    UnsuccessfulResponse(structure::TpmResponseCode),
    Parse(Backtrace, String),
    InvalidAlgorithmType(structure::TpmAlgorithmType, structure::TpmAlgorithmType),
    Busy,
    Unreadable,
    LocalityReq(u8),
}

impl TpmError {
    fn create_parse_error(details: &str) -> TpmError {
        TpmError::Parse(Backtrace::capture(), details.to_string())
    }
}

impl std::fmt::Display for TpmError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match &self {
            TpmError::UnsuccessfulResponse(rc) => write!(f, "Unsuccessful Result: RC = {:?}", rc),
            TpmError::Parse(bt, details) => {
                write!(f, "TPM Parse: {}\nStacktrace: {:?}", details, bt)
            }
            TpmError::InvalidAlgorithmType(expected, actual) => {
                write!(
                    f,
                    "TPM Invalid Algorithm Type (expected: {:?}, actual: {:?})",
                    expected, actual
                )
            }
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

pub trait TpmData: std::fmt::Debug {
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

pub struct Tpm<'a, T: I2CTpmAccessor> {
    device: &'a mut T,
    current_locality: u8,
}

impl<'a, T: I2CTpmAccessor> Tpm<'a, T> {
    pub fn new(device: &'a mut T) -> TpmResult<Tpm<'a, T>>
    where
        T: I2CTpmAccessor,
    {
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
        structure::Tpm2Response::from_tpm(self.read_fifo()?.as_slice(), 0)
    }

    pub(in crate::tpm) fn execute_with_session(
        &mut self,
        cmd: &Tpm2Command,
        count_handles: usize,
    ) -> TpmResult<structure::Tpm2Response> {
        use std::thread::sleep;
        use std::time::Duration;
        self.request_locality(0)?;
        self.write_fifo(cmd.to_tpm().as_slice())?;
        sleep(Duration::from_millis(5));
        self.write_status(&i2c::TpmStatus::new().with_tpm_go(true))?;
        structure::Tpm2Response::from_tpm(self.read_fifo()?.as_slice(), count_handles)
    }

    pub fn init(&mut self, clear_state: bool) -> TpmResult<()> {
        let (tpm_vendor_id, tpm_device_id, tpm_revision_id) = self.read_identifiers()?;
        // For Infineon SLB9673 only
        assert_eq!(tpm_vendor_id, 0x15d1);
        assert_eq!(tpm_device_id, 0x001c);
        assert_eq!(tpm_revision_id, 0x16);
        if !self.request_locality(0)? {
            return Err(TpmError::LocalityReq(0).into());
        }
        let res = self.startup(clear_state);
        if let Err(Error::TpmError(TpmError::UnsuccessfulResponse(TpmResponseCode::Error(
            TpmResponseCodeFormat0::Initialize,
        )))) = res
        {
            println!("[*] TPM was already initialized");
        } else if res.is_err() {
            return res;
        } else {
            self.selftest(TpmiYesNo::No)?;
        }
        self.release_locality()?;
        Ok(())
    }
}

pub trait TpmDataVec {
    fn to_tpm(&self) -> Vec<u8>;
    fn from_tpm(v: &[u8], count: usize) -> TpmResult<(Self, &[u8])>
    where
        Self: Sized;
}

impl<T: TpmData> TpmDataVec for Vec<T> {
    fn to_tpm(&self) -> Vec<u8> {
        self.iter()
            .map(|x| x.to_tpm())
            .fold(vec![], |acc, x| [acc, x].concat())
    }

    fn from_tpm(_v: &[u8], count: usize) -> TpmResult<(Self, &[u8])>
    where
        Self: Sized,
    {
        let mut ret = vec![];
        for _ in 1..count {
            let (value, _v) = T::from_tpm(_v)?;
            ret.push(value);
        }

        Ok((ret, _v))
    }
}

impl TpmDataVec for Vec<Box<dyn TpmData>> {
    fn to_tpm(&self) -> Vec<u8> {
        self.iter()
            .map(|x| x.to_tpm())
            .fold(vec![], |acc, x| [acc, x].concat())
    }

    fn from_tpm(_v: &[u8], _count: usize) -> TpmResult<(Self, &[u8])>
    where
        Self: Sized,
    {
        panic!();
    }
}
