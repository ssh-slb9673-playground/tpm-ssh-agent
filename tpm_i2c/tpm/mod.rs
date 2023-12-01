use crate::{Error, TpmResult};
use std::backtrace::Backtrace;

use structure::{Tpm2Command, TpmResponseCode, TpmResponseCodeFormat0, TpmiYesNo};

pub mod commands;
mod crypto;
pub mod session;
pub mod structure;
pub mod tcti;

#[derive(Debug)]
pub enum TpmError {
    UnsuccessfulResponse(structure::TpmResponseCode),
    Parse(Backtrace, String),
    InvalidAlgorithmType(structure::TpmAlgorithmType, structure::TpmAlgorithmType),
    IoError(std::io::Error),
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
            TpmError::IoError(io) => write!(f, "I/O Error: io = {:?}", io),
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

impl std::convert::From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Error {
        TpmError::IoError(err).into()
    }
}

pub trait ToTpm: std::fmt::Debug {
    fn to_tpm(&self) -> Vec<u8>;
}

pub trait FromTpm: std::fmt::Debug + Sized {
    fn from_tpm(v: &[u8]) -> TpmResult<(Self, &[u8])>;
}

pub trait FromTpmWithSelector<T>: std::fmt::Debug + Sized {
    fn from_tpm<'a>(v: &'a [u8], selector: &T) -> TpmResult<(Self, &'a [u8])>;
}

pub struct Tpm {
    device: Box<dyn tcti::Tcti>,
}

impl Tpm {
    pub fn new(mut device: Box<dyn tcti::Tcti>) -> TpmResult<Tpm> {
        device.device_init()?;
        Ok(Tpm { device })
    }

    pub(in crate::tpm) fn execute(
        &mut self,
        cmd: &Tpm2Command,
    ) -> TpmResult<structure::Tpm2Response> {
        self.execute_with_session(cmd, 0)
    }

    pub(in crate::tpm) fn execute_with_session(
        &mut self,
        cmd: &Tpm2Command,
        count_handles: usize,
    ) -> TpmResult<structure::Tpm2Response> {
        self.device.send(&cmd.to_tpm())?;
        structure::Tpm2Response::from_tpm(
            self.device.recv()?.as_slice(),
            count_handles,
            &cmd.command_code,
        )
    }

    pub fn init(&mut self, clear_state: bool) -> TpmResult<()> {
        let res = self.startup(clear_state);
        if matches!(
            res,
            Err(Error::TpmError(TpmError::UnsuccessfulResponse(
                TpmResponseCode::Error(TpmResponseCodeFormat0::Initialize)
            )))
        ) {
            println!("[*] TPM was already initialized");
        } else if res.is_err() {
            return res;
        } else {
            self.selftest(TpmiYesNo::No)?;
        }
        Ok(())
    }
}

pub trait TpmDataVec: Sized {
    fn to_tpm(&self) -> Vec<u8>;
    fn from_tpm(v: &[u8], count: usize) -> TpmResult<(Self, &[u8])>;
}

impl<T: ToTpm + FromTpm> TpmDataVec for Vec<T> {
    fn to_tpm(&self) -> Vec<u8> {
        self.iter()
            .map(|x| x.to_tpm())
            .fold(vec![], |acc, x| [acc, x].concat())
    }

    fn from_tpm(_v: &[u8], count: usize) -> TpmResult<(Self, &[u8])> {
        let mut ret = vec![];
        for _ in 1..count {
            let (value, _v) = T::from_tpm(_v)?;
            ret.push(value);
        }

        Ok((ret, _v))
    }
}

impl TpmDataVec for Vec<Box<dyn ToTpm>> {
    fn to_tpm(&self) -> Vec<u8> {
        self.iter()
            .map(|x| x.to_tpm())
            .fold(vec![], |acc, x| [acc, x].concat())
    }

    fn from_tpm(_v: &[u8], _count: usize) -> TpmResult<(Self, &[u8])> {
        panic!();
    }
}
