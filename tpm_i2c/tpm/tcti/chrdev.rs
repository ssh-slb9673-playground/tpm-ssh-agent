use crate::tpm::tcti::Tcti;
use crate::TpmResult;
use std::fs::{File, OpenOptions};
use std::io::prelude::*;

pub struct ChrDevTcti {
    file: File,
}

impl ChrDevTcti {
    pub fn new(path: &str) -> TpmResult<ChrDevTcti> {
        let file = OpenOptions::new().read(true).write(true).open(path)?;
        Ok(ChrDevTcti { file })
    }
}

impl Tcti for ChrDevTcti {
    fn device_init(&mut self) -> TpmResult<()> {
        // do nothing
        Ok(())
    }

    fn recv(&mut self) -> TpmResult<Vec<u8>> {
        let mut res = vec![];
        self.file.read_to_end(&mut res)?;
        Ok(res)
    }

    fn send(&mut self, data: &[u8]) -> TpmResult<()> {
        self.file.write_all(data)?;
        Ok(())
    }
}
