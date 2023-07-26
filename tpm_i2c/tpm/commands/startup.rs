/**
    Ref. [TCG TPM 2.0 Library Part3] Section 9. "Start-up"
*/
use crate::tpm::structure::{
    Tpm2Command, Tpm2CommandCode, TpmResponseCode, TpmStartupType, TpmStructureTag,
};
use crate::tpm::{Tpm, TpmError};
use crate::TpmResult;

impl Tpm {
    pub fn startup(&mut self, st: TpmStartupType) -> TpmResult<()> {
        let res = self.execute(&Tpm2Command::new(
            TpmStructureTag::NoSessions,
            Tpm2CommandCode::Startup,
            vec![Box::new(st)],
        ))?;
        if res.response_code != TpmResponseCode::Success {
            Err(TpmError::UnsuccessfulResponse(res.response_code).into())
        } else {
            Ok(())
        }
    }
}
