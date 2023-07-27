/**
    Ref. [TCG TPM 2.0 Library Part3] Section 10. "Testing"
*/
use crate::tpm::structure::{
    Tpm2Command, Tpm2CommandCode, TpmResponseCode, TpmStructureTag, TpmiYesNo,
};
use crate::tpm::{I2CTpmAccessor, Tpm, TpmError};
use crate::TpmResult;

impl<T: I2CTpmAccessor> Tpm<'_, T> {
    pub fn selftest(&mut self, full_test: TpmiYesNo) -> TpmResult<()> {
        let res = self.execute(&Tpm2Command::new(
            TpmStructureTag::NoSessions,
            Tpm2CommandCode::SelfTest,
            vec![Box::new(full_test)],
        ))?;
        if res.response_code != TpmResponseCode::Success {
            Err(TpmError::UnsuccessfulResponse(res.response_code).into())
        } else {
            Ok(())
        }
    }
}
