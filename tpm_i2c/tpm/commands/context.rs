/**
    Ref. [TCG TPM 2.0 Library Part3] Section 28. "Context Management"
*/
use crate::tpm::structure::{
    Tpm2Command, Tpm2CommandCode, TpmHandle, TpmResponseCode, TpmStructureTag,
};
use crate::tpm::{I2CTpmAccessor, Tpm, TpmError};
use crate::TpmResult;

impl<T: I2CTpmAccessor> Tpm<'_, T> {
    pub fn flush_context(&mut self, flush_handle: TpmHandle) -> TpmResult<()> {
        let cmd = Tpm2Command::new(
            TpmStructureTag::NoSessions,
            Tpm2CommandCode::FlushContext,
            vec![Box::new(flush_handle)],
        );
        let res = self.execute(&cmd)?;
        if res.response_code != TpmResponseCode::Success {
            Err(TpmError::UnsuccessfulResponse(res.response_code).into())
        } else {
            Ok(())
        }
    }
}
