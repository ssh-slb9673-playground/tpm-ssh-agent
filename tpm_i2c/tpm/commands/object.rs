/**
    Ref. [TCG TPM 2.0 Library Part3] Section 12. "Object Commands"
*/
use crate::tpm::structure::{
    Tpm2Command, Tpm2CommandCode, TpmHandle, TpmResponseCode, TpmStructureTag, TpmtPublic,
};
use crate::tpm::{FromTpm, I2CTpmAccessor, Tpm, TpmError};
use crate::TpmResult;

impl<T: I2CTpmAccessor> Tpm<'_, T> {
    pub fn read_public(&mut self, object_handle: TpmHandle) -> TpmResult<TpmtPublic> {
        let res = self.execute(&Tpm2Command::new(
            self,
            TpmStructureTag::NoSessions,
            Tpm2CommandCode::ReadPublic,
            vec![Box::new(object_handle)],
        ))?;
        if res.response_code != TpmResponseCode::Success {
            Err(TpmError::UnsuccessfulResponse(res.response_code).into())
        } else {
            let (buf, _) = TpmtPublic::from_tpm(&res.params)?;
            Ok(buf)
        }
    }
}
