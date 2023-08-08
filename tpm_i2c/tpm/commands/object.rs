/**
    Ref. [TCG TPM 2.0 Library Part3] Section 12. "Object Commands"
*/
use crate::tpm::structure::{
    Tpm2BName, Tpm2BPublic, Tpm2Command, Tpm2CommandCode, TpmHandle, TpmResponseCode,
    TpmStructureTag,
};
use crate::tpm::{FromTpm, Tpm, TpmError};
use crate::TpmResult;

impl Tpm {
    pub fn read_public(
        &mut self,
        object_handle: TpmHandle,
    ) -> TpmResult<(Tpm2BPublic, Tpm2BName, Tpm2BName)> {
        let res = self.execute(&Tpm2Command::new(
            TpmStructureTag::NoSessions,
            Tpm2CommandCode::ReadPublic,
            vec![Box::new(object_handle)],
        ))?;
        if res.response_code != TpmResponseCode::Success {
            Err(TpmError::UnsuccessfulResponse(res.response_code).into())
        } else {
            let (out_public, v) = Tpm2BPublic::from_tpm(&res.params)?;
            let (name, v) = Tpm2BName::from_tpm(v)?;
            let (qualified_name, _) = Tpm2BName::from_tpm(v)?;

            Ok((out_public, name, qualified_name))
        }
    }
}
