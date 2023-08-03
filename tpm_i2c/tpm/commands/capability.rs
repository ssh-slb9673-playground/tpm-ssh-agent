/**
    Ref. [TCG TPM 2.0 Library Part3] Section 30. "Capability Commands"
*/
use crate::tpm::structure::{
    Tpm2Command, Tpm2CommandCode, Tpm2Response, TpmResponseCode, TpmStructureTag, TpmtPublicParams,
};
use crate::tpm::{I2CTpmAccessor, Tpm, TpmError};
use crate::TpmResult;

impl<T: I2CTpmAccessor> Tpm<'_, T> {
    pub fn test_params(&mut self, params: TpmtPublicParams) -> TpmResult<Tpm2Response> {
        let res = self.execute(&Tpm2Command::new(
            TpmStructureTag::NoSessions,
            Tpm2CommandCode::TestParms,
            vec![Box::new(params)],
        ))?;
        if res.response_code != TpmResponseCode::Success {
            Err(TpmError::UnsuccessfulResponse(res.response_code).into())
        } else {
            Ok(res)
        }
    }
}
