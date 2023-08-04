/**
    Ref. [TCG TPM 2.0 Library Part3] Section 24. "Hierarchy Commands"
*/
use crate::tpm::structure::{
    Tpm2BData, Tpm2BPublic, Tpm2BSensitiveCreate, Tpm2Command, Tpm2CommandCode, Tpm2Response,
    TpmAuthCommand, TpmHandle, TpmResponseCode, TpmStructureTag, TpmlPcrSelection,
};
use crate::tpm::{I2CTpmAccessor, Tpm, TpmError};
use crate::TpmResult;

impl<T: I2CTpmAccessor> Tpm<'_, T> {
    pub fn create_primary(
        &mut self,
        primary_handle: TpmHandle,
        auth_area: TpmAuthCommand,
        in_sensitive: Tpm2BSensitiveCreate,
        in_public: Tpm2BPublic,
        outside_info: Tpm2BData,
        creation_pcr: TpmlPcrSelection,
    ) -> TpmResult<Tpm2Response> {
        let res = self.execute_with_session(
            &Tpm2Command::new_with_session(
                TpmStructureTag::Sessions,
                Tpm2CommandCode::CreatePrimary,
                vec![primary_handle],
                vec![auth_area],
                vec![
                    Box::new(in_sensitive),
                    Box::new(in_public),
                    Box::new(outside_info),
                    Box::new(creation_pcr),
                ],
            ),
            1,
        )?;
        if res.response_code != TpmResponseCode::Success {
            Err(TpmError::UnsuccessfulResponse(res.response_code).into())
        } else {
            Ok(res)
        }
    }
}
