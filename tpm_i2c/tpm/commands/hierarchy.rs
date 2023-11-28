use crate::tpm::commands::Tpm2CreateParameters;
/**
    Ref. [TCG TPM 2.0 Library Part3] Section 24. "Hierarchy Commands"
*/
use crate::tpm::session::TpmSession;
use crate::tpm::structure::{
    Tpm2BCreationData, Tpm2BDigest, Tpm2BName, Tpm2BPublic, Tpm2Command, Tpm2CommandCode,
    TpmHandle, TpmResponseCode, TpmStructureTag, TpmtTicketCreation,
};
use crate::tpm::{FromTpm, Tpm, TpmError};
use crate::TpmResult;

impl Tpm {
    pub fn create_primary(
        &mut self,
        primary_handle: TpmHandle,
        auth_area: &mut TpmSession,
        params: Tpm2CreateParameters,
    ) -> TpmResult<Tpm2CreatePrimaryResponse> {
        auth_area.refresh_nonce();
        let res = self.execute_with_session(
            &Tpm2Command::new_with_session(
                TpmStructureTag::Sessions,
                Tpm2CommandCode::CreatePrimary,
                vec![primary_handle],
                vec![auth_area.clone()],
                vec![
                    Box::new(params.in_sensitive),
                    Box::new(params.in_public),
                    Box::new(params.outside_info),
                    Box::new(params.creation_pcr),
                ],
            ),
            1,
        )?;

        if !res.auth_area.is_empty() {
            auth_area.set_tpm_nonce(res.auth_area[0].nonce.buffer.clone());
            assert!(auth_area.validate(&res, &res.auth_area[0].hmac.buffer));
        }

        if res.response_code != TpmResponseCode::Success {
            Err(TpmError::UnsuccessfulResponse(res.response_code).into())
        } else {
            let v = &res.params;
            let (out_public, v) = Tpm2BPublic::from_tpm(v)?;
            let (creation_data, v) = Tpm2BCreationData::from_tpm(v)?;
            let (creation_hash, v) = Tpm2BDigest::from_tpm(v)?;
            let (creation_ticket, v) = TpmtTicketCreation::from_tpm(v)?;
            let (name, v) = Tpm2BName::from_tpm(v)?;
            assert!(v.is_empty());

            Ok(Tpm2CreatePrimaryResponse {
                handle: res.handles[0],
                out_public,
                creation_data,
                creation_hash,
                creation_ticket,
                name,
            })
        }
    }
}

#[derive(Debug)]
pub struct Tpm2CreatePrimaryResponse {
    pub handle: TpmHandle,
    pub out_public: Tpm2BPublic,
    pub creation_data: Tpm2BCreationData,
    pub creation_hash: Tpm2BDigest,
    pub creation_ticket: TpmtTicketCreation,
    pub name: Tpm2BName,
}
