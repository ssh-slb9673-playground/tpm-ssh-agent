use crate::tpm::session::TpmSession;
/**
    Ref. [TCG TPM 2.0 Library Part3] Section 12. "Object Commands"
*/
use crate::tpm::structure::{
    Tpm2BCreationData, Tpm2BData, Tpm2BDigest, Tpm2BName, Tpm2BPrivate, Tpm2BPublic,
    Tpm2BSensitiveCreate, Tpm2Command, Tpm2CommandCode, TpmHandle, TpmResponseCode,
    TpmStructureTag, TpmlPcrSelection, TpmtTicketCreation,
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

    pub fn create(
        &mut self,
        parent_handle: TpmHandle,
        auth_area: &mut TpmSession,
        params: Tpm2CreateParameters,
    ) -> TpmResult<Tpm2CreateResponse> {
        let (public_buf, _, _) = self.read_public(parent_handle)?;

        auth_area.refresh_nonce();
        let mut cmd = Tpm2Command::new_with_session(
            TpmStructureTag::Sessions,
            Tpm2CommandCode::Create,
            vec![parent_handle],
            vec![auth_area.clone()],
            vec![
                Box::new(params.in_sensitive),
                Box::new(params.in_public),
                Box::new(params.outside_info),
                Box::new(params.creation_pcr),
            ],
        );
        cmd.set_public_data_for_object_handle(parent_handle, public_buf.public_area.unwrap());
        let res = self.execute_with_session(&cmd, 0)?;

        if !res.auth_area.is_empty() {
            auth_area.set_tpm_nonce(res.auth_area[0].nonce.buffer.clone());
            assert!(auth_area.validate(&res, &res.auth_area[0].hmac.buffer));
        }

        if res.response_code != TpmResponseCode::Success {
            Err(TpmError::UnsuccessfulResponse(res.response_code).into())
        } else {
            let v = &res.params;
            let (out_private, v) = Tpm2BPrivate::from_tpm(v)?;
            let (out_public, v) = Tpm2BPublic::from_tpm(v)?;
            let (creation_data, v) = Tpm2BCreationData::from_tpm(v)?;
            let (creation_hash, v) = Tpm2BDigest::from_tpm(v)?;
            let (creation_ticket, v) = TpmtTicketCreation::from_tpm(v)?;
            assert!(v.is_empty());

            Ok(Tpm2CreateResponse {
                out_private,
                out_public,
                creation_data,
                creation_hash,
                creation_ticket,
            })
        }
    }
}

#[derive(Debug)]
pub struct Tpm2CreateResponse {
    pub out_public: Tpm2BPublic,
    pub out_private: Tpm2BPrivate,
    pub creation_data: Tpm2BCreationData,
    pub creation_hash: Tpm2BDigest,
    pub creation_ticket: TpmtTicketCreation,
}

#[derive(Debug)]
pub struct Tpm2CreateParameters {
    pub in_sensitive: Tpm2BSensitiveCreate,
    pub in_public: Tpm2BPublic,
    pub outside_info: Tpm2BData,
    pub creation_pcr: TpmlPcrSelection,
}
