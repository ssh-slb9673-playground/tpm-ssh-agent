/**
    Ref. [TCG TPM 2.0 Library Part3] Section 12. "Object Commands"
*/
use crate::tpm::session::TpmSession;
use crate::tpm::structure::{
    Tpm2BCreationData, Tpm2BData, Tpm2BDigest, Tpm2BEncryptedSecret, Tpm2BIdentityObject,
    Tpm2BName, Tpm2BPrivate, Tpm2BPublic, Tpm2BSensitiveCreate, Tpm2Command, Tpm2CommandCode,
    TpmHandle, TpmResponseCode, TpmStructureTag, TpmlPcrSelection, TpmtTicketCreation,
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

    pub fn load(
        &mut self,
        parent_handle: TpmHandle,
        auth_area: &mut TpmSession,
        in_private: Tpm2BPrivate,
        in_public: Tpm2BPublic,
    ) -> TpmResult<(TpmHandle, Tpm2BName)> {
        let (public_buf, _, _) = self.read_public(parent_handle)?;

        auth_area.refresh_nonce();
        let mut cmd = Tpm2Command::new_with_session(
            TpmStructureTag::Sessions,
            Tpm2CommandCode::Load,
            vec![parent_handle],
            vec![auth_area.clone()],
            vec![Box::new(in_private), Box::new(in_public)],
        );
        cmd.set_public_data_for_object_handle(parent_handle, public_buf.public_area.unwrap());
        let res = self.execute_with_session(&cmd, 1)?;

        if !res.auth_area.is_empty() {
            auth_area.set_tpm_nonce(res.auth_area[0].nonce.buffer.clone());
            assert!(auth_area.validate(&res, &res.auth_area[0].hmac.buffer));
        }

        if res.response_code != TpmResponseCode::Success {
            Err(TpmError::UnsuccessfulResponse(res.response_code).into())
        } else {
            let v = &res.params;
            let (name, v) = Tpm2BName::from_tpm(v)?;
            assert!(v.is_empty());

            Ok((res.handles[0], name))
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

    pub fn make_credential(
        &mut self,
        handle: TpmHandle,
        credential: Tpm2BDigest,
        object_name: Tpm2BName,
    ) -> TpmResult<(Tpm2BIdentityObject, Tpm2BEncryptedSecret)> {
        let (public_buf, _, _) = self.read_public(handle)?;

        let mut cmd = Tpm2Command::new_with_session(
            TpmStructureTag::NoSessions,
            Tpm2CommandCode::MakeCredential,
            vec![handle],
            vec![],
            vec![Box::new(credential), Box::new(object_name)],
        );
        cmd.set_public_data_for_object_handle(handle, public_buf.public_area.unwrap());
        let res = self.execute_with_session(&cmd, 0)?;

        if res.response_code != TpmResponseCode::Success {
            Err(TpmError::UnsuccessfulResponse(res.response_code).into())
        } else {
            let v = &res.params;
            let (credential_blob, v) = Tpm2BIdentityObject::from_tpm(v)?;
            let (secret, v) = Tpm2BEncryptedSecret::from_tpm(v)?;
            assert!(v.is_empty());

            Ok((credential_blob, secret))
        }
    }

    pub fn activate_credential(
        &mut self,
        activate_handle: TpmHandle,
        key_handle: TpmHandle,
        auth_area: (&mut TpmSession, &mut TpmSession),
        credential_blob: Tpm2BIdentityObject,
        secret: Tpm2BEncryptedSecret,
    ) -> TpmResult<Tpm2BDigest> {
        let (public_buf_a, _, _) = self.read_public(activate_handle)?;
        let (public_buf_k, _, _) = self.read_public(key_handle)?;

        auth_area.0.refresh_nonce();
        auth_area.1.refresh_nonce();
        let mut cmd = Tpm2Command::new_with_session(
            TpmStructureTag::Sessions,
            Tpm2CommandCode::ActivateCredential,
            vec![activate_handle, key_handle],
            vec![auth_area.0.clone(), auth_area.1.clone()],
            vec![Box::new(credential_blob), Box::new(secret)],
        );
        cmd.set_public_data_for_object_handle(activate_handle, public_buf_a.public_area.unwrap());
        cmd.set_public_data_for_object_handle(key_handle, public_buf_k.public_area.unwrap());
        let res = self.execute_with_session(&cmd, 0)?;

        if !res.auth_area.is_empty() {
            auth_area
                .0
                .set_tpm_nonce(res.auth_area[0].nonce.buffer.clone());
            assert!(auth_area.0.validate(&res, &res.auth_area[0].hmac.buffer));
            auth_area
                .1
                .set_tpm_nonce(res.auth_area[1].nonce.buffer.clone());
            assert!(auth_area.1.validate(&res, &res.auth_area[1].hmac.buffer));
        }

        if res.response_code != TpmResponseCode::Success {
            Err(TpmError::UnsuccessfulResponse(res.response_code).into())
        } else {
            let v = &res.params;
            let (cert_info, v) = Tpm2BDigest::from_tpm(v)?;
            assert!(v.is_empty());

            Ok(cert_info)
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
