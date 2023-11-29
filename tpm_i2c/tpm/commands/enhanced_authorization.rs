/**
    Ref. [TCG TPM 2.0 Library Part3] Section 23. "Enhanced Authorization (EA) Commands"
*/
use crate::tpm::session::TpmSession;
use crate::tpm::structure::{
    Tpm2BDigest, Tpm2BNonce, Tpm2BTimeout, Tpm2Command, Tpm2CommandCode, TpmHandle, TpmHandleType,
    TpmResponseCode, TpmStructureTag, TpmtTicketAuth,
};
use crate::tpm::{FromTpm, Tpm, TpmError};
use crate::TpmResult;

impl Tpm {
    pub fn policy_secret(
        &mut self,
        auth_handle: TpmHandle,
        policy_session: TpmHandle,
        auth_area: &mut TpmSession,
        params: PolicySecretParameters,
    ) -> TpmResult<(Tpm2BTimeout, TpmtTicketAuth)> {
        auth_area.refresh_nonce();
        let mut cmd = Tpm2Command::new_with_session(
            TpmStructureTag::Sessions,
            Tpm2CommandCode::PolicySecret,
            vec![auth_handle, policy_session],
            vec![auth_area.clone()],
            vec![
                Box::new(params.nonce_tpm),
                Box::new(params.cphash_a),
                Box::new(params.policy_reference),
                Box::new(params.expiration),
            ],
        );
        if (auth_handle >> 24) != TpmHandleType::Permanent as u32 {
            let (public_buf, _, _) = self.read_public(auth_handle)?;
            cmd.set_public_data_for_object_handle(auth_handle, public_buf.public_area.unwrap());
        }
        let res = self.execute_with_session(&cmd, 0)?;

        if !res.auth_area.is_empty() {
            auth_area.set_tpm_nonce(res.auth_area[0].nonce.buffer.clone());
            assert!(auth_area.validate(&res, &res.auth_area[0].hmac.buffer));
        }

        if res.response_code != TpmResponseCode::Success {
            Err(TpmError::UnsuccessfulResponse(res.response_code).into())
        } else {
            let v = &res.params;
            let (timeout, v) = Tpm2BTimeout::from_tpm(v)?;
            let (policy_ticket, v) = TpmtTicketAuth::from_tpm(v)?;
            assert!(v.is_empty());

            Ok((timeout, policy_ticket))
        }
    }
}

#[derive(Debug)]
pub struct PolicySecretParameters {
    pub nonce_tpm: Tpm2BNonce,
    pub cphash_a: Tpm2BDigest,
    pub policy_reference: Tpm2BNonce,
    pub expiration: u32,
}
