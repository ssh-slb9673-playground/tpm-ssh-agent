/**
    Ref. [TCG TPM 2.0 Library Part3] Section 20. "Signing and Signature Verification"
*/
use crate::tpm::session::TpmSession;
use crate::tpm::structure::{
    Tpm2BDigest, Tpm2Command, Tpm2CommandCode, TpmHandle, TpmResponseCode, TpmStructureTag,
    TpmtSignature, TpmtSignatureScheme, TpmtTicketHashCheck,
};
use crate::tpm::{FromTpm, Tpm, TpmError};
use crate::TpmResult;

impl Tpm {
    pub fn sign(
        &mut self,
        key_handle: TpmHandle,
        auth_area: &mut TpmSession,
        auth_value: Vec<u8>,
        digest: &[u8],
        in_scheme: TpmtSignatureScheme,
        validation: TpmtTicketHashCheck,
    ) -> TpmResult<TpmtSignature> {
        let (public_buf, _, _) = self.read_public(key_handle)?;

        auth_area.refresh_nonce();
        let mut cmd = Tpm2Command::new_with_session(
            TpmStructureTag::Sessions,
            Tpm2CommandCode::Sign,
            vec![key_handle],
            vec![auth_area.clone()],
            auth_value.clone(),
            vec![
                Box::new(Tpm2BDigest::new(digest)),
                Box::new(in_scheme),
                Box::new(validation),
            ],
        );
        cmd.set_public_object_for_handle(key_handle, public_buf.public_area.unwrap());
        let res = self.execute_with_session(&cmd, 0)?;

        if !res.auth_area.is_empty() {
            auth_area.set_tpm_nonce(res.auth_area[0].nonce.buffer.clone());
            assert!(auth_area.validate(&res, auth_value.clone(), &res.auth_area[0].hmac.buffer));
        }

        if res.response_code != TpmResponseCode::Success {
            Err(TpmError::UnsuccessfulResponse(res.response_code).into())
        } else {
            let (sig, _) = TpmtSignature::from_tpm(&res.params)?;
            Ok(sig)
        }
    }
}
