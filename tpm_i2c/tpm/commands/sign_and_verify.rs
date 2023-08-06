/**
    Ref. [TCG TPM 2.0 Library Part3] Section 20. "Signing and Signature Verification"
*/
use crate::tpm::session::TpmSession;
use crate::tpm::structure::{
    Tpm2BDigest, Tpm2Command, Tpm2CommandCode, TpmHandle, TpmResponseCode, TpmStructureTag,
    TpmtSignature, TpmtSignatureScheme, TpmtTicketHashCheck,
};
use crate::tpm::{FromTpm, I2CTpmAccessor, Tpm, TpmError};
use crate::TpmResult;

impl<T: I2CTpmAccessor> Tpm<'_, T> {
    pub fn sign(
        &mut self,
        key_handle: TpmHandle,
        auth_area: &mut TpmSession,
        digest: &[u8],
        in_scheme: TpmtSignatureScheme,
        validation: TpmtTicketHashCheck,
    ) -> TpmResult<TpmtSignature> {
        let res = self.execute_with_session(
            &Tpm2Command::new_with_session(
                TpmStructureTag::Sessions,
                Tpm2CommandCode::Sign,
                vec![key_handle],
                vec![auth_area.clone()],
                vec![
                    Box::new(Tpm2BDigest::new(digest)),
                    Box::new(in_scheme),
                    Box::new(validation),
                ],
            ),
            1,
        )?;

        dbg!(&res);

        if res.response_code != TpmResponseCode::Success {
            Err(TpmError::UnsuccessfulResponse(res.response_code).into())
        } else {
            let (sig, _) = TpmtSignature::from_tpm(&res.params)?;
            Ok(sig)
        }
    }
}
