/**
    Ref. [TCG TPM 2.0 Library Part3] Section 11. "Session Commands"
*/
use crate::tpm::structure::{
    Tpm2BEncryptedSecret, Tpm2BNonce, Tpm2Command, Tpm2CommandCode, TpmHandle, TpmResponseCode,
    TpmSessionType, TpmStructureTag, TpmiAlgorithmHash, TpmiDhEntity, TpmiDhObject, TpmtSymdef,
};
use crate::tpm::{FromTpm, I2CTpmAccessor, ToTpm, Tpm, TpmError};
use crate::TpmResult;

impl<T: I2CTpmAccessor> Tpm<'_, T> {
    pub fn start_auth_session(
        &mut self,
        tpm_key: TpmiDhObject,
        bind: TpmiDhEntity,
        nonce_caller: Tpm2BNonce,
        encrypted_salt: Tpm2BEncryptedSecret,
        session_type: TpmSessionType,
        symmetric: TpmtSymdef,
        auth_hash: TpmiAlgorithmHash,
    ) -> TpmResult<(TpmResponseCode, TpmHandle, Tpm2BNonce)> {
        let cmd = Tpm2Command::new_with_session(
            TpmStructureTag::NoSessions,
            Tpm2CommandCode::StartAuthSession,
            vec![TpmHandle::from(&tpm_key), TpmHandle::from(&bind)],
            vec![],
            vec![
                Box::new(nonce_caller),
                Box::new(encrypted_salt),
                Box::new(session_type),
                Box::new(symmetric),
                Box::new(auth_hash),
            ],
        );
        let res = self.execute_with_session(&cmd, 1)?;

        if res.response_code == TpmResponseCode::Success {
            let (handle, v) = TpmHandle::from_tpm(&res.params)?;
            let (nonce, _) = Tpm2BNonce::from_tpm(v)?;
            Ok((res.response_code, handle, nonce))
        } else if let TpmResponseCode::Warning(_) = &res.response_code {
            let (handle, v) = TpmHandle::from_tpm(&res.params)?;
            let (nonce, _) = Tpm2BNonce::from_tpm(v)?;
            Ok((res.response_code, handle, nonce))
        } else {
            Err(TpmError::UnsuccessfulResponse(res.response_code).into())
        }
    }
}
