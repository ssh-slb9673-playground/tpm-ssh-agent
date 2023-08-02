/**
    Ref. [TCG TPM 2.0 Library Part3] Section 11. "Session Commands"
*/
use crate::tpm::structure::{
    Tpm2BEncryptedSecret, Tpm2BNonce, TpmHandle, TpmSessionType, TpmiDhEntity, TpmiDhObject,
};
use crate::tpm::{I2CTpmAccessor, Tpm};
use crate::TpmResult;

impl<T: I2CTpmAccessor> Tpm<'_, T> {
    pub fn start_auth_session(
        &mut self,
        tpm_key: TpmiDhObject,
        bind: TpmiDhEntity,
        // and more
    ) -> TpmResult<TpmHandle> {
        todo!()
    }
}
