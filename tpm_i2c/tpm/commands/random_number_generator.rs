/**
    Ref. [TCG TPM 2.0 Library Part3] Section 16. "Random Number Generator"
*/
use crate::tpm::structure::{
    Tpm2BDigest, Tpm2Command, Tpm2CommandCode, TpmResponseCode, TpmStructureTag, TpmUint16,
};
use crate::tpm::{I2CTpmAccessor, Tpm, TpmData, TpmError};
use crate::TpmResult;

impl<T: I2CTpmAccessor> Tpm<'_, T> {
    pub fn get_random(&mut self, len: u16) -> TpmResult<Vec<u8>> {
        if !self.request_locality(0)? {
            return Err(TpmError::LocalityReq(0).into());
        }
        let res = self.execute(&Tpm2Command::new(
            TpmStructureTag::NoSessions,
            Tpm2CommandCode::GetRandom,
            vec![Box::new(TpmUint16::new(len))],
        ))?;
        self.release_locality()?;
        if res.response_code != TpmResponseCode::Success {
            Err(TpmError::UnsuccessfulResponse(res.response_code).into())
        } else {
            let (buf, _) = Tpm2BDigest::from_tpm(&res.params)?;
            Ok(buf.buffer)
        }
    }
}
