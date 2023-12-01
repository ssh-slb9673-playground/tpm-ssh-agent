/**
    Ref. [TCG TPM 2.0 Library Part3] Section 16. "Random Number Generator"
*/
use crate::tpm::structure::{
    Tpm2BDigest, Tpm2Command, Tpm2CommandCode, TpmResponseCode, TpmStructureTag,
};
use crate::tpm::{FromTpm, Tpm, TpmError};
use crate::TpmResult;

impl Tpm {
    pub fn get_random(&mut self, len: u16) -> TpmResult<Vec<u8>> {
        let res = self.execute(&Tpm2Command::new(
            TpmStructureTag::NoSessions,
            Tpm2CommandCode::GetRandom,
            vec![Box::new(len)],
        ))?;
        if res.response_code != TpmResponseCode::Success {
            Err(TpmError::UnsuccessfulResponse(res.response_code).into())
        } else {
            let (buf, _) = Tpm2BDigest::from_tpm(&res.params)?;
            Ok(buf.buffer)
        }
    }
}
