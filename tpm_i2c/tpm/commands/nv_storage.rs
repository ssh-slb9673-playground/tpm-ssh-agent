use crate::tpm::session::TpmSession;
/**
    Ref. [TCG TPM 2.0 Library Part3] Section 31. "Non-volatile Storage"
*/
use crate::tpm::structure::{
    Tpm2BMaxNvBuffer, Tpm2BName, Tpm2BNvPublic, Tpm2Command, Tpm2CommandCode, TpmResponseCode,
    TpmStructureTag, TpmiHandleNvAuth, TpmiHandleNvIndex,
};
use crate::tpm::{FromTpm, Tpm, TpmError};
use crate::TpmResult;

impl Tpm {
    pub fn nv_read(
        &mut self,
        auth_area: &mut TpmSession,
        auth_value: Vec<u8>,
        auth_handle: &TpmiHandleNvAuth,
        nv_index: &TpmiHandleNvIndex,
        size: u16,
        offset: u16,
    ) -> TpmResult<Vec<u8>> {
        let (public_buf, _) = self.nv_read_public(nv_index)?;

        auth_area.refresh_nonce();
        let mut cmd = Tpm2Command::new_with_session(
            TpmStructureTag::Sessions,
            Tpm2CommandCode::NvRead,
            vec![auth_handle.into(), nv_index.into()],
            vec![auth_area.clone()],
            auth_value.clone(),
            vec![Box::new(size), Box::new(offset)],
        );
        cmd.set_public_data_for_nv_index(nv_index.into(), public_buf.nv_public.unwrap());

        let res = self.execute(&cmd)?;

        if !res.auth_area.is_empty() {
            auth_area.set_tpm_nonce(res.auth_area[0].nonce.buffer.clone());
            assert!(auth_area.validate(&res, auth_value.clone(), &res.auth_area[0].hmac.buffer));
        }

        if res.response_code != TpmResponseCode::Success {
            Err(TpmError::UnsuccessfulResponse(res.response_code).into())
        } else {
            let v = &res.params;
            let (buf, _) = Tpm2BMaxNvBuffer::from_tpm(v)?;
            Ok(buf.buffer)
        }
    }

    pub fn nv_read_public(
        &mut self,
        nv_index: &TpmiHandleNvIndex,
    ) -> TpmResult<(Tpm2BNvPublic, Tpm2BName)> {
        let res = self.execute(&Tpm2Command::new(
            TpmStructureTag::NoSessions,
            Tpm2CommandCode::NvReadPublic,
            vec![Box::new(nv_index.clone())],
        ))?;
        if res.response_code != TpmResponseCode::Success {
            Err(TpmError::UnsuccessfulResponse(res.response_code).into())
        } else {
            let (out_public, v) = Tpm2BNvPublic::from_tpm(&res.params)?;
            let (name, _) = Tpm2BName::from_tpm(v)?;

            Ok((out_public, name))
        }
    }
}
