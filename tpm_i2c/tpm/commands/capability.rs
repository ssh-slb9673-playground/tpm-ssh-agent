/**
    Ref. [TCG TPM 2.0 Library Part3] Section 30. "Capability Commands"
*/
use crate::tpm::structure::{
    Tpm2Command, Tpm2CommandCode, Tpm2Response, TpmCapabilities, TpmResponseCode, TpmStructureTag,
    TpmiYesNo, TpmsCapabilityData, TpmtPublicParams,
};
use crate::tpm::{FromTpm, I2CTpmAccessor, Tpm, TpmError};
use crate::TpmResult;

impl<T: I2CTpmAccessor> Tpm<'_, T> {
    pub fn get_capability(
        &mut self,
        capability: TpmCapabilities,
        property: u32,
        property_count: u32,
    ) -> TpmResult<(bool, TpmsCapabilityData)> {
        let res = self.execute(&Tpm2Command::new(
            TpmStructureTag::NoSessions,
            Tpm2CommandCode::GetCapability,
            vec![
                Box::new(capability),
                Box::new(property),
                Box::new(property_count),
            ],
        ))?;
        if res.response_code != TpmResponseCode::Success {
            Err(TpmError::UnsuccessfulResponse(res.response_code).into())
        } else {
            let v = &res.params;
            let (more_data, v) = TpmiYesNo::from_tpm(v)?;
            let (capability_data, _) = TpmsCapabilityData::from_tpm(v)?;
            Ok((more_data == TpmiYesNo::Yes, capability_data))
        }
    }

    pub fn test_params(&mut self, params: TpmtPublicParams) -> TpmResult<Tpm2Response> {
        let res = self.execute(&Tpm2Command::new(
            TpmStructureTag::NoSessions,
            Tpm2CommandCode::TestParms,
            vec![Box::new(params)],
        ))?;
        if res.response_code != TpmResponseCode::Success {
            Err(TpmError::UnsuccessfulResponse(res.response_code).into())
        } else {
            Ok(res)
        }
    }
}
