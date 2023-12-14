use crate::tpm::structure::macro_defs::{impl_from_tpm, impl_from_tpm_with_selector, impl_to_tpm};
use crate::tpm::structure::{
    TpmAlgorithmIdentifier, TpmAttrAlgorithm, TpmCapabilities, TpmHandle, TpmiAlgorithmHash,
};
use crate::tpm::{FromTpm, FromTpmWithSelector, ToTpm, TpmDataVec, TpmError};
use crate::TpmResult;

#[derive(Debug)]
pub struct TpmsCapabilityData {
    pub capability: TpmCapabilities,
    pub data: TpmuCapabilities,
}

#[derive(Debug)]
pub enum TpmuCapabilities {
    Algorithms(TpmlAlgorithmProperty),
    Handles(TpmlHandle),
}

#[derive(Debug)]
pub struct TpmsAlgorithmProperty {
    pub algorithm: TpmAlgorithmIdentifier,
    pub algorithm_properties: TpmAttrAlgorithm,
}

#[derive(Debug)]
pub struct TpmlAlgorithmProperty {
    pub algorithm_properties: Vec<TpmsAlgorithmProperty>,
}

#[derive(Debug)]
pub struct TpmlHandle {
    pub handle: Vec<TpmHandle>,
}

#[derive(Debug)]
pub struct TpmsPcrSelection {
    pub algorithm_hash: TpmiAlgorithmHash,
    pub pcr_select: Vec<u8>,
}

#[derive(Debug)]
pub struct TpmlPcrSelection {
    pub pcr_selections: Vec<TpmsPcrSelection>,
}

impl_to_tpm! {
    TpmsPcrSelection(self) {
        [
            self.algorithm_hash.to_tpm(),
            vec![self.pcr_select.len() as u8],
            self.pcr_select.to_vec()
        ].concat()
    }

    TpmlPcrSelection(self) {
        [
            (self.pcr_selections.len() as u32).to_tpm(),
            self.pcr_selections.to_tpm()
        ].concat()
    }
}

impl_from_tpm! {
    TpmsCapabilityData(v) {
        let (capability, v) = TpmCapabilities::from_tpm(v)?;
        let (data, v) = TpmuCapabilities::from_tpm(v, &capability)?;
        Ok((TpmsCapabilityData {
            capability,
            data
        }, v))
    }

    TpmsAlgorithmProperty(v) {
        let (algorithm, v) = TpmAlgorithmIdentifier::from_tpm(v)?;
        let (algorithm_properties, v) = TpmAttrAlgorithm::from_tpm(v)?;
        Ok((TpmsAlgorithmProperty {
            algorithm,
            algorithm_properties
        }, v))
    }

    TpmlAlgorithmProperty(_v) {
        let mut v = _v;
        let (count, tmp) = u32::from_tpm(v)?;
        v = tmp;
        let mut algorithm_properties = vec![];
        for _ in 0..count {
            let (prop, tmp) = TpmsAlgorithmProperty::from_tpm(v)?;
            algorithm_properties.push(prop);
            v = tmp;
        }
        Ok((TpmlAlgorithmProperty {
            algorithm_properties
        }, v))
    }

    TpmsPcrSelection(_v) {
        let mut v = _v;
        let (algorithm_hash, tmp) = TpmiAlgorithmHash::from_tpm(v)?;
        v = tmp;
        let (count, tmp) = u8::from_tpm(v)?;
        v = tmp;
        let mut pcr_select = vec![];
        for _ in 0..count {
            let (pcr, tmp) = u8::from_tpm(v)?;
            pcr_select.push(pcr);
            v = tmp;
        }

        Ok((TpmsPcrSelection {
            algorithm_hash,
            pcr_select
        }, v))
    }

    TpmlPcrSelection(_v) {
        let mut v = _v;
        let (count, tmp) = u32::from_tpm(v)?;
        v = tmp;
        let mut pcr_selections = vec![];
        for _ in 0..count {
            let (pcr, tmp) = TpmsPcrSelection::from_tpm(v)?;
            pcr_selections.push(pcr);
            v = tmp;
        }

        Ok((TpmlPcrSelection {
            pcr_selections
        }, v))
    }

    TpmlHandle(_v) {
        let mut v = _v;
        let (count, tmp) = u32::from_tpm(v)?;
        v = tmp;
        let mut handle = vec![];
        for _ in 0..count {
            let (prop, tmp) = TpmHandle::from_tpm(v)?;
            handle.push(prop);
            v = tmp;
        }
        Ok((TpmlHandle {
           handle
        }, v))
    }
}

impl_from_tpm_with_selector! {
    TpmuCapabilities<TpmCapabilities>(v, selector) {
        Ok(match selector {
            TpmCapabilities::Algs => {
                let (list, v) = TpmlAlgorithmProperty::from_tpm(v)?;
                (TpmuCapabilities::Algorithms(list), v)
            },
            TpmCapabilities::Handles => {
                let (list, v) = TpmlHandle::from_tpm(v)?;
                (TpmuCapabilities::Handles(list), v)
            },
            _ => {
                dbg!(&v);
                return Err(TpmError::create_parse_error(
                    &format!("invalid value specified: {:?}", selector)
                ).into());
            }
        })
    }
}
