use crate::tpm::structure::macro_defs::{impl_from_tpm, impl_from_tpm_with_selector};
use crate::tpm::structure::{TpmAlgorithmIdentifier, TpmAttrAlgorithm, TpmCapabilities};
use crate::tpm::{FromTpm, FromTpmWithSelector, TpmError};
use crate::TpmResult;

#[derive(Debug)]
pub struct TpmsCapabilityData {
    pub capability: TpmCapabilities,
    pub data: TpmuCapabilities,
}

#[derive(Debug)]
pub enum TpmuCapabilities {
    Algorithms(TpmlAlgorithmProperty),
}

#[derive(Debug)]
pub struct TpmsAlgorithmProperty {
    pub algorithm: TpmAlgorithmIdentifier,
    pub algorithm_properties: TpmAttrAlgorithm,
}

#[derive(Debug)]
pub struct TpmlAlgorithmProperty {
    pub count: u32,
    pub algorithm_properties: Vec<TpmsAlgorithmProperty>,
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
        let (count, _v) = u32::from_tpm(_v)?;
        let mut algorithm_properties= vec![];
        for _ in 0..count {
            let (prop, _v) = TpmsAlgorithmProperty::from_tpm(_v)?;
            algorithm_properties.push(prop);
        }
        Ok((TpmlAlgorithmProperty {
            count,
            algorithm_properties
        }, _v))
    }
}

impl_from_tpm_with_selector! {
    TpmuCapabilities<TpmCapabilities>(v, selector) {
        Ok(match selector {
            TpmCapabilities::Algs => {
                let (list, v) = TpmlAlgorithmProperty::from_tpm(v)?;
                (TpmuCapabilities::Algorithms(list), v)
            },
            _ => {
                return Err(TpmError::create_parse_error(
                    &format!("invalid value specified: {:?}", selector)
                ).into());
            }
        })
    }
}
