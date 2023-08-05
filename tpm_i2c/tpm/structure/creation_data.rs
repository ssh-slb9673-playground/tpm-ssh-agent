use crate::tpm::structure::macro_defs::{impl_from_tpm, impl_to_tpm};
use crate::tpm::structure::{
    Tpm2BData, Tpm2BDigest, Tpm2BName, TpmAlgorithmIdentifier, TpmAttrLocality, TpmlPcrSelection,
};
use crate::tpm::{FromTpm, ToTpm};
use crate::TpmResult;

#[derive(Debug)]
pub struct TpmsCreationData {
    pcr_select: TpmlPcrSelection,
    pcr_digest: Tpm2BDigest,
    locality: TpmAttrLocality,
    parent_name_algorithm: TpmAlgorithmIdentifier,
    parent_name: Tpm2BName,
    parent_qualified_name: Tpm2BName,
    outside_info: Tpm2BData,
}

impl_to_tpm! {
    TpmsCreationData(self) {
        [
            self.pcr_select.to_tpm(),
            self.pcr_digest.to_tpm(),
            self.locality.to_tpm(),
            self.parent_name_algorithm.to_tpm(),
            self.parent_name.to_tpm(),
            self.parent_qualified_name.to_tpm(),
            self.outside_info.to_tpm()
        ].concat()
    }
}

impl_from_tpm! {
    TpmsCreationData(v) {
        let (pcr_select, v) = TpmlPcrSelection::from_tpm(v)?;
        let (pcr_digest, v) = Tpm2BDigest::from_tpm(v)?;
        let (locality, v) = TpmAttrLocality::from_tpm(v)?;
        let (parent_name_algorithm, v) = TpmAlgorithmIdentifier::from_tpm(v)?;
        let (parent_name, v) = Tpm2BName::from_tpm(v)?;
        let (parent_qualified_name, v) = Tpm2BName::from_tpm(v)?;
        let (outside_info, v) = Tpm2BData::from_tpm(v)?;
        Ok((TpmsCreationData {
            pcr_select,
            pcr_digest,
            locality,
            parent_name_algorithm,
            parent_name,
            parent_qualified_name,
            outside_info
        }, v))
    }
}
