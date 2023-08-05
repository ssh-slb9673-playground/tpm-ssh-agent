use crate::tpm::structure::macro_defs::{impl_from_tpm, impl_to_tpm};
use crate::tpm::structure::{
    Tpm2BData, Tpm2BDigest, Tpm2BName, TpmAlgorithmIdentifier, TpmAttrLocality, TpmlPcrSelection,
};
use crate::tpm::{FromTpm, ToTpm, TpmError};
use crate::util::{p16be, u16be};
use crate::TpmResult;

#[derive(Debug)]
pub struct Tpm2BCreationData {
    pub creation_data: Option<TpmsCreationData>,
}

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
    Tpm2BCreationData(self) {
        if let Some(creation_data) = &self.creation_data {
            let v = creation_data.to_tpm();
            [p16be(v.len() as u16).to_vec(), v].concat()
        } else {
            vec![]
        }
    }

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
    Tpm2BCreationData(v) {
        if v.len() < 2 {
            return Err(TpmError::create_parse_error("Length mismatch").into());
        }
        let (len, v) = (u16be(&v[0..2]) as usize, &v[2..]);
        Ok(if len == 0 {
            (Tpm2BCreationData {
                creation_data: None
            }, v)
        } else {
            let (res, v) = TpmsCreationData::from_tpm(v)?;
            (Tpm2BCreationData { creation_data: Some(res) }, v)
        })
    }

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
