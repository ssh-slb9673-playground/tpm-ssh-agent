use crate::tpm::structure::macro_defs::{impl_from_tpm, impl_to_tpm};
use crate::tpm::structure::{Tpm2BDigest, TpmAttrNv, TpmiAlgorithmHash, TpmiHandleNvIndex};
use crate::tpm::{FromTpm, ToTpm, TpmError};
use crate::util::{p16be, u16be};
use crate::TpmResult;

#[derive(Debug)]
pub struct Tpm2BNvPublic {
    pub nv_public: Option<TpmsNvPublic>,
}

#[derive(Debug)]
pub struct TpmsNvPublic {
    pub nv_index: TpmiHandleNvIndex,
    pub algorithm_name: TpmiAlgorithmHash,
    pub attributes: TpmAttrNv,
    pub auth_policy: Tpm2BDigest,
    pub data_size: u16,
}

impl_to_tpm! {
    Tpm2BNvPublic(self) {
        if let Some(public) = &self.nv_public {
            let v = public.to_tpm();
            [p16be(v.len() as u16).to_vec(), v].concat()
        } else {
            vec![]
        }
    }

    TpmsNvPublic(self) {
        [
            self.nv_index.to_tpm(),
            self.algorithm_name.to_tpm(),
            self.attributes.to_tpm(),
            self.auth_policy.to_tpm(),
            self.data_size.to_tpm(),
        ]
        .concat()
    }
}

impl_from_tpm! {
    Tpm2BNvPublic(v) {
        if v.len() < 2 {
            return Err(TpmError::create_parse_error("Length mismatch").into());
        }
        let (len, v) = (u16be(&v[0..2]) as usize, &v[2..]);
        Ok(if len == 0 {
            (Tpm2BNvPublic {
                nv_public: None
            }, v)
        } else {
            let (res, v) = TpmsNvPublic::from_tpm(v)?;
            (Tpm2BNvPublic { nv_public: Some(res) }, v)
        })
    }

    TpmsNvPublic(v) {
        let (nv_index, v) = TpmiHandleNvIndex::from_tpm(v)?;
        let (algorithm_name, v) = TpmiAlgorithmHash::from_tpm(v)?;
        let (attributes, v) = TpmAttrNv::from_tpm(v)?;
        let (auth_policy, v) = Tpm2BDigest::from_tpm(v)?;
        let (data_size, v) = u16::from_tpm(v)?;
        Ok((TpmsNvPublic {
            nv_index,
            algorithm_name,
            attributes,
            auth_policy,
            data_size
        }, v))
    }
}
