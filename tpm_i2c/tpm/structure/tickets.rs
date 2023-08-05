use crate::tpm::structure::macro_defs::{impl_from_tpm, impl_to_tpm};
use crate::tpm::structure::{Tpm2BDigest, TpmStructureTag, TpmiHandleHierarchy};
use crate::tpm::{FromTpm, ToTpm};
use crate::TpmResult;

#[derive(Debug)]
pub struct TpmtTicketCreation {
    pub tag: TpmStructureTag,
    pub hierarchy: TpmiHandleHierarchy,
    pub digest: Tpm2BDigest,
}

impl_from_tpm! {
    TpmtTicketCreation(v) {
        let (tag, v) = TpmStructureTag::from_tpm(v)?;
        let (hierarchy, v) = TpmiHandleHierarchy::from_tpm(v)?;
        let (digest, v) = Tpm2BDigest::from_tpm(v)?;
        Ok((TpmtTicketCreation {
            tag,
            hierarchy,
            digest,
        }, v))
    }
}

impl_to_tpm! {
    TpmtTicketCreation(self) {
        [
            self.tag.to_tpm(),
            self.hierarchy.to_tpm(),
            self.digest.to_tpm(),
        ].concat()
    }
}
