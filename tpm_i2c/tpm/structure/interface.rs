use crate::tpm::structure::macro_defs::{impl_from_tpm, impl_to_tpm, set_tpm_data_codec};
use crate::tpm::structure::{
    pack_enum_to_u8, unpack_u8_to_enum, TpmHandle, TpmHandleConstants, TpmPermanentHandle,
};
use crate::tpm::{FromTpm, ToTpm, TpmError};
use crate::TpmResult;
use num_derive::{FromPrimitive, ToPrimitive};
use num_traits::cast::FromPrimitive;
use serde::{Deserialize, Serialize};

#[derive(FromPrimitive, ToPrimitive, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum TpmiYesNo {
    No = 0,
    Yes = 1,
}

#[derive(Debug, PartialEq, Eq, Clone, Deserialize, Serialize)]
pub enum TpmiDhObject {
    Transient(TpmHandle),
    Persistent(TpmHandle),
    Null,
}

#[derive(Debug, PartialEq, Eq, Clone, Deserialize, Serialize)]
pub enum TpmiDhEntity {
    Transient(TpmHandle),
    Persistent(TpmHandle),
    NvIndex(TpmHandle),
    Pcr(TpmHandle),
    VendorSpecific(TpmHandle),
    Owner,
    Endorsement,
    Platform,
    Lockout,
    Null,
}

#[derive(Debug)]
pub enum TpmiHandleHierarchy {
    Owner,
    Endorsement,
    Platform,
    Null,
}

#[derive(Debug, Clone)]
pub enum TpmiHandleNvAuth {
    Owner,
    Platform,
    NvIndex(TpmHandle),
}

#[derive(Debug, Clone)]
pub enum TpmiHandleNvIndex {
    NvIndex(TpmHandle),
}

set_tpm_data_codec!(TpmiYesNo, pack_enum_to_u8, unpack_u8_to_enum);

impl From<&TpmiDhObject> for TpmHandle {
    fn from(other: &TpmiDhObject) -> TpmHandle {
        match other {
            TpmiDhObject::Transient(v) => *v,
            TpmiDhObject::Persistent(v) => *v,
            TpmiDhObject::Null => TpmPermanentHandle::Null.into(),
        }
    }
}

impl From<&TpmiHandleHierarchy> for TpmHandle {
    fn from(other: &TpmiHandleHierarchy) -> TpmHandle {
        match other {
            TpmiHandleHierarchy::Owner => TpmPermanentHandle::Owner,
            TpmiHandleHierarchy::Endorsement => TpmPermanentHandle::Endorsement,
            TpmiHandleHierarchy::Platform => TpmPermanentHandle::Platform,
            TpmiHandleHierarchy::Null => TpmPermanentHandle::Null,
        }
        .into()
    }
}

impl From<&TpmiHandleNvAuth> for TpmHandle {
    fn from(other: &TpmiHandleNvAuth) -> TpmHandle {
        match other {
            TpmiHandleNvAuth::Owner => TpmPermanentHandle::Owner.into(),
            TpmiHandleNvAuth::Platform => TpmPermanentHandle::Platform.into(),
            TpmiHandleNvAuth::NvIndex(index) => *index,
        }
    }
}

impl From<&TpmiHandleNvIndex> for TpmHandle {
    fn from(other: &TpmiHandleNvIndex) -> TpmHandle {
        match other {
            TpmiHandleNvIndex::NvIndex(index) => *index,
        }
    }
}

impl From<&TpmiDhEntity> for TpmHandle {
    fn from(other: &TpmiDhEntity) -> TpmHandle {
        match other {
            TpmiDhEntity::Transient(v) => *v,
            TpmiDhEntity::Persistent(v) => *v,
            TpmiDhEntity::NvIndex(v) => *v,
            TpmiDhEntity::Pcr(v) => *v,
            TpmiDhEntity::VendorSpecific(v) => *v,
            TpmiDhEntity::Owner => TpmPermanentHandle::Owner.into(),
            TpmiDhEntity::Endorsement => TpmPermanentHandle::Endorsement.into(),
            TpmiDhEntity::Platform => TpmPermanentHandle::Platform.into(),
            TpmiDhEntity::Lockout => TpmPermanentHandle::Lockout.into(),
            TpmiDhEntity::Null => TpmPermanentHandle::Null.into(),
        }
    }
}

impl From<TpmPermanentHandle> for TpmHandle {
    fn from(handle: TpmPermanentHandle) -> TpmHandle {
        handle as TpmHandle
    }
}

impl_to_tpm! {
    TpmiHandleHierarchy(self) {
        let handle: TpmHandle = self.into();
        handle.to_tpm()
    }

    TpmiDhObject(self) {
        let handle: TpmHandle = self.into();
        handle.to_tpm()
    }

    TpmiHandleNvAuth(self) {
        let handle: TpmHandle = self.into();
        handle.to_tpm()
    }
    TpmiHandleNvIndex(self) {
        let handle: TpmHandle = self.into();
        handle.to_tpm()
    }
}

impl_from_tpm! {
    TpmiHandleHierarchy(v) {
        let (handle, v) = TpmHandle::from_tpm(v)?;
        Ok((
            if let Some(t) = TpmPermanentHandle::from_u32(handle) {
                match t {
                    TpmPermanentHandle::Owner => TpmiHandleHierarchy::Owner,
                    TpmPermanentHandle::Endorsement => TpmiHandleHierarchy::Endorsement,
                    TpmPermanentHandle::Platform => TpmiHandleHierarchy::Platform,
                    TpmPermanentHandle::Null => TpmiHandleHierarchy::Null,
                    x => {
                        return Err(TpmError::create_parse_error(&format!(
                            "invalid handle specified: {:?}",
                            x
                        ))
                        .into());
                    }
                }
            } else {
                return Err(TpmError::create_parse_error(&format!(
                    "invalid value specified: {:?}",
                    handle
                ))
                .into());
            },
            v,
        ))
    }

    TpmiDhObject(v) {
        let (handle, v) = TpmHandle::from_tpm(v)?;
        Ok((
            if let Some(t) = TpmPermanentHandle::from_u32(handle) {
                match t {
                    TpmPermanentHandle::Null => TpmiDhObject::Null,
                    x => {
                        return Err(TpmError::create_parse_error(&format!(
                            "invalid handle specified: {:?}",
                            x
                        ))
                        .into());
                    }
                }
            } else if TpmHandleConstants::TransientFirst as u32 <= handle
                && handle <= TpmHandleConstants::TransientLast as u32
            {
                TpmiDhObject::Transient(handle)
            } else if TpmHandleConstants::PersistentFirst as u32 <= handle
                && handle <= TpmHandleConstants::PersistentLast as u32
            {
                TpmiDhObject::Persistent(handle)
            } else {
                return Err(TpmError::create_parse_error(&format!(
                    "invalid handle specified: {}",
                    handle
                ))
                .into());
            },
            v,
        ))
    }

    TpmiHandleNvAuth(v) {
        let (handle, v) = TpmHandle::from_tpm(v)?;
        Ok((
            if let Some(t) = TpmPermanentHandle::from_u32(handle) {
                match t {
                    TpmPermanentHandle::Owner => TpmiHandleNvAuth::Owner,
                    TpmPermanentHandle::Platform => TpmiHandleNvAuth::Platform,
                    x => {
                        return Err(TpmError::create_parse_error(&format!(
                            "invalid handle specified: {:?}",
                            x
                        )).into())
                    }
                }
            } else if TpmHandleConstants::NvIndexFirst as u32 <= handle
                && handle <= TpmHandleConstants::NvIndexLast as u32 {
                TpmiHandleNvAuth::NvIndex(handle)
            } else {
                return Err(TpmError::create_parse_error(&format!(
                    "invalid handle specified: {}",
                    handle
                ))
                .into());
            }
        ,v
        ))
    }

    TpmiHandleNvIndex(v) {
        let (handle, v) = TpmHandle::from_tpm(v)?;
        Ok((
            if TpmHandleConstants::NvIndexFirst as u32 <= handle
                && handle <= TpmHandleConstants::NvIndexLast as u32 {
                TpmiHandleNvIndex::NvIndex(handle)
            } else {
                return Err(TpmError::create_parse_error(&format!(
                    "invalid handle specified: {}",
                    handle
                ))
                .into());
            }
        ,v
        ))
    }
}
