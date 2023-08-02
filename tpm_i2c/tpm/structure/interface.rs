use crate::tpm::structure::macro_defs::set_tpm_data_codec;
use crate::tpm::structure::{
    pack_enum_to_u8, unpack_u8_to_enum, TpmHandle, TpmHandleConstants, TpmPermanentHandle,
};
use crate::tpm::{TpmData, TpmError};
use crate::TpmResult;
use num_derive::{FromPrimitive, ToPrimitive};
use num_traits::cast::FromPrimitive;

#[derive(FromPrimitive, ToPrimitive, Debug)]
#[repr(u8)]
pub enum TpmiYesNo {
    No = 0,
    Yes = 1,
}

#[derive(Debug, PartialEq, Eq)]
pub enum TpmiDhObject {
    Transient(TpmHandle),
    Persistent(TpmHandle),
    Null,
}

#[derive(Debug)]
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

impl TpmData for TpmiHandleHierarchy {
    fn to_tpm(&self) -> Vec<u8> {
        let handle: TpmHandle = self.into();
        handle.to_tpm()
    }

    fn from_tpm(v: &[u8]) -> TpmResult<(Self, &[u8])> {
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
}

impl TpmData for TpmiDhObject {
    fn to_tpm(&self) -> Vec<u8> {
        let handle: TpmHandle = self.into();
        handle.to_tpm()
    }

    fn from_tpm(v: &[u8]) -> TpmResult<(Self, &[u8])> {
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
}

impl From<TpmPermanentHandle> for TpmHandle {
    fn from(handle: TpmPermanentHandle) -> TpmHandle {
        handle as TpmHandle
    }
}