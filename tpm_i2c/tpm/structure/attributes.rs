use crate::tpm::structure::macro_defs::{impl_from_tpm, impl_to_tpm};
use crate::tpm::{FromTpm, ToTpm, TpmError};
use crate::util::{p32be, u32be};
use crate::TpmResult;
use bitfield_struct::bitfield;
use serde::{Deserialize, Serialize};

#[bitfield(u8)]
pub struct TpmAttrLocality {
    pub tpm_loc_zero: bool,
    pub tpm_loc_one: bool,
    pub tpm_loc_two: bool,
    pub tpm_loc_three: bool,
    pub tpm_loc_four: bool,
    #[bits(3)]
    pub extended: u8,
}

#[bitfield(u8)]
#[derive(Deserialize, Serialize)]
pub struct TpmAttrSession {
    pub continue_session: bool,
    pub audit_exclusive: bool,
    pub audit_reset: bool,
    #[bits(2)]
    _reserved: u8,
    pub decrypt: bool,
    pub encrypt: bool,
    pub audit: bool,
}

#[bitfield(u32)]
pub struct TpmAttrAlgorithm {
    pub asymmetric: bool,
    pub symmetric: bool,
    pub hash: bool,
    pub object: bool,
    #[bits(4)]
    _reserved_1: u8,
    pub signing: bool,
    pub encrypting: bool,
    pub method: bool,
    #[bits(21)]
    _reserved_2: u32,
}

#[bitfield(u32)]
pub struct TpmAttrObject {
    _reserved_1: bool,
    pub fixed_tpm: bool,
    pub st_clear: bool,
    _reserved_2: bool,
    pub fixed_parent: bool,
    pub sensitive_data_origin: bool,
    pub user_with_auth: bool,
    pub admin_with_policy: bool,
    #[bits(2)]
    _reserved_3: u8,
    pub no_dictionary_attack: bool,
    pub encrypted_duplication: bool,
    #[bits(4)]
    _reserved_4: u8,
    pub restricted: bool,
    pub decrypt: bool,
    pub sign_or_encrypt: bool,
    pub x509_sign: bool,
    #[bits(12)]
    _reserved_5: u16,
}

#[bitfield(u32)]
pub struct TpmAttrNv {
    pub nv_platform_write: bool,
    pub nv_owner_write: bool,
    pub nv_auth_write: bool,
    pub nv_policy_write: bool,
    #[bits(4)]
    pub nv_index_type: u8,
    #[bits(2)]
    _reserved_1: u8,
    pub nv_policy_delete: bool,
    pub nv_write_locked: bool,
    pub nv_write_all: bool,
    pub nv_write_define: bool,
    pub nv_write_stclear: bool,
    pub nv_global_lock: bool,
    pub nv_platform_read: bool,
    pub nv_owner_read: bool,
    pub nv_auth_read: bool,
    pub nv_policy_read: bool,
    #[bits(5)]
    _reserved_2: u8,
    pub nv_no_da: bool,
    pub nv_orderly: bool,
    pub nv_clear_stclear: bool,
    pub nv_read_locked: bool,
    pub nv_written: bool,
    pub nv_platform_create: bool,
    pub nv_read_stclear: bool,
}

impl_to_tpm! {
    TpmAttrLocality(self) {
        vec![self.0]
    }

    TpmAttrSession(self) {
        vec![self.0]
    }

    TpmAttrAlgorithm(self) {
        p32be(self.0).to_vec()
    }

    TpmAttrObject(self) {
        p32be(self.0).to_vec()
    }

    TpmAttrNv(self) {
        p32be(self.0).to_vec()
    }
}

impl_from_tpm! {
    TpmAttrLocality(v) {
        if v.is_empty() {
            Err(TpmError::create_parse_error("length mismatch").into())
        } else {
            Ok((TpmAttrLocality::from(v[0]), &v[1..]))
        }
    }

    TpmAttrSession(v) {
        if v.is_empty() {
            Err(TpmError::create_parse_error("length mismatch").into())
        } else {
            Ok((TpmAttrSession::from(v[0]), &v[1..]))
        }
    }

    TpmAttrAlgorithm(v) {
        if v.is_empty() {
            Err(TpmError::create_parse_error("length mismatch").into())
        } else {
            Ok((TpmAttrAlgorithm::from(u32be(&v[0..4])), &v[4..]))
        }
    }

    TpmAttrObject(v) {
        if v.is_empty() {
            Err(TpmError::create_parse_error("length mismatch").into())
        } else {
            Ok((TpmAttrObject::from(u32be(&v[0..4])), &v[4..]))
        }
    }

    TpmAttrNv(v) {
        if v.is_empty() {
            Err(TpmError::create_parse_error("length mismatch").into())
        } else {
            Ok((TpmAttrNv::from(u32be(&v[0..4])), &v[4..]))
        }
    }
}
