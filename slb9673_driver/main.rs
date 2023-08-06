mod driver;
mod saved_state;
use saved_state::State;
use std::path::Path;
use tpm_i2c::tpm::session::TpmSession;
use tpm_i2c::tpm::structure::*;
use tpm_i2c::tpm::{I2CTpmAccessor, Tpm};

type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    IoError(std::io::Error),
    TpmError(tpm_i2c::Error),
    JsonError(serde_json::Error),
}

macro_rules! error_wrapping_arm {
    ($et:ty, $arm:ident) => {
        impl std::convert::From<$et> for Error {
            fn from(err: $et) -> Self {
                Error::$arm(err)
            }
        }
    };
}

error_wrapping_arm!(std::io::Error, IoError);
error_wrapping_arm!(tpm_i2c::Error, TpmError);
error_wrapping_arm!(serde_json::Error, JsonError);

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match &self {
            Error::IoError(e) => write!(f, "{}", e),
            Error::TpmError(e) => write!(f, "{}", e),
            Error::JsonError(e) => write!(f, "{}", e),
        }
    }
}

impl std::error::Error for Error {}

fn remove_handles<T: I2CTpmAccessor>(tpm: &mut Tpm<T>, ht: TpmHandleType) -> Result<()> {
    use tpm_i2c::tpm::structure::*;
    if let TpmuCapabilities::Handles(x) = &tpm
        .get_capability(TpmCapabilities::Handles, (ht as u32) << 24, 5)?
        .1
        .data
    {
        for handle in &x.handle {
            println!("[+] Flush 0x{:08x}", handle);
            let _ = &tpm.flush_context(*handle);
        }
    }
    Ok(())
}

fn get_rsa_public_template(bits: u16, symmetric: TpmtSymdefObject) -> TpmuPublicParams {
    TpmuPublicParams::RsaDetail(TpmsRsaParams {
        symmetric,
        scheme: TpmtRsaScheme {
            scheme: TpmiAlgorithmRsaScheme::RsaEs,
            details: TpmuAsymmetricScheme::Encryption(TpmsEncryptionScheme::AE(TpmsEmpty::new())),
        },
        key_bits: bits,
        exponent: 65537,
    })
}

fn get_aes_symdefobj() -> TpmtSymdefObject {
    TpmtSymdefObject {
        algorithm: TpmiAlgorithmSymObject::Aes,
        key_bits: TpmuSymKeybits::SymmetricAlgo(128),
        mode: TpmuSymMode::SymmetricAlgo(TpmiAlgorithmSymMode::CFB),
    }
}

fn get_null_symdefobj() -> TpmtSymdefObject {
    TpmtSymdefObject {
        algorithm: TpmiAlgorithmSymObject::Null,
        key_bits: TpmuSymKeybits::Null,
        mode: TpmuSymMode::Null,
    }
}

fn create_primary_key<T: I2CTpmAccessor>(
    tpm: &mut Tpm<T>,
    session: &mut TpmSession,
    auth_value: &[u8],
) -> Result<tpm_i2c::tpm::commands::Tpm2CreatePrimaryResponse> {
    tpm.create_primary(
        TpmPermanentHandle::Platform.into(),
        session,
        Tpm2BSensitiveCreate {
            sensitive: TpmsSensitiveCreate {
                user_auth: Tpm2BAuth::new(auth_value),
                data: Tpm2BSensitiveData::new(&[]),
            },
        },
        Tpm2BPublic::new(TpmtPublic {
            algorithm_type: TpmiAlgorithmPublic::Rsa,
            algorithm_name: TpmiAlgorithmHash::Sha256,
            object_attributes: TpmAttrObject::new()
                .with_fixed_tpm(true)
                .with_fixed_parent(true)
                .with_sensitive_data_origin(true)
                .with_no_dictionary_attack(true)
                .with_decrypt(true)
                .with_user_with_auth(true),
            auth_policy: Tpm2BDigest::new(&[]),
            parameters: get_rsa_public_template(2048, get_null_symdefobj()),
            unique: TpmuPublicIdentifier::Rsa(Tpm2BDigest::new(&[])),
        }),
        Tpm2BData::new(&[]),
        TpmlPcrSelection {
            pcr_selections: vec![],
        },
    )
    .map_err(|err| err.into())
}

fn create_session<T: tpm_i2c::tpm::I2CTpmAccessor>(
    tpm: &mut Tpm<T>,
    first_nonce: &[u8],
) -> Result<TpmSession> {
    tpm.start_auth_session(
        TpmiDhObject::Null,
        TpmiDhEntity::Null,
        Tpm2BNonce::new(first_nonce),
        Tpm2BEncryptedSecret::new(&[]),
        TpmSessionType::Hmac,
        TpmtSymdef {
            algorithm: TpmiAlgorithmSymmetric::Null,
            key_bits: TpmuSymKeybits::Null,
            mode: TpmuSymMode::Null,
        },
        TpmiAlgorithmHash::Sha256,
    )
    .map_err(|err| err.into())
}

#[allow(unused_must_use)]
fn main() -> Result<()> {
    let state_file_path = Path::new("state.json");

    let mut device = driver::hidapi::MCP2221A::new(0x2e)?;
    let mut tpm = Tpm::new(&mut device)?;
    tpm.init(false)?;

    tpm.print_info()?;

    let mut state = match State::load(state_file_path)? {
        Some(x) => x,
        None => {
            println!("Reset && create states");
            remove_handles(&mut tpm, TpmHandleType::HmacOrLoadedSession)?;
            remove_handles(&mut tpm, TpmHandleType::Transient)?;
            let session = create_session(&mut tpm, &[0; 16])?;
            State {
                session,
                primary_handle: None,
            }
        }
    };

    println!("Key handle: {:08x}", state.session.handle);

    if state.primary_handle.is_none() {
        let res = create_primary_key(&mut tpm, &mut state.session, "password".as_bytes())?;
        state.primary_handle = Some(res.handle);
    }

    println!("state: {:?}", &state);

    state.save(state_file_path)?;

    tpm.shutdown(false)?;

    Ok(())
}
