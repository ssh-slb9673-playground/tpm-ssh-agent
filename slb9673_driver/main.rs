mod driver;
mod state;
use rand::prelude::*;
use ssh_key::public::{KeyData, RsaPublicKey};
use ssh_key::{MPInt, PublicKey};
use state::State;
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
    SshKeyError(ssh_key::Error),
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
error_wrapping_arm!(ssh_key::Error, SshKeyError);

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match &self {
            Error::IoError(e) => write!(f, "{}", e),
            Error::TpmError(e) => write!(f, "{}", e),
            Error::JsonError(e) => write!(f, "{}", e),
            Error::SshKeyError(e) => write!(f, "{}", e),
        }
    }
}

impl std::error::Error for Error {}

fn get_rsa_public_template(bits: u16, symmetric: TpmtSymdefObject) -> TpmuPublicParams {
    TpmuPublicParams::RsaDetail(TpmsRsaParams {
        symmetric,
        scheme: TpmtRsaScheme {
            scheme: TpmiAlgorithmRsaScheme::RsaPss,
            details: TpmuAsymmetricScheme::Signature(TpmsSignatureScheme::AX(TpmsSchemeHash {
                hash_algorithm: TpmiAlgorithmHash::Sha256,
            })),
        },
        key_bits: bits,
        exponent: 65537,
    })
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
        TpmPermanentHandle::Owner.into(),
        session,
        vec![],
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
                .with_sign_or_encrypt(true)
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
        vec![],
    )
    .map_or_else(
        |err| Err(err.into()),
        |mut x| {
            x.attributes.set_continue_session(true);
            Ok(x)
        },
    )
}

struct TpmSshAgent<'a, T: I2CTpmAccessor> {
    pub state_file_path: &'a Path,
    pub tpm: Tpm<'a, T>,
    pub state: State,
}

fn next_nonce() -> [u8; 16] {
    let mut rng = rand::thread_rng();
    let mut ret = [0u8; 16];
    rng.fill_bytes(&mut ret);
    ret
}

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

impl<'a, T: I2CTpmAccessor> TpmSshAgent<'a, T> {
    pub fn new(state_file_path: &'a Path, device: &'a mut T) -> Result<TpmSshAgent<'a, T>> {
        let mut tpm = Tpm::new(device)?;
        tpm.init(false)?;
        let state = State::load(state_file_path)?.map_or_else(
            || -> Result<State> {
                println!("Reset && create states");
                remove_handles(&mut tpm, TpmHandleType::HmacOrLoadedSession)?;
                remove_handles(&mut tpm, TpmHandleType::Transient)?;
                let session = create_session(&mut tpm, &next_nonce())?;
                Ok(State {
                    session,
                    primary_handle: None,
                })
            },
            Ok,
        )?;

        tpm.print_info()?;

        Ok(TpmSshAgent {
            state_file_path,
            tpm,
            state,
        })
    }

    pub fn sign(&mut self, msg: &[u8]) -> Result<Vec<u8>> {
        let digest = self.state.session.algorithm.digest(msg);
        let sig = self.tpm.sign(
            self.state.primary_handle.unwrap(),
            &mut self.state.session,
            "password".as_bytes().to_vec(),
            &digest,
            TpmtSignatureScheme {
                scheme: TpmiAlgorithmSigScheme::RsaPss,
                details: TpmsSignatureScheme::AX(TpmsSchemeHash {
                    hash_algorithm: TpmiAlgorithmHash::Sha256,
                }),
            },
            TpmtTicketHashCheck {
                tag: TpmStructureTag::HashCheck,
                hierarchy: TpmiHandleHierarchy::Owner,
                digest: Tpm2BDigest::new(&[]),
            },
        )?;

        Ok(match sig.details {
            TpmuSignature::Rsa(x) => x.signature.buffer,
            _ => todo!(),
        })
    }

    pub fn close(&mut self) -> Result<()> {
        self.state.save(self.state_file_path)?;
        self.tpm.shutdown(false)?;
        Ok(())
    }
}

#[allow(unused_must_use)]
fn main() -> Result<()> {
    let state_file_path = Path::new("state.json");
    let mut device = driver::hidapi::MCP2221A::new(0x2e)?;
    let mut agent = TpmSshAgent::new(state_file_path, &mut device)?;

    println!("session handle: {:08x}", agent.state.session.handle);

    if agent.state.primary_handle.is_none() {
        agent.state.session.set_nonce(next_nonce().to_vec());
        let res = create_primary_key(
            &mut agent.tpm,
            &mut agent.state.session,
            "password".as_bytes(),
        )?;
        agent.state.primary_handle = Some(res.handle);
    }
    println!("state: {:?}", &agent.state);

    agent.state.session.set_nonce(next_nonce().to_vec());
    // let signature = sign(&mut tpm, &mut state, "hello world".as_bytes())?;

    let public_data = agent.tpm.read_public(agent.state.primary_handle.unwrap())?;
    if let Some(x) = public_data.0.public_area {
        if let TpmuPublicIdentifier::Rsa(y) = x.unique {
            let pubkey = PublicKey::new(
                KeyData::Rsa(RsaPublicKey {
                    e: MPInt::from_bytes(&[0x1, 0x00, 0x01])?,
                    n: MPInt::from_bytes(&y.buffer)?,
                }),
                "",
            );
            println!("[+] Public key: {}", pubkey.to_openssh()?);
        }
    }

    agent.close()?;

    Ok(())
}
