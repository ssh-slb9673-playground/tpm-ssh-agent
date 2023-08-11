use crate::state::State;
use crate::Result;
use rand::prelude::*;
use std::path::PathBuf;
use tpm_i2c::tpm::structure::*;
use tpm_i2c::tpm::{I2CTpmAccessor, Tpm};

#[derive(Debug)]
pub struct RsaPublicKey {
    pub e: Vec<u8>,
    pub n: Vec<u8>,
}

#[derive(Debug)]
pub struct EcDsaPublicKey {
    pub x: Vec<u8>,
    pub y: Vec<u8>,
}

pub struct TpmKeyManager {
    state_file_path: PathBuf,
    tpm: Tpm,
    state: State,
    pub identities: Vec<EcDsaPublicKey>,
}

fn next_nonce() -> [u8; 16] {
    let mut rng = rand::thread_rng();
    let mut ret = [0u8; 16];
    rng.fill_bytes(&mut ret);
    ret
}

impl TpmKeyManager {
    pub fn new(state_file_path: PathBuf, device: Box<dyn I2CTpmAccessor>) -> Result<TpmKeyManager> {
        let mut tpm = Tpm::new(device)?;
        if let Err(tpm_i2c::Error::TpmError(tpm_i2c::tpm::TpmError::UnsuccessfulResponse(
            TpmResponseCode::ErrorForParam((_, TpmResponseCodeFormat1::Value)),
        ))) = tpm.init(false)
        {
            println!("[*] Startup without all data");
            tpm.init(true)?;
        }

        let state = State::load(&state_file_path)?.map_or_else(
            || -> Result<State> {
                TpmKeyManager::remove_handles(&mut tpm, TpmHandleType::HmacOrLoadedSession)?;
                TpmKeyManager::remove_handles(&mut tpm, TpmHandleType::Transient)?;
                Ok(State {
                    session: None,
                    primary_handle: None,
                })
            },
            Ok,
        )?;

        tpm.print_info()?;

        Ok(TpmKeyManager {
            state_file_path,
            tpm,
            state,
            identities: vec![],
        })
    }

    pub fn setup(&mut self) -> Result<()> {
        self.open_session()?;
        if self.state.primary_handle.is_none() {
            let res = self.create_primary_key("password".as_bytes())?;
            self.state.primary_handle = Some(res.handle);
        }

        self.enumerate_identities()?;

        Ok(())
    }

    pub fn close(&mut self) -> Result<()> {
        if let Some(session) = self.state.session.take() {
            self.tpm.flush_context(session.handle)?;
        }
        self.state.save(&self.state_file_path)?;
        self.tpm.shutdown(false)?;
        Ok(())
    }

    fn remove_handles(tpm: &mut Tpm, ht: TpmHandleType) -> Result<()> {
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

    fn create_primary_key(
        &mut self,
        auth_value: &[u8],
    ) -> Result<tpm_i2c::tpm::commands::Tpm2CreatePrimaryResponse> {
        self.tpm
            .create_primary(
                TpmPermanentHandle::Owner.into(),
                self.state.session.as_mut().unwrap(),
                vec![],
                Tpm2BSensitiveCreate {
                    sensitive: TpmsSensitiveCreate {
                        user_auth: Tpm2BAuth::new(auth_value),
                        data: Tpm2BSensitiveData::new(&[]),
                    },
                },
                Tpm2BPublic::new(TpmtPublic {
                    algorithm_type: TpmiAlgorithmPublic::Ecc,
                    algorithm_name: TpmiAlgorithmHash::Sha256,
                    object_attributes: TpmAttrObject::new()
                        .with_fixed_tpm(true)
                        .with_fixed_parent(true)
                        .with_sensitive_data_origin(true)
                        .with_sign_or_encrypt(true)
                        .with_user_with_auth(true),
                    auth_policy: Tpm2BDigest::new(&[]),
                    parameters: TpmuPublicParams::EccDetail(TpmsEccParams {
                        symmetric: TpmtSymdefObject {
                            algorithm: TpmiAlgorithmSymObject::Null,
                            key_bits: TpmuSymKeybits::Null,
                            mode: TpmuSymMode::Null,
                        },
                        scheme: TpmtEccScheme {
                            scheme: TpmiAlgorithmEccScheme::EcDsa,
                            details: TpmuAsymmetricScheme::Signature(TpmsSignatureScheme::AX(
                                TpmsSchemeHash {
                                    hash_algorithm: TpmiAlgorithmHash::Sha256,
                                },
                            )),
                        },
                        curve_id: TpmEccCurve::NistP256,
                        kdf: TpmtKdfScheme {
                            scheme: TpmiAlgorithmKdf::Null,
                            details: TpmuKdfScheme::Null,
                        },
                    }),
                    unique: TpmuPublicIdentifier::Ecc(TpmsEccPoint {
                        x: Tpm2BDigest::new(&[]),
                        y: Tpm2BDigest::new(&[]),
                    }),
                }),
                Tpm2BData::new(&[]),
                TpmlPcrSelection {
                    pcr_selections: vec![],
                },
            )
            .map_err(|err| err.into())
    }

    fn open_session(&mut self) -> Result<()> {
        let mut session = self.tpm.start_auth_session(
            TpmiDhObject::Null,
            TpmiDhEntity::Null,
            Tpm2BNonce::new(&next_nonce()),
            Tpm2BEncryptedSecret::new(&[]),
            TpmSessionType::Hmac,
            TpmtSymdef {
                algorithm: TpmiAlgorithmSymmetric::Null,
                key_bits: TpmuSymKeybits::Null,
                mode: TpmuSymMode::Null,
            },
            TpmiAlgorithmHash::Sha256,
            vec![],
        )?;
        session.attributes.set_continue_session(true);

        self.state.session = Some(session);
        Ok(())
    }

    pub fn sign(&mut self, msg: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        let digest = TpmiAlgorithmHash::Sha256.digest(msg);
        let sig = self.tpm.sign(
            self.state.primary_handle.unwrap(),
            self.state.session.as_mut().unwrap(),
            "password".as_bytes().to_vec(),
            &digest,
            TpmtSignatureScheme {
                scheme: TpmiAlgorithmSigScheme::EcDsa,
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
            TpmuSignature::Ecc(x) => (x.signature_r.buffer, x.signature_s.buffer),
            _ => todo!(),
        })
    }

    pub fn enumerate_identities(&mut self) -> Result<()> {
        let public_data = self.tpm.read_public(self.state.primary_handle.unwrap())?;
        if let Some(x) = public_data.0.public_area {
            if let TpmuPublicIdentifier::Ecc(y) = x.unique {
                self.identities.push(EcDsaPublicKey {
                    x: y.x.buffer,
                    y: y.y.buffer,
                });
            }
        }
        Ok(())
    }
}
