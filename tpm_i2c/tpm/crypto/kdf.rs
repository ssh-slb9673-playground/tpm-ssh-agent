use crate::tpm::structure::{TpmHandle, TpmiAlgorithmHash, TpmsNvPublic, TpmtPublic};
use crate::tpm::ToTpm;

#[derive(Debug)]
pub(in crate::tpm) enum PublicData {
    Object(TpmtPublic),
    NvIndex(TpmsNvPublic),
}

impl PublicData {
    fn get_algorithm_name(&self) -> TpmiAlgorithmHash {
        match self {
            PublicData::Object(public) => public.algorithm_name,
            PublicData::NvIndex(public) => public.algorithm_name,
        }
    }

    fn get_contents(&self) -> Vec<u8> {
        match self {
            PublicData::Object(public) => public.to_tpm(),
            PublicData::NvIndex(public) => public.to_tpm(),
        }
    }
}

fn key_iteration(
    algorithm_hash: &TpmiAlgorithmHash,
    i: u32,
    secret_key: &[u8],
    label: &[u8],
    context: &[u8],
    num_of_bits: u32,
) -> Vec<u8> {
    let intermediate_zero: Vec<u8> = if label.is_empty() || label[label.len() - 1] != 0 {
        [0u8].to_vec()
    } else {
        vec![]
    };
    algorithm_hash.hmac(
        secret_key,
        &[
            &i.to_tpm(),
            label,
            &intermediate_zero,
            context,
            &num_of_bits.to_tpm(),
        ]
        .concat(),
    )
}

pub(in crate::tpm) fn kdf_a(
    algorithm_hash: &TpmiAlgorithmHash,
    secret_key: &[u8],
    label: &[u8],
    context_u: &[u8],
    context_v: &[u8],
    num_of_bits: u32,
) -> Vec<u8> {
    // [TCG TPM Specification Part 1] 11.4.10.2 "KDFa"
    // [NIST SP 800-108r1] 4.1 "KDF in Counter Mode"
    let mut res = vec![];
    let mut generated_len = 0;
    let target_len = ((num_of_bits + 7) / 8) as usize;
    let mut i = 1;
    let context = [context_u, context_v].concat();
    loop {
        let buf = key_iteration(algorithm_hash, i, secret_key, label, &context, num_of_bits);
        generated_len += buf.len();
        res.push(buf);
        if generated_len >= target_len {
            break;
        }
        i += 1;
    }
    res.concat()[0..target_len].to_vec()
}

pub(in crate::tpm) fn get_name_of_handle<'a, F>(handle: TpmHandle, handle_to_public: F) -> Vec<u8>
where
    F: Fn(TpmHandle) -> &'a PublicData,
{
    // [TCG TPM Specification Part 1] Section 16 "Names" and Table 3
    let v = handle.to_tpm();
    let mso = v[0];
    if mso == 0x00u8 || mso == 0x02u8 || mso == 0x03u8 || mso == 0x40 {
        // PCR, HMAC Session, Policy Session, Permanent Values
        v
    } else if mso == 0x01u8 // NV Index
           || mso == 0x80u8 || mso == 0x81
    // Transient / Persistent Objects
    {
        // Nv Index
        let public = handle_to_public(handle);
        let hash = public.get_algorithm_name();
        [hash.to_tpm(), hash.digest(&public.get_contents())]
            .concat()
            .to_vec()
    } else {
        // Invalid argument
        unimplemented!();
    }
}

#[cfg(test)]
mod test {
    #[test]
    fn test_kdfa() {
        // https://github.com/google/go-tpm/blob/e9722e4450de281f46cb7f4241f59695de4ed998/legacy/tpm2/test/kdf_test.go#L35-L41
        use crate::tpm::crypto::kdf_a;
        use crate::tpm::structure::*;
        let actual = kdf_a(
            &TpmiAlgorithmHash::Sha256,
            "yolo\0".as_bytes(),
            "IDENTITY".as_bytes(),
            "kek\0".as_bytes(),
            "yoyo\0".as_bytes(),
            128,
        );
        let expected = [
            0xd2, 0xd7, 0x2c, 0xc7, 0xa8, 0xa5, 0xeb, 0x09, 0xe8, 0xc7, 0x90, 0x12, 0xe2, 0xda,
            0x9f, 0x22,
        ];
        assert_eq!(actual, expected);
    }
}
