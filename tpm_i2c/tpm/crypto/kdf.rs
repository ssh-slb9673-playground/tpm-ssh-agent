use crate::tpm::structure::{TpmHandle, TpmiAlgorithmHash};
use crate::tpm::ToTpm;

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

pub fn kdf_a(
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
    let mut i = 0;
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

pub fn get_name_of_handle(handle: TpmHandle) -> Vec<u8> {
    // [TCG TPM Specification Part 1] Section 16 "Names" and Table 3
    let v = handle.to_tpm();
    let mso = v[0];
    if mso == 0x00u8 || mso == 0x02u8 || mso == 0x03u8 || mso == 0x40 {
        // PCR, HMAC Session, Policy Session, Permanent Values
        v
    } else if mso == 0x01u8 {
        // Nv Index
        todo!();
    } else if mso == 0x80u8 {
        // Transient Objects
        todo!();
    } else if mso == 0x81 {
        // Persistent Objects
        todo!();
    } else {
        // Invalid argument
        unimplemented!();
    }
}
