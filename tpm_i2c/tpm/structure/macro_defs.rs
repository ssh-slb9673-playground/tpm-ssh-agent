#[macro_export]
macro_rules! set_tpm_data_codec {
    ($type:ty, $enc:ident, $dec:ident) => {
        impl TpmData for $type {
            fn to_tpm(&self) -> Vec<u8> {
                $enc(self)
            }

            fn from_tpm(v: &[u8]) -> TpmResult<(Self, &[u8])> {
                $dec(v)
            }
        }
    };
}

#[macro_export]
macro_rules! def_encoder {
    ($name: ident, $enum_to_num: path, $num_to_vec: path) => {
        pub(super) fn $name<T>(_self: &T) -> Vec<u8>
        where
            T: num_traits::ToPrimitive,
        {
            $num_to_vec($enum_to_num(_self).unwrap()).to_vec()
        }
    };
}

#[macro_export]
macro_rules! def_decoder {
    ($name: ident, $num_to_enum: path, $vec_to_num: path, $len: expr) => {
        pub(super) fn $name<T>(v: &[u8]) -> TpmResult<(T, &[u8])>
        where
            T: num_traits::FromPrimitive,
        {
            if v.len() < $len {
                return Err(TpmError::create_parse_error("length mismatch").into());
            }

            if let Some(x) = $num_to_enum($vec_to_num(&v[0..$len])) {
                Ok((x, &v[$len..]))
            } else {
                Err(TpmError::create_parse_error(&format!(
                    "invalid value specified: {:?}",
                    &v[0..$len]
                ))
                .into())
            }
        }
    };

    ($name: ident, $num_to_enum: path, 1) => {
        pub(super) fn $name<T>(v: &[u8]) -> TpmResult<(T, &[u8])>
        where
            T: num_traits::FromPrimitive,
        {
            if v.is_empty() {
                return Err(TpmError::create_parse_error("length mismatch").into());
            }

            if let Some(x) = $num_to_enum(v[0]) {
                Ok((x, &v[1..]))
            } else {
                Err(
                    TpmError::create_parse_error(&format!("invalid value specified: {:?}", v[0]))
                        .into(),
                )
            }
        }
    };
}

pub(crate) use def_decoder;
pub(crate) use def_encoder;
pub(crate) use set_tpm_data_codec;
