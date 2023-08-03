#[macro_export]
macro_rules! set_tpm_data_codec {
    ($type:ty, $enc:ident, $dec:ident) => {
        impl ToTpm for $type {
            fn to_tpm(&self) -> Vec<u8> {
                $enc(self)
            }
        }

        impl FromTpm for $type {
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

#[macro_export]
macro_rules! impl_to_tpm {
    ($($name:ident ($sel: ident) $bl:block)*) => {
        $(impl ToTpm for $name {
            fn to_tpm(&$sel) -> Vec<u8>
                $bl
        })*
    }
}

#[macro_export]
macro_rules! impl_from_tpm {
    ($($name:ident ($var: ident) $bl:block)*) => {
        $(impl FromTpm for $name {
            fn from_tpm($var: &[u8]) -> TpmResult<($name, &[u8])>
                $bl
        })*
    }
}

#[macro_export]
macro_rules! impl_from_tpm_with_selector {
    ($($name:ident <$type:ty>($var: ident, $selector: ident) $bl:block)*) => {
        $(impl FromTpmWithSelector<$type> for $name {
            fn from_tpm<'a>($var: &'a [u8], $selector: &$type) -> TpmResult<($name, &'a [u8])>
                $bl
        })*
    }
}

pub(crate) use def_decoder;
pub(crate) use def_encoder;
pub(crate) use impl_from_tpm;
pub(crate) use impl_from_tpm_with_selector;
pub(crate) use impl_to_tpm;
pub(crate) use set_tpm_data_codec;
