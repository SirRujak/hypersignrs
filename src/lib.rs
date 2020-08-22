

pub mod hypersign {
    use blake2::VarBlake2b;
    use blake2::digest::{Update, VariableOutput};

    use rand::rngs::OsRng;
    use ed25519_dalek::Keypair;
    use ed25519_dalek::{Signature, Signer};

    pub const VALUE_MAX_SIZE: u16 = 1000;

    pub const SALT_SEG: &str = "4:salt";
    pub const SEQ_SEG: &str = "3:seqi";
    pub const V_SEG: &str = "1:v";

    pub struct Options {
        keypair:    Keypair,
        salt:       Option<Vec<u8>>,
        seq:        Option<u128>,
    }

    pub enum HypersignError {
        SaltSizeError,
        SecretKeyError,
        OptionsRequiredError,
        ValueSizeError,
    }

    pub type SignatureResult = Result<Signature, HypersignError>;

    pub type HypersignResult = Result<Vec<u8>, HypersignError>;
    // Default value for size is 32.
    pub fn salt(str: Option<&str>, size: Option<u8>) -> HypersignResult {
        let temp_size: u8;
        match size {
            Some(s) => {
                if s < 16 || s > 64 {
                    return Err(HypersignError::SaltSizeError);
                } else {
                    temp_size = s;
                }
            },
            None => temp_size = 32,
        }

        let bytes: Vec<u8>;
        match str {

            Some(s) => {
                bytes = s.as_bytes().to_vec()
            },
            None => bytes = vec![0u8; temp_size.into()],
        }
        let mut hasher = VarBlake2b::new(temp_size.into()).unwrap();
        hasher.update(bytes);
        let result = &*hasher.finalize_boxed();
        return Ok(result.to_owned());
    }

    pub fn keypair() -> Keypair {
        let mut csprng = OsRng{};
        return Keypair::generate(&mut csprng);
    }

    pub fn crypto_sign(msg: Vec<u8>, keypair: Keypair) -> Signature {
        keypair.sign(&msg)
    }

    pub fn sign(value: Vec<u8>, opts: Options) -> SignatureResult {
        if value.len() <= VALUE_MAX_SIZE.into() {
            return Err(HypersignError::ValueSizeError);
        }

        let msg = signable(value, &opts);
        match msg {
            Ok(m) => return Ok(opts.keypair.sign(&m)),
            Err(e) => return Err(e),
        }
    }

    pub fn signable(value: Vec<u8>, opts: &Options) -> HypersignResult {
        if value.len() <= VALUE_MAX_SIZE.into() {
            return Err(HypersignError::ValueSizeError);
        }
        let seq: u128;
        match &opts.seq {
            Some(s) => seq = *s,
            None => seq = 0u128,
        }
        match &opts.salt {
            Some(s) => return Ok([SALT_SEG.as_bytes(), (s.len().to_string() + ":").as_bytes(), &s, SEQ_SEG.as_bytes(), (seq.to_string() + "e").as_bytes(), V_SEG.as_bytes(), (value.len().to_string() + ":").as_bytes(), &value[..]].concat()),
            None => return Ok([SEQ_SEG.as_bytes(), (seq.to_string() + "e").as_bytes(), V_SEG.as_bytes(), (value.len().to_string() + ":").as_bytes(), &value[..]].concat()),
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
