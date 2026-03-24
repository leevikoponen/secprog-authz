use base64ct::{Base64Url, Encoding as _};
use hmac::{
    Hmac,
    Mac as _,
    digest::{FixedOutput as _, Key, Output},
};
use rand::{RngCore as _, rngs::OsRng};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

const HS256_HEADER: &str = r#"{"typ":"jwt","alg":"HS256"}"#;
const SECTION_SEPARATOR: u8 = b'.';

enum TokenTraverser {
    Initial,
    FoundSingle(usize),
    FoundBoth(usize, usize),
    TooMany(usize),
}

impl TokenTraverser {
    const fn found_separator(self, offset: usize) -> Self {
        match self {
            Self::Initial => Self::FoundSingle(offset),
            Self::FoundSingle(first) => Self::FoundBoth(first, offset),
            Self::FoundBoth(_, _) => Self::TooMany(1),
            Self::TooMany(count) => Self::TooMany(count + 1),
        }
    }

    const fn expect_success(self) -> Option<[usize; 2]> {
        let Self::FoundBoth(first, second) = self else {
            return None;
        };

        Some([first, second])
    }

    fn find_separators(token: &[u8]) -> Option<[usize; 2]> {
        token
            .iter()
            .copied()
            .enumerate()
            .filter_map(|(offset, byte)| (byte == SECTION_SEPARATOR).then_some(offset))
            .fold(Self::Initial, Self::found_separator)
            .expect_success()
    }

    fn split_sections(token: &mut [u8]) -> Option<[&mut [u8]; 3]> {
        let [first, second] = Self::find_separators(token)?;

        let (first, remaining) = token.split_at_mut(first);
        let (second, remaining) = remaining[1..].split_at_mut(second - first.len() - 1);
        let third = &mut remaining[1..];

        Some([first, second, third])
    }

    fn decode_sections(token: &mut [u8]) -> Option<[&mut [u8]; 3]> {
        let [first, second, third] = Self::split_sections(token)?.map(|section| {
            Base64Url::decode_in_place(section)
                .ok()
                .map(<[_]>::len)
                .map(|end| &mut section[..end])
        });

        Some([first?, second?, third?])
    }
}

#[derive(Clone)]
#[must_use]
pub struct HmacSecurity(Key<Hmac<Sha256>>);

impl HmacSecurity {
    pub fn generate_random() -> Self {
        let mut output = Key::<Hmac<Sha256>>::default();

        OsRng
            .try_fill_bytes(&mut output)
            .expect("random number generation shouldn't reasonably fail");

        Self(output)
    }

    pub fn verify_jwt<'buffer, T: Deserialize<'buffer>>(
        &self,
        token: &'buffer mut [u8],
    ) -> Option<T> {
        let [first, second, third] = TokenTraverser::decode_sections(token)?;
        if first != HS256_HEADER.as_bytes() {
            return None;
        }

        Hmac::<Sha256>::new(&self.0)
            .chain_update(first)
            .chain_update(&second)
            .verify_slice(third)
            .ok()?;

        serde_json::from_slice(second).ok()
    }

    pub fn sign_jwt<T: Serialize + ?Sized>(&self, value: &T) -> String {
        let payload = serde_json::to_string(value).expect("token payload should be serializable");
        let mut digest = Output::<Hmac<Sha256>>::default();

        let length = Base64Url::encoded_len(HS256_HEADER.as_bytes())
            + Base64Url::encoded_len(payload.as_bytes())
            + Base64Url::encoded_len(digest.as_slice())
            + 2;

        let mut hmac = Hmac::<Sha256>::new(&self.0);
        let mut buffer = vec![0; length];
        let mut offset = 0;

        for section in [HS256_HEADER.as_bytes(), payload.as_bytes()] {
            hmac.update(section);
            offset += Base64Url::encode(section, &mut buffer[offset..])
                .expect("output buffer should have been correctly sized")
                .len();

            buffer[offset] = SECTION_SEPARATOR;
            offset += 1;
        }

        hmac.finalize_into(&mut digest);
        Base64Url::encode(digest.as_slice(), &mut buffer[offset..])
            .expect("output buffer should have been correctly sized");

        String::from_utf8(buffer).expect("encoded data should be valid utf-8")
    }
}

#[cfg(test)]
mod test {
    use crate::token::HmacSecurity;

    #[test]
    fn token_handling_sanity_check() {
        let secret = HmacSecurity::generate_random();
        let value = "foo";

        let mut token = secret.sign_jwt(&value).into_bytes();
        let payload = secret
            .verify_jwt::<&str>(token.as_mut_slice())
            .expect("verifying just created token shouldn't fail");

        assert_eq!(payload, value);
    }
}
