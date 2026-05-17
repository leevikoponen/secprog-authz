use std::{
    fmt::Write as _,
    time::{Duration, SystemTime},
};

use arrayvec::ArrayString;
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
const TOTP_DIGITS: usize = 8;
const TOTP_STEP: Duration = Duration::from_secs(30);

/// Slightly wonky state machine based approach for finding the section ranges
/// of the full token value.
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

/// HS256 continues to be perfectly fine and secure, I really don't see a point
/// in using anything else if you don't need the public/private key
/// infrastructure that something like OpenID Connect ends up utilizing.
#[derive(Clone)]
#[must_use]
pub struct HmacSecurity(Key<Hmac<Sha256>>);

impl HmacSecurity {
    /// I originally wanted to store the key in database to persist across
    /// restarts, but realistically there's no point since these JWTs are only
    /// used for short lived access tokens that can be transparently refreshed
    /// anyways without the whole redirect flow.
    pub fn generate_random() -> Self {
        let mut output = Key::<Hmac<Sha256>>::default();

        OsRng
            .try_fill_bytes(&mut output)
            .expect("random number generation shouldn't reasonably fail");

        Self(output)
    }

    /// But using a stored secret is required for the TOTP codepath.
    pub fn from_secret(value: &[u8]) -> Self {
        Self(Key::<Hmac<Sha256>>::clone_from_slice(value))
    }

    /// Dedode and verify that the given token is parsable as such and has been
    /// signed with this key and then parse it's payload as JSON.
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

    /// Construct a token with the given payload that will be then signed.
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

    /// Might as well implement the TOTP exactly how it's described in the spec.
    pub fn generate_totp(&self, time: SystemTime) -> ArrayString<TOTP_DIGITS> {
        let time = time
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("time shouldn't reasonably be before unix epoch")
            .as_secs();

        let hash = Hmac::<Sha256>::new(&self.0)
            .chain_update((time / TOTP_STEP.as_secs()).to_be_bytes())
            .finalize()
            .into_bytes();

        let offset = usize::from(hash.last().expect("computed hash shouln't be empty") & 0xf);
        let binary = (u64::from(hash[offset] & 0x7f) << 24)
            | (u64::from(hash[offset + 1]) << 16)
            | (u64::from(hash[offset + 2]) << 8)
            | u64::from(hash[offset + 3]);

        let mut output = ArrayString::new();
        write!(
            &mut output,
            "{:01$}",
            binary
                % 10u64.pow(
                    TOTP_DIGITS
                        .try_into()
                        .expect("totp digits shouldn't be unreasonably large")
                ),
            TOTP_DIGITS
        )
        .expect("totp code should be writable to correctly sized buffer");

        output
    }

    /// Clock spread or otherwise submitting and the request being handled
    /// taking some time in the middle is common enough to need accommodating by
    /// allowing the values of previous and next steps is instructed in the
    /// spec, but I'm actually quite restrictive to only go one step away.
    pub fn verify_totp(&self, time: SystemTime, given: &str) -> bool {
        [time, time - TOTP_STEP, time + TOTP_STEP]
            .into_iter()
            .any(|attempt| &self.generate_totp(attempt) == given)
    }
}

#[cfg(test)]
mod test {
    use std::time::{Duration, SystemTime};

    use argon2::{Argon2, PasswordHasher as _, PasswordVerifier as _, password_hash::SaltString};
    use rand::distributions::{Alphanumeric, DistString as _, Distribution as _, Uniform};

    use crate::crypto::{HmacSecurity, TOTP_DIGITS, TOTP_STEP};

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

    #[test]
    fn password_hasher_sanity_check() {
        let mut rng = rand::thread_rng();
        let secret = Alphanumeric.sample_string(&mut rng, 32);

        let instance = Argon2::default();

        let salt = SaltString::generate(&mut rng);
        let hashed = instance
            .hash_password(secret.as_bytes(), &salt)
            .expect("hashing password with default parameters shouldn't fail");

        instance
            .verify_password(secret.as_bytes(), &hashed)
            .expect("verifying just created password hash shouldn't fail");
    }

    #[test]
    fn totp_generation_sanity_check() {
        let secret = HmacSecurity::generate_random();
        let time = SystemTime::now();

        for offset in Uniform::new(Duration::ZERO, TOTP_STEP)
            .sample_iter(&mut rand::thread_rng())
            .take(100)
        {
            let code = secret.generate_totp(time);

            assert!(
                code.chars().filter(char::is_ascii_digit).count() == TOTP_DIGITS,
                "totp codes should only contain digits"
            );

            assert!(
                secret.verify_totp(time + offset, &code),
                "totp codes of times well within step should match"
            );
        }
    }
}
