use argon2::password_hash::PasswordHashString;
use rusqlite::{Connection, Error, OptionalExtension};
use secrecy::SecretBox;

// let's be strict since supposed to get token immediately after redirect back
const PKCE_LIFETIME_SECONDS: i64 = 60 * 2;

// session lifetime can be quite strict as it's calculated against last usage
const SESSION_LIFETIME_SECONDS: i64 = 60 * 60 * 3;

pub struct UserInfo {
    pub id: i64,
    pub password: PasswordHashString,
    pub totp: Option<SecretBox<[u8]>>,
}

pub struct CodeExchange {
    pub user: i64,
    pub challenge: Box<str>,
}

pub struct SessionState {
    pub user: i64,
}

pub struct UserRepository(Connection);

impl UserRepository {
    pub fn initialize_from_env() -> Result<Self, Error> {
        let database = std::env::var_os("DATABASE_PATH")
            .map_or_else(Connection::open_in_memory, Connection::open)?;

        database.execute_batch(
            "
            create table if not exists user (
                id integer primary key,
                username text unique not null,
                password_hash text not null,
                totp_secret blob
            ) strict;

            create table if not exists session (
                key text primary key default (hex(randomblob(16))),
                user integer not null references user,
                created integer not null default (unixepoch()),
                utilized integer
            ) strict;

            create table if not exists exchange (
                code text primary key default (hex(randomblob(16))),
                user integer not null references user,
                created integer not null default (unixepoch()),
                state text not null,
                challenge text not null
            ) strict;
            ",
        )?;

        let cleaned = database.execute(
            "
            delete from exchange
            where created + ?1 > unixepoch()
            ",
            [PKCE_LIFETIME_SECONDS],
        )?;

        if cleaned > 0 {
            tracing::info!("cleaned up {cleaned} expired pkce exchanges");
        }

        Ok(Self(database))
    }

    pub fn fetch_by_name(&self, name: &str) -> Result<Option<UserInfo>, Error> {
        OptionalExtension::optional(self.0.query_row(
            "
            select id, password_hash, totp_secret from user
            where username = ?1
            ",
            [name],
            |row| {
                Ok(UserInfo {
                    id: row.get(0)?,
                    password: row
                        .get_ref(1)?
                        .as_str()?
                        .parse()
                        .expect("user database shouldn't contain invalid password hashes"),
                    totp: row
                        .get_ref(2)?
                        .as_blob_or_null()?
                        .map(Vec::from)
                        .map(Vec::into_boxed_slice)
                        .map(SecretBox::from),
                })
            },
        ))
    }

    pub fn create_new_account(&self, name: &str, hashed: &str) -> Result<bool, Error> {
        let changed = self.0.execute(
            "
            insert into user (username, password_hash)
            values (?1, ?2)
            ",
            [name, hashed],
        )?;

        Ok(changed == 1)
    }

    pub fn create_code_exchange(
        &self,
        user: i64,
        state: &str,
        challenge: &str,
    ) -> Result<Box<str>, Error> {
        self.0.query_one(
            "
            insert into exchange (user, state, challenge)
            values (?1, ?2, ?3)
            returning code
            ",
            (user, state, challenge),
            |row| row.get(0),
        )
    }

    pub fn take_code_exchange(
        &self,
        code: &str,
        state: &str,
    ) -> Result<Option<CodeExchange>, Error> {
        OptionalExtension::optional(self.0.query_one(
            "
            delete from exchange
            where code = ?1
            and state = ?2
            and created + ?3 < unixepoch()
            returning user, challenge
            ",
            (code, state, PKCE_LIFETIME_SECONDS),
            |row| {
                Ok(CodeExchange {
                    user: row.get(0)?,
                    challenge: row.get_ref(2)?.as_str()?.to_owned().into_boxed_str(),
                })
            },
        ))
    }

    pub fn create_user_session(&self, user: i64) -> Result<Box<str>, Error> {
        self.0.query_one(
            "
            insert into session (user)
            values (?1)
            returning key
            ",
            [user],
            |row| Ok(row.get_ref(0)?.as_str()?.to_owned().into_boxed_str()),
        )
    }

    pub fn resolve_user_session(&self, id: &[u8]) -> Result<Option<SessionState>, Error> {
        OptionalExtension::optional(self.0.query_one(
            "
            update session
            set utilized = unixepoch()
            where key = ?1
            and utilized + ?2 < unixepoch()
            returning user
            ",
            (id, SESSION_LIFETIME_SECONDS),
            |row| Ok(SessionState { user: row.get(0)? }),
        ))
    }
}
