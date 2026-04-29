use argon2::password_hash::PasswordHashString;
use rusqlite::{Connection, Error, OptionalExtension};

pub struct UserInfo {
    pub id: i64,
    pub password: PasswordHashString,
    pub totp: Option<Box<[u8]>>,
}

pub struct CodeExchange {
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

            create table if not exists exchange (
                code text primary key,
                user integer not null references user
            ) strict;
            ",
        )?;

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
                        .map(Vec::into_boxed_slice),
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

    pub fn create_code_exchange(&self, user: i64, state: Option<&str>) -> Result<Box<str>, Error> {
        self.0.query_one(
            "
            insert into exchange (code, user, state)
            values (hex(randomblob(16)), ?1, ?2)
            returning code
            ",
            (user, state),
            |row| row.get(0),
        )
    }

    pub fn take_code_exchange(
        &self,
        code: &str,
        state: Option<&str>,
    ) -> Result<Option<CodeExchange>, Error> {
        OptionalExtension::optional(self.0.query_one(
            "
            delete from exchange
            where code = ?1 and state = ?2
            returning user
            ",
            (code, state),
            |row| Ok(CodeExchange { user: row.get(0)? }),
        ))
    }
}
