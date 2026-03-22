use argon2::PasswordHash;
use rusqlite::{Connection, Error, OptionalExtension as _};

pub struct UserInfo {
    pub id: i64,
    pub password: PasswordHash,
}

pub struct UserRepository(Connection);

impl UserRepository {
    pub fn initialize_from_env() -> Result<Self, Error> {
        let database = std::env::var_os("DATABASE_PATH")
            .map_or_else(Connection::open_in_memory, Connection::open)?;

        database.execute_batch(
            "
            create table if not exists users (
                id integer primary key,
                username text unique not null,
                password_hash text not null
            ) strict;
            ",
        )?;

        Ok(Self(database))
    }

    pub fn fetch_by_name(&self, name: &str) -> Result<Option<UserInfo>, Error> {
        self.0
            .query_row(
                "
                select (id, password_hash) from users
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
                    })
                },
            )
            .optional()
    }

    pub fn create_new_account(&self, name: &str, hashed: &str) -> Result<bool, Error> {
        let changed = self.0.execute(
            "
            insert into users (username, password_hash)
            values (?1, ?2)
            ",
            [name, hashed],
        )?;

        Ok(changed == 1)
    }
}
