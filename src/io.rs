extern crate rand;

use rand::{rng, Rng};

use std::time::Duration;

use sqlx::Row;
use std::fmt::Display;

use sqlx::sqlite::{SqliteConnectOptions, SqlitePool};
use sqlx::Executor;

pub struct WritePool(pub SqlitePool);

impl WritePool {
    pub async fn new(file_name: &str) -> Result<WritePool, IOError> {
        Ok(WritePool(
            sqlx::pool::PoolOptions::<sqlx::Sqlite>::new()
                .max_connections(1)
                .idle_timeout(Duration::from_secs(180))
                .acquire_timeout(Duration::from_secs(5))
                .connect_with(
                    SqliteConnectOptions::new()
                        .filename(file_name)
                        .create_if_missing(true)
                        .read_only(false),
                )
                .await?,
        ))
    }

    pub async fn init(&self) -> Result<(), IOError> {
        let mut cnx = self.0.acquire().await?;
        cnx.execute(
            "CREATE TABLE IF NOT EXISTS entries (
            internal_id INTEGER PRIMARY KEY AUTOINCREMENT,
            id VARCHAR(16) UNIQUE,
            data TEXT NOT NULL
        )",
        )
        .await?;

        cnx.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_id ON entries(id)")
            .await?;

        Ok(())
    }
}

pub struct ReadPool(SqlitePool);

impl ReadPool {
    pub async fn new(file_name: &str, max_connections: u32) -> Result<ReadPool, IOError> {
        Ok(ReadPool(
            sqlx::pool::PoolOptions::<sqlx::Sqlite>::new()
                .max_connections(max_connections)
                .connect_with(
                    SqliteConnectOptions::new()
                        .filename(file_name)
                        .read_only(true),
                )
                .await?,
        ))
    }
}

fn generate_id(length: usize) -> String {
    // removed 0/o, i/1/l, u/v as they are too similar. with 4 char this gives us >700'000 unique ids
    const CHARSET: &[u8] = b"abcdefghjkmnpqrstwxyz23456789";
    (0..length)
        .map(|_| {
            let idx = rng().random_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect::<String>()
}

pub async fn remove_old(
    cnx: &mut sqlx::pool::PoolConnection<sqlx::Sqlite>,
    max_entries: i32,
) -> Result<u64, IOError> {
    let result = cnx
        .execute(
            sqlx::query(
                "DELETE FROM entries WHERE internal_id IN (
            SELECT internal_id FROM entries ORDER BY internal_id ASC LIMIT (
                SELECT MAX(COUNT(*) - ?,0)  FROM entries))",
            )
            .bind(max_entries),
        )
        .await?;

    Ok(result.rows_affected())
}

/// Delete a paste under the given id
pub async fn delete_paste<'a>(pool: &WritePool, id: &'a str) -> Result<&'a str, IOError> {
    let result = sqlx::query("DELETE FROM entries WHERE id = ?")
        .bind(id)
        .execute(&pool.0)
        .await?;

    if result.rows_affected() == 0 {
        return Err(IOError("Not found".to_owned()));
    }
    Ok(id)
}

/// Stores a paste under a new id
pub async fn store_paste(
    pool: &WritePool,
    id_length: usize,
    max_entries: i32,
    content: String,
) -> Result<String, IOError> {
    // If we acquire the connection, nobody else can get it
    let mut cnx = pool.0.acquire().await?;

    let id = generate_id(id_length);
    let result = cnx
        .execute(
            sqlx::query("INSERT OR IGNORE INTO entries (id, data) VALUES (?, ?)")
                .bind(&id)
                .bind(&content),
        )
        .await?;

    if result.rows_affected() == 1 {
        return Ok(id);
    }

    let entries = cnx
        .fetch_one(sqlx::query("select count(*) from entries"))
        .await?
        .get::<i32, usize>(0);

    warn!(
        "ID Collision ({} entries), cleaning up old entries and retrying",
        entries
    );
    let nb_entries_removed = remove_old(&mut cnx, max_entries).await?;
    warn!("Removed {} entries", nb_entries_removed);

    let mut retries = 0;
    let max_retries = 20;
    while retries < max_entries {
        warn!("Another ID Collision: {}/{}", retries, max_retries);
        let id = generate_id(id_length);
        let result = cnx
            .execute(
                sqlx::query("INSERT OR IGNORE INTO entries (id, data) VALUES (?, ?)")
                    .bind(&id)
                    .bind(&content),
            )
            .await?;

        if result.rows_affected() == 1 {
            return Ok(id);
        }
        retries += 1;
    }

    warn!("ID Collision again, last attempt");
    let id = generate_id(id_length);
    cnx.execute(
        sqlx::query("INSERT INTO entries (id, data) VALUES (?, ?)")
            .bind(generate_id(id_length))
            .bind(&content),
    )
    .await?;

    Ok(id)
}

/// Stores a paste under a new id
pub async fn store_paste_given_id(
    pool: &WritePool,
    id: String,
    content: String,
) -> Result<String, IOError> {
    let mut cnx = pool.0.acquire().await?;

    let _result = cnx
        .execute(
            sqlx::query("INSERT OR REPLACE INTO entries (id, data) VALUES (?, ?)")
                .bind(&id)
                .bind(&content),
        )
        .await?;

    Ok(id)
}

pub async fn get_paste(pool: &ReadPool, id: &str) -> Result<Option<String>, IOError> {
    let result = sqlx::query("SELECT data FROM entries WHERE id = ?")
        .bind(id)
        .fetch_one(&pool.0)
        .await;

    match result {
        Err(sqlx::Error::RowNotFound) => Ok(None),
        Ok(row) => Ok(row.get(0)),
        Err(e) => Err(e.into()),
    }
}

pub async fn get_all_paste(pool: &ReadPool) -> Result<Vec<(String, String)>, IOError> {
    let result = sqlx::query("SELECT id, data FROM entries")
        .fetch_all(&pool.0)
        .await?;

    Ok(result.iter().map(|row| (row.get(0), row.get(1))).collect())
}

#[derive(Debug)]
pub struct IOError(String);

impl Display for IOError {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> Result<(), ::std::fmt::Error> {
        f.write_str(&self.0)
    }
}

impl From<sqlx::error::Error> for IOError {
    fn from(e: sqlx::error::Error) -> IOError {
        IOError(format!("DB Error: {}", e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[async_test]
    async fn simple_workflow() {
        // See this page for more details on in-memory DBs and how they
        // should share caches for this to work properly
        // https://www.sqlite.org/inmemorydb.html
        let uri_shared_memory = "file::memory:?cache=shared";

        let write_pool = WritePool::new(uri_shared_memory).await.unwrap();
        assert!(write_pool.init().await.is_ok());

        let read_pool = ReadPool::new(uri_shared_memory, 10).await.unwrap();

        let data = String::from("SOME_DATA");

        let id = store_paste(&write_pool, 4, 2048, data.clone())
            .await
            .unwrap();
        assert_eq!(get_paste(&read_pool, &id).await.unwrap().unwrap(), data);
        assert_eq!(
            get_all_paste(&read_pool).await.unwrap(),
            vec![(id.clone(), data.clone())]
        );
        assert_eq!(delete_paste(&write_pool, &id).await.unwrap(), id);
        assert!(delete_paste(&write_pool, &id).await.is_err());
        assert!(get_paste(&read_pool, &id).await.unwrap().is_none());
        assert_eq!(get_all_paste(&read_pool).await.unwrap(), vec![]);
    }
}
