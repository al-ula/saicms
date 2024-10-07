use std::{
    path::PathBuf,
    sync::{Arc, OnceLock},
};

use redb::Database;

use crate::CONFIG;

pub struct Db {
    pub db: Arc<Database>,
}

impl Db {
    pub fn init(path_buf: PathBuf) -> Result<Db, redb::Error> {
        let db = Database::create(path_buf)?;
        Ok(Self { db: Arc::new(db) })
    }
}

pub static DB: OnceLock<Db> = OnceLock::new();

pub fn initialize_db() -> Result<(), redb::Error> {
    let path = CONFIG.get().unwrap().db_path.clone().join("saicms.db");
    let db = Db::init(path)?;
    DB.set(db).ok();
    Ok(())
}
