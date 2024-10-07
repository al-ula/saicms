use std::{path::PathBuf, sync::OnceLock};

use tracing::info;

#[derive(Debug)]
pub struct Config {
    pub db_path: PathBuf,
    pub admin_static: PathBuf,
}

pub static CONFIG: OnceLock<Config> = OnceLock::new();

impl Default for Config {
    fn default() -> Self {
        Self {
            db_path: "tmp".into(),
            admin_static: "admin/dist".into(),
        }
    }
}

impl Config {
    pub fn init() {
        let config = Config::default();
        info!("Initializing config");
        CONFIG.set(config).unwrap();
    }
}
