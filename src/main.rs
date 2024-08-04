mod authentication;
mod admin;
mod template;

use rocket::fairing::AdHoc;
use rocket::figment::{Figment, Profile};
use rocket::figment::providers::{Env, Format, Serialized, Toml};
use serde::{Deserialize, Serialize};
use crate::authentication::{routes::auth_routes, auth_db::{AuthDbInit, AuthDbCleaner}};
use admin::routes::admin_routes;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let figment = Figment::from(rocket::Config::default())
        // When need additional server config
        .merge(Serialized::defaults(Config::default()))
        // should be made configurable with user home config directory as default
        .merge(Toml::file("config/server.toml").nested())
        // to configure each config via env var
        .merge(Env::prefixed("SAICMS_").global())
        .select(Profile::from_env_or("SAICMS_PROFILE", "default"))
        .merge(("jwt_secret", "secret"))
        .merge(("login_timeout", 60))
        .merge(("cleanup_interval", 24));
    let login_timeout = figment.extract::<Config>()?.login_timeout;
    let _rocket = rocket::custom(figment)
        .attach(AdHoc::config::<Config>())
        .attach(AuthDbInit)
        .attach(AuthDbCleaner::new(login_timeout))
        .mount("/auth", auth_routes())
        .mount("/admin", admin_routes())
        .launch().await?;
    Ok(())  
}

#[derive(Debug, Default, Serialize, Deserialize)]   
struct Config {
    jwt_secret: String,
    login_timeout: u32,
    cleanup_interval: u32
}