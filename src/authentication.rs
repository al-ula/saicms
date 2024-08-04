use crate::Config;
use jsonwebtoken as jwt;
use jwt::{encode, DecodingKey, EncodingKey};
use redb::{backends::InMemoryBackend, ReadableTable, TableDefinition};
use rocket::{
    fairing::Fairing, get, http::Status, post, request::Outcome, response::status, Build, Orbit,
    Rocket, State,
};
use serde::{Deserialize, Serialize};
use std::{sync::Arc, time::Duration};
use tokio::time::interval;

use auth_db::*;
use auth_guard::*;
use login_control::*;

pub mod auth_guard {
    use super::*;
    #[derive(Deserialize)]
    pub struct LoginInfo {
        pub username: String,
        pub password: String,
    }

    #[derive(Debug, Deserialize)]
    pub struct SignupInfo {
        pub username: String,
        pub password: String,
    }

    #[derive(Serialize)]
    pub struct LoginResponse {
        pub token: String,
    }

    #[derive(Debug, Deserialize, Serialize, Clone)]
    pub struct Claims {
        pub sub: String,
        pub exp: i64,
    }

    #[derive(Debug)]
    pub enum BearerError {
        NoToken,
        Corrupt,
        Invalid,
    }
    #[derive(Debug)]
    pub struct BearerToken(Arc<str>);
    impl BearerToken {
        pub fn get(&self) -> Arc<str> {
            self.0.clone()
        }

        pub fn new(token: Arc<str>) -> Self {
            Self(token)
        }

        pub fn create(claim: Claims, secret: &str) -> Result<Self, jwt::errors::Error> {
            let key = EncodingKey::from_secret(secret.as_ref());
            let token = encode(&jwt::Header::default(), &claim, &key)?;
            Ok(Self(token.into()))
        }

        pub fn decode(&self, secret: &str) -> Result<Claims, jwt::errors::Error> {
            let key = DecodingKey::from_secret(secret.as_ref());
            let token = jwt::decode::<Claims>(&self.0, &key, &jwt::Validation::default())?;
            Ok(token.claims)
        }
    }

    impl From<&str> for BearerToken {
        fn from(token: &str) -> Self {
            Self(Arc::from(token))
        }
    }

    impl From<String> for BearerToken {
        fn from(token: String) -> Self {
            Self(Arc::from(token))
        }
    }

    #[rocket::async_trait]
    impl<'r> rocket::request::FromRequest<'r> for BearerToken {
        type Error = BearerError;

        async fn from_request(req: &'r rocket::Request<'_>) -> Outcome<Self, Self::Error> {
            let auth_header = match req.headers().get_one("Authorization") {
                Some(token) => token,
                None => return Outcome::Error((Status::Unauthorized, BearerError::NoToken)),
            };
            let token = match auth_header {
                auth_header if auth_header.starts_with("Bearer ") => {
                    match auth_header.strip_prefix("Bearer ") {
                        None => {
                            return Outcome::Error((Status::Unauthorized, BearerError::Corrupt))
                        }
                        Some(t) => t,
                    }
                }
                _ => return Outcome::Error((Status::Unauthorized, BearerError::Corrupt)),
            };
            let config = match req.guard::<&State<Config>>().await {
                Outcome::Success(config) => config,
                _ => {
                    eprintln!("Error from bearer\nFailed to get config");
                    return Outcome::Error((Status::Unauthorized, BearerError::Invalid));
                }
            };
            let secret = config.jwt_secret.as_str();
            let auth_db = match req.guard::<&State<AuthDb>>().await {
                Outcome::Success(auth) => auth,
                _ => {
                    eprintln!("Error from bearer\nFailed to get AuthDB");
                    return Outcome::Error((Status::Unauthorized, BearerError::Invalid));
                }
            };
            if !is_token_authorized(&BearerToken::from(token), secret, auth_db) {
                eprintln!("Error from bearer\nFailed to authorize token");
                return Outcome::Error((Status::Unauthorized, BearerError::Invalid));
            }
            Outcome::Success(BearerToken::new(Arc::from(token)))
        }
    }

    pub fn is_token_authorized(token: &BearerToken, secret: &str, auth_db: &AuthDb) -> bool {
        let claim = match token.decode(secret) {
            Ok(c) => c,
            Err(_) => return false,
        };
        println!("Claim: {:?}", claim);
        let check_login = check_login(&token.get(), auth_db)
            .map_err(|e| {
                eprintln!("Error from auth check\nFailed to check login: {}", e);
            })
            .ok();
        println!("Check login: {:?}", check_login);
        match check_login {
            None => return false,
            Some(true) => {}
            Some(false) => return false,
        }
        if claim.sub != "admin" {
            return false;
        }
        if claim.exp < chrono::Utc::now().timestamp() {
            let _invalidate = invalidate_login(&token.get(), auth_db).map_err(|e| {
                eprintln!(
                    "Error from auth check\nFailed to invalidate expired login: {}",
                    e
                );
            });
            println!("Invalidated login because expired");
            return false;
        }
        true
    }

    pub fn account_authorize(
        login: &LoginInfo,
        secret: &str,
        duration: u64,
    ) -> Option<(BearerToken, i64)> {
        if login.username != "admin" || login.password != "admin" {
            return None;
        }
        let duration = Duration::from_secs(duration * 3600);
        let timestamp = chrono::Utc::now().timestamp() + duration.as_secs() as i64;
        let claim = Claims {
            sub: login.username.clone(),
            exp: timestamp,
        };
        let bearer = BearerToken::create(claim.clone(), secret).ok();
        match bearer {
            None => None,
            Some(bearer) => Some((bearer, claim.exp)),
        }
    }
}

pub mod auth_db {
    use super::*;

    use redb::Database;
    use std::sync::Arc;

    pub type AuthDb = Arc<Database>;
    pub fn init_db() -> Result<AuthDb, redb::Error> {
        let mem = InMemoryBackend::new();
        println!("Init memory backend....");
        let db = Database::builder()
            .create_with_backend(mem)
            .expect("Failed to init auth db");
        Ok(Arc::new(db))
    }

    pub struct AuthDbInit;

    #[rocket::async_trait]
    impl Fairing for AuthDbInit {
        fn info(&self) -> rocket::fairing::Info {
            rocket::fairing::Info {
                name: "Init AuthDB",
                kind: rocket::fairing::Kind::Ignite | rocket::fairing::Kind::Liftoff,
            }
        }

        async fn on_ignite(&self, rocket: Rocket<Build>) -> rocket::fairing::Result {
            let db = init_db().expect("Failed to init auth db");
            let managed = rocket.manage(db);
            Ok(managed)
        }
    }

    pub struct AuthDbCleaner {
        timeout: u32,
    }
    impl AuthDbCleaner {
        pub fn new(timeout: u32) -> Self {
            Self { timeout }
        }
    }

    #[rocket::async_trait]
    impl Fairing for AuthDbCleaner {
        fn info(&self) -> rocket::fairing::Info {
            rocket::fairing::Info {
                name: "AuthDB Cleaner",
                kind: rocket::fairing::Kind::Liftoff,
            }
        }

        async fn on_liftoff(&self, rocket: &Rocket<Orbit>) {
            let mut interval = interval(Duration::from_secs((self.timeout * 3600) as u64));
            let db = match rocket.state::<AuthDb>() {
                None => {
                    eprintln!("AuthDB is not ready");
                    panic!()
                }
                Some(d) => d.to_owned(),
            };
            tokio::spawn(async move {
                loop {
                    interval.tick().await;
                    let _ = clean_expired_logins(&db).await;
                }
            });
        }
    }

    pub const LOGIN_TABLE: TableDefinition<&str, &str> = TableDefinition::new("login_table");
    pub const TIMEOUT_TABLE: TableDefinition<&str, i64> = TableDefinition::new("timeout_table");
}
pub mod login_control {
    use super::*;

    pub fn invalidate_login(token: &str, db: &AuthDb) -> Result<(), redb::Error> {
        let write_txn = db.begin_write()?;
        {
            let mut table = write_txn.open_table(LOGIN_TABLE)?;
            table.remove(token)?;
            let mut table = write_txn.open_table(TIMEOUT_TABLE)?;
            table.remove(token)?;
        }
        write_txn.commit().map_err(|e| e.into())
    }

    pub fn check_login(token: &str, db: &AuthDb) -> Result<bool, redb::Error> {
        let read_txn = db.begin_read()?;
        let table = read_txn.open_table(LOGIN_TABLE)?;
        Ok(table.get(token)?.is_some())
    }

    pub fn add_login(
        token: &str,
        timeout: i64,
        login: &LoginInfo,
        db: &AuthDb,
    ) -> Result<(), redb::Error> {
        let write_txn = db.begin_write()?;
        {
            let mut table = write_txn.open_table(LOGIN_TABLE)?;
            table.insert(token, &*login.username)?;
            let mut table = write_txn.open_table(TIMEOUT_TABLE)?;
            table.insert(token, timeout)?;
        }
        write_txn.commit().map_err(|e| e.into())
    }

    pub async fn clean_expired_logins(db: &AuthDb) -> Result<(), redb::Error> {
        let write_txn = db.begin_write()?;
        {
            let mut table = write_txn.open_table(TIMEOUT_TABLE)?;
            let current_time = chrono::Utc::now().timestamp();

            let expired_keys: Vec<String> = table
                .iter()?
                .filter_map(|result| {
                    result.ok().and_then(|(key, value)| {
                        if value.value() < current_time {
                            Some(key.value().to_string())
                        } else {
                            None
                        }
                    })
                })
                .collect();
            for key in expired_keys.as_slice() {
                table.remove(key.as_str())?;
            }
            let mut table = write_txn.open_table(LOGIN_TABLE)?;
            for key in expired_keys {
                table.remove(key.as_str())?;
            }
        }
        write_txn.commit().map_err(|e| {
            eprintln!("Timeout cleanup error: {}", e);
            e.into()
        })
    }
}

pub mod routes {
    use super::*;
    use password_auth::{generate_hash, verify_password};
    pub fn auth_routes() -> Vec<rocket::Route> {
        rocket::routes![login, signup, logout, login_info]
    }

    #[post("/login", data = "<login>")]
    pub async fn login(
        config: &State<Config>,
        login: rocket::serde::json::Json<LoginInfo>,
        db: &State<AuthDb>,
    ) -> Result<rocket::serde::json::Json<LoginResponse>, status::Custom<&'static str>> {
        let secret = config.jwt_secret.as_str();
        let duration = config.login_timeout as u64;
        let token = account_authorize(&login, secret, duration);
        match token {
            Some(t) => {
                let token = t.0.get();
                match add_login(&token, t.1, &login, db) {
                    Ok(_) => {}
                    Err(e) => {
                        eprintln!("Error on login: {}", e);
                        return Err(status::Custom(
                            Status::InternalServerError,
                            "Login process failed",
                        ));
                    }
                };
                let login_response = LoginResponse {
                    token: token.to_string(),
                };
                Ok(rocket::serde::json::Json(login_response))
            }
            None => Err(status::Custom(
                Status::Unauthorized,
                "Invalid login credentials",
            )),
        }
    }

    #[post("/signup", data = "<signup>")]
    pub async fn signup(signup: rocket::serde::json::Json<SignupInfo>) -> status::Custom<&'static str> {
        let signup = signup.into_inner();
        if !signup.username.is_empty() && !signup.password.is_empty() {
            // validate username/password later
            println!("{:#?}", signup);
            let hashed = generate_hash(signup.password.as_str());
            println!("{:#?}", hashed);
            let unhashed = verify_password(signup.password, hashed.as_str());
            println!("{:#?}", unhashed);
            return status::Custom(Status::Ok, "Signup successful");
        }
        status::Custom(Status::BadRequest, "Signup Failed")
    }

    #[get("/login-info")]
    pub async fn login_info(
        config: &State<Config>,
        token: BearerToken,
        db: &State<AuthDb>,
    ) -> Result<rocket::serde::json::Json<Claims>, status::Custom<String>> {
        let secret = config.jwt_secret.to_owned();
        let get_token = token.get();
        let read_txn = db.begin_read().map_err(|e| {
            eprintln!("Error on login-info: {}", e);
            status::Custom(Status::Unauthorized, "Cannot verify session".to_string())
        })?;
        let table = read_txn.open_table(LOGIN_TABLE).map_err(|e| {
            eprintln!("Error on login-info: {}", e);
            status::Custom(Status::Unauthorized, "Cannot verify session".to_string())
        })?;
        let get_token = table.get(&*get_token).map_err(|e| {
            eprintln!("Error on login-info: {}", e);
            status::Custom(Status::Unauthorized, "Cannot verify session".to_string())
        })?;

        if get_token.is_none() {
            return Err(status::Custom(
                Status::Unauthorized,
                "Cannot verify session".to_string(),
            ));
        }
        match token.decode(&secret) {
            Ok(c) => Ok(rocket::serde::json::Json(c)),
            Err(e) => Err(status::Custom(Status::Unauthorized, e.to_string())),
        }
    }

    #[get("/logout")]
    pub async fn logout(token: BearerToken, db: &State<AuthDb>) -> status::Custom<String> {
        match invalidate_login(&token.get(), db) {
            Ok(_) => status::Custom(Status::Ok, "Logged out successfully".to_string()),
            Err(e) => {
                eprintln!("Error on logout: {}", e);
                status::Custom(
                    Status::InternalServerError,
                    "Logout process failed".to_string(),
                )
            }
        }
    }
    
    #[get("/check-token")]
    pub async fn check_token(token: BearerToken, db: &State<AuthDb>) -> status::Custom<String> {
        match check_login(&token.get(), db) {
            Ok(b) => status::Custom(Status::Ok, b.to_string()),
            Err(e) => {
                eprintln!("Error on check-token: {}", e);
                status::Custom(
                    Status::InternalServerError,
                    "Check token process failed".to_string(),
                )
            }
        }
    }
}
