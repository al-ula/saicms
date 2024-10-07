use crate::db::DB;
use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::{Encoding, SaltString};
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use serde::{Deserialize, Serialize};
use serde_email::Email;
use ulid::Ulid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Account {
    id: u128,
    username: String,
    email: Email,
    secret: String,
}

impl Account {
    pub fn create(username: String, email: Email, secret: String) -> Self {
        let id = Ulid::new().0;
        Self {
            id,
            username,
            email,
            secret,
        }
    }

    pub fn create_with_id(id: u128, username: String, email: Email, secret: String) -> Self {
        Self {
            id,
            username,
            email,
            secret,
        }
    }

    pub fn get_id(&self) -> u128 {
        self.id
    }

    pub fn get_username(&self) -> String {
        self.username.clone()
    }

    pub fn get_email(&self) -> Email {
        self.email.clone()
    }

    pub fn get_secret(&self) -> String {
        self.secret.clone()
    }

    pub fn change_secret(&mut self, new_secret: String) {
        self.secret = new_secret;
    }

    pub fn change_email(&mut self, new_email: Email) {
        self.email = new_email;
    }

    pub fn change_username(&mut self, new_username: String) {
        self.username = new_username;
    }
}

pub struct Register {
    username: String,
    email: Email,
    password: String,
}

impl Register {
    pub fn new(username: String, email: Email, password: String) -> Self {
        Self {
            username,
            email,
            password,
        }
    }
    pub fn check(self) -> Result<Register, Box<dyn Send + Sync + std::error::Error>> {
        let db = match DB.get() {
            None => return Err("Database not initialized".into()),
            Some(d) => d,
        };
        let is_username = db.query_account_by_username(self.username.as_ref()).is_ok();
        let is_email = db.query_account_by_email(self.email.as_ref()).is_ok();
        if !is_username && !is_email {
            return Ok(self);
        }
        Err("Username or email already exists".into())
    }
    pub fn register(&self) -> Account {
        let salt = SaltString::generate(&mut OsRng);
        let hash = Argon2::default()
            .hash_password(self.password.as_bytes(), &salt)
            .unwrap();
        let secret = hash.hash.unwrap().to_string();
        Account::create(self.username.clone(), self.email.clone(), secret)
    }
}

pub struct Login {
    identity: LoginType,
    password: String,
}

pub enum LoginType {
    Username(String),
    Email(Email),
}

impl Login {
    pub fn new(identity: LoginType, password: String) -> Self {
        Self { identity, password }
    }

    pub async fn try_login(&self) -> Result<bool, Box<dyn Send + Sync + std::error::Error>> {
        match &self.identity {
            LoginType::Username(username) => {
                let db = match DB.get() {
                    None => return Err("Database not initialized".into()),
                    Some(d) => d,
                };
                let acc = db.query_account_by_username(username.as_ref())?;
                let pass = self.password.clone();
                let pass_hash = match PasswordHash::parse(&pass, Encoding::default()) {
                    Ok(p) => p,
                    Err(e) => return Err(e.to_string().into()),
                };
                Ok(Argon2::default()
                    .verify_password(acc.get_secret().as_bytes(), &pass_hash)
                    .is_ok())
            }
            LoginType::Email(email) => {
                let db = match DB.get() {
                    None => return Err("Database not initialized".into()),
                    Some(d) => d,
                };
                let acc = db.query_account_by_email(email.as_ref())?;
                let pass = self.password.clone();
                let pass_hash = match PasswordHash::parse(&pass, Encoding::default()) {
                    Ok(p) => p,
                    Err(e) => return Err(e.to_string().into()),
                };
                Ok(Argon2::default()
                    .verify_password(acc.get_secret().as_bytes(), &pass_hash)
                    .is_ok())
            }
        }
    }
}

pub fn hash_password(password: &str) -> Result<String, Box<dyn Send + Sync + std::error::Error>> {
    let salt = SaltString::generate(&mut OsRng);
    Ok(Argon2::default()
        .hash_password(password.as_ref(), &salt)
        .map_err(|e| e.to_string())?
        .to_string())
}

pub fn verify_password(
    hash: &str,
    password: &str,
) -> Result<bool, Box<dyn Send + Sync + std::error::Error>> {
    let pass_hash = PasswordHash::parse(&hash, Encoding::default()).map_err(|e| e.to_string())?;
    Ok(Argon2::default()
        .verify_password(password.as_bytes(), &pass_hash)
        .is_ok())
}
