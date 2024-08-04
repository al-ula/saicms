mod template;

use std::sync::Arc;
use rocket::get;
use rocket::http::Status;
use rocket::response::Redirect;
use rocket::response::status;
use crate::authentication::auth_guard::BearerToken;
use crate::template::{load_template, render_template};

pub mod routes {
    use super::*;
    pub fn admin_routes() -> Vec<rocket::Route> {
        rocket::routes![index, login]
    }
}


#[get ("/")]
pub async fn index(_token: BearerToken) -> Arc<str>{
    let s = load_template().await;
    let r = render_template(&s).await;
    Arc::from(r)
}

#[ get("/login")]
pub async fn login() -> Arc<str> {
    let s = load_template().await;
    let r = render_template(&s).await;
    Arc::from(r)
}

#[get("/logout")]
pub async fn logout(bearer_token: BearerToken) -> Result<Redirect, status::Custom<&'static str>> {
    let token = bearer_token.get();
    if token.is_empty() {
        return Err(status::Custom(Status::InternalServerError, "Cannot log out"));
    }
    Ok(Redirect::to("/login"))
}