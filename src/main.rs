mod admin;
mod config;
mod content;
mod db;
mod middlewares;
mod routes;

use admin::routes::AdminRouter;
use config::{Config, CONFIG};
use db::DB;
use eyre::{eyre, Report, WrapErr};
use routes::PublicRouter;
use salvo::{
    catcher::{Catcher, DefaultGoal},
    prelude::*,
};
use tracing::info;

#[tokio::main]
async fn main() -> Result<(), Report> {
    tracing_subscriber::fmt().init();
    info!("Starting saicms");

    Config::init();

    db::initialize_db().wrap_err("Failed to initialize database")?;
    let _is_db = match DB.get() {
        Some(s) => s,
        None => return Err(eyre!("DB is not initialized")),
    };
    let router = Router::new().admin().public();
    let acceptor = TcpListener::new("0.0.0.0:8000").bind().await;
    let goal = DefaultGoal::with_footer("TEST");
    let catcher = Catcher::default().hoop(goal);
    let service = Service::new(router).catcher(catcher);
    info!("Starting endpoint");
    Server::new(acceptor).serve(service).await;
    Ok(())
}
