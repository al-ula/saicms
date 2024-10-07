use crate::middlewares;
use salvo::fs::NamedFile;
use salvo::prelude::StatusCode;
use salvo::writing::Text;
use salvo::{handler, Request, Response, Router};
use serde_json::Value;
use tracing::error;

use crate::CONFIG;
pub trait AdminRouter {
    fn admin(self) -> Router;
}
impl AdminRouter for Router {
    fn admin(self) -> Router {
        self.unshift(
            Router::with_path("admin")
                .get(index)
                .push(Router::with_path("login").get(login_page))
                .push(Router::with_path("static/<file>").get(static_file))
                .push(
                    Router::with_path("login")
                        .hoop(middlewares::content_json)
                        .post(login_form),
                )
                .push(
                    Router::with_path("logout")
                        .hoop(middlewares::have_auth_header)
                        .get(logout),
                ),
        )
    }
}

#[handler]
pub async fn login_page() -> &'static str {
    "OK"
}

#[handler]
pub async fn login_form(req: &mut Request) -> &'static str {
    let content_type = req.headers().get("Content-Type").unwrap();
    println!("{:#?}", content_type);
    let body: Value = req
        .parse_body()
        .await
        .map_err(|e| {
            error!("{:#?}", e);
            e
        })
        .unwrap();
    println!("{:#?}", body);
    "OK"
}

#[handler]
pub async fn logout(req: &mut Request, res: &mut Response) -> &'static str {
    let token = match req.headers().get("Authorization") {
        Some(t) => t,
        None => {
            res.status_code(StatusCode::INTERNAL_SERVER_ERROR);
            return "Error";
        }
    };
    println!("{:#?}", token);
    "OK"
}

#[handler]
pub async fn static_file(req: &mut Request, res: &mut Response) {
    let file = match req.uri().path().strip_prefix("/admin/static/") {
        Some(p) => p,
        None => return,
    };
    let file_path = CONFIG.get().unwrap().admin_static.clone();
    let file_builder = file_path.join(file);
    NamedFile::builder(file_builder)
        // .attached_name(file)
        .send(req.headers(), res)
        .await;
}

#[handler]
pub async fn index(res: &mut Response) {
    res.render(Text::Plain("Admin"))
}
