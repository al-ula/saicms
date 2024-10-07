use salvo::prelude::{handler, Request, Response, StatusCode, Text};

#[handler]
pub async fn content_json(req: &mut Request, res: &mut Response) {
    if let Some(content_type) = req.headers().get("Content-Type") {
        if content_type != "application/json" {
            res.status_code(StatusCode::BAD_REQUEST);
            res.render(Text::Plain("Invalid Content-Type"));
        }
    }
}

#[handler]
pub async fn have_auth_header(req: &mut Request, res: &mut Response) {
    if req.headers().get("Authorization").is_none() {
        res.status_code(StatusCode::UNAUTHORIZED);
        res.render(Text::Plain("Unauthorized"));
    }
}