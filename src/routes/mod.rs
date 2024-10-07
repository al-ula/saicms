use salvo::{handler, writing::Text, Response, Router};

pub trait PublicRouter {
    fn public(self) -> Router;
}

impl PublicRouter for Router {
    fn public(self) -> Router {
        self.get(index).push(Router::with_path("hello").get(hello))
    }
}

#[handler]
pub async fn index(res: &mut Response) {
    res.render(Text::Html(
        r#"
    <html>
        <head>
            <title>SaiCMS</title>
        </head>
        <body>
            <h1><a href="/">SaiCMS</a></h1>
            <p>Welcome to SaiCMS</p>
            <button><a href="/hello">Hello</a></button>
        </body>
    </html>
    "#,
    ))
}

#[handler]
pub async fn hello(res: &mut Response) {
    res.render(Text::Html(
        r#"
    <html>
        <head>
            <title>SaiCMS</title>
        </head>
        <body>
            <h1><a href="/">SaiCMS</a></h1>
            <p>Hello World</p>
        </body>
    </html>
    "#,
    ))
}
