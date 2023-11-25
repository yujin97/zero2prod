use actix_web::{http::header::ContentType, web, HttpResponse};

use crate::startup::HmacSecret;

#[derive(serde::Deserialize)]
pub struct QueryParams {
    error: String,
    tag: String,
}

pub async fn login_form(
    query: web::Query<Option<QueryParams>>,
    secret: web::Data<HmacSecret>,
) -> HttpResponse {
    let error_html = match query.0 {
        None => "".into(),
        Some(query) => {
            format!("<p><i>{}</i></p>", htmlescape::encode_minimal(&query.error))
        }
    };
    HttpResponse::Ok()
        .content_type(ContentType::html())
        .body(format!(
            r#"<!DOCTYPE html>
            <head>
                <meta http-equiv="content-type" content="text/html"; charset=utf-8>
                <title>Login</title>
            </head>
            <body>
                <p><i>{error_html}</i></p>
                <form action="/login" method="post">
                    <label>Username
                        <input
                            type="text"
                            placeholder="Enter Username"
                            name="username"
                        >
                    </label>
                    <label>Password
                        <input
                            type="password"
                            placeholder="Enter Password"
                            name="password"
                        >
                    </label>
                    <button type="submit">Login</button>
                </form>
            </body>
            </html>"#,
        ))
}
