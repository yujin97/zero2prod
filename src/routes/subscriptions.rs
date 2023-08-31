use crate::FormData;
use actix_web::{web, HttpResponse};

pub async fn subscribe(_form: web::Form<FormData>) -> HttpResponse {
    HttpResponse::Ok().finish()
}
