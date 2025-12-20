use crate::auth;
use crate::io::{delete_paste, store_paste, store_paste_given_id, WritePool};
use rocket::data::ToByteUnit;
use rocket::form::Form;
use rocket::http::Status;
use rocket::response::Redirect;
use rocket::tokio::io::AsyncReadExt;
use rocket::uri;
use rocket::Data;
use rocket::State;

use crate::config::BibinConfig;
use crate::get;
use crate::IndexForm;

#[post("/", data = "<input>")]
pub async fn submit(
    config: &State<BibinConfig>,
    input: Form<IndexForm>,
    pool: &State<WritePool>,
) -> Result<Redirect, Status> {
    let form_data = input.into_inner();
    if !form_data.password.is_valid(&config.password_hash) {
        Err(Status::Unauthorized)
    } else {
        match store_paste(pool, config.id_length, config.max_entries, form_data.val).await {
            Ok(id) => {
                let uri = uri!(get::get_item(id));
                Ok(Redirect::to(uri))
            }
            Err(e) => {
                error!("[SUBMIT] {} (pool {:?})", e, pool.0);
                Err(Status::InternalServerError)
            }
        }
    }
}

#[post("/<key>", data = "<input>")]
pub async fn submit_with_key(
    config: &State<BibinConfig>,
    input: Form<IndexForm>,
    pool: &State<WritePool>,
    key: String,
) -> Result<Redirect, Status> {
    let form_data = input.into_inner();
    if !form_data.password.is_valid(&config.password_hash) {
        Err(Status::Unauthorized)
    } else {
        match store_paste_given_id(pool, key, form_data.val).await {
            Ok(id) => {
                let uri = uri!(get::get_item(id));
                Ok(Redirect::to(uri))
            }
            Err(e) => {
                error!("[SUBMIT_WITH_KEY] {} (pool {:?})", e, pool.0);
                Err(Status::InternalServerError)
            }
        }
    }
}

#[put("/", data = "<input>")]
pub async fn submit_raw(
    input: Data<'_>,
    config: &State<BibinConfig>,
    password: auth::AuthKey,
    pool: &State<WritePool>,
) -> Result<String, Status> {
    if !password.is_valid(&config.password_hash) {
        return Err(Status::Unauthorized);
    }

    let mut data = String::new();
    input
        .open(5.megabytes())
        .read_to_string(&mut data)
        .await
        .map_err(|_| Status::InternalServerError)?;

    match store_paste(pool, config.id_length, config.max_entries, data).await {
        Ok(id) => {
            let uri = uri!(get::get_item(id));
            Ok(format!("{}{}", config.prefix, uri))
        }
        Err(e) => {
            error!("[SUBMIT_RAW] {} (pool {:?})", e, pool.0);
            Err(Status::InternalServerError)
        }
    }
}

#[put("/<key>", data = "<input>")]
pub async fn submit_raw_with_key(
    input: Data<'_>,
    config: &State<BibinConfig>,
    password: auth::AuthKey,
    pool: &State<WritePool>,
    key: String,
) -> Result<String, Status> {
    if !password.is_valid(&config.password_hash) {
        return Err(Status::Unauthorized);
    }

    let mut data = String::new();
    input
        .open(5.megabytes())
        .read_to_string(&mut data)
        .await
        .map_err(|_| Status::InternalServerError)?;

    match store_paste_given_id(pool, key, data).await {
        Ok(id) => {
            let uri = uri!(get::get_item(id));
            Ok(format!("{}{}", config.prefix, uri))
        }
        Err(e) => {
            error!("[SUBMIT_RAW_WITH_KEY] {} (pool {:?})", e, pool.0);
            Err(Status::InternalServerError)
        }
    }
}

#[delete("/<id>")]
pub async fn delete(
    id: String,
    config: &State<BibinConfig>,
    password: auth::AuthKey,
    pool: &State<WritePool>,
) -> Result<String, Status> {
    if !password.is_valid(&config.password_hash) {
        return Err(Status::Unauthorized);
    }

    match delete_paste(pool, &id).await {
        Ok(id) => Ok(format!("{} deleted", id)),
        Err(e) => {
            error!("[DELETE_PASTE] {}", e);
            Err(Status::InternalServerError)
        }
    }
}

#[cfg(test)]
mod test {
    use crate::io::{get_all_paste, ReadPool};
    use crate::rocket;
    use rocket::http::{Header, Status};

    use super::{rocket_uri_macro_delete, rocket_uri_macro_submit};

    use crate::test::{create_test_client, PASSWORD};

    const ENTRY_CONTENT: &str = "This is a test";

    #[rocket::async_test]
    async fn test_simple_case() {
        let (_temp, client) = create_test_client().await;
        let read_pool = client.rocket().state::<ReadPool>().unwrap();

        let response = client
            .put(uri!(submit()))
            .body(ENTRY_CONTENT)
            .header(Header::new("X-API-Key", PASSWORD))
            .dispatch()
            .await;

        assert_eq!(response.status(), Status::Ok);
        let mut all_paste = get_all_paste(read_pool).await.unwrap();
        assert_eq!(all_paste.len(), 1);
        let the_paste = all_paste.pop().unwrap();
        assert_eq!(the_paste.1, ENTRY_CONTENT);
        let paste_id = the_paste.0;

        let response = response.into_string().await.unwrap();
        assert!(response.contains(&paste_id));

        let response = client
            .delete(uri!(delete(&paste_id)))
            .body(ENTRY_CONTENT)
            .header(Header::new("X-API-Key", PASSWORD))
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Ok);

        assert_eq!(get_all_paste(read_pool).await.unwrap().len(), 0);
    }
}
