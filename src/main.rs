#[macro_use]
extern crate rocket;

#[macro_use]
extern crate log;

mod auth;
mod config;
mod get;
mod highlight;
mod io;
mod isplaintextrequest;
mod write;

use auth::AuthKey;
use config::BibinConfig;
use highlight::Highlighter;
use rocket::response::Redirect;

use io::{ReadPool, WritePool};

#[derive(Responder)]
pub enum HtmlOrPlain {
    #[response(content_type = "html")]
    Html(String),

    #[response(content_type = "plain")]
    Plain(String),
}

#[allow(clippy::large_enum_variant)]
#[derive(Responder)]
pub enum RedirectOrContent {
    Redirect(Redirect),

    #[response(content_type = "image/png")]
    Png(Vec<u8>),

    #[response(content_type = "html")]
    Html(String),

    #[response(content_type = "plain")]
    Plain(String),
}

#[derive(FromForm, Clone)]
pub struct IndexForm {
    val: String,
    password: AuthKey,
}

#[rocket::launch]
async fn rocket() -> rocket::Rocket<rocket::Build> {
    let highlighter = Highlighter::new();

    let rkt = rocket::Rocket::build();

    // I would like to use the ADHoc helpers instead, but I need to configure the database before
    // starting rocket. I prefer to not register Pools that are in a non-working state, and then
    // read the config and init them.
    // With the current system the pools are either created and working or don't exist.
    let config = match rkt.figment().extract::<BibinConfig>() {
        Err(e) => {
            rocket::config::pretty_print_error(e);
            panic!("Configuration error");
        }
        Ok(config) => config,
    };

    let write_pool = WritePool::new(&config.database_file)
        .await
        .expect("Error when creating the writing pool");

    write_pool
        .init()
        .await
        .expect("Error during initialization");

    let read_pool = ReadPool::new(&config.database_file, config.database_connections)
        .await
        .expect("Error when creating the reading pool");

    // 16 is the ID field size in the db
    if config.id_length > 16 {
        panic!("The maximum ID size is 16");
    }

    rkt.mount(
        "/",
        routes![
            get::index,
            write::submit,
            write::submit_with_key,
            write::submit_raw,
            write::submit_raw_with_key,
            get::get_item,
            get::get_qr,
            get::all_entries,
            get::get_item_raw,
            write::delete
        ],
    )
    .manage(config)
    .manage(highlighter)
    .manage(read_pool)
    .manage(write_pool)
}

#[cfg(test)]
pub mod test {
    use crate::config::BibinConfig;
    use crate::highlight::Highlighter;
    use crate::io::{ReadPool, WritePool};
    use crate::rocket;
    use rocket::local::asynchronous::Client;
    use tempfile::NamedTempFile;

    use crate::get::{all_entries, get_item, get_item_raw, get_qr, index};
    use crate::write::{delete, submit, submit_raw, submit_raw_with_key};

    pub const PASSWORD: &str = "password123";
    pub const PASSWORD_HASH: &str = "$argon2id$v=19$m=19456,t=2,p=1$PtF+PwbhZkXXMytQXH/8FQ$X5h9fRlI4Wmutwmy9NHEijsnjqrofBaosZLrjBSCvd4";

    pub async fn create_test_client() -> (NamedTempFile, Client) {
        let temp = NamedTempFile::new().unwrap();
        let file_name = temp.path().to_str().unwrap();
        let write_pool = WritePool::new(file_name)
            .await
            .expect("Error when creating the writing pool");

        write_pool
            .init()
            .await
            .expect("Error during initialization");

        let read_pool = ReadPool::new(file_name, 10)
            .await
            .expect("Error when creating the reading pool");

        let rocket = rocket::Rocket::build()
            .manage(read_pool)
            .manage(write_pool)
            .manage(Highlighter::new())
            .manage(
                serde_json::from_str::<BibinConfig>(
                    &(r#"{ "password_hash": ""#.to_string()
                        + PASSWORD_HASH
                        + r#"", "prefix": "/" }"#),
                )
                .unwrap(),
            )
            .mount(
                "/",
                routes![
                    index,
                    all_entries,
                    get_qr,
                    get_item,
                    get_item_raw,
                    delete,
                    submit,
                    submit_raw,
                    submit_raw_with_key
                ],
            );
        // the NamedTempFile will be deleted when `temp` goes out of scope. We need
        // to hand it over to the tests so that it stays on the fs until the end of the test
        (temp, Client::untracked(rocket).await.unwrap())
    }
}
