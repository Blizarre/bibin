use std::io::stdin;

use argon2::{
    password_hash::{rand_core::OsRng, PasswordHasher, SaltString},
    Argon2,
};

fn main() {
    println!("Please enter the password");
    let mut pwd_clear_raw1 = String::new();
    if let Err(err_read) = stdin().read_line(&mut pwd_clear_raw1) {
        eprintln!("Error when reading the password: {:?}", err_read);
        std::process::exit(1);
    }
    // As per the doc, the trailing \n is not going to be removed if present.
    let pwd_clear1 = pwd_clear_raw1.strip_suffix("\n").unwrap_or(&pwd_clear_raw1);

    println!("Please re-enter the password");
    let mut pwd_clear_raw2 = String::new();
    if let Err(err_read) = stdin().read_line(&mut pwd_clear_raw2) {
        eprintln!("Error when reading the password: {:?}", err_read);
        std::process::exit(1);
    }
    let pwd_clear2 = pwd_clear_raw2.strip_suffix("\n").unwrap_or(&pwd_clear_raw2);

    if pwd_clear1 != pwd_clear2 {
        eprintln!("The passwords are different, please try again");
        std::process::exit(2);
    }

    let salt = SaltString::generate(&mut OsRng);

    // Argon2 with default params (Argon2id v19)
    let argon2 = Argon2::default();

    // Hash password to PHC string ($argon2id$v=19$...)
    let password_hash = argon2.hash_password(pwd_clear1.as_bytes(), &salt);
    match password_hash {
        Err(err_hash) => {
            eprintln!("Error when hashing the password: {:?}", err_hash);
            std::process::exit(3);
        }
        Ok(hash) => {
            println!("Please write this line in the Rocket.toml configuration file:");
            println!();
            println!("password_hash = \"{}\"", hash);
        }
    }
}
