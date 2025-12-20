use crate::auth::AuthKeyHash;

fn default_id_length() -> usize {
    4
}

fn default_database_connections() -> u32 {
    10
}

fn default_max_entries() -> i32 {
    10000
}

fn default_database_file() -> String {
    "bibin.sqlite".to_owned()
}

#[derive(serde::Deserialize)]
pub struct BibinConfig {
    pub password_hash: AuthKeyHash,
    pub prefix: String,
    #[serde(default = "default_id_length")]
    pub id_length: usize,
    #[serde(default = "default_database_file")]
    pub database_file: String,
    #[serde(default = "default_database_connections")]
    pub database_connections: u32,
    #[serde(default = "default_max_entries")]
    pub max_entries: i32,
}

#[cfg(test)]
mod tests {
    const VALID_PASSWORD_HASH: &str = "$argon2id$v=19$m=19456,t=2,p=1$PtF+PwbhZkXXMytQXH/8FQ$X5h9fRlI4Wmutwmy9NHEijsnjqrofBaosZLrjBSCvd4";

    use super::{
        default_database_connections, default_database_file, default_id_length,
        default_max_entries, BibinConfig,
    };

    #[test]
    fn check_default_values() {
        let default_values = serde_json::from_str::<BibinConfig>(
            &(r#"{ "password_hash": ""#.to_string()
                + VALID_PASSWORD_HASH
                + r#"", "prefix": "/" }"#),
        )
        .unwrap();
        assert_eq!(default_values.prefix, "/");
        assert_eq!(default_values.id_length, default_id_length());
        assert_eq!(
            default_values.database_connections,
            default_database_connections()
        );
        assert_eq!(default_values.max_entries, default_max_entries());
        assert_eq!(default_values.database_file, default_database_file());
    }

    #[test]
    fn check_invalid_password_hash() {
        assert!(serde_json::from_str::<BibinConfig>(
            &(r#"{ "password_hash": ""#.to_string() + "AAA" + r#"", "prefix": "/" }"#)
        )
        .is_err());
    }

    #[test]
    fn check_missing_values() {
        assert!(serde_json::from_str::<BibinConfig>(r#"{ "password_hash": "A" }"#).is_err());
        assert!(serde_json::from_str::<BibinConfig>(r#"{ "prefix": "/" }"#).is_err());
        assert!(serde_json::from_str::<BibinConfig>(r#"{ }"#).is_err());
        assert!(serde_json::from_str::<BibinConfig>(r#"AAAAA"#).is_err());
    }

    #[test]
    fn check_invalid_json() {
        assert!(
            serde_json::from_str::<BibinConfig>(r#"{ "password_hash": A", "prefix": "/" }"#)
                .is_err()
        );
        assert!(
            serde_json::from_str::<BibinConfig>(r#"{ "password_hash": "A", "prefix": 0.3 }"#)
                .is_err()
        );
        assert!(
            serde_json::from_str::<BibinConfig>(r#" "password_hash": "A", "prefix": "/" }"#)
                .is_err()
        );
    }
}
