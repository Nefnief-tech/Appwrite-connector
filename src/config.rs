use std::env;
use anyhow::Result;
use dotenv::dotenv;

#[derive(Clone)]
pub struct Config {
    pub database_url: String,
    pub redis_url: String,
    pub encryption_key: Vec<u8>,
    pub appwrite_api_key: String,
    pub appwrite_endpoint: String,
    pub host: String,
    pub port: u16,
}

impl Config {
    pub fn from_env() -> Result<Self> {
        dotenv().ok();

        let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");
        let redis_url = env::var("REDIS_URL").expect("REDIS_URL must be set");
        let key_hex = env::var("ENCRYPTION_KEY").expect("ENCRYPTION_KEY must be set");
        let encryption_key = hex::decode(key_hex).expect("ENCRYPTION_KEY must be valid hex");
        let appwrite_api_key = env::var("APPWRITE_API_KEY").unwrap_or_else(|_| "secret_key".to_string());
        let appwrite_endpoint = env::var("APPWRITE_ENDPOINT").unwrap_or_else(|_| "https://cloud.appwrite.io/v1".to_string());
        let host = env::var("HOST").unwrap_or_else(|_| "127.0.0.1".to_string());
        let port = env::var("PORT")
            .unwrap_or_else(|_| "8080".to_string())
            .parse()
            .expect("PORT must be a number");

        if encryption_key.len() != 32 {
            panic!("ENCRYPTION_KEY must be 32 bytes (64 hex characters) for AES-256");
        }

        Ok(Config {
            database_url,
            redis_url,
            encryption_key,
            appwrite_api_key,
            appwrite_endpoint,
            host,
            port,
        })
    }
}
