use std::env;
use anyhow::Result;
use dotenv::dotenv;

#[derive(Clone)]
pub struct Config {
    pub database_url: String,
    pub redis_url: String,
    pub redis_mirrors: Vec<String>,
    pub encryption_key: Vec<u8>,
    pub appwrite_api_key: String,
    pub appwrite_endpoint: String,
    pub appwrite_project_id: String,
    pub host: String,
    pub port: u16,
    pub load_balancer_mode: bool,
}

impl Config {
    pub fn from_env() -> Result<Self> {
        dotenv().ok();

        let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");
        let redis_url = env::var("REDIS_URL").expect("REDIS_URL must be set");
        let redis_mirrors = env::var("REDIS_MIRRORS")
            .unwrap_or_default()
            .split(',')
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .collect();
        let key_hex = env::var("ENCRYPTION_KEY").expect("ENCRYPTION_KEY must be set");
        let encryption_key = hex::decode(key_hex).expect("ENCRYPTION_KEY must be valid hex");
        let appwrite_api_key = env::var("APPWRITE_API_KEY").unwrap_or_else(|_| "secret_key".to_string());
        let appwrite_endpoint = env::var("APPWRITE_ENDPOINT").unwrap_or_else(|_| "https://cloud.appwrite.io/v1".to_string());
        let appwrite_project_id = env::var("APPWRITE_PROJECT_ID").unwrap_or_else(|_| "YOUR_PROJECT_ID".to_string());
        let host = env::var("HOST").unwrap_or_else(|_| "127.0.0.1".to_string());
        let port = env::var("PORT")
            .unwrap_or_else(|_| "8080".to_string())
            .parse()
            .expect("PORT must be a number");
        let load_balancer_mode = env::var("LOAD_BALANCER_MODE")
            .unwrap_or_else(|_| "false".to_string())
            .parse()
            .unwrap_or(false);

        if encryption_key.len() != 32 {
            panic!("ENCRYPTION_KEY must be 32 bytes (64 hex characters) for AES-256");
        }

        Ok(Config {
            database_url,
            redis_url,
            redis_mirrors,
            encryption_key,
            appwrite_api_key,
            appwrite_endpoint,
            appwrite_project_id,
            host,
            port,
            load_balancer_mode,
        })
    }
}
