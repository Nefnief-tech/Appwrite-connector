use sqlx::postgres::PgPoolOptions;
use sqlx::{Pool, Postgres, Row};
use redis::Client;
use anyhow::Result;
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Clone)]
pub struct AppState {
    pub db: Pool<Postgres>, // Primary DB
    pub mirrors: Arc<RwLock<Vec<Pool<Postgres>>>>, // Mirror DBs
    pub redis: Client,
    pub crypto_key: Arc<RwLock<Vec<u8>>>,
    pub appwrite_api_key: String,
    pub appwrite_endpoint: String,
}

pub async fn init_db(database_url: &str) -> Result<Pool<Postgres>> {
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(database_url)
        .await?;
    
    // Ensure table exists
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS data_store (
            id UUID PRIMARY KEY,
            user_id TEXT NOT NULL,
            encrypted_content TEXT NOT NULL,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
        );
        "#
    )
    .execute(&pool)
    .await?;

    // Migrate: Add user_id if it doesn't exist
    sqlx::query(
        r#"
        DO $$ 
        BEGIN 
            IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='data_store' AND column_name='user_id') THEN
                ALTER TABLE data_store ADD COLUMN user_id TEXT NOT NULL DEFAULT 'unknown';
            END IF;
        END $$;
        "#
    )
    .execute(&pool)
    .await?;

    // Ensure user_profiles exists
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS user_profiles (
            user_id TEXT PRIMARY KEY,
            roles TEXT[] NOT NULL DEFAULT '{}',
            updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
        );
        "#
    )
    .execute(&pool)
    .await?;

    // Migrate: Add roles array if it doesn't exist (and remove old role column if needed)
    sqlx::query(
        r#"
        DO $$ 
        BEGIN 
            IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='user_profiles' AND column_name='roles') THEN
                ALTER TABLE user_profiles ADD COLUMN roles TEXT[] NOT NULL DEFAULT '{}';
            END IF;
        END $$;
        "#
    )
    .execute(&pool)
    .await?;

    // Ensure roles definition table exists
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS roles_definition (
            name TEXT PRIMARY KEY,
            permissions TEXT[] NOT NULL DEFAULT '{}'
        );
        "#
    )
    .execute(&pool)
    .await?;

    // Ensure users table exists
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
        );
        "#
    )
    .execute(&pool)
    .await?;

    // Ensure registered_databases table exists
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS registered_databases (
            id SERIAL PRIMARY KEY,
            url TEXT UNIQUE NOT NULL,
            name TEXT NOT NULL,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
        );
        "#
    )
    .execute(&pool)
    .await?;

    // Insert default roles if table is empty
    sqlx::query(
        "INSERT INTO roles_definition (name, permissions) VALUES 
         ('admin', '{\"data:read\", \"data:write\", \"roles:manage\"}'),
         ('user', '{\"data:read\", \"data:write\"}')
         ON CONFLICT DO NOTHING"
    )
    .execute(&pool)
    .await?;

    Ok(pool)
}

pub async fn init_mirrors(pool: &Pool<Postgres>) -> Result<Vec<Pool<Postgres>>> {
    let rows = sqlx::query("SELECT url FROM registered_databases")
        .fetch_all(pool)
        .await?;

    // Get current columns from primary to sync with mirrors
    let columns: Vec<String> = sqlx::query(
        "SELECT column_name FROM information_schema.columns WHERE table_name = 'data_store'"
    )
    .fetch_all(pool)
    .await?
    .into_iter()
    .map(|r| r.get("column_name"))
    .collect();

    let mut mirrors = Vec::new();
    for row in rows {
        let url: String = row.get("url");
        match init_db(&url).await {
            Ok(mirror_pool) => {
                log::info!("Connected and initialized mirror: {}", url);
                
                // Sync dynamic columns
                for col in &columns {
                    // Skip base columns
                    if col == "id" || col == "user_id" || col == "encrypted_content" || col == "created_at" {
                        continue;
                    }
                    let alter_query = format!("ALTER TABLE data_store ADD COLUMN IF NOT EXISTS \"{}\" TEXT", col);
                    if let Err(e) = sqlx::query(&alter_query).execute(&mirror_pool).await {
                        log::error!("Failed to sync column {} to mirror: {}", col, e);
                    }
                }

                mirrors.push(mirror_pool);
            },
            Err(e) => log::error!("Failed to initialize mirror {}: {}", url, e),
        }
    }
    Ok(mirrors)
}

pub fn init_redis(redis_url: &str) -> Result<Client> {
    let client = Client::open(redis_url)?;
    Ok(client)
}
