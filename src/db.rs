use sqlx::postgres::PgPoolOptions;
use sqlx::{Pool, Postgres, Row};
use redis::Client;
use anyhow::Result;
use std::sync::Arc;
use tokio::sync::RwLock;
use std::sync::atomic::{AtomicBool, AtomicUsize};

#[derive(Clone)]
pub struct AppState {
    pub db: Pool<Postgres>, // Primary DB
    pub mirrors: Arc<RwLock<Vec<Pool<Postgres>>>>, // Mirror DBs
    pub redis: Client,
    pub redis_mirrors: Arc<RwLock<Vec<Client>>>,
    pub crypto_key: Arc<RwLock<Vec<u8>>>,
    pub appwrite_api_key: String,
    pub session_duration: u64,
    pub under_attack: Arc<AtomicBool>,
    pub lockdown_mode: Arc<AtomicBool>,
    pub load_balancer_mode: Arc<AtomicBool>,
    pub redis_read_index: Arc<AtomicUsize>,
    pub total_requests: Arc<AtomicUsize>,
    pub realtime_sender: tokio::sync::broadcast::Sender<String>,
    pub logs: Arc<RwLock<Vec<crate::models::LogEntry>>>,
    pub s3_client: Arc<RwLock<Option<s3::Bucket>>>,
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
            database_id TEXT NOT NULL DEFAULT 'default',
            collection_id TEXT NOT NULL DEFAULT 'default',
            user_id TEXT NOT NULL,
            encrypted_content TEXT NOT NULL,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
        );
        "#
    )
    .execute(&pool)
    .await?;

    // Migration: Add columns if missing
    sqlx::query(
        r#"
        DO $$ 
        BEGIN 
            IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='data_store' AND column_name='database_id') THEN
                ALTER TABLE data_store ADD COLUMN database_id TEXT NOT NULL DEFAULT 'default';
            END IF;
            IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='data_store' AND column_name='collection_id') THEN
                ALTER TABLE data_store ADD COLUMN collection_id TEXT NOT NULL DEFAULT 'default';
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
            username TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
        );
        "#
    )
    .execute(&pool)
    .await?;

    // Migration: Add email if missing and drop old username unique constraint
    sqlx::query(
        r#"
        DO $$ 
        BEGIN 
            IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='users' AND column_name='email') THEN
                ALTER TABLE users ADD COLUMN email TEXT;
                UPDATE users SET email = username || '@local.system' WHERE email IS NULL;
                ALTER TABLE users ALTER COLUMN email SET NOT NULL;
                IF NOT EXISTS (SELECT 1 FROM pg_indexes WHERE tablename = 'users' AND indexname = 'users_email_key') THEN
                    ALTER TABLE users ADD CONSTRAINT users_email_key UNIQUE (email);
                END IF;
            END IF;
            -- Remove unique constraint from username if it exists
            IF EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'users_username_key') THEN
                ALTER TABLE users DROP CONSTRAINT users_username_key;
            END IF;

            -- Email Verification Migration
            IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='users' AND column_name='email_verified') THEN
                ALTER TABLE users ADD COLUMN email_verified BOOLEAN NOT NULL DEFAULT FALSE;
            END IF;
            IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='users' AND column_name='verification_token') THEN
                ALTER TABLE users ADD COLUMN verification_token TEXT;
            END IF;
            IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='users' AND column_name='status') THEN
                ALTER TABLE users ADD COLUMN status BOOLEAN NOT NULL DEFAULT TRUE;
            END IF;
        END $$;
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

    // Ensure registered_redis table exists
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS registered_redis (
            id SERIAL PRIMARY KEY,
            url TEXT UNIQUE NOT NULL,
            name TEXT NOT NULL,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
        );
        "#
    )
    .execute(&pool)
    .await?;

    // Ensure smtp_config table exists
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS smtp_config (
            id SERIAL PRIMARY KEY,
            host TEXT NOT NULL,
            port INTEGER NOT NULL,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            from_email TEXT NOT NULL,
            enabled BOOLEAN NOT NULL DEFAULT FALSE
        );
        "#
    )
    .execute(&pool)
    .await?;

    // Ensure s3_config table exists
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS s3_config (
            id SERIAL PRIMARY KEY,
            provider TEXT NOT NULL DEFAULT 's3',
            bucket TEXT NOT NULL,
            region TEXT NOT NULL,
            access_key TEXT NOT NULL,
            secret_key TEXT NOT NULL,
            endpoint TEXT,
            enabled BOOLEAN NOT NULL DEFAULT FALSE
        );
        "#
    )
    .execute(&pool)
    .await?;

    // Migration: Add provider to s3_config if missing
    sqlx::query(
        r#"
        DO $$ 
        BEGIN 
            IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='s3_config' AND column_name='provider') THEN
                ALTER TABLE s3_config ADD COLUMN provider TEXT NOT NULL DEFAULT 's3';
            END IF;
        END $$;
        "#
    )
    .execute(&pool)
    .await?;

    // Ensure storage_metadata table exists
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS storage_metadata (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            mime_type TEXT NOT NULL,
            size_bytes BIGINT NOT NULL,
            user_id TEXT NOT NULL,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
        );
        "#
    )
    .execute(&pool)
    .await?;

    // Ensure functions table exists
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS functions (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            runtime TEXT NOT NULL,
            enabled BOOLEAN NOT NULL DEFAULT TRUE,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
            updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
        );
        "#
    )
    .execute(&pool)
    .await?;

    // Ensure executions table exists
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS executions (
            id TEXT PRIMARY KEY,
            function_id TEXT NOT NULL,
            status TEXT NOT NULL,
            stdout TEXT NOT NULL DEFAULT '',
            stderr TEXT NOT NULL DEFAULT '',
            duration FLOAT NOT NULL DEFAULT 0,
            status_code INTEGER NOT NULL DEFAULT 0,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
        );
        "#
    )
    .execute(&pool)
    .await?;

    // Ensure websites table exists
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS websites (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            domain TEXT,
            enabled BOOLEAN NOT NULL DEFAULT TRUE,
            container_id TEXT,
            port INTEGER,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
        );
        "#
    )
    .execute(&pool)
    .await?;

    // Ensure websites table exists
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS waf_logs (
            id SERIAL PRIMARY KEY,
            ip TEXT NOT NULL,
            path TEXT NOT NULL,
            violation TEXT NOT NULL,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
        );
        "#
    )
    .execute(&pool)
    .await?;

    // Ensure traffic_logs table exists
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS traffic_logs (
            id SERIAL PRIMARY KEY,
            website_id TEXT NOT NULL,
            ip TEXT NOT NULL,
            method TEXT NOT NULL,
            path TEXT NOT NULL,
            status_code INTEGER NOT NULL,
            latency_ms BIGINT NOT NULL,
            bytes_sent BIGINT NOT NULL,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
        );
        "#
    )
    .execute(&pool)
    .await?;

    // Migration for websites table
    sqlx::query(
        r#"
        DO $$ 
        BEGIN 
            IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='websites' AND column_name='container_id') THEN
                ALTER TABLE websites ADD COLUMN container_id TEXT;
            END IF;
            IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='websites' AND column_name='port') THEN
                ALTER TABLE websites ADD COLUMN port INTEGER;
            END IF;
            IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='websites' AND column_name='ssl_cert') THEN
                ALTER TABLE websites ADD COLUMN ssl_cert TEXT;
            END IF;
            IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='websites' AND column_name='ssl_key') THEN
                ALTER TABLE websites ADD COLUMN ssl_key TEXT;
            END IF;
        END $$;
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
                        
                                    // Initial Data Sync
                                    if let Err(e) = sync_mirrors(pool, &mirror_pool, &columns).await {
                                        log::error!("Failed initial data sync for mirror {}: {}", url, e);
                                    } else {
                                        log::info!("Successfully synchronized data to mirror: {}", url);
                                    }
                        
                                    mirrors.push(mirror_pool);
                                },
                                Err(e) => log::error!("Failed to initialize mirror {}: {}", url, e),
                            }
                        }
                            Ok(mirrors)
                        }
                        
                        pub async fn ensure_collection_table(pool: &Pool<Postgres>, db_id: &str, col_id: &str) -> Result<String> {
                            // Sanitize table name: only alphanumeric and underscores
                            let sanitized_db = db_id.chars().filter(|c| c.is_alphanumeric()).collect::<String>();
                            let sanitized_col = col_id.chars().filter(|c| c.is_alphanumeric()).collect::<String>();
                            let table_name = format!("coll_{}_{}", sanitized_db, sanitized_col);
                        
                            let query = format!(
                                r#"
                                CREATE TABLE IF NOT EXISTS {} (
                                    id UUID PRIMARY KEY,
                                    user_id TEXT NOT NULL,
                                    encrypted_content TEXT NOT NULL,
                                    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
                                );
                                "#,
                                table_name
                            );
                        
                            sqlx::query(&query).execute(pool).await?;
                            Ok(table_name)
                        }
                        
                        async fn sync_mirrors(primary: &Pool<Postgres>, mirror: &Pool<Postgres>, data_store_cols: &[String]) -> Result<()> {
                        
                        // 1. Sync roles_definition
                        let roles = sqlx::query("SELECT name, permissions FROM roles_definition")
                            .fetch_all(primary)
                            .await?;
                        for role in roles {
                            let name: String = role.get("name");
                            let perms: Vec<String> = role.get("permissions");
                            sqlx::query("INSERT INTO roles_definition (name, permissions) VALUES ($1, $2) ON CONFLICT (name) DO NOTHING")
                                .bind(name)
                                .bind(perms)
                                .execute(mirror)
                                .await?;
                        }
                        
                        // 2. Sync users
                        let users = sqlx::query("SELECT id, username, email, password_hash, created_at, email_verified, verification_token, status FROM users")
                            .fetch_all(primary)
                            .await?;
                        for user in users {
                            let id: String = user.get("id");
                            let username: String = user.get("username");
                            let email: String = user.get("email");
                            let hash: String = user.get("password_hash");
                            let created: chrono::DateTime<chrono::Utc> = user.get("created_at");
                            let verified: bool = user.get("email_verified");
                            let token: Option<String> = user.get("verification_token");
                            let status: bool = user.get("status");

                            sqlx::query("INSERT INTO users (id, username, email, password_hash, created_at, email_verified, verification_token, status) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) ON CONFLICT (id) DO UPDATE SET email_verified = EXCLUDED.email_verified, verification_token = EXCLUDED.verification_token, status = EXCLUDED.status, email = EXCLUDED.email, username = EXCLUDED.username")
                                .bind(id)
                                .bind(username)
                                .bind(email)
                                .bind(hash)
                                .bind(created)
                                .bind(verified)
                                .bind(token)
                                .bind(status)
                                .execute(mirror)
                                .await?;
                        }
                        
                        // 3. Sync user_profiles
                        let profiles = sqlx::query("SELECT user_id, roles, updated_at FROM user_profiles")
                            .fetch_all(primary)
                            .await?;
                        for profile in profiles {
                            let uid: String = profile.get("user_id");
                            let roles: Vec<String> = profile.get("roles");
                            let updated: chrono::DateTime<chrono::Utc> = profile.get("updated_at");
                            sqlx::query("INSERT INTO user_profiles (user_id, roles, updated_at) VALUES ($1, $2, $3) ON CONFLICT (user_id) DO NOTHING")
                                .bind(uid)
                                .bind(roles)
                                .bind(updated)
                                .execute(mirror)
                                .await?;
                        }
                        
                        // 4. Sync data_store with dynamic columns
                        let data_rows = sqlx::query("SELECT * FROM data_store")
                            .fetch_all(primary)
                            .await?;
                        
                        for row in data_rows {
                            let mut col_names = Vec::new();
                            let mut placeholders = Vec::new();
                        
                            for (i, col) in data_store_cols.iter().enumerate() {
                                col_names.push(format!("\"{}\"", col));
                                placeholders.push(format!("${}", i + 1));
                            }
                        
                            let query = format!(
                                "INSERT INTO data_store ({}) VALUES ({}) ON CONFLICT (id) DO NOTHING",
                                col_names.join(", "),
                                placeholders.join(", ")
                            );
                        
                            let mut q = sqlx::query(&query);
                            for col in data_store_cols {
                                if col == "id" {
                                    let val: uuid::Uuid = row.try_get(col.as_str())?;
                                    q = q.bind(val);
                                } else if col == "created_at" {
                                    let val: chrono::DateTime<chrono::Utc> = row.try_get(col.as_str())?;
                                    q = q.bind(val);
                                } else if col == "database_id" || col == "collection_id" {
                                    let val: String = row.try_get(col.as_str())?;
                                    q = q.bind(val);
                                } else {
                                    let val: Option<String> = row.try_get(col.as_str())?;
                                    q = q.bind(val);
                                }
                            }
                            q.execute(mirror).await?;
                        }

                        // 5. Sync websites
                        let website_rows = sqlx::query("SELECT id, name, domain, enabled, container_id, port, created_at FROM websites")
                            .fetch_all(primary)
                            .await?;
                        for row in website_rows {
                            sqlx::query("INSERT INTO websites (id, name, domain, enabled, container_id, port, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7) ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name, domain = EXCLUDED.domain, enabled = EXCLUDED.enabled, container_id = EXCLUDED.container_id, port = EXCLUDED.port")
                                .bind(row.get::<String, _>("id"))
                                .bind(row.get::<String, _>("name"))
                                .bind(row.get::<Option<String>, _>("domain"))
                                .bind(row.get::<bool, _>("enabled"))
                                .bind(row.get::<Option<String>, _>("container_id"))
                                .bind(row.get::<Option<i32>, _>("port"))
                                .bind(row.get::<chrono::DateTime<chrono::Utc>, _>("created_at"))
                                .execute(mirror)
                                .await?;
                        }
                        
                        Ok(())
                        }
pub fn init_redis(redis_url: &str) -> Result<Client> {
    let client = Client::open(redis_url)?;
    Ok(client)
}

pub async fn init_redis_mirrors(pool: &Pool<Postgres>) -> Result<Vec<Client>> {
    let rows = sqlx::query("SELECT url FROM registered_redis")
        .fetch_all(pool)
        .await?;

    let mut mirrors = Vec::new();
    for row in rows {
        let url: String = row.get("url");
        match init_redis(&url) {
            Ok(client) => {
                log::info!("Connected to Redis mirror: {}", url);
                mirrors.push(client);
            },
            Err(e) => log::error!("Failed to connect to Redis mirror {}: {}", url, e),
        }
    }
    Ok(mirrors)
}
