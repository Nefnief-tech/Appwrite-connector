use actix_web::{get, post, web, HttpRequest, HttpResponse, Responder};
use crate::models::{AppwriteRequest, ApiResponse, DataSummary, UserProfile, RoleDefinition, MessageResponse, AuthRequest, AuthResponse, SystemStats, UserSummary, DatabaseConfig, DatabaseStatus};
use crate::db::AppState;
use crate::crypto::CryptoService;
use uuid::Uuid;
use redis::AsyncCommands;
use sqlx::Row;
use sqlx::postgres::PgPoolOptions;
use std::sync::atomic::Ordering;

#[post("/admin/security/attack")]
pub async fn toggle_under_attack(
    req: HttpRequest,
    state: web::Data<AppState>,
) -> impl Responder {
    let is_auth = validate_api_key(&req, &state) || verify_appwrite_session(&req, &state).await.is_some();
    if !is_auth { return HttpResponse::Unauthorized().body("Unauthorized"); }

    let current = state.under_attack.fetch_xor(true, Ordering::SeqCst);
    let new_state = !current;

    if new_state {
        log::warn!("UNDER ATTACK MODE ACTIVATED - Triggering immediate key reroll");
        if let Err(e) = reroll_key_logic(state.get_ref()).await {
             log::error!("Emergency key reroll failed: {}", e);
             return HttpResponse::InternalServerError().body(format!("Attack mode failed to reroll: {}", e));
        }
    }

    HttpResponse::Ok().json(MessageResponse { 
        message: format!("Under attack mode: {}", if new_state { "ENABLED" } else { "DISABLED" }) 
    })
}

#[get("/admin/security/status")]
pub async fn get_security_status(
    req: HttpRequest,
    state: web::Data<AppState>,
) -> impl Responder {
    let is_auth = validate_api_key(&req, &state) || verify_appwrite_session(&req, &state).await.is_some();
    if !is_auth { return HttpResponse::Unauthorized().body("Unauthorized"); }

    let status = crate::models::SecurityStatus {
        under_attack: state.under_attack.load(Ordering::SeqCst),
        load_balancer_mode: state.load_balancer_mode.load(Ordering::SeqCst),
        redis_mirrors_count: state.redis_mirrors.read().await.len(),
    };

    HttpResponse::Ok().json(status)
}

#[post("/admin/security/load-balancer")]
pub async fn toggle_load_balancer(
    req: HttpRequest,
    state: web::Data<AppState>,
) -> impl Responder {
    let is_auth = validate_api_key(&req, &state) || verify_appwrite_session(&req, &state).await.is_some();
    if !is_auth { return HttpResponse::Unauthorized().body("Unauthorized"); }

    let current = state.load_balancer_mode.fetch_xor(true, Ordering::SeqCst);
    let new_state = !current;

    HttpResponse::Ok().json(MessageResponse { 
        message: format!("Load balancer mode: {}", if new_state { "ENABLED" } else { "DISABLED" }) 
    })
}

#[post("/admin/security/reroll")]
pub async fn reroll_key(
    req: HttpRequest,
    state: web::Data<AppState>,
) -> impl Responder {
    log::info!("Manual key reroll requested via dashboard");
    let is_auth = validate_api_key(&req, &state) || verify_appwrite_session(&req, &state).await.is_some();
    if !is_auth { return HttpResponse::Unauthorized().body("Unauthorized"); }

    match reroll_key_logic(state.get_ref()).await {
        Ok(_) => HttpResponse::Ok().json(MessageResponse { message: "Encryption key rerolled successfully".to_string() }),
        Err(e) => HttpResponse::InternalServerError().body(format!("Reroll failed: {}", e)),
    }
}

pub async fn reroll_key_logic(state: &AppState) -> anyhow::Result<()> {
    // Acquire WRITE lock for the entire duration to prevent inconsistent writes
    let mut key_lock = state.crypto_key.write().await;
    let old_key = key_lock.clone();
    let old_crypto = CryptoService::new(old_key);
    
    // 1. Fetch all data that needs re-encryption
    let data_rows = sqlx::query("SELECT id, user_id, encrypted_content FROM data_store")
        .fetch_all(&state.db)
        .await?;

    let user_rows = sqlx::query("SELECT id, password_hash FROM users")
        .fetch_all(&state.db)
        .await?;

    // 2. Generate new key
    let new_key = CryptoService::generate_key();
    let new_crypto = CryptoService::new(new_key.clone());

    // 3. Re-encrypt data_store
    log::info!("Re-encrypting {} data_store records...", data_rows.len());
    let mut updated_records = Vec::new();
    for row in &data_rows {
        let id: Uuid = row.get("id");
        let user_id: String = row.get("user_id");
        let old_encrypted: String = row.get("encrypted_content");
        
        if let Ok(decrypted) = old_crypto.decrypt(&old_encrypted) {
            if let Ok(new_encrypted) = new_crypto.encrypt(&decrypted) {
                updated_records.push((id, user_id, new_encrypted));
            }
        }
    }
    log::info!("Re-encrypted {}/{} data_store records successfully", updated_records.len(), data_rows.len());

    // 4. Re-encrypt users
    log::info!("Re-encrypting {} user password hashes...", user_rows.len());
    let mut updated_users = Vec::new();
    for row in &user_rows {
        let id: String = row.get("id");
        let old_hash_enc: String = row.get("password_hash");
        
        if let Ok(decrypted) = old_crypto.decrypt(&old_hash_enc) {
            if let Ok(new_encrypted) = new_crypto.encrypt(&decrypted) {
                updated_users.push((id, new_encrypted));
            }
        }
    }
    log::info!("Re-encrypted {}/{} user password hashes successfully", updated_users.len(), user_rows.len());

    // 5. Update mirrors first
    {
        let mirrors = state.mirrors.read().await;
        log::info!("Updating {} mirrors with new encrypted data...", mirrors.len());
        for mirror in mirrors.iter() {
            // Update data_store on mirror
            for (id, _user_id, content) in &updated_records {
                if let Err(e) = sqlx::query("UPDATE data_store SET encrypted_content = $1 WHERE id = $2")
                    .bind(content)
                    .bind(id)
                    .execute(mirror)
                    .await {
                        log::error!("Mirror data re-encryption failed: {}", e);
                    }
            }
            // Update users on mirror
            for (id, content) in &updated_users {
                if let Err(e) = sqlx::query("UPDATE users SET password_hash = $1 WHERE id = $2")
                    .bind(content)
                    .bind(id)
                    .execute(mirror)
                    .await {
                        log::error!("Mirror user re-encryption failed: {}", e);
                    }
            }
        }
    }

    // 6. Update primary
    log::info!("Updating primary database with new encrypted data...");
    for (id, _user_id, content) in &updated_records {
        sqlx::query("UPDATE data_store SET encrypted_content = $1 WHERE id = $2")
            .bind(content)
            .bind(id)
            .execute(&state.db)
            .await?;
    }
    for (id, content) in &updated_users {
        sqlx::query("UPDATE users SET password_hash = $1 WHERE id = $2")
            .bind(content)
            .bind(id)
            .execute(&state.db)
            .await?;
    }
    log::info!("Primary database update complete.");

    // 7. Update the key in AppState (we already hold the lock)
    *key_lock = new_key.clone();

    // 8. Persist to .env
    let new_key_hex = hex::encode(new_key);
    let _ = update_env_file("ENCRYPTION_KEY", &new_key_hex);

    // 9. Flush Redis (Old encrypted data is invalid)
    if let Ok(mut conn) = state.redis.get_async_connection().await {
        let _: Result<(), _> = redis::cmd("FLUSHDB").query_async(&mut conn).await;
    }
    {
        let redis_mirrors = state.redis_mirrors.read().await;
        for mirror in redis_mirrors.iter() {
            if let Ok(mut conn) = mirror.get_async_connection().await {
                let _: Result<(), _> = redis::cmd("FLUSHDB").query_async(&mut conn).await;
            }
        }
    }

    Ok(())
}

fn update_env_file(key: &str, value: &str) -> std::io::Result<()> {
    use std::fs;
    let content = fs::read_to_string(".env").unwrap_or_default();
    let mut new_content = String::new();
    let mut found = false;
    let key_prefix = format!("{}=", key);
    for line in content.lines() {
        if line.starts_with(&key_prefix) {
            new_content.push_str(&format!("{}={}\n", key, value));
            found = true;
        } else {
            new_content.push_str(line);
            new_content.push_str("\n");
        }
    }
    if !found {
        new_content.push_str(&format!("{}={}\n", key, value));
    }
    fs::write(".env", new_content)
}

#[get("/admin/redis")]
pub async fn list_redis_mirrors(
    req: HttpRequest,
    state: web::Data<AppState>,
) -> impl Responder {
    let is_auth = validate_api_key(&req, &state) || verify_appwrite_session(&req, &state).await.is_some();
    if !is_auth { return HttpResponse::Unauthorized().body("Unauthorized"); }

    let mut statuses = Vec::new();

    // Primary Redis
    let mut primary_conn = state.redis.get_async_connection().await;
    let primary_online = match &mut primary_conn {
        Ok(c) => redis::cmd("PING").query_async::<_, String>(c).await.is_ok(),
        Err(_) => false,
    };
    
    statuses.push(DatabaseStatus {
        name: "Primary Redis".to_string(),
        url: "PROTECTED".to_string(),
        online: primary_online,
        is_mirror: false,
    });

    // Mirror Redis from DB
    let mirrors = sqlx::query("SELECT name, url FROM registered_redis")
        .fetch_all(&state.db)
        .await
        .unwrap_or_default();

    for row in mirrors {
        let name: String = row.get("name");
        let url: String = row.get("url");
        
        let mut client = crate::db::init_redis(&url);
        let online = match &mut client {
            Ok(c) => {
                if let Ok(mut conn) = c.get_async_connection().await {
                    redis::cmd("PING").query_async::<_, String>(&mut conn).await.is_ok()
                } else { false }
            },
            Err(_) => false,
        };

        statuses.push(DatabaseStatus {
            name,
            url,
            online,
            is_mirror: true,
        });
    }

    HttpResponse::Ok().json(statuses)
}

#[post("/admin/redis")]
pub async fn add_redis_mirror(
    req: HttpRequest,
    data: web::Json<DatabaseConfig>,
    state: web::Data<AppState>,
) -> impl Responder {
    let is_auth = validate_api_key(&req, &state) || verify_appwrite_session(&req, &state).await.is_some();
    if !is_auth { return HttpResponse::Unauthorized().body("Unauthorized"); }

    // 1. Try to connect
    let client = match crate::db::init_redis(&data.url) {
        Ok(c) => c,
        Err(e) => return HttpResponse::BadRequest().body(format!("Invalid Redis URL: {}", e)),
    };

    if let Err(e) = client.get_async_connection().await {
        return HttpResponse::BadRequest().body(format!("Failed to connect to Redis: {}", e));
    }

    // 2. Persist
    let res = sqlx::query("INSERT INTO registered_redis (name, url) VALUES ($1, $2)")
        .bind(&data.name)
        .bind(&data.url)
        .execute(&state.db)
        .await;

    match res {
        Ok(_) => {
            let mut mirrors = state.redis_mirrors.write().await;
            mirrors.push(client);
            HttpResponse::Ok().json(MessageResponse { message: "Redis mirror added".to_string() })
        },
        Err(e) => HttpResponse::InternalServerError().body(format!("Database error: {}", e)),
    }
}

#[get("/admin/db-status")]
pub async fn get_db_status(
    req: HttpRequest,
    state: web::Data<AppState>,
) -> impl Responder {
    let is_auth = validate_api_key(&req, &state) || verify_appwrite_session(&req, &state).await.is_some();
    if !is_auth { return HttpResponse::Unauthorized().body("Unauthorized"); }

    let mut statuses = Vec::new();

    // Check primary
    let primary_online = sqlx::query("SELECT 1").execute(&state.db).await.is_ok();
    statuses.push(DatabaseStatus {
        name: "Primary".to_string(),
        url: "PROTECTED".to_string(), // Don't expose main URL
        online: primary_online,
        is_mirror: false,
    });

    // Check mirrors
    let mirror_configs = sqlx::query("SELECT name, url FROM registered_databases")
        .fetch_all(&state.db)
        .await
        .unwrap_or_default();

    for config in mirror_configs {
        let name: String = config.get("name");
        let url: String = config.get("url");
        
        let test_online = PgPoolOptions::new()
            .max_connections(1)
            .acquire_timeout(std::time::Duration::from_secs(2))
            .connect(&url)
            .await.is_ok();

        statuses.push(DatabaseStatus {
            name,
            url,
            online: test_online,
            is_mirror: true,
        });
    }

    HttpResponse::Ok().json(statuses)
}

#[get("/admin/databases")]
pub async fn list_databases(
    req: HttpRequest,
    state: web::Data<AppState>,
) -> impl Responder {
    let is_auth = validate_api_key(&req, &state) || verify_appwrite_session(&req, &state).await.is_some();
    if !is_auth { return HttpResponse::Unauthorized().body("Unauthorized"); }

    let rows = sqlx::query("SELECT name, url FROM registered_databases")
        .fetch_all(&state.db)
        .await;

    match rows {
        Ok(rows) => {
            let dbs: Vec<DatabaseConfig> = rows.iter().map(|r| {
                DatabaseConfig {
                    name: r.get("name"),
                    url: r.get("url"),
                }
            }).collect();
            HttpResponse::Ok().json(dbs)
        },
        Err(e) => HttpResponse::InternalServerError().body(format!("Database error: {}", e)),
    }
}

#[post("/admin/databases")]
pub async fn add_database(
    req: HttpRequest,
    data: web::Json<DatabaseConfig>,
    state: web::Data<AppState>,
) -> impl Responder {
    let is_auth = validate_api_key(&req, &state) || verify_appwrite_session(&req, &state).await.is_some();
    if !is_auth { return HttpResponse::Unauthorized().body("Unauthorized"); }

    // 1. Try to connect to ensure it's valid
    let pool_res = PgPoolOptions::new()
        .max_connections(5)
        .connect(&data.url)
        .await;

    let pool = match pool_res {
        Ok(p) => p,
        Err(e) => return HttpResponse::BadRequest().body(format!("Failed to connect to database: {}", e)),
    };

    // 2. Initialize schema on the new mirror
    if let Err(e) = crate::db::init_db(&data.url).await {
        return HttpResponse::InternalServerError().body(format!("Failed to initialize mirror schema: {}", e));
    }

    // Sync dynamic columns from primary to the new mirror
    let columns: Vec<String> = sqlx::query(
        "SELECT column_name FROM information_schema.columns WHERE table_name = 'data_store'"
    )
    .fetch_all(&state.db)
    .await.unwrap_or_default()
    .into_iter()
    .map(|r| r.get("column_name"))
    .collect();

    for col in columns {
        let alter_query = format!("ALTER TABLE data_store ADD COLUMN IF NOT EXISTS \"{}\" TEXT", col);
        let _ = sqlx::query(&alter_query).execute(&pool).await;
    }

    // 3. Save to registered_databases
    let res = sqlx::query("INSERT INTO registered_databases (name, url) VALUES ($1, $2)")
        .bind(&data.name)
        .bind(&data.url)
        .execute(&state.db)
        .await;

    match res {
        Ok(_) => {
            // 4. Add to mirrors in memory
            let mut mirrors = state.mirrors.write().await;
            mirrors.push(pool);
            HttpResponse::Ok().json(MessageResponse { message: "Database added and initialized".to_string() })
        },
        Err(e) => HttpResponse::InternalServerError().body(format!("Database error: {}", e)),
    }
}

fn validate_api_key(req: &HttpRequest, state: &AppState) -> bool {
    state.total_requests.fetch_add(1, Ordering::Relaxed);
    match req.headers().get("x-appwrite-key") {
        Some(val) => val.to_str().unwrap_or("") == state.appwrite_api_key,
        None => false,
    }
}

async fn verify_appwrite_session(req: &HttpRequest, state: &AppState) -> Option<String> {
    let jwt = req.headers().get("x-appwrite-jwt")?.to_str().ok()?;
    
    // Try to get project ID from request headers first, fallback to config
    let project_id = req.headers().get("x-appwrite-project")
        .and_then(|h| h.to_str().ok())
        .unwrap_or(&state.appwrite_project_id);

    let client = reqwest::Client::new();
    let res = client.get(format!("{}/account", state.appwrite_endpoint))
        .header("X-Appwrite-JWT", jwt)
        .header("X-Appwrite-Project", project_id)
        .send()
        .await
        .ok()?;

    if res.status().is_success() {
        let user: serde_json::Value = res.json().await.ok()?;
        return user["$id"].as_str().map(|s| s.to_string());
    }
    None
}

#[get("/admin/stats")]
pub async fn get_stats(
    req: HttpRequest,
    state: web::Data<AppState>,
) -> impl Responder {
    let is_auth = validate_api_key(&req, &state) || verify_appwrite_session(&req, &state).await.is_some();
    if !is_auth { return HttpResponse::Unauthorized().body("Unauthorized"); }

    let records: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM data_store").fetch_one(&state.db).await.unwrap_or(0);
    let users: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users").fetch_one(&state.db).await.unwrap_or(0);
    let roles: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM roles_definition").fetch_one(&state.db).await.unwrap_or(0);

    HttpResponse::Ok().json(SystemStats {
        total_records: records,
        total_users: users,
        total_roles: roles,
        total_requests: state.total_requests.load(Ordering::Relaxed),
        under_attack: state.under_attack.load(Ordering::Relaxed),
        load_balancer_mode: state.load_balancer_mode.load(Ordering::Relaxed),
    })
}

#[get("/admin/users")]
pub async fn list_users(
    req: HttpRequest,
    state: web::Data<AppState>,
) -> impl Responder {
    let is_auth = validate_api_key(&req, &state) || verify_appwrite_session(&req, &state).await.is_some();
    if !is_auth { return HttpResponse::Unauthorized().body("Unauthorized"); }

    let rows = sqlx::query_as::<_, UserSummary>(
        "SELECT id, username, created_at FROM users ORDER BY created_at DESC"
    ).fetch_all(&state.db).await;

    match rows {
        Ok(users) => HttpResponse::Ok().json(users),
        Err(e) => HttpResponse::InternalServerError().body(format!("Database error: {}", e)),
    }
}

#[post("/data")]
pub async fn store_data(
    req: HttpRequest,
    data: web::Json<AppwriteRequest>,
    state: web::Data<AppState>,
) -> impl Responder {
    state.total_requests.fetch_add(1, Ordering::Relaxed);
    let authenticated_user_id = if validate_api_key(&req, &state) {
        req.headers().get("x-appwrite-user-id")
            .and_then(|h| h.to_str().ok())
            .map(|s| s.to_string())
    } else {
        verify_appwrite_session(&req, &state).await
    };

    let user_id = match authenticated_user_id {
        Some(id) => id,
        None => return HttpResponse::Unauthorized().body("Invalid authentication"),
    };

    let payload_str = serde_json::to_string(&data.payload).unwrap_or_default();
    
    let crypto = CryptoService::new(state.crypto_key.read().await.clone());
    let encrypted_data = match crypto.encrypt(payload_str.as_bytes()) {
        Ok(enc) => enc,
        Err(e) => return HttpResponse::InternalServerError().body(format!("Encryption error: {}", e)),
    };

    let id = Uuid::new_v4();

    // 1. Initial Insert
    let pg_res = sqlx::query("INSERT INTO data_store (id, user_id, encrypted_content) VALUES ($1, $2, $3)")
        .bind(id)
        .bind(&user_id)
        .bind(&encrypted_data)
        .execute(&state.db)
        .await;

    if let Err(e) = pg_res {
        return HttpResponse::InternalServerError().body(format!("Database error: {}", e));
    }

    // Mirror Initial Insert
    {
        let mirrors = state.mirrors.read().await;
        for mirror in mirrors.iter() {
            if let Err(e) = sqlx::query("INSERT INTO data_store (id, user_id, encrypted_content) VALUES ($1, $2, $3)")
                .bind(id)
                .bind(&user_id)
                .bind(&encrypted_data)
                .execute(mirror)
                .await {
                    log::error!("Mirror initial insert failed: {}", e);
                }
        }
    }

    // 2. Dynamic Column Sync
    if let Some(obj) = data.payload.as_object() {
        for (key, value) in obj {
            // Sanitize key (allow only alphanumeric and underscores)
            let sanitized_key: String = key.chars().filter(|c| c.is_alphanumeric() || *c == '_').collect();
            if sanitized_key.is_empty() { continue; }

            let val_str = match value {
                serde_json::Value::String(s) => s.clone(),
                _ => value.to_string(),
            };

            // Sync on Primary
            let alter_query = format!("ALTER TABLE data_store ADD COLUMN IF NOT EXISTS \"{}\" TEXT", sanitized_key);
            let _ = sqlx::query(&alter_query).execute(&state.db).await;

            let update_query = format!("UPDATE data_store SET \"{}\" = $1 WHERE id = $2", sanitized_key);
            let _ = sqlx::query(&update_query)
                .bind(&val_str)
                .bind(id)
                .execute(&state.db)
                .await;

            // Sync on Mirrors
            {
                let mirrors = state.mirrors.read().await;
                for mirror in mirrors.iter() {
                    if let Err(e) = sqlx::query(&alter_query).execute(mirror).await {
                         log::error!("Mirror ALTER TABLE failed for column {}: {}", sanitized_key, e);
                    }
                    if let Err(e) = sqlx::query(&update_query)
                        .bind(&val_str)
                        .bind(id)
                        .execute(mirror)
                        .await {
                             log::error!("Mirror column update failed for {}: {}", sanitized_key, e);
                        }
                }
            }
        }
    }

    // Store in Redis (Key now includes user_id for safety)
    let redis_key = format!("data:{}:{}", user_id, id);
    
    // Primary Redis
    if let Ok(mut conn) = state.redis.get_async_connection().await {
        let _: Result<(), _> = conn.set_ex(&redis_key, &encrypted_data, 3600).await;
    }

    // Mirror Redis
    {
        let mirrors = state.redis_mirrors.read().await;
        for mirror in mirrors.iter() {
            if let Ok(mut conn) = mirror.get_async_connection().await {
                let _: Result<(), _> = conn.set_ex(&redis_key, &encrypted_data, 3600).await;
            }
        }
    }

    HttpResponse::Ok().json(ApiResponse {
        id,
        status: "stored".to_string(),
    })
}

#[get("/data")]
pub async fn list_data(
    req: HttpRequest,
    state: web::Data<AppState>,
) -> impl Responder {
    state.total_requests.fetch_add(1, Ordering::Relaxed);
    let authenticated_user_id = if validate_api_key(&req, &state) {
        req.headers().get("x-appwrite-user-id")
            .and_then(|h| h.to_str().ok())
            .map(|s| s.to_string())
    } else {
        verify_appwrite_session(&req, &state).await
    };

    let user_id = match authenticated_user_id {
        Some(id) => id,
        None => return HttpResponse::Unauthorized().body("Invalid authentication"),
    };

    let rows = sqlx::query_as::<_, DataSummary>("SELECT id, created_at FROM data_store WHERE user_id = $1 ORDER BY created_at DESC")
        .bind(user_id)
        .fetch_all(&state.db)
        .await;

    match rows {
        Ok(items) => HttpResponse::Ok().json(items),
        Err(e) => HttpResponse::InternalServerError().body(format!("Database error: {}", e)),
    }
}

#[post("/auth/register")]
pub async fn register(
    data: web::Json<AuthRequest>,
    state: web::Data<AppState>,
) -> impl Responder {
    state.total_requests.fetch_add(1, Ordering::Relaxed);
    let hashed_password = match bcrypt::hash(&data.password, bcrypt::DEFAULT_COST) {
        Ok(h) => h,
        Err(_) => return HttpResponse::InternalServerError().body("Hashing error"),
    };

    // Encrypt the hash before storing
    let crypto = CryptoService::new(state.crypto_key.read().await.clone());
    let encrypted_hash = match crypto.encrypt(hashed_password.as_bytes()) {
        Ok(enc) => enc,
        Err(e) => return HttpResponse::InternalServerError().body(format!("Encryption error: {}", e)),
    };

    let user_id = Uuid::new_v4().to_string();

    let res = sqlx::query("INSERT INTO users (id, username, password_hash) VALUES ($1, $2, $3)")
        .bind(&user_id)
        .bind(&data.username)
        .bind(&encrypted_hash)
        .execute(&state.db)
        .await;

    if let Ok(_) = res {
        // Mirroring
        let mirrors = state.mirrors.read().await;
        for mirror in mirrors.iter() {
            if let Err(e) = sqlx::query("INSERT INTO users (id, username, password_hash) VALUES ($1, $2, $3)")
                .bind(&user_id)
                .bind(&data.username)
                .bind(&encrypted_hash)
                .execute(mirror)
                .await {
                    log::error!("Mirroring registration failed: {}", e);
                }
        }
    }

    match res {
        Ok(_) => HttpResponse::Ok().json(AuthResponse { user_id, username: data.username.clone() }),
        Err(e) => HttpResponse::BadRequest().body(format!("Registration failed: {}", e)),
    }
}

#[post("/auth/login")]
pub async fn login(
    data: web::Json<AuthRequest>,
    state: web::Data<AppState>,
) -> impl Responder {
    state.total_requests.fetch_add(1, Ordering::Relaxed);
    let row = sqlx::query("SELECT id, username, password_hash FROM users WHERE username = $1")
        .bind(&data.username)
        .fetch_optional(&state.db)
        .await;

    match row {
        Ok(Some(r)) => {
            let encrypted_password_hash: String = r.get("password_hash");
            let user_id: String = r.get("id");
            
            // Decrypt the hash first
            let crypto = CryptoService::new(state.crypto_key.read().await.clone());
            let decrypted_hash_bytes = match crypto.decrypt(&encrypted_password_hash) {
                Ok(bytes) => bytes,
                Err(_) => return HttpResponse::InternalServerError().body("Decryption error"),
            };
            let password_hash = String::from_utf8_lossy(&decrypted_hash_bytes);
            
            match bcrypt::verify(&data.password, &password_hash) {
                Ok(true) => HttpResponse::Ok().json(AuthResponse { user_id, username: data.username.clone() }),
                _ => HttpResponse::Unauthorized().body("Invalid credentials"),
            }
        },
        _ => HttpResponse::Unauthorized().body("Invalid credentials"),
    }
}

#[get("/roles")]
pub async fn list_roles(
    req: HttpRequest,
    state: web::Data<AppState>,
) -> impl Responder {
    let is_auth = validate_api_key(&req, &state) || verify_appwrite_session(&req, &state).await.is_some();
    if !is_auth {
        return HttpResponse::Unauthorized().body("Invalid authentication");
    }

    let rows = sqlx::query("SELECT name, permissions FROM roles_definition")
        .fetch_all(&state.db)
        .await;

    match rows {
        Ok(rows) => {
            let roles: Vec<RoleDefinition> = rows.iter().map(|r| {
                RoleDefinition {
                    name: r.get("name"),
                    permissions: r.get("permissions"),
                }
            }).collect();
            HttpResponse::Ok().json(roles)
        },
        Err(e) => HttpResponse::InternalServerError().body(format!("Database error: {}", e)),
    }
}

#[post("/roles")]
pub async fn update_role_definition(
    req: HttpRequest,
    data: web::Json<RoleDefinition>,
    state: web::Data<AppState>,
) -> impl Responder {
    let is_auth = validate_api_key(&req, &state) || verify_appwrite_session(&req, &state).await.is_some();
    if !is_auth {
        return HttpResponse::Unauthorized().body("Invalid authentication");
    }

    let res = sqlx::query(
        "INSERT INTO roles_definition (name, permissions) VALUES ($1, $2) 
         ON CONFLICT (name) DO UPDATE SET permissions = EXCLUDED.permissions"
    )
    .bind(&data.name)
    .bind(&data.permissions)
    .execute(&state.db)
    .await;

    if let Ok(_) = res {
        let mirrors = state.mirrors.read().await;
        for mirror in mirrors.iter() {
            if let Err(e) = sqlx::query(
                "INSERT INTO roles_definition (name, permissions) VALUES ($1, $2) 
                 ON CONFLICT (name) DO UPDATE SET permissions = EXCLUDED.permissions"
            )
            .bind(&data.name)
            .bind(&data.permissions)
            .execute(mirror)
            .await {
                log::error!("Mirroring role update failed: {}", e);
            }
        }
    }

    match res {
        Ok(_) => HttpResponse::Ok().json(MessageResponse { message: "Role definition updated".to_string() }),
        Err(e) => HttpResponse::InternalServerError().body(format!("Database error: {}", e)),
    }
}

#[get("/profile/{user_id}")]
pub async fn get_profile(
    req: HttpRequest,
    path: web::Path<String>,
    state: web::Data<AppState>,
) -> impl Responder {
    let is_auth = validate_api_key(&req, &state) || verify_appwrite_session(&req, &state).await.is_some();
    if !is_auth {
        return HttpResponse::Unauthorized().body("Invalid authentication");
    }

    let user_id = path.into_inner();
    let row = sqlx::query("SELECT user_id, roles FROM user_profiles WHERE user_id = $1")
        .bind(&user_id)
        .fetch_optional(&state.db)
        .await;

    match row {
        Ok(Some(r)) => HttpResponse::Ok().json(UserProfile {
            user_id: r.get("user_id"),
            roles: r.get("roles"),
        }),
        Ok(None) => HttpResponse::Ok().json(UserProfile {
            user_id,
            roles: vec!["user".to_string()],
        }),
        Err(e) => HttpResponse::InternalServerError().body(format!("Database error: {}", e)),
    }
}

#[post("/profile")]
pub async fn update_profile(
    req: HttpRequest,
    data: web::Json<UserProfile>,
    state: web::Data<AppState>,
) -> impl Responder {
    let is_auth = validate_api_key(&req, &state) || verify_appwrite_session(&req, &state).await.is_some();
    if !is_auth {
        return HttpResponse::Unauthorized().body("Invalid authentication");
    }

    let res = sqlx::query(
        "INSERT INTO user_profiles (user_id, roles) VALUES ($1, $2) 
         ON CONFLICT (user_id) DO UPDATE SET roles = EXCLUDED.roles, updated_at = NOW()"
    )
    .bind(&data.user_id)
    .bind(&data.roles)
    .execute(&state.db)
    .await;

    if let Ok(_) = res {
        let mirrors = state.mirrors.read().await;
        for mirror in mirrors.iter() {
            if let Err(e) = sqlx::query(
                "INSERT INTO user_profiles (user_id, roles) VALUES ($1, $2) 
                 ON CONFLICT (user_id) DO UPDATE SET roles = EXCLUDED.roles, updated_at = NOW()"
            )
            .bind(&data.user_id)
            .bind(&data.roles)
            .execute(mirror)
            .await {
                log::error!("Mirroring profile update failed: {}", e);
            }
        }
    }

    match res {
        Ok(_) => HttpResponse::Ok().json(MessageResponse { message: "Profile updated".to_string() }),
        Err(e) => HttpResponse::InternalServerError().body(format!("Database error: {}", e)),
    }
}

#[get("/data/{id}")]
pub async fn get_data(
    req: HttpRequest,
    path: web::Path<Uuid>,
    state: web::Data<AppState>,
) -> impl Responder {
    let authenticated_user_id = if validate_api_key(&req, &state) {
        req.headers().get("x-appwrite-user-id")
            .and_then(|h| h.to_str().ok())
            .map(|s| s.to_string())
    } else {
        verify_appwrite_session(&req, &state).await
    };

    let user_id = match authenticated_user_id {
        Some(id) => id,
        None => return HttpResponse::Unauthorized().body("Invalid authentication"),
    };

    let id = path.into_inner();
    let crypto = CryptoService::new(state.crypto_key.read().await.clone());

    // Try Redis first (Scoped by user_id)
    let redis_key = format!("data:{}:{}", user_id, id);
    
    let lb_enabled = state.load_balancer_mode.load(Ordering::Relaxed);
    
    if lb_enabled {
        let mirrors = state.redis_mirrors.read().await;
        let total_count = mirrors.len() + 1; // +1 for primary
        let idx = state.redis_read_index.fetch_add(1, Ordering::SeqCst) % total_count;
        
        if idx == 0 {
            if let Ok(mut conn) = state.redis.get_async_connection().await {
                if let Ok(val) = conn.get::<_, String>(&redis_key).await {
                    return decrypt_and_respond(val, crypto);
                }
            }
        } else {
            let mirror = &mirrors[idx - 1];
            if let Ok(mut conn) = mirror.get_async_connection().await {
                if let Ok(val) = conn.get::<_, String>(&redis_key).await {
                    return decrypt_and_respond(val, crypto);
                }
            }
        }
    } else {
        // Fallback to primary-only read if LB is disabled
        if let Ok(mut conn) = state.redis.get_async_connection().await {
            let res: Result<String, _> = conn.get(&redis_key).await;
            if let Ok(val) = res {
                return decrypt_and_respond(val, crypto);
            }
        }
    }

    // If not in Redis, check Postgres (Filtered by user_id)
    let row = sqlx::query("SELECT encrypted_content FROM data_store WHERE id = $1 AND user_id = $2")
        .bind(id)
        .bind(user_id)
        .fetch_optional(&state.db)
        .await;

    match row {
        Ok(Some(r)) => {
            let content: String = r.get("encrypted_content");
            
            // Cache back to all Redis nodes
            if let Ok(mut conn) = state.redis.get_async_connection().await {
                let _: Result<(), _> = conn.set_ex(&redis_key, &content, 3600).await;
            }
            {
                let mirrors = state.redis_mirrors.read().await;
                for mirror in mirrors.iter() {
                    if let Ok(mut conn) = mirror.get_async_connection().await {
                        let _: Result<(), _> = conn.set_ex(&redis_key, &content, 3600).await;
                    }
                }
            }

            decrypt_and_respond(content, crypto)
        },
        Ok(None) => HttpResponse::NotFound().body("Data not found or access denied"),
        Err(e) => HttpResponse::InternalServerError().body(format!("Database error: {}", e)),
    }
}

pub async fn proxy_to_appwrite(
    req: HttpRequest,
    body: web::Bytes,
    state: web::Data<AppState>,
) -> impl Responder {
    let path = req.path();
    let method_str = req.method().as_str();
    let query = req.query_string();
    
    let url = if query.is_empty() {
        format!("{}{}", state.appwrite_endpoint, path)
    } else {
        format!("{}{}?{}", state.appwrite_endpoint, path, query)
    };

    let client = reqwest::Client::new();
    let method = reqwest::Method::from_bytes(method_str.as_bytes()).unwrap_or(reqwest::Method::GET);
    let mut proxy_req = client.request(method, url);

    // Forward headers
    for (name, value) in req.headers().iter() {
        let name_str = name.as_str();
        if name_str.to_lowercase() != "host" {
            proxy_req = proxy_req.header(name_str, value.as_bytes());
        }
    }

    // Send body
    let res = proxy_req
        .body(body)
        .send()
        .await;

    match res {
        Ok(response) => {
            let status_u16 = response.status().as_u16();
            let mut client_resp = HttpResponse::build(actix_web::http::StatusCode::from_u16(status_u16).unwrap_or(actix_web::http::StatusCode::INTERNAL_SERVER_ERROR));
            
            for (name, value) in response.headers().iter() {
                client_resp.insert_header((name.as_str(), value.as_bytes()));
            }

            let bytes = response.bytes().await.unwrap_or_default();
            client_resp.body(bytes)
        },
        Err(e) => {
            log::error!("Proxy error: {}", e);
            HttpResponse::InternalServerError().body(format!("Proxy error: {}", e))
        }
    }
}

fn decrypt_and_respond(enc: String, crypto: CryptoService) -> HttpResponse {
    match crypto.decrypt(&enc) {
        Ok(decrypted_bytes) => {
            let decrypted_str = String::from_utf8(decrypted_bytes).unwrap_or_default();
            let json_val: serde_json::Value = serde_json::from_str(&decrypted_str).unwrap_or(serde_json::Value::Null);
            HttpResponse::Ok().json(json_val)
        },
        Err(e) => HttpResponse::InternalServerError().body(format!("Decryption error: {}", e)),
    }
}
