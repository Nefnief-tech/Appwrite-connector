use actix_web::{get, post, delete, web, HttpRequest, HttpResponse, Responder};
use crate::models::*;
use crate::db::AppState;
use crate::crypto::CryptoService;
use uuid::Uuid;
use redis::AsyncCommands;
use sqlx::Row;
use sqlx::postgres::PgPoolOptions;
use std::sync::atomic::Ordering;
use chrono::Utc;

// --- Helper: Local Session Management ---

async fn create_local_session(state: &AppState, user_id: &str) -> anyhow::Result<String> {
    let session_token = Uuid::new_v4().to_string();
    let mut conn = state.redis.get_async_connection().await?;
    let key = format!("session:{}", session_token);
    let _: () = conn.set_ex(&key, user_id, state.session_duration).await?;
    
    // Mirror to other Redis nodes
    let mirrors = state.redis_mirrors.read().await;
    for mirror in mirrors.iter() {
        if let Ok(mut m_conn) = mirror.get_async_connection().await {
            let _: Result<(), _> = m_conn.set_ex(&key, user_id, state.session_duration).await;
        }
    }
    
    Ok(session_token)
}

async fn get_user_from_session(req: &HttpRequest, state: &AppState) -> Option<String> {
    // Check for standard Appwrite header or Cookie
    let token_owned = req.headers().get("x-appwrite-jwt")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string())
        .or_else(|| {
            req.cookie("a_session_console") 
                .map(|c| c.value().to_string())
        })
        .or_else(|| {
            // Also check standard Appwrite session header if JWT is missing
            req.headers().get("x-fallback-session")
                .and_then(|h| h.to_str().ok())
                .map(|s| s.to_string())
        })?;

    let mut conn = state.redis.get_async_connection().await.ok()?;
    let key = format!("session:{}", token_owned);
    conn.get::<_, String>(key).await.ok()
}

// --- Appwrite API Implementation ---

#[get("/v1/account")]
pub async fn get_account(
    req: HttpRequest,
    state: web::Data<AppState>,
) -> impl Responder {
    state.total_requests.fetch_add(1, Ordering::Relaxed);
    let user_id = match get_user_from_session(&req, &state).await {
        Some(id) => id,
        None => return HttpResponse::Unauthorized().finish(),
    };

    let row = sqlx::query("SELECT id, username, email, created_at FROM users WHERE id = $1")
        .bind(&user_id)
        .fetch_optional(&state.db)
        .await;

    match row {
        Ok(Some(r)) => {
            let created: chrono::DateTime<Utc> = r.get("created_at");
            HttpResponse::Ok().json(AppwriteUser {
                id: r.get("id"),
                created_at: created.to_rfc3339(),
                updated_at: created.to_rfc3339(),
                name: r.get("username"),
                email: r.get("email"),
                status: true,
            })
        },
        _ => HttpResponse::NotFound().finish(),
    }
}

#[post("/v1/account")]
pub async fn register_account(
    _req: HttpRequest,
    data: web::Json<serde_json::Value>,
    state: web::Data<AppState>,
) -> impl Responder {
    state.total_requests.fetch_add(1, Ordering::Relaxed);
    let name = data["name"].as_str().unwrap_or("unknown");
    let password = data["password"].as_str().unwrap_or("");
    let email = data["email"].as_str().unwrap_or("");
    let user_id_input = data["userId"].as_str().unwrap_or("unique()");
    
    let user_id = if user_id_input == "unique()" {
        Uuid::new_v4().to_string()
    } else {
        user_id_input.to_string()
    };

    if email.is_empty() || password.is_empty() {
        return HttpResponse::BadRequest().body("Missing email or password");
    }

    let hashed_password = match bcrypt::hash(password, bcrypt::DEFAULT_COST) {
        Ok(h) => h,
        Err(_) => return HttpResponse::InternalServerError().finish(),
    };

    let crypto = CryptoService::new(state.crypto_key.read().await.clone());
    let encrypted_hash = crypto.encrypt(hashed_password.as_bytes()).unwrap();

    let res = sqlx::query("INSERT INTO users (id, username, email, password_hash) VALUES ($1, $2, $3, $4)")
        .bind(&user_id)
        .bind(name)
        .bind(email)
        .bind(&encrypted_hash)
        .execute(&state.db)
        .await;

    if res.is_ok() {
        let mirrors = state.mirrors.read().await;
        for mirror in mirrors.iter() {
            let _ = sqlx::query("INSERT INTO users (id, username, email, password_hash) VALUES ($1, $2, $3, $4)")
                .bind(&user_id)
                .bind(name)
                .bind(email)
                .bind(&encrypted_hash)
                .execute(mirror).await;
        }
        
        let now = Utc::now().to_rfc3339();
        HttpResponse::Created().json(AppwriteUser {
            id: user_id,
            created_at: now.clone(),
            updated_at: now,
            name: name.to_string(),
            email: email.to_string(),
            status: true,
        })
    } else {
        HttpResponse::BadRequest().body("User or email already exists")
    }
}

#[post("/v1/account/sessions/email")]
pub async fn create_session(
    _req: HttpRequest,
    data: web::Json<serde_json::Value>,
    state: web::Data<AppState>,
) -> impl Responder {
    state.total_requests.fetch_add(1, Ordering::Relaxed);
    let email = data["email"].as_str().unwrap_or("");
    let password = data["password"].as_str().unwrap_or("");
    
    let row = sqlx::query("SELECT id, password_hash FROM users WHERE email = $1")
        .bind(email)
        .fetch_optional(&state.db)
        .await;

    if let Ok(Some(r)) = row {
        let enc_hash: String = r.get("password_hash");
        let crypto = CryptoService::new(state.crypto_key.read().await.clone());
        if let Ok(dec_hash) = crypto.decrypt(&enc_hash) {
            let hash = String::from_utf8_lossy(&dec_hash);
            if bcrypt::verify(password, &hash).unwrap_or(false) {
                let user_id: String = r.get("id");
                if let Ok(token) = create_local_session(&state, &user_id).await {
                    let now = Utc::now();
                    let expire = now + chrono::Duration::seconds(state.session_duration as i64);
                    
                    return HttpResponse::Created()
                        .cookie(actix_web::cookie::Cookie::build("a_session_console", &token)
                            .path("/")
                            .http_only(true)
                            .finish())
                        .json(AppwriteSession {
                            id: token,
                            created_at: now.to_rfc3339(),
                            user_id,
                            expire: expire.to_rfc3339(),
                            provider: "email".to_string(),
                        });
                }
            }
        }
    }
    HttpResponse::Unauthorized().body("Invalid credentials")
}

#[delete("/v1/account/sessions/current")]
pub async fn delete_session(
    req: HttpRequest,
    state: web::Data<AppState>,
) -> impl Responder {
    let token = req.headers().get("x-appwrite-jwt")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string());

    if let Some(t) = token {
        let mut conn = state.redis.get_async_connection().await.unwrap();
        let _: () = conn.del(format!("session:{}", t)).await.unwrap();
    }
    HttpResponse::NoContent().finish()
}

#[post("/v1/databases/{db}/collections/{col}/documents")]
pub async fn create_document(
    req: HttpRequest,
    path: web::Path<(String, String)>,
    data: web::Json<serde_json::Value>,
    state: web::Data<AppState>,
) -> impl Responder {
    state.total_requests.fetch_add(1, Ordering::Relaxed);
    let (db_id, col_id) = path.into_inner();
    
    let user_id = match get_user_from_session(&req, &state).await {
        Some(id) => id,
        None => {
            if validate_api_key(&req, &state) {
                req.headers().get("x-appwrite-user-id").and_then(|h| h.to_str().ok()).unwrap_or("admin").to_string()
            } else {
                return HttpResponse::Unauthorized().finish();
            }
        }
    };

    let doc_id = data["$id"].as_str().map(|s| s.to_string()).unwrap_or_else(|| Uuid::new_v4().to_string());
    let mut payload = data.0.clone();
    if let Some(obj) = payload.as_object_mut() {
        obj.remove("$id");
        obj.remove("$permissions");
    }
    
    let payload_str = serde_json::to_string(&payload).unwrap();
    let crypto = CryptoService::new(state.crypto_key.read().await.clone());
    let encrypted = crypto.encrypt(payload_str.as_bytes()).unwrap();

    let id = Uuid::new_v4();
    let res = sqlx::query("INSERT INTO data_store (id, user_id, encrypted_content) VALUES ($1, $2, $3)")
        .bind(id)
        .bind(&user_id)
        .bind(&encrypted)
        .execute(&state.db)
        .await;

    if res.is_ok() {
        let now = Utc::now().to_rfc3339();
        HttpResponse::Created().json(AppwriteDocument {
            id: doc_id,
            collection_id: col_id,
            database_id: db_id,
            created_at: now.clone(),
            updated_at: now,
            data: payload,
        })
    } else {
        HttpResponse::InternalServerError().finish()
    }
}

// --- Admin & Logic ---

pub async fn reroll_key_logic(state: &AppState) -> anyhow::Result<()> {
    let mut key_lock = state.crypto_key.write().await;
    let old_key = key_lock.clone();
    let old_crypto = CryptoService::new(old_key);
    
    let data_rows = sqlx::query("SELECT id, user_id, encrypted_content FROM data_store").fetch_all(&state.db).await?;
    let user_rows = sqlx::query("SELECT id, password_hash FROM users").fetch_all(&state.db).await?;

    let new_key = CryptoService::generate_key();
    let new_crypto = CryptoService::new(new_key.clone());

    for row in &data_rows {
        let id: Uuid = row.get("id");
        let old_enc: String = row.get("encrypted_content");
        if let Ok(dec) = old_crypto.decrypt(&old_enc) {
            let new_enc = new_crypto.encrypt(&dec).unwrap();
            sqlx::query("UPDATE data_store SET encrypted_content = $1 WHERE id = $2").bind(new_enc).bind(id).execute(&state.db).await?;
        }
    }

    for row in &user_rows {
        let id: String = row.get("id");
        let old_enc: String = row.get("password_hash");
        if let Ok(dec) = old_crypto.decrypt(&old_enc) {
            let new_enc = new_crypto.encrypt(&dec).unwrap();
            sqlx::query("UPDATE users SET password_hash = $1 WHERE id = $2").bind(new_enc).bind(id).execute(&state.db).await?;
        }
    }

    *key_lock = new_key.clone();
    let _ = update_env_file("ENCRYPTION_KEY", &hex::encode(new_key));
    Ok(())
}

fn update_env_file(key: &str, value: &str) -> std::io::Result<()> {
    use std::fs;
    let content = fs::read_to_string(".env").unwrap_or_default();
    let mut new_content = String::new();
    let mut found = false;
    let prefix = format!("{}=", key);
    for line in content.lines() {
        if line.starts_with(&prefix) {
            new_content.push_str(&format!("{}={}\n", key, value));
            found = true;
        } else {
            new_content.push_str(line);
            new_content.push_str("\n");
        }
    }
    if !found { new_content.push_str(&format!("{}={}\n", key, value)); }
    fs::write(".env", new_content)
}

#[get("/admin/security/status")]
pub async fn get_security_status(req: HttpRequest, state: web::Data<AppState>) -> impl Responder {
    if !validate_api_key(&req, &state) { return HttpResponse::Unauthorized().finish(); }
    HttpResponse::Ok().json(SecurityStatus {
        under_attack: state.under_attack.load(Ordering::SeqCst),
        load_balancer_mode: state.load_balancer_mode.load(Ordering::SeqCst),
        redis_mirrors_count: state.redis_mirrors.read().await.len(),
    })
}

#[post("/admin/security/attack")]
pub async fn toggle_under_attack(req: HttpRequest, state: web::Data<AppState>) -> impl Responder {
    if !validate_api_key(&req, &state) { return HttpResponse::Unauthorized().finish(); }
    let _ = reroll_key_logic(state.get_ref()).await;
    HttpResponse::Ok().json(MessageResponse { message: "Security protocol executed".to_string() })
}

#[get("/admin/stats")]
pub async fn get_stats(req: HttpRequest, state: web::Data<AppState>) -> impl Responder {
    if !validate_api_key(&req, &state) { return HttpResponse::Unauthorized().finish(); }
    let records: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM data_store").fetch_one(&state.db).await.unwrap_or(0);
    let users: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users").fetch_one(&state.db).await.unwrap_or(0);
    HttpResponse::Ok().json(SystemStats {
        total_records: records,
        total_users: users,
        total_roles: 0,
        total_requests: state.total_requests.load(Ordering::Relaxed),
        under_attack: state.under_attack.load(Ordering::SeqCst),
        load_balancer_mode: state.load_balancer_mode.load(Ordering::SeqCst),
    })
}

fn validate_api_key(req: &HttpRequest, state: &AppState) -> bool {
    req.headers().get("x-appwrite-key").map(|v| v.to_str().unwrap_or("") == state.appwrite_api_key).unwrap_or(false)
}

#[get("/admin/db-status")]
pub async fn get_db_status(req: HttpRequest, state: web::Data<AppState>) -> impl Responder {
    if !validate_api_key(&req, &state) { return HttpResponse::Unauthorized().finish(); }
    let primary_online = sqlx::query("SELECT 1").execute(&state.db).await.is_ok();
    HttpResponse::Ok().json(vec![DatabaseStatus {
        name: "Primary".to_string(),
        url: "PROTECTED".to_string(),
        online: primary_online,
        is_mirror: false,
    }])
}

#[get("/admin/redis")]
pub async fn list_redis_mirrors(req: HttpRequest, state: web::Data<AppState>) -> impl Responder {
    if !validate_api_key(&req, &state) { return HttpResponse::Unauthorized().finish(); }
    HttpResponse::Ok().json(vec![DatabaseStatus {
        name: "Local Cache".to_string(),
        url: "PROTECTED".to_string(),
        online: true,
        is_mirror: false,
    }])
}

#[post("/admin/security/load-balancer")]
pub async fn toggle_load_balancer(req: HttpRequest, state: web::Data<AppState>) -> impl Responder {
    if !validate_api_key(&req, &state) { return HttpResponse::Unauthorized().finish(); }
    state.load_balancer_mode.fetch_xor(true, Ordering::SeqCst);
    HttpResponse::Ok().json(MessageResponse { message: "Toggled".to_string() })
}

#[post("/admin/security/reroll")]
pub async fn reroll_key(req: HttpRequest, state: web::Data<AppState>) -> impl Responder {
    if !validate_api_key(&req, &state) { return HttpResponse::Unauthorized().finish(); }
    let _ = reroll_key_logic(state.get_ref()).await;
    HttpResponse::Ok().json(MessageResponse { message: "Rerolled".to_string() })
}
