use actix_web::{get, post, delete, web, HttpRequest, HttpResponse, Responder};
use crate::models::*;
use crate::db::AppState;
use crate::crypto::CryptoService;
use uuid::Uuid;
use redis::AsyncCommands;
use sqlx::Row;
use std::sync::atomic::Ordering;
use chrono::Utc;
use actix_ws::Message;
use futures_util::StreamExt as _;

// --- Helpers ---

async fn decrypt_smart(state: &AppState, encrypted_data: &str) -> Option<Vec<u8>> {
    // 1. Try current key in memory first (Fastest)
    let current_key = state.crypto_key.read().await.clone();
    let crypto = CryptoService::new(current_key);
    if let Ok(dec) = crypto.decrypt(encrypted_data) {
        log::debug!("Decryption successful with current key");
        return Some(dec);
    }

    // 2. Fallback to all keys in keys.json
    if let Ok(ks) = crate::crypto::KeyStore::load() {
        let all_keys = ks.get_all_keys();
        log::debug!("Current key failed. Trying {} previous keys...", all_keys.len());
        for (i, key_bytes) in all_keys.iter().enumerate() {
            let fallback_crypto = CryptoService::new(key_bytes.clone());
            if let Ok(dec) = fallback_crypto.decrypt(encrypted_data) {
                log::info!("Decryption successful with fallback key #{}", i);
                return Some(dec);
            }
        }
    }

    log::error!("Decryption failed with all available keys");
    None
}

async fn create_local_session(state: &AppState, user_id: &str) -> anyhow::Result<String> {
    let session_token = Uuid::new_v4().to_string();
    let mut conn = match state.redis.get_async_connection().await {
        Ok(c) => c,
        Err(e) => {
            let info = state.redis.get_connection_info();
            log::error!("Primary Redis connection failed for session creation to {}: {}", info.addr, e);
            return Err(anyhow::anyhow!("Redis primary down or auth failed"));
        }
    };
    let key = format!("session:{}", session_token);
    let _: () = conn.set_ex(&key, user_id, state.session_duration).await?;
    
    // Mirror to other Redis nodes
    let mirrors = state.redis_mirrors.read().await;
    for (i, mirror) in mirrors.iter().enumerate() {
        match mirror.get_async_connection().await {
            Ok(mut m_conn) => {
                let _: Result<(), _> = m_conn.set_ex(&key, user_id, state.session_duration).await;
            },
            Err(e) => {
                log::warn!("Failed to connect to Redis mirror #{} for session sync: {}", i, e);
            }
        }
    }
    
    Ok(session_token)
}

async fn get_user_from_session(req: &HttpRequest, state: &AppState) -> Option<String> {
    // Log all cookies for debugging
    if let Ok(cookies) = req.cookies() {
        for cookie in cookies.iter() {
            log::debug!("Incoming cookie: {}={}", cookie.name(), cookie.value());
        }
    }

    // 1. Try X-Appwrite-JWT
    let mut token = req.headers().get("x-appwrite-jwt")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string());

    // 2. Try cookies (Standard Console and Project-specific)
    if token.is_none() {
        token = req.cookie("a_session_console")
            .map(|c| c.value().to_string());
    }
    
    if token.is_none() {
        if let Some(project_id) = req.headers().get("x-appwrite-project").and_then(|h| h.to_str().ok()) {
            let cookie_name = format!("a_session_{}", project_id);
            token = req.cookie(&cookie_name).map(|c| c.value().to_string());
        }
    }

    // 3. Try Fallback header
    if token.is_none() {
        token = req.headers().get("x-fallback-session")
            .and_then(|h| h.to_str().ok())
            .map(|s| s.to_string());
    }

    let token_val = match token {
        Some(t) if !t.is_empty() => t,
        _ => {
            return None;
        }
    };

    log::debug!("Attempting to verify session token: {}", token_val);

    let mut conn = match state.redis.get_async_connection().await {
        Ok(c) => c,
        Err(e) => {
            let info = state.redis.get_connection_info();
            log::error!("Redis connection error in session check to {}: {}", info.addr, e);
            return None;
        }
    };

    let key = format!("session:{}", token_val);
    match conn.get::<_, String>(key).await {
        Ok(user_id) => {
            log::info!("Session verified for user: {}", user_id);
            Some(user_id)
        },
        Err(e) => {
            log::warn!("Session token {} not found in Redis: {}", token_val, e);
            None
        }
    }
}

// --- Appwrite API Implementation ---

#[get("/v1/ping")]
pub async fn ping() -> impl Responder {
    HttpResponse::Ok().body("pong")
}

#[get("/v1/realtime")]
pub async fn realtime(
    req: HttpRequest,
    stream: web::Payload,
    state: web::Data<AppState>,
) -> Result<HttpResponse, actix_web::Error> {
    log::info!("Realtime handshake initiated from {}", req.peer_addr().map(|a| a.to_string()).unwrap_or_else(|| "unknown".into()));
    let (res, mut session, mut msg_stream) = actix_ws::handle(&req, stream)?;

    // Extract channels from query string (Appwrite format: ?channels[]=...)
    let query = req.query_string();
    let channels: Vec<String> = query.split('&')
        .filter(|s| s.contains("channels[]="))
        .map(|s| {
            let val = s.split('=').last().unwrap_or_default();
            urlencoding::decode(val).unwrap_or_default().into_owned()
        })
        .collect();

    log::info!("Realtime connection established. Subscriptions: {:?}", channels);

    let mut broadcast_rx = state.realtime_sender.subscribe();

    actix_web::rt::spawn(async move {
        loop {
            tokio::select! {
                // Handle WebSocket message from client
                Some(res) = msg_stream.next() => {
                    match res {
                        Ok(msg) => {
                            match msg {
                                Message::Ping(bytes) => {
                                    if let Err(_) = session.pong(&bytes).await { break; }
                                }
                                Message::Close(_) => break,
                                _ => {}
                            }
                        }
                        Err(_) => break,
                    }
                }
                // Handle Broadcast event from other parts of the system (via Redis)
                Ok(event_json) = broadcast_rx.recv() => {
                    if let Ok(event) = serde_json::from_str::<AppwriteRealtimeEvent>(&event_json) {
                        let interested = if channels.is_empty() {
                            true
                        } else {
                            event.channels.iter().any(|c| channels.contains(c))
                        };

                        if interested {
                            if let Err(_) = session.text(event_json).await { break; }
                        }
                    }
                }
            }
        }
        let _ = session.close(None).await;
        log::info!("Realtime connection closed");
    });

    Ok(res)
}

async fn publish_realtime_event(
    state: &AppState,
    event_type: &str,
    db_id: &str,
    col_id: &str,
    doc_id: &str,
    payload: serde_json::Value,
) {
    let event_name = format!("databases.{}.collections.{}.documents.{}.{}", db_id, col_id, doc_id, event_type);
    let channels = vec![
        format!("databases.{}.collections.{}.documents", db_id, col_id),
        format!("databases.{}.collections.{}.documents.{}", db_id, col_id, doc_id),
        format!("databases.{}", db_id),
        "documents".to_string()
    ];

    let event = AppwriteRealtimeEvent {
        events: vec![event_name],
        channels,
        timestamp: Utc::now().to_rfc3339(),
        payload,
    };

    if let Ok(json) = serde_json::to_string(&event) {
        if let Ok(mut conn) = state.redis.get_async_connection().await {
            let _: Result<(), _> = redis::cmd("PUBLISH")
                .arg("realtime_events")
                .arg(json)
                .query_async(&mut conn).await;
        }
    }
}

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

    log::info!("User {} is fetching their account profile", user_id);

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
    log::debug!("Registration request body: {:?}", data);
    
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
        log::warn!("Registration failed: email or password empty. Body: {:?}", data);
        return HttpResponse::BadRequest().body("Missing email or password");
    }

    log::info!("New registration request for email: {} (User ID: {})", email, user_id);

    let hashed_password = match bcrypt::hash(password, bcrypt::DEFAULT_COST) {
        Ok(h) => h,
        Err(_) => return HttpResponse::InternalServerError().finish(),
    };

    let crypto = CryptoService::new(state.crypto_key.read().await.clone());
    let encrypted_hash = match crypto.encrypt(hashed_password.as_bytes()) {
        Ok(h) => h,
        Err(e) => {
            log::error!("Encryption failed during registration: {}", e);
            return HttpResponse::InternalServerError().finish();
        }
    };

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
        log::error!("Registration DB error: {:?}", res.err());
        HttpResponse::BadRequest().body("User or email already exists")
    }
}

#[post("/v1/account/sessions/email")]
pub async fn create_session(
    req: HttpRequest,
    data: web::Json<serde_json::Value>,
    state: web::Data<AppState>,
) -> impl Responder {
    state.total_requests.fetch_add(1, Ordering::Relaxed);
    let email_input = data["email"].as_str().unwrap_or("");
    let password = data["password"].as_str().unwrap_or("");
    
    let email = if email_input.contains('@') { email_input.to_string() } else { format!("{}@local.system", email_input) };
    
    log::info!("Login attempt for identifier: {}", email);

    let row = sqlx::query("SELECT id, password_hash FROM users WHERE email = $1 OR username = $2")
        .bind(&email)
        .bind(email_input)
        .fetch_optional(&state.db)
        .await;

    match row {
        Ok(Some(r)) => {
            let enc_hash: String = r.get("password_hash");
            if let Some(dec_hash) = decrypt_smart(&state, &enc_hash).await {
                let hash = String::from_utf8_lossy(&dec_hash);
                match bcrypt::verify(password, &hash) {
                    Ok(true) => {
                        let user_id: String = r.get("id");
                        if let Ok(token) = create_local_session(&state, &user_id).await {
                            let now = Utc::now();
                            let expire = now + chrono::Duration::seconds(state.session_duration as i64);
                            
                            let project_id = req.headers().get("x-appwrite-project")
                                .and_then(|h| h.to_str().ok())
                                .unwrap_or("console");

                            let cookie_name = if project_id == "console" {
                                "a_session_console".to_string()
                            } else {
                                format!("a_session_{}", project_id)
                            };

                            log::info!("Login successful for user: {}", user_id);
                            return HttpResponse::Created()
                                .cookie(actix_web::cookie::Cookie::build("a_session_console", &token)
                                    .path("/")
                                    .http_only(true)
                                    .same_site(actix_web::cookie::SameSite::None)
                                    .secure(true)
                                    .finish())
                                .cookie(actix_web::cookie::Cookie::build(cookie_name, &token)
                                    .path("/")
                                    .http_only(true)
                                    .same_site(actix_web::cookie::SameSite::None)
                                    .secure(true)
                                    .finish())
                                .json(AppwriteSession {
                                    id: token,
                                    created_at: now.to_rfc3339(),
                                    user_id,
                                    expire: expire.to_rfc3339(),
                                    provider: "email".to_string(),
                                });
                        }
                    },
                    Ok(false) => log::warn!("Invalid password for identifier: {}", email),
                    Err(e) => log::error!("Bcrypt verify error: {}", e),
                }
            }
        },
        _ => log::warn!("Auth failed for identifier: {}", email),
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
        log::info!("Logout request: Invalidating session token ending in ...{}", &t[t.len().saturating_sub(8)..]);
        if let Ok(mut conn) = state.redis.get_async_connection().await {
            let _: () = conn.del(format!("session:{}", t)).await.unwrap_or_default();
        }
    }
    HttpResponse::NoContent().finish()
}

#[get("/v1/databases/{db}/collections/{col}/documents/{id}")]
pub async fn get_document(
    req: HttpRequest,
    path: web::Path<(String, String, String)>,
    state: web::Data<AppState>,
) -> impl Responder {
    state.total_requests.fetch_add(1, Ordering::Relaxed);
    let (db_id, col_id, doc_id) = path.into_inner();
    
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

    log::info!("User {} is fetching document {} from collection {} (DB: {})", user_id, doc_id, col_id, db_id);

    let redis_key = format!("data:{}:{}", user_id, doc_id);
    let lb_enabled = state.load_balancer_mode.load(Ordering::Relaxed);

    let mut cached_val: Option<String> = None;
    if lb_enabled {
        let mirrors = state.redis_mirrors.read().await;
        let total = mirrors.len() + 1;
        let idx = state.redis_read_index.fetch_add(1, Ordering::SeqCst) % total;
        
        if idx == 0 {
            if let Ok(mut conn) = state.redis.get_async_connection().await {
                cached_val = conn.get(&redis_key).await.ok();
            }
        } else if let Some(mirror) = mirrors.get(idx - 1) {
            if let Ok(mut conn) = mirror.get_async_connection().await {
                cached_val = conn.get(&redis_key).await.ok();
            }
        }
    } else if let Ok(mut conn) = state.redis.get_async_connection().await {
        cached_val = conn.get(&redis_key).await.ok();
    }

    if let Some(enc) = cached_val {
        if let Some(dec) = decrypt_smart(&state, &enc).await {
            let data: serde_json::Value = serde_json::from_slice(&dec).unwrap_or(serde_json::Value::Null);
            return HttpResponse::Ok().json(AppwriteDocument {
                id: doc_id,
                collection_id: col_id,
                database_id: db_id,
                created_at: Utc::now().to_rfc3339(), 
                updated_at: Utc::now().to_rfc3339(),
                data,
            });
        }
    }

    let row = sqlx::query("SELECT encrypted_content, created_at FROM data_store WHERE id = $1 AND user_id = $2")
        .bind(Uuid::parse_str(&doc_id).unwrap_or_default())
        .bind(&user_id)
        .fetch_optional(&state.db)
        .await;

    if let Ok(Some(r)) = row {
        let enc: String = r.get("encrypted_content");
        let created: chrono::DateTime<Utc> = r.get("created_at");
        if let Some(dec) = decrypt_smart(&state, &enc).await {
            let data: serde_json::Value = serde_json::from_slice(&dec).unwrap_or(serde_json::Value::Null);
            return HttpResponse::Ok().json(AppwriteDocument {
                id: doc_id,
                collection_id: col_id,
                database_id: db_id,
                created_at: created.to_rfc3339(),
                updated_at: created.to_rfc3339(),
                data,
            });
        }
    }

    HttpResponse::NotFound().finish()
}

#[get("/v1/databases/{db}/collections/{col}/documents")]
pub async fn list_documents(
    req: HttpRequest,
    path: web::Path<(String, String)>,
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

    log::info!("User {} is listing documents in collection {} (DB: {})", user_id, col_id, db_id);

    let rows = sqlx::query("SELECT id, encrypted_content, created_at FROM data_store WHERE database_id = $1 AND collection_id = $2 AND user_id = $3 ORDER BY created_at DESC")
        .bind(&db_id)
        .bind(&col_id)
        .bind(&user_id)
        .fetch_all(&state.db)
        .await;

    match rows {
        Ok(rows) => {
            let mut documents = Vec::new();
            for row in rows {
                let id: Uuid = row.get("id");
                let enc: String = row.get("encrypted_content");
                let created: chrono::DateTime<Utc> = row.get("created_at");
                if let Some(dec) = decrypt_smart(&state, &enc).await {
                    let data: serde_json::Value = serde_json::from_slice(&dec).unwrap_or(serde_json::Value::Null);
                    documents.push(AppwriteDocument {
                        id: id.to_string(),
                        collection_id: col_id.clone(),
                        database_id: db_id.clone(),
                        created_at: created.to_rfc3339(),
                        updated_at: created.to_rfc3339(),
                        data,
                    });
                }
            }
            HttpResponse::Ok().json(AppwriteDocumentList {
                total: documents.len() as i64,
                documents,
            })
        },
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
    }
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

    log::info!("User {} is creating a new document in collection {} (DB: {})", user_id, col_id, db_id);

    let doc_id = data["$id"].as_str().map(|s| s.to_string()).unwrap_or_else(|| Uuid::new_v4().to_string());
    let mut payload = data.0.clone();
    if let Some(obj) = payload.as_object_mut() {
        obj.remove("$id");
        obj.remove("$permissions");
    }
    
    let payload_str = serde_json::to_string(&payload).unwrap_or_default();
    let crypto = CryptoService::new(state.crypto_key.read().await.clone());
    let encrypted = match crypto.encrypt(payload_str.as_bytes()) {
        Ok(enc) => enc,
        Err(_) => return HttpResponse::InternalServerError().finish(),
    };

    let internal_id = Uuid::new_v4();
    let res = sqlx::query("INSERT INTO data_store (id, database_id, collection_id, user_id, encrypted_content) VALUES ($1, $2, $3, $4, $5)")
        .bind(internal_id)
        .bind(&db_id)
        .bind(&col_id)
        .bind(&user_id)
        .bind(&encrypted)
        .execute(&state.db)
        .await;

    if res.is_ok() {
        let now = Utc::now().to_rfc3339();
        let doc = AppwriteDocument {
            id: doc_id.clone(),
            collection_id: col_id.clone(),
            database_id: db_id.clone(),
            created_at: now.clone(),
            updated_at: now,
            data: payload.clone(),
        };

        // Emit Realtime Event
        publish_realtime_event(&state, "create", &db_id, &col_id, &doc_id, serde_json::to_value(&doc).unwrap_or_default()).await;

        HttpResponse::Created().json(doc)
    } else {
        HttpResponse::InternalServerError().finish()
    }
}

#[delete("/v1/databases/{db}/collections/{col}/documents/{id}")]
pub async fn delete_document(
    req: HttpRequest,
    path: web::Path<(String, String, String)>,
    state: web::Data<AppState>,
) -> impl Responder {
    state.total_requests.fetch_add(1, Ordering::Relaxed);
    let (db_id, col_id, doc_id) = path.into_inner();
    
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

    log::info!("User {} is deleting document {} from collection {} (DB: {})", user_id, doc_id, col_id, db_id);

    let id_uuid = match Uuid::parse_str(&doc_id) {
        Ok(u) => u,
        Err(_) => return HttpResponse::BadRequest().body("Invalid document ID format"),
    };

    let res = sqlx::query("DELETE FROM data_store WHERE id = $1 AND user_id = $2")
        .bind(id_uuid)
        .bind(&user_id)
        .execute(&state.db)
        .await;

    match res {
        Ok(r) if r.rows_affected() > 0 => {
            // Emit Realtime Event
            publish_realtime_event(&state, "delete", &db_id, &col_id, &doc_id, serde_json::json!({ "$id": doc_id })).await;

            let mirrors = state.mirrors.read().await;
            for mirror in mirrors.iter() {
                let _ = sqlx::query("DELETE FROM data_store WHERE id = $1 AND user_id = $2")
                    .bind(id_uuid)
                    .bind(&user_id)
                    .execute(mirror)
                    .await;
            }

            let redis_key = format!("data:{}:{}", user_id, doc_id);
            if let Ok(mut conn) = state.redis.get_async_connection().await {
                let _: () = conn.del(&redis_key).await.unwrap_or_default();
            }
            let redis_mirrors = state.redis_mirrors.read().await;
            for mirror in redis_mirrors.iter() {
                if let Ok(mut conn) = mirror.get_async_connection().await {
                    let _: () = conn.del(&redis_key).await.unwrap_or_default();
                }
            }

            HttpResponse::NoContent().finish()
        },
        Ok(_) => HttpResponse::NotFound().finish(),
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
    }
}

#[post("/admin/security/wipe")]
pub async fn wipe_database(
    req: HttpRequest,
    state: web::Data<AppState>,
) -> impl Responder {
    if !validate_api_key(&req, &state) { return HttpResponse::Unauthorized().finish(); }
    
    log::warn!("FULL SYSTEM WIPE REQUESTED");

    let tables = vec!["data_store", "users", "user_profiles", "registered_databases", "registered_redis"];

    {
        let mirrors = state.mirrors.read().await;
        for mirror in mirrors.iter() {
            for table in &tables {
                let query = format!("TRUNCATE TABLE {} CASCADE", table);
                if let Err(e) = sqlx::query(&query).execute(mirror).await {
                    log::error!("Failed to truncate mirror table {}: {}", table, e);
                }
            }
        }
    }

    for table in &tables {
        let query = format!("TRUNCATE TABLE {} CASCADE", table);
        if let Err(e) = sqlx::query(&query).execute(&state.db).await {
            log::error!("Failed to truncate primary table {}: {}", table, e);
        }
    }

    let _ = sqlx::query("INSERT INTO roles_definition (name, permissions) VALUES ('admin', '{{\"data:read\", \"data:write\", \"roles:manage\"}}'), ('user', '{{\"data:read\", \"data:write\"}}') ON CONFLICT (name) DO UPDATE SET permissions = EXCLUDED.permissions").execute(&state.db).await;

    {
        let mirrors = state.mirrors.read().await;
        for mirror in mirrors.iter() {
            if let Err(e) = sqlx::query("INSERT INTO roles_definition (name, permissions) VALUES ('admin', '{{\"data:read\", \"data:write\", \"roles:manage\"}}'), ('user', '{{\"data:read\", \"data:write\"}}') ON CONFLICT (name) DO UPDATE SET permissions = EXCLUDED.permissions").execute(mirror).await {
                log::error!("Failed to reset default roles on mirror: {}", e);
            }
        }
    }

    log::info!("Clearing encrypted data from Redis caches...");
    let clear_script = "for i, name in ipairs(redis.call('KEYS', 'data:*')) do redis.call('DEL', name) end";
    
    if let Ok(mut conn) = state.redis.get_async_connection().await {
        let _: Result<(), _> = redis::cmd("EVAL").arg(clear_script).arg("0").query_async(&mut conn).await;
    }
    let redis_mirrors = state.redis_mirrors.read().await;
    for mirror in redis_mirrors.iter() {
        if let Ok(mut conn) = mirror.get_async_connection().await {
            let _: Result<(), _> = redis::cmd("EVAL").arg(clear_script).arg("0").query_async(&mut conn).await;
        }
    }

    log::info!("System wipe completed successfully.");
    HttpResponse::Ok().json(MessageResponse { message: "System wiped successfully".to_string() })
}

// --- Admin & Logic ---

pub async fn reroll_key_logic(state: &AppState) -> anyhow::Result<()> {
    log::info!("Starting atomic master key reroll process...");
    
    let mut key_lock = state.crypto_key.write().await;
    let old_key = key_lock.clone();
    
    let data_rows = sqlx::query("SELECT id, database_id, collection_id, user_id, encrypted_content FROM data_store").fetch_all(&state.db).await?;
    let user_rows = sqlx::query("SELECT id, username, email, password_hash FROM users").fetch_all(&state.db).await?;

    let old_crypto = CryptoService::new(old_key);
    let new_key = CryptoService::generate_key();
    let new_crypto = CryptoService::new(new_key.clone());

    log::info!("Verifying and re-encrypting data in memory...");
    
    let mut new_data_payloads = Vec::new();
    for row in &data_rows {
        let id: Uuid = row.get("id");
        let old_enc: String = row.get("encrypted_content");
        let dec = old_crypto.decrypt(&old_enc).map_err(|e| {
            log::error!("CRITICAL: Failed to decrypt data_store record {}. Aborting reroll. Error: {}", id, e);
            anyhow::anyhow!("Decryption failed for record {}", id)
        })?;
        let new_enc = new_crypto.encrypt(&dec).unwrap();
        new_data_payloads.push((id, new_enc));
    }

    let mut new_user_payloads = Vec::new();
    for row in &user_rows {
        let id: String = row.get("id");
        let old_enc: String = row.get("password_hash");
        let dec = old_crypto.decrypt(&old_enc).map_err(|e| {
            log::error!("CRITICAL: Failed to decrypt user hash {}. Aborting reroll. Error: {}", id, e);
            anyhow::anyhow!("Decryption failed for user {}", id)
        })?;
        let new_enc = new_crypto.encrypt(&dec).unwrap();
        new_user_payloads.push((id, new_enc));
    }

    log::info!("Verification successful. Committing to database...");
    let mut tx = state.db.begin().await?;

    for (id, new_enc) in &new_data_payloads {
        sqlx::query("UPDATE data_store SET encrypted_content = $1 WHERE id = $2")
            .bind(new_enc)
            .bind(id)
            .execute(&mut *tx)
            .await?;
    }

    for (id, new_enc) in &new_user_payloads {
        sqlx::query("UPDATE users SET password_hash = $1 WHERE id = $2")
            .bind(new_enc)
            .bind(id)
            .execute(&mut *tx)
            .await?;
    }

    tx.commit().await?;

    {
        let mirrors = state.mirrors.read().await;
        log::info!("Updating {} mirrors with new encrypted data...", mirrors.len());
        for mirror in mirrors.iter() {
            for (id, new_enc) in &new_data_payloads {
                let _ = sqlx::query("UPDATE data_store SET encrypted_content = $1 WHERE id = $2")
                    .bind(new_enc)
                    .bind(id)
                    .execute(mirror)
                    .await;
            }
            for (id, new_enc) in &new_user_payloads {
                let _ = sqlx::query("UPDATE users SET password_hash = $1 WHERE id = $2")
                    .bind(new_enc)
                    .bind(id)
                    .execute(mirror)
                    .await;
            }
        }
    }

    *key_lock = new_key.clone();
    let new_hex = hex::encode(new_key);
    
    if let Ok(mut ks) = crate::crypto::KeyStore::load() {
        let _ = ks.update_key(new_hex.clone());
    } else {
        let ks = crate::crypto::KeyStore {
            current_key: new_hex.clone(),
            previous_keys: Vec::new(),
            last_updated: Utc::now().to_rfc3339(),
        };
        let _ = ks.save();
    }

    let _ = update_env_file("ENCRYPTION_KEY", &new_hex);

    log::info!("Invalidating encrypted data in Redis caches...");
    let clear_script = "for i, name in ipairs(redis.call('KEYS', 'data:*')) do redis.call('DEL', name) end";
    if let Ok(mut conn) = state.redis.get_async_connection().await {
        let _: Result<(), _> = redis::cmd("EVAL").arg(clear_script).arg("0").query_async(&mut conn).await;
    }
    let redis_mirrors = state.redis_mirrors.read().await;
    for mirror in redis_mirrors.iter() {
        if let Ok(mut conn) = mirror.get_async_connection().await {
            let _: Result<(), _> = redis::cmd("EVAL").arg(clear_script).arg("0").query_async(&mut conn).await;
        }
    }

    log::info!("Master key reroll completed successfully.");
    Ok(())
}

fn update_env_file(key: &str, value: &str) -> std::io::Result<()> {
    use std::fs;
    let content = fs::read_to_string(".env").unwrap_or_default();
    let mut new_content = String::new();
    let mut found = false;
    let prefix = format!("{}=", key);
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with(&prefix) {
            if !found {
                new_content.push_str(&format!("{}={}\n", key, value));
                found = true;
            }
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

#[get("/admin/users")]
pub async fn list_users(req: HttpRequest, state: web::Data<AppState>) -> impl Responder {
    if !validate_api_key(&req, &state) { return HttpResponse::Unauthorized().finish(); }
    let rows = sqlx::query_as::<_, UserSummary>("SELECT id, username, created_at FROM users ORDER BY created_at DESC").fetch_all(&state.db).await;
    match rows {
        Ok(u) => HttpResponse::Ok().json(u),
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
    }
}

#[get("/data")]
pub async fn list_data(req: HttpRequest, state: web::Data<AppState>) -> impl Responder {
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
    let rows = sqlx::query_as::<_, DataSummary>("SELECT id, created_at FROM data_store WHERE user_id = $1 ORDER BY created_at DESC")
        .bind(user_id).fetch_all(&state.db).await;
    match rows {
        Ok(items) => HttpResponse::Ok().json(items),
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
    }
}

#[get("/roles")]
pub async fn list_roles(req: HttpRequest, state: web::Data<AppState>) -> impl Responder {
    if !validate_api_key(&req, &state) && get_user_from_session(&req, &state).await.is_none() { 
        return HttpResponse::Unauthorized().finish(); 
    }
    let rows = sqlx::query("SELECT name, permissions FROM roles_definition").fetch_all(&state.db).await;
    match rows {
        Ok(rows) => HttpResponse::Ok().json(rows.iter().map(|r| RoleDefinition { 
            name: r.get("name"), 
            permissions: r.get::<Vec<String>, _>("permissions") 
        }).collect::<Vec<_>>()),
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
    }
}

#[post("/roles")]
pub async fn update_role_definition(req: HttpRequest, data: web::Json<RoleDefinition>, state: web::Data<AppState>) -> impl Responder {
    if !validate_api_key(&req, &state) { return HttpResponse::Unauthorized().finish(); }
    log::info!("Admin is updating role definition for: {}", data.name);
    let _ = sqlx::query("INSERT INTO roles_definition (name, permissions) VALUES ($1, $2) ON CONFLICT (name) DO UPDATE SET permissions = EXCLUDED.permissions")
        .bind(&data.name).bind(&data.permissions).execute(&state.db).await;
    HttpResponse::Ok().json(MessageResponse { message: "Updated".to_string() })
}

#[get("/admin/databases")]
pub async fn list_databases(req: HttpRequest, state: web::Data<AppState>) -> impl Responder {
    if !validate_api_key(&req, &state) { return HttpResponse::Unauthorized().finish(); }
    let rows = sqlx::query("SELECT name, url FROM registered_databases").fetch_all(&state.db).await;
    match rows {
        Ok(rows) => HttpResponse::Ok().json(rows.iter().map(|r| DatabaseConfig { name: r.get("name"), url: r.get("url") }).collect::<Vec<_>>()),
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
    }
}

#[post("/admin/databases")]
pub async fn add_database(req: HttpRequest, data: web::Json<DatabaseConfig>, state: web::Data<AppState>) -> impl Responder {
    if !validate_api_key(&req, &state) { return HttpResponse::Unauthorized().finish(); }
    log::info!("Admin is registering a new database mirror: {} ({})", data.name, data.url);
    let _ = sqlx::query("INSERT INTO registered_databases (name, url) VALUES ($1, $2)").bind(&data.name).bind(&data.url).execute(&state.db).await;
    HttpResponse::Ok().json(MessageResponse { message: "Added".to_string() })
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
    
    let mut statuses = Vec::new();

    // 1. Primary Redis
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

    // 2. Mirror Redis from DB
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
    if !validate_api_key(&req, &state) { return HttpResponse::Unauthorized().finish(); }

    log::info!("Admin is registering a new Redis mirror: {} ({})", data.name, data.url);

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