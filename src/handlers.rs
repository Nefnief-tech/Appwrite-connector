use actix_web::{get, post, delete, web, HttpRequest, HttpResponse, Responder};
use actix_files::NamedFile;
use crate::models::{
    ApiResponse, AppwriteDocument, AppwriteDocumentList, AppwriteRealtimeEvent, AppwriteRequest,
    AppwriteSession, AppwriteUser, AuthRequest, AuthResponse, DatabaseConfig, DatabaseStatus,
    MessageResponse, RoleDefinition, SecurityStatus, SystemStats, UserProfile, UserSummary,
    SmtpConfig, LogEntry, DataSummary, S3Config, FileMetadata, AppwriteFunction, AppwriteExecution,
    AppwriteWebsite
};
use actix_multipart::Multipart;
use futures_util::TryStreamExt;

use crate::db::AppState;
use crate::crypto::CryptoService;
use uuid::Uuid;
use redis::AsyncCommands;
use sqlx::Row;
use std::sync::atomic::Ordering;
use chrono::Utc;
use actix_ws::Message;
use futures_util::StreamExt as _;
use lettre::{transport::smtp::authentication::Credentials, SmtpTransport, Transport, Message as LettreMessage, transport::smtp::client::Tls, transport::smtp::client::TlsParameters, message::SinglePart};
use std::process::Command;
use std::time::Instant;

use std::sync::Mutex;
use std::collections::HashMap;

lazy_static::lazy_static! {
    static ref ACME_CHALLENGES: Mutex<HashMap<String, String>> = Mutex::new(HashMap::new());
}

#[get("/.well-known/acme-challenge/{token}")]
pub async fn acme_challenge(path: web::Path<String>) -> impl Responder {
    let token = path.into_inner();
    let challenges = ACME_CHALLENGES.lock().unwrap();
    if let Some(proof) = challenges.get(&token) {
        HttpResponse::Ok().body(proof.clone())
    } else {
        HttpResponse::NotFound().finish()
    }
}

// --- Helpers ---

async fn send_verification_email(state: &AppState, to_email: &str, link: &str) -> anyhow::Result<()> {
    let smtp_config = sqlx::query_as::<_, SmtpConfig>("SELECT host, port, username, password, from_email, enabled FROM smtp_config LIMIT 1")
        .fetch_optional(&state.db)
        .await?;

    if let Some(config) = smtp_config {
        if !config.enabled {
            log::info!("SMTP is disabled, skipping email to {}", to_email);
            return Ok(());
        }

        log::info!("Sending verification email to {} via {}:{}", to_email, config.host, config.port);

        let html_body = format!(r#"
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="utf-8">
                <style>
                    body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; line-height: 1.6; color: #333; margin: 0; padding: 0; }}
                    .wrapper {{ background-color: #f4f7f9; padding: 40px 20px; }}
                    .container {{ max-width: 600px; margin: 0 auto; background: #ffffff; border-radius: 16px; overflow: hidden; box-shadow: 0 4px 12px rgba(0,0,0,0.05); border: 1px solid #eef2f6; }}
                    .header {{ background: #3b82f6; padding: 30px; text-align: center; color: white; }}
                    .content {{ padding: 40px; text-align: center; }}
                    .footer {{ padding: 20px; text-align: center; font-size: 12px; color: #94a3b8; background: #f8fafc; }}
                    .btn {{ display: inline-block; background-color: #3b82f6; color: #ffffff !important; padding: 14px 28px; border-radius: 10px; text-decoration: none; font-weight: bold; margin: 20px 0; }}
                    .link-alt {{ font-size: 12px; color: #64748b; word-break: break-all; margin-top: 20px; }}
                    h1 {{ margin: 0; font-size: 24px; }}
                </style>
            </head>
            <body>
                <div class="wrapper">
                    <div class="container">
                        <div class="header">
                            <h1>Account Verification</h1>
                        </div>
                        <div class="content">
                            <h2 style="color: #1e293b; margin-top: 0;">Confirm your email address</h2>
                            <p>Thank you for joining. Please click the button below to verify your email and complete your registration.</p>
                            <a href="{}" class="btn">Verify Email Address</a>
                            <p style="margin-top: 30px; font-size: 14px; color: #475569;">If you didn't create an account, you can safely ignore this email.</p>
                            <div class="link-alt">
                                <p>Or copy and paste this link:</p>
                                <a href="{}" style="color: #3b82f6;">{}</a>
                            </div>
                        </div>
                        <div class="footer">
                            &copy; 2025 Appwrite Connector. Secure Encrypted Infrastructure.
                        </div>
                    </div>
                </div>
            </body>
            </html>
        "#, link, link, link);

        let email = LettreMessage::builder()
            .from(config.from_email.parse()?)
            .to(to_email.parse()?)
            .subject("Verify your email address")
            .singlepart(SinglePart::html(html_body))?;

        let creds = Credentials::new(config.username, config.password);

        let tls_parameters = TlsParameters::builder(config.host.clone())
            .build()?;

        let mut mailer_builder = SmtpTransport::relay(&config.host)?
            .port(config.port as u16)
            .credentials(creds);

        // Port 465 is usually implicit TLS, Port 587 is STARTTLS
        if config.port == 465 {
            mailer_builder = mailer_builder.tls(Tls::Required(tls_parameters));
        } else {
            // Opportunistic or Required STARTTLS for 587/other
            mailer_builder = mailer_builder.tls(Tls::Opportunistic(tls_parameters));
        }

        let mailer = mailer_builder.build();

        // Use a blocking task for sending email if needed, or use async transport
        // For simplicity with lettre 0.11 we can use the sync transport in a spawn_blocking if we want to avoid blocking the executor
        // but lettre also has an async-trait based transport.
        // Let's use spawn_blocking for the synchronous build.
        tokio::task::spawn_blocking(move || {
            mailer.send(&email)
        }).await??;

        log::info!("Verification email sent successfully to {}", to_email);
    } else {
        log::warn!("SMTP not configured, cannot send verification email to {}", to_email);
    }

    Ok(())
}

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
    let mut conn = match state.redis.get_multiplexed_async_connection().await {
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
        match mirror.get_multiplexed_async_connection().await {
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

    let mut conn = match state.redis.get_multiplexed_async_connection().await {
        Ok(c) => c,
        Err(e) => {
            let info = state.redis.get_connection_info();
            log::error!("Redis connection error in session check to {}: {}", info.addr, e);
            return None;
        }
    };

    let key = format!("session:{}", token_val);
    match conn.get::<_, Option<String>>(key).await {
        Ok(Some(user_id)) => {
            log::info!("Session verified for user: {}", user_id);
            Some(user_id)
        },
        Ok(None) => {
            log::warn!("Session token {} not found in Redis", token_val);
            None
        }
        Err(e) => {
            log::error!("Redis error in session check: {}", e);
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
                // Handle Broadcast event from other parts of the system
                Ok(event_json) = broadcast_rx.recv() => {
                    // Check if it's an internal system message (log/traffic) or an Appwrite event
                    if let Ok(val) = serde_json::from_str::<serde_json::Value>(&event_json) {
                        let is_system = val.get("type").map(|t| t == "log" || t == "traffic").unwrap_or(false);
                        
                        if is_system {
                            // System messages are sent to all admin consoles
                            if let Err(_) = session.text(event_json).await { break; }
                        } else if let Ok(event) = serde_json::from_value::<AppwriteRealtimeEvent>(val) {
                            // Standard Appwrite Realtime filtering
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
        if let Ok(mut conn) = state.redis.get_multiplexed_async_connection().await {
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
        None => {
            if validate_api_key(&req, &state) {
                req.headers().get("x-appwrite-user-id").and_then(|h| h.to_str().ok()).unwrap_or("admin").to_string()
            } else {
                return HttpResponse::Unauthorized().finish();
            }
        }
    };

    log::info!("User {} is fetching their account profile", user_id);

    if user_id == "admin" {
        let now = Utc::now();
        return HttpResponse::Ok().json(AppwriteUser {
            id: "admin".to_string(),
            created_at: now.to_rfc3339(),
            updated_at: now.to_rfc3339(),
            name: "Administrator".to_string(),
            email: "admin@local.system".to_string(),
            status: true,
            emailVerification: true,
        });
    }

    let row = sqlx::query("SELECT id, username, email, created_at, email_verified FROM users WHERE id = $1")
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
                emailVerification: r.get("email_verified"),
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
    let email_input = data["email"].as_str().unwrap_or("");
    let user_id_input = data["userId"].as_str().unwrap_or("unique()");
    
    let user_id = if user_id_input == "unique()" {
        Uuid::new_v4().to_string()
    } else {
        user_id_input.to_string()
    };

    if email_input.is_empty() || password.is_empty() {
        log::warn!("Registration failed: email or password empty. Body: {:?}", data);
        return HttpResponse::BadRequest().body("Missing email or password");
    }

    let email = if email_input.contains('@') { email_input.to_string() } else { format!("{}@local.system", email_input) };

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

    let verification_token = Uuid::new_v4().to_string();
    let verification_link = format!("http://127.0.0.1:8080/v1/account/verification?userId={}&secret={}", user_id, verification_token);
    
    // Simulate sending email
    log::info!("----------------------------------------------------------------");
    log::info!("EMAIL VERIFICATION LINK for {}:", email);
    log::info!("{}", verification_link);
    log::info!("----------------------------------------------------------------");

    // Send actual email if SMTP is configured
    let email_clone = email.clone();
    let link_clone = verification_link.clone();
    let state_clone = state.get_ref().clone();
    tokio::spawn(async move {
        if let Err(e) = send_verification_email(&state_clone, &email_clone, &link_clone).await {
            log::error!("Failed to send verification email: {}", e);
        }
    });

    let res = sqlx::query("INSERT INTO users (id, username, email, password_hash, verification_token, email_verified) VALUES ($1, $2, $3, $4, $5, FALSE)")
        .bind(&user_id)
        .bind(name)
        .bind(&email)
        .bind(&encrypted_hash)
        .bind(&verification_token)
        .execute(&state.db)
        .await;

    if res.is_ok() {
        let mirrors = state.mirrors.read().await;
        for mirror in mirrors.iter() {
            let _ = sqlx::query("INSERT INTO users (id, username, email, password_hash, verification_token, email_verified) VALUES ($1, $2, $3, $4, $5, FALSE)")
                .bind(&user_id)
                .bind(name)
                .bind(&email)
                .bind(&encrypted_hash)
                .bind(&verification_token)
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
            emailVerification: false,
        })
    } else {
        log::error!("Registration DB error: {:?}", res.err());
        HttpResponse::BadRequest().body("User or email already exists")
    }
}

#[get("/v1/account/verification")]
pub async fn verify_email(
    req: HttpRequest,
    state: web::Data<AppState>,
) -> impl Responder {
    state.total_requests.fetch_add(1, Ordering::Relaxed);
    let query = req.query_string();
    let params: std::collections::HashMap<String, String> = url::form_urlencoded::parse(query.as_bytes())
        .into_owned()
        .collect();

    let user_id = match params.get("userId") {
        Some(uid) => uid,
        None => return HttpResponse::BadRequest().body("Missing userId"),
    };

    let secret = match params.get("secret") {
        Some(s) => s,
        None => return HttpResponse::BadRequest().body("Missing secret"),
    };

    log::info!("Verifying email for user {} with token {}", user_id, secret);

    let row = sqlx::query("SELECT verification_token FROM users WHERE id = $1")
        .bind(user_id)
        .fetch_optional(&state.db)
        .await;

    match row {
        Ok(Some(r)) => {
            let stored_token: Option<String> = r.get("verification_token");
            if let Some(token) = stored_token {
                if token == *secret {
                    // Update user as verified
                    let _ = sqlx::query("UPDATE users SET email_verified = TRUE, verification_token = NULL WHERE id = $1")
                        .bind(user_id)
                        .execute(&state.db)
                        .await;

                    // Sync to mirrors
                    let mirrors = state.mirrors.read().await;
                    for mirror in mirrors.iter() {
                        let _ = sqlx::query("UPDATE users SET email_verified = TRUE, verification_token = NULL WHERE id = $1")
                            .bind(user_id)
                            .execute(mirror)
                            .await;
                    }

                    return HttpResponse::Ok().content_type("text/html").body(r#"
                        <!DOCTYPE html>
                        <html lang="en">
                        <head>
                            <meta charset="UTF-8">
                            <meta name="viewport" content="width=device-width, initial-scale=1.0">
                            <title>Email Verified | Connector</title>
                            <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.0/font/bootstrap-icons.css">
                            <style>
                                @import url('https://fonts.googleapis.com/css2?family=Geist:wght@400;600;700&display=swap');
                                body { font-family: 'Geist', sans-serif; background-color: #020617; color: #f1f5f9; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; }
                                .card { background: rgba(30, 41, 59, 0.4); border: 1px solid rgba(51, 65, 85, 0.5); backdrop-filter: blur(12px); padding: 48px; border-radius: 24px; text-align: center; max-width: 400px; width: 90%; box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.5); }
                                .icon { width: 64px; height: 64px; background: #3b82f6; color: white; border-radius: 20px; display: flex; align-items: center; justify-content: center; margin: 0 auto 24px; font-size: 32px; box-shadow: 0 0 20px rgba(59, 130, 246, 0.3); }
                                h1 { margin: 0 0 12px; font-size: 24px; font-weight: 700; color: white; }
                                p { color: #94a3b8; font-size: 15px; line-height: 1.6; margin-bottom: 32px; }
                                .btn { display: block; background: #3b82f6; color: white; text-decoration: none; padding: 14px; border-radius: 12px; font-weight: 600; transition: 0.2s; }
                                .btn:hover { background: #2563eb; transform: translateY(-1px); }
                            </style>
                        </head>
                        <body>
                            <div class="card">
                                <div class="icon"><i class="bi bi-check2-circle"></i></div>
                                <h1>Email Verified!</h1>
                                <p>Your identity has been confirmed. Your account is now fully active and ready for secure data operations.</p>
                            </div>
                        </body>
                        </html>
                    "#);
                }
            }
        },
        _ => {}
    }

    HttpResponse::BadRequest().content_type("text/html").body(r#"
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Verification Failed | Connector</title>
            <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.0/font/bootstrap-icons.css">
            <style>
                @import url('https://fonts.googleapis.com/css2?family=Geist:wght@400;600;700&display=swap');
                body { font-family: 'Geist', sans-serif; background-color: #020617; color: #f1f5f9; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; }
                .card { background: rgba(30, 41, 59, 0.4); border: 1px solid rgba(239, 68, 68, 0.2); backdrop-filter: blur(12px); padding: 48px; border-radius: 24px; text-align: center; max-width: 400px; width: 90%; box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.5); }
                .icon { width: 64px; height: 64px; background: rgba(239, 68, 68, 0.2); color: #ef4444; border-radius: 20px; display: flex; align-items: center; justify-content: center; margin: 0 auto 24px; font-size: 32px; }
                h1 { margin: 0 0 12px; font-size: 24px; font-weight: 700; color: white; }
                p { color: #94a3b8; font-size: 15px; line-height: 1.6; margin-bottom: 0px; }
            </style>
        </head>
        <body>
            <div class="card">
                <div class="icon"><i class="bi bi-exclamation-triangle"></i></div>
                <h1>Verification Failed</h1>
                <p>The verification link is either invalid, expired, or has already been used. Please try requesting a new link.</p>
            </div>
        </body>
        </html>
    "#)
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

    let row = sqlx::query("SELECT id, password_hash, status FROM users WHERE email = $1 OR username = $2")
        .bind(&email)
        .bind(email_input)
        .fetch_optional(&state.db)
        .await;

    match row {
        Ok(Some(r)) => {
            let status: bool = r.get("status");
            if !status {
                log::warn!("Login attempt for suspended user: {}", email);
                return HttpResponse::Forbidden().body("Account is suspended");
            }
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
        if let Ok(mut conn) = state.redis.get_multiplexed_async_connection().await {
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

    let sanitized_db = db_id.chars().filter(|c| c.is_alphanumeric()).collect::<String>();
    let sanitized_col = col_id.chars().filter(|c| c.is_alphanumeric()).collect::<String>();
    let table_name = format!("coll_{}_{}", sanitized_db, sanitized_col);

    let redis_key = format!("data:{}:{}", user_id, doc_id);
    let lb_enabled = state.load_balancer_mode.load(Ordering::Relaxed);

    let mut cached_val: Option<String> = None;
    if lb_enabled {
        let mirrors = state.redis_mirrors.read().await;
        let total = mirrors.len() + 1;
        let idx = state.redis_read_index.fetch_add(1, Ordering::SeqCst) % total;
        
        if idx == 0 {
            if let Ok(mut conn) = state.redis.get_multiplexed_async_connection().await {
                cached_val = conn.get(&redis_key).await.ok();
            }
        } else if let Some(mirror) = mirrors.get(idx - 1) {
            if let Ok(mut conn) = mirror.get_multiplexed_async_connection().await {
                cached_val = conn.get(&redis_key).await.ok();
            }
        }
    } else if let Ok(mut conn) = state.redis.get_multiplexed_async_connection().await {
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

    let query = format!("SELECT encrypted_content, created_at FROM {} WHERE id = $1 AND user_id = $2", table_name);
    let row = sqlx::query(&query)
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

    let sanitized_db = db_id.chars().filter(|c| c.is_alphanumeric()).collect::<String>();
    let sanitized_col = col_id.chars().filter(|c| c.is_alphanumeric()).collect::<String>();
    let table_name = format!("coll_{}_{}", sanitized_db, sanitized_col);

    let query = format!("SELECT id, encrypted_content, created_at FROM {} WHERE user_id = $1 ORDER BY created_at DESC", table_name);
    let rows = sqlx::query(&query)
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

    // Ensure table exists
    let table_name = match crate::db::ensure_collection_table(&state.db, &db_id, &col_id).await {
        Ok(t) => t,
        Err(e) => {
            log::error!("Failed to ensure collection table: {}", e);
            return HttpResponse::InternalServerError().finish();
        }
    };

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

    let internal_id = match Uuid::parse_str(&doc_id) {
        Ok(u) => u,
        Err(_) => Uuid::new_v4(),
    };

    let query = format!("INSERT INTO {} (id, user_id, encrypted_content) VALUES ($1, $2, $3)", table_name);
    let res = sqlx::query(&query)
        .bind(internal_id)
        .bind(&user_id)
        .bind(&encrypted)
        .execute(&state.db)
        .await;

    if res.is_ok() {
        // Sync to mirrors
        let mirrors = state.mirrors.read().await;
        for mirror in mirrors.iter() {
            let _ = crate::db::ensure_collection_table(mirror, &db_id, &col_id).await;
            let _ = sqlx::query(&query)
                .bind(internal_id)
                .bind(&user_id)
                .bind(&encrypted)
                .execute(mirror).await;
        }

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

    let sanitized_db = db_id.chars().filter(|c| c.is_alphanumeric()).collect::<String>();
    let sanitized_col = col_id.chars().filter(|c| c.is_alphanumeric()).collect::<String>();
    let table_name = format!("coll_{}_{}", sanitized_db, sanitized_col);

    let id_uuid = match Uuid::parse_str(&doc_id) {
        Ok(u) => u,
        Err(_) => return HttpResponse::BadRequest().body("Invalid document ID format"),
    };

    let query = format!("DELETE FROM {} WHERE id = $1 AND user_id = $2", table_name);
    let res = sqlx::query(&query)
        .bind(id_uuid)
        .bind(&user_id)
        .execute(&state.db)
        .await;
// ... sync logic ...
    match res {
        Ok(r) if r.rows_affected() > 0 => {
            // Emit Realtime Event
            publish_realtime_event(&state, "delete", &db_id, &col_id, &doc_id, serde_json::json!({ "$id": doc_id })).await;

            let mirrors = state.mirrors.read().await;
            for mirror in mirrors.iter() {
                let _ = sqlx::query(&query)
                    .bind(id_uuid)
                    .bind(&user_id)
                    .execute(mirror)
                    .await;
            }

            let redis_key = format!("data:{}:{}", user_id, doc_id);
            if let Ok(mut conn) = state.redis.get_multiplexed_async_connection().await {
                let _: () = conn.del(&redis_key).await.unwrap_or_default();
            }
            let redis_mirrors = state.redis_mirrors.read().await;
            for mirror in redis_mirrors.iter() {
                if let Ok(mut conn) = mirror.get_multiplexed_async_connection().await {
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

    let mirrors = state.mirrors.read().await;

    // 1. Drop all collection tables
    let table_rows = sqlx::query("SELECT table_name FROM information_schema.tables WHERE table_name LIKE 'coll_%'").fetch_all(&state.db).await;
    if let Ok(rows) = table_rows {
        for row in rows {
            let table_name: String = row.get("table_name");
            let drop_query = format!("DROP TABLE IF EXISTS {}", table_name);
            let _ = sqlx::query(&drop_query).execute(&state.db).await;
            
            for mirror in mirrors.iter() {
                let _ = sqlx::query(&drop_query).execute(mirror).await;
            }
        }
    }

    // 2. Truncate static tables
    let tables = vec!["users", "user_profiles", "registered_databases", "registered_redis", "smtp_config"];

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

    let _ = sqlx::query("INSERT INTO roles_definition (name, permissions) VALUES ('admin', '{\"data:read\", \"data:write\", \"roles:manage\"}'), ('user', '{\"data:read\", \"data:write\"}') ON CONFLICT (name) DO UPDATE SET permissions = EXCLUDED.permissions").execute(&state.db).await;

    {
        let mirrors = state.mirrors.read().await;
        for mirror in mirrors.iter() {
            if let Err(e) = sqlx::query("INSERT INTO roles_definition (name, permissions) VALUES ('admin', '{\"data:read\", \"data:write\", \"roles:manage\"}'), ('user', '{\"data:read\", \"data:write\"}') ON CONFLICT (name) DO UPDATE SET permissions = EXCLUDED.permissions").execute(mirror).await {
                log::error!("Failed to reset default roles on mirror: {}", e);
            }
        }
    }

    log::info!("Clearing encrypted data from Redis caches...");
    let clear_script = "for i, name in ipairs(redis.call('KEYS', 'data:*')) do redis.call('DEL', name) end";
    
    if let Ok(mut conn) = state.redis.get_multiplexed_async_connection().await {
        let _: Result<(), _> = redis::cmd("EVAL").arg(clear_script).arg("0").query_async(&mut conn).await;
    }
    let redis_mirrors = state.redis_mirrors.read().await;
    for mirror in redis_mirrors.iter() {
        if let Ok(mut conn) = mirror.get_multiplexed_async_connection().await {
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
    
    // Find all collection tables
    let table_rows = sqlx::query("SELECT table_name FROM information_schema.tables WHERE table_name LIKE 'coll_%'").fetch_all(&state.db).await?;
    
    let mut all_data = Vec::new();
    for row in table_rows {
        let table_name: String = row.get("table_name");
        let query = format!("SELECT id, encrypted_content FROM {}", table_name);
        let items = sqlx::query(&query).fetch_all(&state.db).await?;
        for item in items {
            all_data.push((table_name.clone(), item.get::<Uuid, _>("id"), item.get::<String, _>("encrypted_content")));
        }
    }

    let user_rows = sqlx::query("SELECT id, username, email, password_hash FROM users").fetch_all(&state.db).await?;

    let old_crypto = CryptoService::new(old_key);
    let new_key = CryptoService::generate_key();
    let new_crypto = CryptoService::new(new_key.clone());

    log::info!("Verifying and re-encrypting data in memory...");
    
    let mut new_data_payloads = Vec::new();
    for (table, id, old_enc) in all_data {
        let dec = old_crypto.decrypt(&old_enc).map_err(|e| {
            log::error!("CRITICAL: Failed to decrypt record {} from {}. Aborting reroll. Error: {}", id, table, e);
            anyhow::anyhow!("Decryption failed for record {}", id)
        })?;
        let new_enc = new_crypto.encrypt(&dec).unwrap();
        new_data_payloads.push((table, id, new_enc));
    }
// ... user re-encryption ...
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

    for (table, id, new_enc) in &new_data_payloads {
        let query = format!("UPDATE {} SET encrypted_content = $1 WHERE id = $2", table);
        sqlx::query(&query)
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
            for (table, id, new_enc) in &new_data_payloads {
                let query = format!("UPDATE {} SET encrypted_content = $1 WHERE id = $2", table);
                let _ = sqlx::query(&query)
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
    if let Ok(mut conn) = state.redis.get_multiplexed_async_connection().await {
        let _: Result<(), _> = redis::cmd("EVAL").arg(clear_script).arg("0").query_async(&mut conn).await;
    }
    let redis_mirrors = state.redis_mirrors.read().await;
    for mirror in redis_mirrors.iter() {
        if let Ok(mut conn) = mirror.get_multiplexed_async_connection().await {
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
    let rows = sqlx::query_as::<_, UserSummary>("SELECT id, username, created_at, status FROM users ORDER BY created_at DESC").fetch_all(&state.db).await;
    match rows {
        Ok(u) => HttpResponse::Ok().json(u),
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
    }
}

#[post("/admin/users/{id}/status")]
pub async fn toggle_user_status(req: HttpRequest, path: web::Path<String>, state: web::Data<AppState>) -> impl Responder {
    if !validate_api_key(&req, &state) { return HttpResponse::Unauthorized().finish(); }
    let user_id = path.into_inner();
    
    // Toggle status
    let res = sqlx::query("UPDATE users SET status = NOT status WHERE id = $1 RETURNING status")
        .bind(&user_id)
        .fetch_one(&state.db)
        .await;

    match res {
        Ok(row) => {
            let new_status: bool = row.get("status");
            log::info!("Admin toggled status for user {}: {}", user_id, new_status);
            
            // Sync to mirrors
            let mirrors = state.mirrors.read().await;
            for mirror in mirrors.iter() {
                let _ = sqlx::query("UPDATE users SET status = $1 WHERE id = $2")
                    .bind(new_status)
                    .bind(&user_id)
                    .execute(mirror)
                    .await;
            }
            
            HttpResponse::Ok().json(MessageResponse { message: format!("User status updated to {}", if new_status { "active" } else { "suspended" }) })
        },
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

    // Since we have dynamic tables, we need to find all tables starting with 'coll_'
    let tables = sqlx::query("SELECT table_name FROM information_schema.tables WHERE table_name LIKE 'coll_%'")
        .fetch_all(&state.db)
        .await;

    let mut all_items = Vec::new();
    if let Ok(rows) = tables {
        for row in rows {
            let table_name: String = row.get("table_name");
            let query = format!("SELECT id, created_at FROM {} WHERE user_id = $1", table_name);
            if let Ok(items) = sqlx::query_as::<_, DataSummary>(&query).bind(&user_id).fetch_all(&state.db).await {
                all_items.extend(items);
            }
        }
    }

    all_items.sort_by(|a, b| b.created_at.cmp(&a.created_at));
    HttpResponse::Ok().json(all_items)
}

#[get("/data/{id}")]
pub async fn get_data_by_id(req: HttpRequest, path: web::Path<Uuid>, state: web::Data<AppState>) -> impl Responder {
    if !validate_api_key(&req, &state) { return HttpResponse::Unauthorized().finish(); }
    let id = path.into_inner();
    
    // Scan all collection tables
    let table_rows = sqlx::query("SELECT table_name FROM information_schema.tables WHERE table_name LIKE 'coll_%'").fetch_all(&state.db).await;
    
    if let Ok(rows) = table_rows {
        for row in rows {
            let table_name: String = row.get("table_name");
            let query = format!("SELECT user_id, encrypted_content, created_at FROM {} WHERE id = $1", table_name);
            let res = sqlx::query(&query).bind(id).fetch_optional(&state.db).await;
            
            if let Ok(Some(r)) = res {
                let enc: String = r.get("encrypted_content");
                if let Some(dec) = decrypt_smart(&state, &enc).await {
                    let data: serde_json::Value = serde_json::from_slice(&dec).unwrap_or(serde_json::Value::Null);
                    
                    // Extract db and col from table name 'coll_db_col'
                    let parts: Vec<&str> = table_name.split('_').collect();
                    let db_id = parts.get(1).unwrap_or(&"unknown").to_string();
                    let col_id = parts.get(2).unwrap_or(&"unknown").to_string();

                    return HttpResponse::Ok().json(serde_json::json!({
                        "id": id,
                        "database_id": db_id,
                        "collection_id": col_id,
                        "user_id": r.get::<String, _>("user_id"),
                        "created_at": r.get::<chrono::DateTime<chrono::Utc>, _>("created_at"),
                        "data": data
                    }));
                }
            }
        }
    }

    HttpResponse::NotFound().finish()
}

#[delete("/data/{id}")]
pub async fn delete_data_by_id(req: HttpRequest, path: web::Path<Uuid>, state: web::Data<AppState>) -> impl Responder {
    if !validate_api_key(&req, &state) { return HttpResponse::Unauthorized().finish(); }
    let id = path.into_inner();
    
    let table_rows = sqlx::query("SELECT table_name FROM information_schema.tables WHERE table_name LIKE 'coll_%'").fetch_all(&state.db).await;
    
    if let Ok(rows) = table_rows {
        for row in rows {
            let table_name: String = row.get("table_name");
            let query_select = format!("SELECT user_id FROM {} WHERE id = $1", table_name);
            
            if let Ok(Some(r)) = sqlx::query(&query_select).bind(id).fetch_optional(&state.db).await {
                let user_id: String = r.get("user_id");
                let parts: Vec<&str> = table_name.split('_').collect();
                let db_id = parts.get(1).unwrap_or(&"unknown").to_string();
                let col_id = parts.get(2).unwrap_or(&"unknown").to_string();
                let doc_id = id.to_string();

                let query_delete = format!("DELETE FROM {} WHERE id = $1", table_name);
                let res = sqlx::query(&query_delete).bind(id).execute(&state.db).await;

                if res.is_ok() {
                    // Emit Realtime Event
                    publish_realtime_event(&state, "delete", &db_id, &col_id, &doc_id, serde_json::json!({ "$id": doc_id })).await;

                    // Sync mirrors
                    let mirrors = state.mirrors.read().await;
                    for mirror in mirrors.iter() {
                        let _ = sqlx::query(&query_delete).bind(id).execute(mirror).await;
                    }

                    // Invalidate cache
                    let redis_key = format!("data:{}:{}", user_id, doc_id);
                    if let Ok(mut conn) = state.redis.get_multiplexed_async_connection().await {
                        let _: () = conn.del(&redis_key).await.unwrap_or_default();
                    }
                    return HttpResponse::NoContent().finish();
                }
            }
        }
    }
    
    HttpResponse::NotFound().finish()
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
    HttpResponse::Ok().json(serde_json::json!({
        "under_attack": state.under_attack.load(Ordering::SeqCst),
        "lockdown_mode": state.lockdown_mode.load(Ordering::SeqCst),
        "load_balancer_mode": state.load_balancer_mode.load(Ordering::SeqCst),
        "redis_mirrors_count": state.redis_mirrors.read().await.len(),
    }))
}

#[post("/admin/security/lockdown")]
pub async fn toggle_lockdown(req: HttpRequest, state: web::Data<AppState>) -> impl Responder {
    if !validate_api_key(&req, &state) { return HttpResponse::Unauthorized().finish(); }
    let current = state.lockdown_mode.fetch_xor(true, Ordering::SeqCst);
    log::warn!("Admin toggled LOCKDOWN MODE to {}", !current);
    HttpResponse::Ok().json(MessageResponse { message: format!("Lockdown Mode {}", if !current { "Activated" } else { "Deactivated" }) })
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
    let mut primary_conn = state.redis.get_multiplexed_async_connection().await;
    let primary_online = match &mut primary_conn {
        Ok(c) => redis::cmd("PING").query_async::<String>(c).await.is_ok(),
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
                if let Ok(mut conn) = c.get_multiplexed_async_connection().await {
                    redis::cmd("PING").query_async::<String>(&mut conn).await.is_ok()
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

    if let Err(e) = client.get_multiplexed_async_connection().await {
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



#[delete("/admin/users/{id}")]
pub async fn delete_user(req: HttpRequest, path: web::Path<String>, state: web::Data<AppState>) -> impl Responder {
    if !validate_api_key(&req, &state) { return HttpResponse::Unauthorized().finish(); }
    let user_id = path.into_inner();
    log::warn!("Admin is deleting user: {}", user_id);
    
    // Delete from users, user_profiles and data_store
    let _ = sqlx::query("DELETE FROM users WHERE id = $1").bind(&user_id).execute(&state.db).await;
    let _ = sqlx::query("DELETE FROM user_profiles WHERE user_id = $1").bind(&user_id).execute(&state.db).await;
    let _ = sqlx::query("DELETE FROM data_store WHERE user_id = $1").bind(&user_id).execute(&state.db).await;
    
    // Sync to mirrors
    let mirrors = state.mirrors.read().await;
    for mirror in mirrors.iter() {
        let _ = sqlx::query("DELETE FROM users WHERE id = $1").bind(&user_id).execute(mirror).await;
        let _ = sqlx::query("DELETE FROM user_profiles WHERE user_id = $1").bind(&user_id).execute(mirror).await;
        let _ = sqlx::query("DELETE FROM data_store WHERE user_id = $1").bind(&user_id).execute(mirror).await;
    }

    HttpResponse::Ok().json(MessageResponse { message: "User and associated data deleted".to_string() })
}

#[get("/admin/smtp")]

pub async fn get_smtp_config(state: web::Data<AppState>) -> impl Responder {

    let row = sqlx::query_as::<_, SmtpConfig>("SELECT host, port, username, password, from_email, enabled FROM smtp_config LIMIT 1")

        .fetch_optional(&state.db)

        .await;



    match row {

        Ok(Some(config)) => HttpResponse::Ok().json(config),

        Ok(None) => HttpResponse::NotFound().body("SMTP not configured"),

        Err(e) => {

            log::error!("DB error fetching SMTP: {}", e);

            HttpResponse::InternalServerError().finish()

        }

    }

}



#[post("/admin/smtp")]

pub async fn update_smtp_config(

    data: web::Json<SmtpConfig>,

    state: web::Data<AppState>,

) -> impl Responder {

    let res = sqlx::query("INSERT INTO smtp_config (id, host, port, username, password, from_email, enabled) VALUES (1, $1, $2, $3, $4, $5, $6) ON CONFLICT (id) DO UPDATE SET host = EXCLUDED.host, port = EXCLUDED.port, username = EXCLUDED.username, password = EXCLUDED.password, from_email = EXCLUDED.from_email, enabled = EXCLUDED.enabled")

        .bind(&data.host)

        .bind(data.port)

        .bind(&data.username)

        .bind(&data.password)

        .bind(&data.from_email)

        .bind(data.enabled)

        .execute(&state.db)

        .await;



    match res {

        Ok(_) => {

            log::info!("SMTP configuration updated");

            HttpResponse::Ok().json(MessageResponse { message: "SMTP configuration updated".into() })

        },

        Err(e) => {

            log::error!("DB error updating SMTP: {}", e);

            HttpResponse::InternalServerError().finish()

        }

    }

}



#[post("/admin/server/restart")]
pub async fn restart_server(req: HttpRequest, state: web::Data<AppState>) -> impl Responder {
    if !validate_api_key(&req, &state) { return HttpResponse::Unauthorized().finish(); }
    
    log::warn!("SERVER RESTART INITIATED BY ADMIN");

    #[cfg(windows)]
    let mut cmd = {
        let mut c = std::process::Command::new("cmd");
        // Wait 2 seconds before starting the new instance to allow port to be released
        let cmd_str = "timeout 2 > nul && cargo run".to_string();
        c.args(&["/C", &cmd_str]);
        c
    };

    #[cfg(not(windows))]
    let mut cmd = {
        let mut c = std::process::Command::new("sh");
        let cmd_str = "sleep 2 && cargo run".to_string();
        c.args(&["-c", &cmd_str]);
        c
    };

    match cmd.spawn() {
        Ok(_) => {
            log::info!("Restart subprocess spawned. System will exit in 500ms.");
            tokio::spawn(async {
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                std::process::exit(0);
            });
            HttpResponse::Ok().json(MessageResponse { message: "Server is restarting. Please refresh the page in a few seconds.".to_string() })
        },
        Err(e) => {
            log::error!("Failed to spawn restart command: {}", e);
            HttpResponse::InternalServerError().body(format!("Failed to restart: {}", e))
        }
    }
}

#[get("/admin/logs")]

pub async fn get_logs(state: web::Data<AppState>) -> impl Responder {

    let logs = state.logs.read().await;

    HttpResponse::Ok().json(logs.clone())

}



// --- Storage API ---



#[post("/v1/storage/buckets/{bucketId}/files")]

pub async fn upload_file(
    path: web::Path<String>,
    mut payload: Multipart,
    req: HttpRequest,
    state: web::Data<AppState>,
) -> impl Responder {
    state.total_requests.fetch_add(1, Ordering::Relaxed);
    let _bucket_id = path.into_inner();
    
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

    let mut file_id = Uuid::new_v4().to_string();
    let mut file_name = String::new();
    let mut mime_type = String::from("application/octet-stream");
    let mut content = Vec::new();

    while let Ok(Some(mut field)) = payload.try_next().await {
        if field.name() == "file" {
            file_name = field.content_disposition().get_filename().unwrap_or("unnamed").to_string();
            mime_type = field.content_type().map(|m| m.to_string()).unwrap_or_else(|| "application/octet-stream".into());
            while let Ok(Some(chunk)) = field.try_next().await {
                content.extend_from_slice(&chunk);
            }
        } else if field.name() == "fileId" {
            let mut id_bytes = Vec::new();
            while let Ok(Some(chunk)) = field.try_next().await {
                id_bytes.extend_from_slice(&chunk);
            }
            let id_str = String::from_utf8_lossy(&id_bytes).to_string();
            if id_str != "unique()" { file_id = id_str; }
        }
    }

    let size = content.len() as i64;
    
    // Encrypt file content
    let crypto = CryptoService::new(state.crypto_key.read().await.clone());
    let encrypted = match crypto.encrypt(&content) {
        Ok(e) => e,
        Err(_) => return HttpResponse::InternalServerError().finish(),
    };

    // Fetch S3 config for provider and bucket name
    let s3_config = match sqlx::query_as::<_, S3Config>("SELECT * FROM s3_config WHERE enabled = TRUE LIMIT 1").fetch_one(&state.db).await {
        Ok(c) => c,
        Err(_) => return HttpResponse::InternalServerError().body("No active storage provider"),
    };

    if s3_config.provider == "local" {
        let storage_dir = "./storage";
        let _ = std::fs::create_dir_all(storage_dir);
        let path = format!("{}/{}", storage_dir, file_id);
        if let Err(e) = std::fs::write(&path, encrypted.as_bytes()) {
            log::error!("Local storage write error: {}", e);
            return HttpResponse::InternalServerError().body(e.to_string());
        }
    } else {
        // Upload to S3
        let s3_lock = state.s3_client.read().await;
        let s3 = match s3_lock.as_ref() {
            Some(s) => s,
            None => return HttpResponse::InternalServerError().body("S3 not configured"),
        };
        let s3_key = format!("files/{}", file_id);
        if let Err(e) = s3.put_object(&s3_key, encrypted.as_bytes()).await {
            log::error!("S3 upload error: {}", e);
            return HttpResponse::InternalServerError().body(e.to_string());
        }
    }

    // Store metadata
    let res_meta = sqlx::query("INSERT INTO storage_metadata (id, name, mime_type, size_bytes, user_id) VALUES ($1, $2, $3, $4, $5)")
        .bind(&file_id)
        .bind(&file_name)
        .bind(&mime_type)
        .bind(size)
        .bind(&user_id)
        .execute(&state.db)
        .await;

    if let Err(e) = res_meta {
        log::error!("Failed to store storage metadata: {}", e);
        return HttpResponse::InternalServerError().body("Failed to store metadata");
    }

    let meta = FileMetadata {
        id: file_id,
        name: file_name,
        mime_type,
        size_bytes: size,
        user_id,
        created_at: Utc::now(),
    };

    HttpResponse::Created().json(meta)
}



#[get("/v1/storage/buckets/{bucketId}/files/{fileId}/view")]
pub async fn get_file_view(
    path: web::Path<(String, String)>,
    state: web::Data<AppState>,
) -> impl Responder {
    let (_bucket_id, file_id) = path.into_inner();
    
    let meta_res = sqlx::query_as::<_, FileMetadata>("SELECT * FROM storage_metadata WHERE id = $1")
        .bind(&file_id)
        .fetch_optional(&state.db)
        .await;
    
    let meta = match meta_res {
        Ok(Some(m)) => m,
        Ok(None) => {
            log::warn!("File metadata not found for ID: {}", file_id);
            return HttpResponse::NotFound().finish();
        }
        Err(e) => {
            log::error!("Database error fetching file metadata: {}", e);
            return HttpResponse::InternalServerError().body(e.to_string());
        }
    };

    let s3_config = match sqlx::query_as::<_, S3Config>("SELECT * FROM s3_config WHERE enabled = TRUE LIMIT 1").fetch_one(&state.db).await {
        Ok(c) => c,
        Err(_) => return HttpResponse::InternalServerError().finish(),
    };

    let body_bytes = if s3_config.provider == "local" {
        let path = format!("./storage/{}", file_id);
        match std::fs::read(&path) {
            Ok(b) => b,
            Err(e) => {
                log::error!("Local storage read error: {}", e);
                return HttpResponse::InternalServerError().finish();
            }
        }
    } else {
        let s3_lock = state.s3_client.read().await;
        let s3 = match s3_lock.as_ref() {
            Some(s) => s,
            None => return HttpResponse::InternalServerError().body("S3 not configured"),
        };
        let s3_key = format!("files/{}", file_id);
        let output = match s3.get_object(&s3_key).await {
            Ok(o) => o,
            Err(e) => {
                log::error!("S3 fetch error: {}", e);
                return HttpResponse::InternalServerError().finish();
            }
        };
        output.to_vec()
    };

    let enc_str = String::from_utf8_lossy(&body_bytes);
    
    if let Some(dec) = decrypt_smart(&state, &enc_str).await {
        return HttpResponse::Ok()
            .content_type(meta.mime_type)
            .body(dec);
    }

    HttpResponse::InternalServerError().body("Decryption failed")
}

#[get("/v1/storage/buckets/{bucketId}/files")]
pub async fn list_files(
    req: HttpRequest,
    state: web::Data<AppState>,
) -> impl Responder {
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

    let rows = sqlx::query_as::<_, FileMetadata>("SELECT * FROM storage_metadata WHERE user_id = $1 ORDER BY created_at DESC")
        .bind(user_id)
        .fetch_all(&state.db)
        .await;

    match rows {
        Ok(files) => HttpResponse::Ok().json(serde_json::json!({ "total": files.len(), "files": files })),
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
    }
}



#[delete("/v1/storage/buckets/{bucketId}/files/{fileId}")]
pub async fn delete_file(
    req: HttpRequest,
    path: web::Path<(String, String)>,
    state: web::Data<AppState>,
) -> impl Responder {
    let (_bucket_id, file_id) = path.into_inner();
    
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

    let s3_config = match sqlx::query_as::<_, S3Config>("SELECT * FROM s3_config WHERE enabled = TRUE LIMIT 1").fetch_one(&state.db).await {
        Ok(c) => c,
        Err(_) => return HttpResponse::InternalServerError().finish(),
    };

    if s3_config.provider == "local" {
        let path = format!("./storage/{}", file_id);
        let _ = std::fs::remove_file(&path);
    } else {
        let s3_lock = state.s3_client.read().await;
        let s3 = match s3_lock.as_ref() {
            Some(s) => s,
            None => return HttpResponse::InternalServerError().body("S3 not configured"),
        };
        let _ = s3.delete_object(format!("files/{}", file_id)).await;
    }

    let _ = sqlx::query("DELETE FROM storage_metadata WHERE id = $1").bind(file_id).execute(&state.db).await;

    HttpResponse::NoContent().finish()
}



// --- Admin Storage Config ---



#[get("/admin/s3")]
pub async fn get_s3_config(state: web::Data<AppState>) -> impl Responder {
    let row = sqlx::query_as::<_, S3Config>("SELECT provider, bucket, region, access_key, secret_key, endpoint, enabled FROM s3_config LIMIT 1")
        .fetch_optional(&state.db)
        .await;

    match row {
        Ok(Some(config)) => HttpResponse::Ok().json(config),
        Ok(None) => HttpResponse::NotFound().body("Storage not configured"),
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
    }
}

#[post("/admin/s3")]
pub async fn update_s3_config(
    data: web::Json<S3Config>,
    state: web::Data<AppState>,
) -> impl Responder {
    let res = sqlx::query("INSERT INTO s3_config (id, provider, bucket, region, access_key, secret_key, endpoint, enabled) VALUES (1, $1, $2, $3, $4, $5, $6, $7) ON CONFLICT (id) DO UPDATE SET provider = EXCLUDED.provider, bucket = EXCLUDED.bucket, region = EXCLUDED.region, access_key = EXCLUDED.access_key, secret_key = EXCLUDED.secret_key, endpoint = EXCLUDED.endpoint, enabled = EXCLUDED.enabled")
        .bind(&data.provider)
        .bind(&data.bucket)
        .bind(&data.region)
        .bind(&data.access_key)
        .bind(&data.secret_key)
        .bind(&data.endpoint)
        .bind(data.enabled)
        .execute(&state.db)
        .await;

    if res.is_ok() {
        // Re-initialize S3 Client if provider is s3
        if data.enabled && data.provider == "s3" {
            let mut client_lock = state.s3_client.write().await;
            let creds = s3::creds::Credentials::new(
                Some(&data.access_key),
                Some(&data.secret_key),
                None,
                None,
                None,
            ).unwrap();

            let region = data.region.parse::<s3::Region>().unwrap_or(s3::Region::Custom {
                region: data.region.clone(),
                endpoint: data.endpoint.clone().unwrap_or_else(|| "https://s3.amazonaws.com".to_string()),
            });

            *client_lock = s3::Bucket::new(&data.bucket, region, creds).ok();
        }
        HttpResponse::Ok().json(MessageResponse { message: "Storage Configuration updated".into() })
    } else {
        HttpResponse::InternalServerError().body("DB Error".to_string())
    }
}

// --- Appwrite Functions API ---

#[get("/v1/functions")]
pub async fn list_functions(
    req: HttpRequest,
    state: web::Data<AppState>,
) -> impl Responder {
    if !validate_api_key(&req, &state) { return HttpResponse::Unauthorized().finish(); }
    
    let rows = sqlx::query_as::<_, AppwriteFunction>("SELECT * FROM functions ORDER BY created_at DESC")
        .fetch_all(&state.db)
        .await;

    match rows {
        Ok(funcs) => HttpResponse::Ok().json(serde_json::json!({ "total": funcs.len(), "functions": funcs })),
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
    }
}

#[post("/v1/functions")]
pub async fn create_function(
    req: HttpRequest,
    data: web::Json<serde_json::Value>,
    state: web::Data<AppState>,
) -> impl Responder {
    if !validate_api_key(&req, &state) { return HttpResponse::Unauthorized().finish(); }

    let function_id = data["functionId"].as_str().map(|s| s.to_string()).unwrap_or_else(|| Uuid::new_v4().to_string());
    let name = data["name"].as_str().unwrap_or("Untitled Function");
    let runtime = data["runtime"].as_str().unwrap_or("node-18.0");

    let res = sqlx::query("INSERT INTO functions (id, name, runtime) VALUES ($1, $2, $3) RETURNING *")
        .bind(&function_id)
        .bind(name)
        .bind(runtime)
        .fetch_one(&state.db)
        .await;

    match res {
        Ok(row) => {
            let func = AppwriteFunction {
                id: row.get("id"),
                name: row.get("name"),
                runtime: row.get("runtime"),
                enabled: row.get("enabled"),
                created_at: row.get("created_at"),
                updated_at: row.get("updated_at"),
            };
            HttpResponse::Created().json(func)
        },
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
    }
}

#[post("/v1/functions/{functionId}/executions")]
pub async fn create_execution(
    path: web::Path<String>,
    req: HttpRequest,
    state: web::Data<AppState>,
) -> impl Responder {
    let function_id = path.into_inner();
    
    // 1. Fetch function metadata
    let func = match sqlx::query_as::<_, AppwriteFunction>("SELECT * FROM functions WHERE id = $1")
        .bind(&function_id)
        .fetch_optional(&state.db)
        .await {
            Ok(Some(f)) => f,
            Ok(None) => return HttpResponse::NotFound().finish(),
            Err(_) => return HttpResponse::InternalServerError().finish(),
        };

    if !func.enabled {
        return HttpResponse::BadRequest().body("Function is disabled");
    }

    let execution_id = Uuid::new_v4().to_string();
    let start_time = Instant::now();

    log::info!("Executing function: {} ({})", func.name, function_id);

    // 2. Identify script to run
    let base_path = format!("./functions/{}", function_id);
    let (cmd, args) = match func.runtime.split('-').next().unwrap_or("node") {
        "node" => ("node", vec![format!("{}/index.js", base_path)]),
        "python" => ("python", vec![format!("{}/index.py", base_path)]),
        _ => ("node", vec![format!("{}/index.js", base_path)]),
    };

    // 3. Run child process
    let output = Command::new(cmd)
        .args(&args)
        .output();

    let duration = start_time.elapsed().as_secs_f64();

    let (status, stdout, stderr, status_code) = match output {
        Ok(out) => (
            if out.status.success() { "completed" } else { "failed" },
            String::from_utf8_lossy(&out.stdout).to_string(),
            String::from_utf8_lossy(&out.stderr).to_string(),
            out.status.code().unwrap_or(0),
        ),
        Err(e) => (
            "failed",
            "".to_string(),
            format!("Failed to execute process: {}", e),
            -1,
        ),
    };

    // 4. Store execution result
    let res = sqlx::query("INSERT INTO executions (id, function_id, status, stdout, stderr, duration, status_code) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *")
        .bind(&execution_id)
        .bind(&function_id)
        .bind(status)
        .bind(&stdout)
        .bind(&stderr)
        .bind(duration)
        .bind(status_code)
        .fetch_one(&state.db)
        .await;

    match res {
        Ok(row) => {
            let execution = AppwriteExecution {
                id: row.get("id"),
                function_id: row.get("function_id"),
                status: row.get("status"),
                stdout: row.get("stdout"),
                stderr: row.get("stderr"),
                duration: row.get("duration"),
                status_code: row.get("status_code"),
                created_at: row.get("created_at"),
            };
            HttpResponse::Created().json(execution)
        },
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
    }
}

use std::io::Read;

#[post("/v1/functions/{functionId}/deployments")]
pub async fn create_deployment(
    path: web::Path<String>,
    mut payload: Multipart,
    state: web::Data<AppState>,
) -> impl Responder {
    let function_id = path.into_inner();
    let mut zip_data = Vec::new();

    while let Ok(Some(mut field)) = payload.try_next().await {
        if field.name() == "code" {
            while let Ok(Some(chunk)) = field.try_next().await {
                zip_data.extend_from_slice(&chunk);
            }
        }
    }

    if zip_data.is_empty() {
        return HttpResponse::BadRequest().body("No code file provided");
    }

    let target_dir = format!("./functions/{}", function_id);
    let _ = std::fs::create_dir_all(&target_dir);

    // Extract ZIP
    let reader = std::io::Cursor::new(zip_data);
    let mut archive = match zip::ZipArchive::new(reader) {
        Ok(a) => a,
        Err(e) => return HttpResponse::BadRequest().body(format!("Invalid ZIP: {}", e)),
    };

    for i in 0..archive.len() {
        let mut file = archive.by_index(i).unwrap();
        let outpath = match file.enclosed_name() {
            Some(path) => std::path::Path::new(&target_dir).join(path),
            None => continue,
        };

        if (*file.name()).ends_with('/') {
            std::fs::create_dir_all(&outpath).unwrap();
        } else {
            if let Some(p) = outpath.parent() {
                if !p.exists() {
                    std::fs::create_dir_all(&p).unwrap();
                }
            }
            let mut outfile = std::fs::File::create(&outpath).unwrap();
            std::io::copy(&mut file, &mut outfile).unwrap();
        }
    }

    log::info!("Deployment successful for function {}", function_id);
    HttpResponse::Created().json(serde_json::json!({ "status": "success", "message": "Deployed" }))
}

#[post("/v1/functions/{functionId}/git")]
pub async fn clone_repo(
    path: web::Path<String>,
    data: web::Json<serde_json::Value>,
    state: web::Data<AppState>,
) -> impl Responder {
    let function_id = path.into_inner();
    let repo_url = match data["url"].as_str() {
        Some(u) => u,
        None => return HttpResponse::BadRequest().body("Missing repo URL"),
    };

    let target_dir = format!("./functions/{}", function_id);
    let _ = std::fs::remove_dir_all(&target_dir); // Clean start

    log::info!("Cloning git repo {} into {}", repo_url, target_dir);

    let output = Command::new("git")
        .args(&["clone", repo_url, &target_dir])
        .output();

    match output {
        Ok(out) if out.status.success() => {
            HttpResponse::Ok().json(serde_json::json!({ "status": "success", "message": "Repository cloned" }))
        },
        Ok(out) => {
            let err = String::from_utf8_lossy(&out.stderr);
            HttpResponse::InternalServerError().body(format!("Git clone failed: {}", err))
        },
        Err(e) => HttpResponse::InternalServerError().body(format!("Failed to execute git: {}", e)),
    }
}

#[get("/v1/functions/{functionId}/executions")]
pub async fn list_executions(
    path: web::Path<String>,
    state: web::Data<AppState>,
) -> impl Responder {
    let function_id = path.into_inner();
    
    let rows = sqlx::query_as::<_, AppwriteExecution>("SELECT * FROM executions WHERE function_id = $1 ORDER BY created_at DESC LIMIT 100")
        .bind(&function_id)
        .fetch_all(&state.db)
        .await;

    match rows {
        Ok(execs) => HttpResponse::Ok().json(serde_json::json!({ "total": execs.len(), "executions": execs })),
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
    }
}

#[get("/v1/functions/{functionId}/executions/{executionId}")]
pub async fn get_execution(
    path: web::Path<(String, String)>,
    state: web::Data<AppState>,
) -> impl Responder {
    let (_function_id, execution_id) = path.into_inner();
    
    let res = sqlx::query_as::<_, AppwriteExecution>("SELECT * FROM executions WHERE id = $1")
        .bind(&execution_id)
        .fetch_optional(&state.db)
        .await;

    match res {
        Ok(Some(exec)) => HttpResponse::Ok().json(exec),
        Ok(None) => HttpResponse::NotFound().finish(),
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
    }
}

// --- Website Hosting API ---

#[get("/v1/websites")]
pub async fn list_websites(
    req: HttpRequest,
    state: web::Data<AppState>,
) -> impl Responder {
    if !validate_api_key(&req, &state) { return HttpResponse::Unauthorized().finish(); }
    let rows = sqlx::query_as::<_, AppwriteWebsite>("SELECT * FROM websites ORDER BY created_at DESC")
        .fetch_all(&state.db)
        .await;

    match rows {
        Ok(sites) => HttpResponse::Ok().json(serde_json::json!({ "total": sites.len(), "websites": sites })),
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
    }
}

#[post("/v1/websites")]
pub async fn create_website(
    req: HttpRequest,
    data: web::Json<serde_json::Value>,
    state: web::Data<AppState>,
) -> impl Responder {
    if !validate_api_key(&req, &state) { return HttpResponse::Unauthorized().finish(); }

    let id = data["websiteId"].as_str().map(|s| s.to_string()).unwrap_or_else(|| Uuid::new_v4().to_string());
    let name = data["name"].as_str().unwrap_or("Untitled Website");

    let res = sqlx::query("INSERT INTO websites (id, name) VALUES ($1, $2) RETURNING *")
        .bind(&id)
        .bind(name)
        .fetch_one(&state.db)
        .await;

    match res {
        Ok(row) => {
            let site = AppwriteWebsite {
                id: row.get("id"),
                name: row.get("name"),
                domain: row.get("domain"),
                enabled: row.get("enabled"),
                container_id: row.get("container_id"),
                port: row.get("port"),
                created_at: row.get("created_at"),
            };
            HttpResponse::Created().json(site)
        },
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
    }
}

#[post("/v1/websites/{websiteId}/content")]
pub async fn upload_website_content(
    path: web::Path<String>,
    mut payload: Multipart,
    _state: web::Data<AppState>,
) -> impl Responder {
    let website_id = path.into_inner();
    let mut zip_data = Vec::new();

    while let Ok(Some(mut field)) = payload.try_next().await {
        if field.name() == "file" {
            while let Ok(Some(chunk)) = field.try_next().await {
                zip_data.extend_from_slice(&chunk);
            }
        }
    }

    if zip_data.is_empty() {
        return HttpResponse::BadRequest().body("No ZIP file provided");
    }

    let target_dir = format!("./websites/{}", website_id);
    let _ = std::fs::remove_dir_all(&target_dir); // Clean existing
    let _ = std::fs::create_dir_all(&target_dir);

    // Extract ZIP
    let reader = std::io::Cursor::new(zip_data);
    let mut archive = match zip::ZipArchive::new(reader) {
        Ok(a) => a,
        Err(e) => return HttpResponse::BadRequest().body(format!("Invalid ZIP: {}", e)),
    };

    for i in 0..archive.len() {
        let mut file = archive.by_index(i).unwrap();
        let outpath = match file.enclosed_name() {
            Some(path) => std::path::Path::new(&target_dir).join(path),
            None => continue,
        };

        if (*file.name()).ends_with('/') {
            std::fs::create_dir_all(&outpath).unwrap();
        } else {
            if let Some(p) = outpath.parent() {
                if !p.exists() {
                    std::fs::create_dir_all(&p).unwrap();
                }
            }
            let mut outfile = std::fs::File::create(&outpath).unwrap();
            std::io::copy(&mut file, &mut outfile).unwrap();
        }
    }

    log::info!("Website content deployed for ID: {}", website_id);
    HttpResponse::Ok().json(serde_json::json!({ "status": "success" }))
}

#[post("/v1/websites/{websiteId}/git")]
pub async fn clone_website_repo(
    path: web::Path<String>,
    data: web::Json<serde_json::Value>,
    _state: web::Data<AppState>,
) -> impl Responder {
    let website_id = path.into_inner();
    let repo_url = match data["url"].as_str() {
        Some(u) => u,
        None => return HttpResponse::BadRequest().body("Missing repo URL"),
    };

    let target_dir = format!("./websites/{}", website_id);
    let _ = std::fs::remove_dir_all(&target_dir); // Clean start

    log::info!("Cloning website repo {} into {}", repo_url, target_dir);

    let output = Command::new("git")
        .args(&["clone", repo_url, &target_dir])
        .output();

    match output {
        Ok(out) if out.status.success() => {
            HttpResponse::Ok().json(serde_json::json!({ "status": "success", "message": "Repository cloned" }))
        },
        Ok(out) => {
            let err = String::from_utf8_lossy(&out.stderr);
            HttpResponse::InternalServerError().body(format!("Git clone failed: {}", err))
        },
        Err(e) => HttpResponse::InternalServerError().body(format!("Failed to execute git: {}", e)),
    }
}

#[post("/v1/websites/{websiteId}/build")]
pub async fn build_website(
    path: web::Path<String>,
    data: web::Json<serde_json::Value>,
    _state: web::Data<AppState>,
) -> impl Responder {
    let website_id = path.into_inner();
    let command_str = data["command"].as_str().unwrap_or("npm install && npm run build");
    
    let target_dir = format!("./websites/{}", website_id);
    if !std::path::Path::new(&target_dir).exists() {
        return HttpResponse::NotFound().body("Website directory not found");
    }

    log::info!("Building website {} with command: {}", website_id, command_str);

    #[cfg(windows)]
    let (shell, shell_flag) = ("cmd", "/C");
    #[cfg(not(windows))]
    let (shell, shell_flag) = ("sh", "-c");

    let output = Command::new(shell)
        .args(&[shell_flag, command_str])
        .current_dir(&target_dir)
        .output();

    match output {
        Ok(out) => {
            let stdout = String::from_utf8_lossy(&out.stdout).to_string();
            let stderr = String::from_utf8_lossy(&out.stderr).to_string();
            HttpResponse::Ok().json(serde_json::json!({
                "status": if out.status.success() { "success" } else { "failed" },
                "stdout": stdout,
                "stderr": stderr,
                "exitCode": out.status.code().unwrap_or(-1)
            }))
        },
        Err(e) => HttpResponse::InternalServerError().body(format!("Failed to execute build: {}", e)),
    }
}

#[post("/v1/websites/{websiteId}/docker")]
pub async fn docker_deploy(
    path: web::Path<String>,
    state: web::Data<AppState>,
) -> impl Responder {
    let website_id = path.into_inner();
    let target_dir = format!("./websites/{}", website_id);
    
    if !std::path::Path::new(&target_dir).exists() {
        return HttpResponse::NotFound().body("Website directory not found");
    }

    // 1. Auto-generate Dockerfile
    let dockerfile_path = format!("{}/Dockerfile", target_dir);
    log::info!("Updating Dockerfile for website {}", website_id);
    
    // Detect Next.js or Vite
    let content = if std::path::Path::new(&format!("{}/next.config.js", target_dir)).exists() || 
       std::path::Path::new(&format!("{}/next.config.mjs", target_dir)).exists() {
        "FROM node:18-alpine\nWORKDIR /app\nCOPY package*.json ./\nRUN npm install\nCOPY . .\nRUN npm run build\nEXPOSE 3000\nCMD [\"npm\", \"start\"]\n".to_string()
    } else if std::path::Path::new(&format!("{}/dist", target_dir)).exists() {
        // For Vite/Static with dist folder
        "FROM nginx:alpine\nCOPY dist/ /usr/share/nginx/html/\n".to_string()
    } else {
        // Pure static from root
        "FROM nginx:alpine\nCOPY . /usr/share/nginx/html/\n".to_string()
    };
    
    let _ = std::fs::write(&dockerfile_path, content);

    let image_name = format!("site-{}", website_id.to_lowercase().replace("()", "unique"));
    
    // 2. Build Image
    log::info!("Building Docker image: {}", image_name);
    let build_result = Command::new("docker")
        .args(&["build", "-t", &image_name, "."])
        .current_dir(&target_dir)
        .output();

    let (build_success, build_stdout, build_stderr) = match build_result {
        Ok(out) => (
            out.status.success(),
            String::from_utf8_lossy(&out.stdout).to_string(),
            String::from_utf8_lossy(&out.stderr).to_string(),
        ),
        Err(e) => (false, "".to_string(), format!("Failed to execute docker build: {}", e)),
    };

    if !build_success {
        log::error!("Docker build failed for {}: {}", image_name, build_stderr);
        return HttpResponse::InternalServerError().json(serde_json::json!({
            "status": "failed",
            "message": "Docker build failed",
            "stdout": build_stdout,
            "stderr": build_stderr
        }));
    }

    // 3. Stop old container if exists
    let _ = Command::new("docker").args(&["stop", &image_name]).output();
    let _ = Command::new("docker").args(&["rm", &image_name]).output();

    // 4. Run Container on an automatically assigned random port
    let container_port = if std::path::Path::new(&format!("{}/next.config.js", target_dir)).exists() || 
       std::path::Path::new(&format!("{}/next.config.mjs", target_dir)).exists() {
        3000
    } else {
        80
    };
    
    log::info!("Starting Docker container: {} mapping container port {}", image_name, container_port);
    let run_out = Command::new("docker")
        .args(&["run", "-d", "--name", &image_name, "-p", &format!("0:{}", container_port), &image_name])
        .output();

    match run_out {
        Ok(out) if out.status.success() => {
            let container_id = String::from_utf8_lossy(&out.stdout).trim().to_string();
            
            // 5. Get the assigned host port
            let port_out = Command::new("docker")
                .args(&["port", &image_name, &container_port.to_string()])
                .output();
            
            let assigned_port = match port_out {
                Ok(p_out) if p_out.status.success() => {
                    let p_str = String::from_utf8_lossy(&p_out.stdout);
                    // Output format is like "0.0.0.0:12345" or ":::12345"
                    p_str.split(':').last().unwrap_or("0").trim().parse::<i32>().unwrap_or(0)
                },
                _ => 0,
            };

            if assigned_port == 0 {
                return HttpResponse::InternalServerError().json(serde_json::json!({
                    "status": "failed",
                    "message": "Failed to retrieve assigned port from Docker",
                    "stdout": build_stdout,
                    "stderr": "docker port command failed"
                }));
            }
            
            // 6. Update DB
            let _ = sqlx::query("UPDATE websites SET container_id = $1, port = $2 WHERE id = $3")
                .bind(&container_id)
                .bind(assigned_port)
                .bind(&website_id)
                .execute(&state.db)
                .await;

            HttpResponse::Ok().json(serde_json::json!({
                "status": "success",
                "containerId": container_id,
                "port": assigned_port,
                "stdout": build_stdout,
                "stderr": build_stderr
            }))
        },
        Ok(out) => HttpResponse::InternalServerError().json(serde_json::json!({
            "status": "failed",
            "message": "Docker run failed",
            "stdout": build_stdout,
            "stderr": String::from_utf8_lossy(&out.stderr)
        })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "status": "failed",
            "message": "Failed to start container",
            "stdout": build_stdout,
            "stderr": e.to_string()
        })),
    }
}

#[post("/v1/websites/{websiteId}/domain")]
pub async fn update_website_domain(
    req: HttpRequest,
    path: web::Path<String>,
    data: web::Json<serde_json::Value>,
    state: web::Data<AppState>,
) -> impl Responder {
    if !validate_api_key(&req, &state) { return HttpResponse::Unauthorized().finish(); }
    let website_id = path.into_inner();
    let domain = data["domain"].as_str();
    let ssl_cert = data["sslCert"].as_str();
    let ssl_key = data["sslKey"].as_str();

    let res = sqlx::query("UPDATE websites SET domain = $1, ssl_cert = $2, ssl_key = $3 WHERE id = $4")
        .bind(domain)
        .bind(ssl_cert)
        .bind(ssl_key)
        .bind(&website_id)
        .execute(&state.db)
        .await;

    match res {
        Ok(_) => HttpResponse::Ok().json(MessageResponse { message: "Domain updated".to_string() }),
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
    }
}

async fn get_lego_path() -> anyhow::Result<std::path::PathBuf> {
    let bin_dir = std::path::Path::new("./bin");
    let _ = std::fs::create_dir_all(bin_dir);
    let lego_bin = bin_dir.join("lego.exe");

    if !lego_bin.exists() {
        log::info!("Lego binary not found. Downloading for Windows...");
        // Download lego v4.16.1 for Windows
        let url = "https://github.com/go-acme/lego/releases/download/v4.16.1/lego_v4.16.1_windows_amd64.zip";
        let res = reqwest::get(url).await?.bytes().await?;
        
        let reader = std::io::Cursor::new(res);
        let mut archive = zip::ZipArchive::new(reader)?;
        let mut file = archive.by_name("lego.exe")?;
        let mut outfile = std::fs::File::create(&lego_bin)?;
        std::io::copy(&mut file, &mut outfile)?;
        log::info!("Lego binary downloaded successfully.");
    }
    Ok(lego_bin)
}

#[post("/v1/websites/{websiteId}/ssl")]
pub async fn provision_ssl(
    req: HttpRequest,
    path: web::Path<String>,
    state: web::Data<AppState>,
) -> impl Responder {
    if !validate_api_key(&req, &state) { return HttpResponse::Unauthorized().finish(); }
    let website_id = path.into_inner();

    let site = match sqlx::query_as::<_, AppwriteWebsite>("SELECT * FROM websites WHERE id = $1")
        .bind(&website_id)
        .fetch_optional(&state.db)
        .await {
            Ok(Some(s)) => s,
            _ => return HttpResponse::NotFound().body("Website not found"),
        };

    let domain = match site.domain {
        Some(d) if !d.is_empty() => d,
        _ => return HttpResponse::BadRequest().body("Website must have a custom domain set first"),
    };

    let lego_path = match get_lego_path().await {
        Ok(p) => p,
        Err(e) => return HttpResponse::InternalServerError().body(format!("Failed to setup ACME tool: {}", e)),
    };

    log::info!("Running Lego for domain: {}", domain);

    // Use the built-in HTTP server mode of lego, but we need to stop our port 80 briefly or use webroot
    // Since we have a /static folder, we can use webroot mode if we wanted, 
    // but lego's 'http' mode is easiest if we can bind.
    // Better: use 'manual' mode or similar? No, let's use '--http.webroot' pointing to a temp folder
    // and our server already serves /.well-known/acme-challenge/ from ACME_CHALLENGES.
    
    // Actually, Lego doesn't easily support a custom hook for just providing the token string.
    // Let's use 'lego' with the '--http' flag. We will briefly stop our Port 80 listener.
    // BUT we are in the same process. 
    
    // NEW PLAN: We'll use Lego's 'manual' mode with a script hook that calls our own API to set the challenge.
    // OR just use 'lego' with '--http' and tell the user to make sure port 80 is free? No.
    
    // BEST PLAN: We use Lego's '--http' flag. Since our Port 80 listener is a separate HttpServer,
    // we can't easily "stop" it. 
    // Let's use Lego with '--webroot'. We'll create a temp dir.
    let webroot = std::path::Path::new("./storage/acme-webroot");
    let _ = std::fs::create_dir_all(webroot);

    let output = Command::new(lego_path)
        .args(&[
            "--email", "admin@local.system",
            "--accept-tos",
            "--domains", &domain,
            "--path", "./storage/acme",
            "run",
            "--http",
            "--http.webroot", "./storage/acme-webroot"
        ])
        .output();

    // We need to make sure our server serves files from ./storage/acme-webroot/.well-known/acme-challenge/
    // I will add a static file handler for this in main.rs.

    match output {
        Ok(out) if out.status.success() => {
            let cert_dir = format!("./storage/acme/certificates");
            let cert_path = format!("{}/{}.crt", cert_dir, domain);
            let key_path = format!("{}/{}.key", cert_dir, domain);

            if std::path::Path::new(&cert_path).exists() {
                let _ = sqlx::query("UPDATE websites SET ssl_cert = $1, ssl_key = $2 WHERE id = $3")
                    .bind(&cert_path)
                    .bind(&key_path)
                    .bind(&website_id)
                    .execute(&state.db)
                    .await;

                HttpResponse::Ok().json(serde_json::json!({ "status": "success", "message": "SSL Certificate issued and installed" }))
            } else {
                HttpResponse::InternalServerError().body("Lego reported success but files not found")
            }
        },
        Ok(out) => {
            let err = String::from_utf8_lossy(&out.stderr);
            HttpResponse::InternalServerError().body(format!("ACME failed: {}", err))
        },
        Err(e) => HttpResponse::InternalServerError().body(format!("Execution error: {}", e)),
    }
}

#[delete("/v1/websites/{websiteId}")]
pub async fn delete_website(
    req: HttpRequest,
    path: web::Path<String>,
    state: web::Data<AppState>,
) -> impl Responder {
    if !validate_api_key(&req, &state) { return HttpResponse::Unauthorized().finish(); }
    let website_id = path.into_inner();
    
    let _ = sqlx::query("DELETE FROM websites WHERE id = $1").bind(&website_id).execute(&state.db).await;
    let _ = std::fs::remove_dir_all(format!("./websites/{}", website_id));

    HttpResponse::NoContent().finish()
}

#[get("/admin/waf/logs")]
pub async fn get_waf_logs(
    req: HttpRequest,
    state: web::Data<AppState>,
) -> impl Responder {
    if !validate_api_key(&req, &state) { return HttpResponse::Unauthorized().finish(); }
    
    let rows = sqlx::query("SELECT id, ip, path, violation, created_at FROM waf_logs ORDER BY created_at DESC LIMIT 100")
        .fetch_all(&state.db)
        .await;

    match rows {
        Ok(rows) => {
            let logs: Vec<serde_json::Value> = rows.iter().map(|r| serde_json::json!({
                "id": r.get::<i32, _>("id"),
                "ip": r.get::<String, _>("ip"),
                "path": r.get::<String, _>("path"),
                "violation": r.get::<String, _>("violation"),
                "created_at": r.get::<chrono::DateTime<chrono::Utc>, _>("created_at"),
            })).collect();
            HttpResponse::Ok().json(logs)
        },
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
    }
}

#[get("/sites/{websiteId}/{tail:.*}")]
pub async fn serve_website(
    req: HttpRequest,
    path: web::Path<(String, String)>,
    state: web::Data<AppState>,
) -> impl Responder {
    let (website_id, tail) = path.into_inner();
    
    // Check if container exists
    let row = sqlx::query("SELECT port FROM websites WHERE id = $1 AND container_id IS NOT NULL")
        .bind(&website_id)
        .fetch_optional(&state.db)
        .await;

    if let Ok(Some(r)) = row {
        let port: i32 = r.get("port");
        let target_url = format!("http://127.0.0.1:{}/{}", port, tail);
        
        let client = reqwest::Client::new();
        let method_str = req.method().as_str();
        let req_method = reqwest::Method::from_bytes(method_str.as_bytes()).unwrap_or(reqwest::Method::GET);
        
        let mut proxy_req = client.request(req_method, &target_url);
        
        // Manual header copy to avoid crate version conflicts
        for (name, value) in req.headers() {
            if name != "host" {
                if let Ok(v) = value.to_str() {
                    proxy_req = proxy_req.header(name.as_str(), v);
                }
            }
        }

        let start_time = Instant::now();
        match proxy_req.send().await {
            Ok(res) => {
                let latency = start_time.elapsed().as_millis() as i64;
                let status_val = res.status().as_u16();
                let status_code = actix_web::http::StatusCode::from_u16(status_val).unwrap_or(actix_web::http::StatusCode::INTERNAL_SERVER_ERROR);
                
                let mut builder = HttpResponse::build(status_code);
                for (name, value) in res.headers() {
                    if let Ok(v) = value.to_str() {
                        builder.insert_header((name.as_str(), v));
                    }
                }
                
                let body = res.bytes().await.unwrap_or_default();
                let bytes_len = body.len() as i64;

                // Async Logging
                let db = state.db.clone();
                let website_id_log = website_id.clone();
                let ip_log = req.peer_addr().map(|a| a.to_string()).unwrap_or_else(|| "unknown".into());
                let method_log = req.method().to_string();
                let path_log = tail.clone();
                let sender = state.realtime_sender.clone();

                tokio::spawn(async move {
                    let _ = sqlx::query("INSERT INTO traffic_logs (website_id, ip, method, path, status_code, latency_ms, bytes_sent) VALUES ($1, $2, $3, $4, $5, $6, $7)")
                        .bind(website_id_log.clone())
                        .bind(ip_log.clone())
                        .bind(method_log.clone())
                        .bind(path_log.clone())
                        .bind(status_val as i32)
                        .bind(latency)
                        .bind(bytes_len)
                        .execute(&db).await;
                    
                    // Push to Realtime
                    let _ = sender.send(serde_json::to_string(&serde_json::json!({
                        "type": "traffic",
                        "data": {
                            "website_id": website_id_log,
                            "ip": ip_log,
                            "method": method_log,
                            "path": path_log,
                            "status": status_val,
                            "latency": latency,
                            "size": bytes_len,
                            "time": Utc::now().to_rfc3339()
                        }
                    })).unwrap_or_default());
                });

                return builder.body(body).into();
            },
            Err(_) => return HttpResponse::ServiceUnavailable().body("Container unreachable").into(),
        }
    }

    // Fallback to static serving
    let mut file_path = tail.clone();
    let start_time = Instant::now();

    let result = (|| async {
        // 1. Try Next.js default export dir 'out'
        let next_path = std::path::Path::new("./websites").join(&website_id).join("out").join(&file_path);
        if next_path.exists() && next_path.is_file() {
            if file_path.ends_with("index.html") {
                if let Ok(content) = std::fs::read_to_string(&next_path) {
                    let base_tag = format!("<head><base href=\"/sites/{}/\">", website_id);
                    let injected = content.replace("<head>", &base_tag);
                    return Ok((HttpResponse::Ok().content_type("text/html").body(injected), "out"));
                }
            }
            return Ok((NamedFile::open(next_path)?.into_response(&req), "out"));
        }

        // 2. Try Vite default export dir 'dist'
        let vite_path = std::path::Path::new("./websites").join(&website_id).join("dist").join(&file_path);
        if vite_path.exists() && vite_path.is_file() {
            if file_path.ends_with("index.html") {
                if let Ok(content) = std::fs::read_to_string(&vite_path) {
                    let base_tag = format!("<head><base href=\"/sites/{}/\">", website_id);
                    let injected = content.replace("<head>", &base_tag);
                    return Ok((HttpResponse::Ok().content_type("text/html").body(injected), "dist"));
                }
            }
            return Ok((NamedFile::open(vite_path)?.into_response(&req), "dist"));
        }

        // 3. Try root dir
        let full_path = std::path::Path::new("./websites").join(&website_id).join(&file_path);

        if !full_path.exists() || !full_path.is_file() {
            // Fallback to out/index.html, dist/index.html or root/index.html
            let next_index = std::path::Path::new("./websites").join(&website_id).join("out").join("index.html");
            if next_index.exists() {
                 if let Ok(content) = std::fs::read_to_string(&next_index) {
                    let base_tag = format!("<head><base href=\"/sites/{}/\">", website_id);
                    let injected = content.replace("<head>", &base_tag);
                    return Ok((HttpResponse::Ok().content_type("text/html").body(injected), "out-fallback"));
                 }
            }

            let vite_index = std::path::Path::new("./websites").join(&website_id).join("dist").join("index.html");
            if vite_index.exists() {
                 if let Ok(content) = std::fs::read_to_string(&vite_index) {
                    let base_tag = format!("<head><base href=\"/sites/{}/\">", website_id);
                    let injected = content.replace("<head>", &base_tag);
                    return Ok((HttpResponse::Ok().content_type("text/html").body(injected), "dist-fallback"));
                 }
            }

            let index_path = std::path::Path::new("./websites").join(&website_id).join("index.html");
            if index_path.exists() {
                return Ok((NamedFile::open(index_path)?.into_response(&req), "root-fallback"));
            }
            return Err(anyhow::anyhow!("File not found"));
        }

        Ok((NamedFile::open(full_path)?.into_response(&req), "root"))
    })().await;

    match result {
        Ok((res, _src)) => {
            let latency = start_time.elapsed().as_millis() as i64;
            let status = res.status().as_u16();
            
            // Async Logging for static traffic
            let db = state.db.clone();
            let website_id_log = website_id.clone();
            let ip_log = req.peer_addr().map(|a| a.to_string()).unwrap_or_else(|| "unknown".into());
            let method_log = req.method().to_string();
            let path_log = tail.clone();
            let sender = state.realtime_sender.clone();

            tokio::spawn(async move {
                let _ = sqlx::query("INSERT INTO traffic_logs (website_id, ip, method, path, status_code, latency_ms, bytes_sent) VALUES ($1, $2, $3, $4, $5, $6, $7)")
                    .bind(website_id_log.clone())
                    .bind(ip_log.clone())
                    .bind(method_log.clone())
                    .bind(path_log.clone())
                    .bind(status as i32)
                    .bind(latency)
                    .bind(0) // Bytes sent not easily captured for NamedFile here without wrapping
                    .execute(&db).await;
                
                let _ = sender.send(serde_json::to_string(&serde_json::json!({
                    "type": "traffic",
                    "data": {
                        "website_id": website_id_log,
                        "ip": ip_log,
                        "method": method_log,
                        "path": path_log,
                        "status": status,
                        "latency": latency,
                        "size": 0,
                        "time": Utc::now().to_rfc3339()
                    }
                })).unwrap_or_default());
            });

            res
        },
        Err(_) => HttpResponse::NotFound().body("File not found")
    }
}


