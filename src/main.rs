mod config;
mod crypto;
mod db;
mod handlers;
mod models;

use actix_web::{web, App, HttpServer, middleware};
use actix_files as fs;
use actix_cors::Cors;
use config::Config;
use db::{init_db, init_redis, init_mirrors, AppState};
use handlers::*;
use dotenv::dotenv;
use std::sync::Arc;
use tokio::sync::RwLock;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));

    let config = Config::from_env().expect("Failed to load configuration");

    log::info!("Starting Standalone Server at http://{}:{}", config.host, config.port);

    let pool = init_db(&config.database_url).await.expect("Failed to connect to Database");
    let mirrors = init_mirrors(&pool).await.expect("Failed to initialize mirrors");
    let redis_client = init_redis(&config.redis_url).expect("Failed to connect to Redis");
    let redis_mirrors = db::init_redis_mirrors(&pool).await.unwrap_or_default();

    let state = AppState {
        db: pool,
        mirrors: Arc::new(RwLock::new(mirrors)),
        redis: redis_client,
        redis_mirrors: Arc::new(RwLock::new(redis_mirrors)),
        crypto_key: Arc::new(RwLock::new(config.encryption_key.clone())),
        appwrite_api_key: config.appwrite_api_key.clone(),
        session_duration: config.session_duration,
        under_attack: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        load_balancer_mode: Arc::new(std::sync::atomic::AtomicBool::new(config.load_balancer_mode)),
        redis_read_index: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        total_requests: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
    };

    let background_state = state.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(86400));
        // Skip the immediate tick that happens on creation
        interval.tick().await;
        loop {
            interval.tick().await;
            log::info!("Starting scheduled background key rotation...");
            let _ = reroll_key_logic(&background_state).await;
        }
    });

    HttpServer::new(move || {
        let cors = Cors::default()
            .allowed_origin("http://localhost:5173")
            .allowed_origin("http://127.0.0.1:5173")
            .allowed_origin("http://localhost:8080")
            .allowed_origin("http://127.0.0.1:8080")
            .allow_any_method()
            .allow_any_header()
            .supports_credentials()
            .expose_any_header()
            .max_age(3600);

        App::new()
            .app_data(web::Data::new(state.clone()))
            .wrap(middleware::Logger::default())
            .wrap(cors)
            // Appwrite Emulator API
            .service(get_account)
            .service(register_account)
            .service(create_session)
            .service(delete_session)
            .service(get_document)
            .service(list_documents)
            .service(create_document)
            .service(delete_document)
            // Admin API
            .service(get_stats)
            .service(list_users)
            .service(list_data)
            .service(list_roles)
            .service(update_role_definition)
            .service(list_databases)
            .service(add_database)
            .service(get_security_status)
            .service(toggle_under_attack)
            .service(get_db_status)
            .service(list_redis_mirrors)
            .service(toggle_load_balancer)
            .service(reroll_key)
            .service(wipe_database)
            .service(fs::Files::new("/console", "./").index_file("test_app.html"))
    })
    .bind((config.host, config.port))?
    .run()
    .await
}