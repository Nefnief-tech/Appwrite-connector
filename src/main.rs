mod config;
mod crypto;
mod db;
mod handlers;
mod models;

use actix_web::{web, App, HttpServer, middleware, HttpResponse};
use actix_files as fs;
use actix_cors::Cors;
use config::Config;
use db::{init_db, init_redis, init_mirrors, AppState};
use handlers::*;
use dotenv::dotenv;
use std::sync::Arc;
use tokio::sync::RwLock;
use futures::StreamExt;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));

    let config = Config::from_env().expect("Failed to load configuration");

    log::info!("Starting Standalone Server at http://{}:{}", config.host, config.port);

    let pool = init_db(&config.database_url).await.expect("Failed to connect to Database");
    
    // Clear stale Redis mirrors from DB to prevent port 1354 conflicts
    log::info!("Cleaning up Redis mirror registry...");
    let _ = sqlx::query("TRUNCATE TABLE registered_redis").execute(&pool).await;

    let mirrors = init_mirrors(&pool).await.expect("Failed to initialize mirrors");
    let redis_client = init_redis(&config.redis_url).expect("Failed to connect to Redis");
    
    // Verify Primary Redis Connection on Startup
    {
        match redis_client.get_async_connection().await {
            Ok(mut conn) => {
                match redis::cmd("PING").query_async::<_, String>(&mut conn).await {
                    Ok(_) => log::info!("Successfully connected to Primary Redis"),
                    Err(e) => log::error!("Redis PING failed. Authentication might have failed: {}", e),
                }
            },
            Err(e) => log::error!("Failed to connect to Primary Redis. Check your REDIS_URL and password: {}", e),
        }
    }

    let redis_mirrors = db::init_redis_mirrors(&pool).await.unwrap_or_default();

    let (rt_tx, _) = tokio::sync::broadcast::channel::<String>(100);

    let state = AppState {
        db: pool,
        mirrors: Arc::new(RwLock::new(mirrors)),
        redis: redis_client.clone(),
        redis_mirrors: Arc::new(RwLock::new(redis_mirrors)),
        crypto_key: Arc::new(RwLock::new(config.encryption_key.clone())),
        appwrite_api_key: config.appwrite_api_key.clone(),
        session_duration: config.session_duration,
        under_attack: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        load_balancer_mode: Arc::new(std::sync::atomic::AtomicBool::new(config.load_balancer_mode)),
        redis_read_index: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        total_requests: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        realtime_sender: rt_tx.clone(),
    };

    // Redis Pub/Sub Listener Task
    let pubsub_client = redis_client.clone();
    tokio::spawn(async move {
        loop {
            match pubsub_client.get_async_connection().await {
                Ok(conn) => {
                    let mut pubsub = conn.into_pubsub();
                    if let Err(e) = pubsub.subscribe("realtime_events").await {
                        log::error!("Redis PubSub subscribe failed: {}", e);
                        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                        continue;
                    }
                    
                    let mut stream = pubsub.on_message();
                    log::info!("Realtime PubSub listener active on channel 'realtime_events'");
                    
                    while let Some(msg) = stream.next().await {
                        let payload: String = msg.get_payload().unwrap_or_default();
                        let _ = rt_tx.send(payload);
                    }
                }
                Err(e) => {
                    log::error!("Redis PubSub connection failed: {}. Retrying...", e);
                    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                }
            }
        }
    });

    // Flush Redis on Startup
    log::info!("Flushing Redis caches on startup...");
    if let Ok(mut conn) = state.redis.get_async_connection().await {
        let _: Result<(), _> = redis::cmd("FLUSHDB").query_async(&mut conn).await;
    }
    {
        let mirrors = state.redis_mirrors.read().await;
        for mirror in mirrors.iter() {
            if let Ok(mut conn) = mirror.get_async_connection().await {
                let _: Result<(), _> = redis::cmd("FLUSHDB").query_async(&mut conn).await;
            }
        }
    }

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
            .service(ping)
            .service(get_account)
            .service(register_account)
            .service(create_session)
            .service(delete_session)
            .service(get_document)
            .service(list_documents)
            .service(create_document)
            .service(delete_document)
            .service(realtime)
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
            .service(add_redis_mirror)
            .service(toggle_load_balancer)
            .service(reroll_key)
            .service(wipe_database)
            .service(fs::Files::new("/console", "./").index_file("test_app.html"))
            .default_service(web::to(|| async { HttpResponse::NotFound().body("Standalone Emulator: Route not found") }))
    })
    .bind((config.host, config.port))?
    .run()
    .await
}