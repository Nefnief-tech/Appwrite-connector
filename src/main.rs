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
use handlers::{
    store_data, get_data, list_data, get_profile, update_profile, 
    list_roles, update_role_definition, login, register, 
    get_stats, list_users, add_database, list_databases, get_db_status,
    reroll_key, reroll_key_logic
};
use dotenv::dotenv;
use std::sync::Arc;
use tokio::sync::RwLock;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));

    let config = Config::from_env().expect("Failed to load configuration");

    log::info!("Starting server at http://{}:{}", config.host, config.port);

    let pool = init_db(&config.database_url).await.expect("Failed to connect to Database");
    let mirrors = init_mirrors(&pool).await.expect("Failed to initialize mirrors");
    log::info!("Loaded {} database mirrors from registry", mirrors.len());
    let redis_client = init_redis(&config.redis_url).expect("Failed to connect to Redis");

    let state = AppState {
        db: pool,
        mirrors: Arc::new(RwLock::new(mirrors)),
        redis: redis_client,
        crypto_key: Arc::new(RwLock::new(config.encryption_key.clone())),
        appwrite_api_key: config.appwrite_api_key.clone(),
        appwrite_endpoint: config.appwrite_endpoint.clone(),
    };

    // Background Task: Daily Key Rotation
    let background_state = state.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(86400)); // 24 hours
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        
        // Skip the immediate tick
        interval.tick().await;

        loop {
            interval.tick().await;
            log::info!("Starting scheduled key rotation...");
            if let Err(e) = reroll_key_logic(&background_state).await {
                log::error!("Scheduled key rotation failed: {}", e);
            } else {
                log::info!("Scheduled key rotation completed successfully.");
            }
        }
    });

    HttpServer::new(move || {
        let cors = Cors::default()
            .allow_any_origin()
            .allow_any_method()
            .allow_any_header()
            .max_age(3600);

        App::new()
            .app_data(web::Data::new(state.clone()))
            .wrap(middleware::Logger::default())
            .wrap(cors)
            .service(register)
            .service(login)
            .service(get_stats)
            .service(list_users)
            .service(store_data)
            .service(list_data)
            .service(get_data)
            .service(get_profile)
            .service(update_profile)
            .service(list_roles)
            .service(update_role_definition)
            .service(add_database)
            .service(list_databases)
            .service(get_db_status)
            .service(reroll_key)
            .service(fs::Files::new("/", "./").index_file("test_app.html"))
    })
    .bind((config.host, config.port))?
    .run()
    .await
}
