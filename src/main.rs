mod config;
mod crypto;
mod db;
mod handlers;
mod models;
mod waf;

use actix_web::{web, App, HttpServer, middleware, HttpResponse};
use actix_files as fs;
use actix_cors::Cors;
use config::Config;
use db::{init_db, init_redis, init_mirrors, AppState};
use handlers::*;
use dotenv::dotenv;
use std::sync::Arc;
use tokio::sync::RwLock;
use crate::models::LogEntry;
use chrono::Utc;

struct CustomLogger {
    logs: Arc<RwLock<Vec<LogEntry>>>,
    realtime_sender: tokio::sync::broadcast::Sender<String>,
}

impl log::Log for CustomLogger {
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        metadata.level() <= log::Level::Info
    }

    fn log(&self, record: &log::Record) {
        if self.enabled(record.metadata()) {
            let entry = LogEntry {
                timestamp: Utc::now().to_rfc3339(),
                level: record.level().to_string(),
                message: record.args().to_string(),
            };
            
            let logs = self.logs.clone();
            let sender = self.realtime_sender.clone();
            
            tokio::spawn(async move {
                let mut logs_write = logs.write().await;
                logs_write.push(entry.clone());
                if logs_write.len() > 100 {
                    logs_write.remove(0);
                }
                
                if let Ok(json) = serde_json::to_string(&serde_json::json!({
                    "type": "log",
                    "data": entry
                })) {
                    let _ = sender.send(json);
                }
            });
        }
    }

    fn flush(&self) {}
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();
    
    let (rt_tx, _) = tokio::sync::broadcast::channel::<String>(100);
    let logs_buffer = Arc::new(RwLock::new(Vec::new()));

    let logger = CustomLogger {
        logs: logs_buffer.clone(),
        realtime_sender: rt_tx.clone(),
    };
    
    log::set_boxed_logger(Box::new(logger)).unwrap();
    log::set_max_level(log::LevelFilter::Info);

    let config = Config::from_env().expect("Failed to load configuration");

    log::info!("Starting Standalone Server at http://{}:{}", config.host, config.port);

    let pool = init_db(&config.database_url).await.expect("Failed to connect to Database");
    
    let _ = sqlx::query("TRUNCATE TABLE registered_redis").execute(&pool).await;

    let mirrors = init_mirrors(&pool).await.expect("Failed to initialize mirrors");
    let redis_client = init_redis(&config.redis_url).expect("Failed to connect to Redis");
    let redis_mirrors = db::init_redis_mirrors(&pool).await.unwrap_or_default();

    let s3_config = sqlx::query_as::<_, crate::models::S3Config>("SELECT bucket, region, access_key, secret_key, endpoint, enabled FROM s3_config WHERE enabled = TRUE LIMIT 1")
        .fetch_optional(&pool).await.ok().flatten();

    let mut s3_client = None;
    if let Some(config) = s3_config {
        let creds = s3::creds::Credentials::new(Some(&config.access_key), Some(&config.secret_key), None, None, None).unwrap();
        let region = config.region.parse::<s3::Region>().unwrap_or(s3::Region::Custom {
            region: config.region.clone(),
            endpoint: config.endpoint.unwrap_or_else(|| "https://s3.amazonaws.com".to_string()),
        });
        s3_client = s3::Bucket::new(&config.bucket, region, creds).ok();
    }

    let state = AppState {
        db: pool.clone(),
        mirrors: Arc::new(RwLock::new(mirrors)),
        redis: redis_client.clone(),
        redis_mirrors: Arc::new(RwLock::new(redis_mirrors)),
        crypto_key: Arc::new(RwLock::new(config.encryption_key.clone())),
        appwrite_api_key: config.appwrite_api_key.clone(),
        session_duration: config.session_duration,
        under_attack: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        lockdown_mode: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        load_balancer_mode: Arc::new(std::sync::atomic::AtomicBool::new(config.load_balancer_mode)),
        redis_read_index: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        total_requests: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        realtime_sender: rt_tx.clone(),
        logs: logs_buffer,
        s3_client: Arc::new(RwLock::new(s3_client)),
    };

    let factory = {
        let state = state.clone();
        let pool = pool.clone();
        move || {
            let cors = Cors::default()
                .allow_any_origin().allow_any_method().allow_any_header().supports_credentials().expose_any_header().max_age(3600);

            App::new()
                .app_data(web::Data::new(state.clone()))
                .app_data(web::PayloadConfig::new(100 * 1024 * 1024))
                .wrap(middleware::Logger::default())
                .wrap(crate::waf::Waf { db: pool.clone() })
                .wrap(cors)
                            .service(ping).service(realtime).service(get_account).service(register_account)
                            .service(acme_challenge)
                            .service(verify_email).service(create_session).service(delete_session)
                            .service(get_document).service(list_documents).service(create_document).service(delete_document)
                            .service(get_stats).service(list_users).service(delete_user).service(toggle_user_status)
                            .service(list_data).service(get_data_by_id).service(delete_data_by_id)
                            .service(list_roles).service(update_role_definition)
                            .service(upload_file).service(get_file_view).service(list_files).service(delete_file)
                            .service(get_s3_config).service(update_s3_config)
                            .service(list_functions).service(create_function).service(create_deployment).service(clone_repo)
                            .service(create_execution).service(list_executions).service(get_execution)
                            .service(list_websites).service(create_website).service(update_website_domain).service(provision_ssl).service(delete_website)
                
                .service(upload_website_content).service(clone_website_repo).service(build_website).service(docker_deploy)
                .service(get_waf_logs).service(serve_website).service(list_databases).service(add_database)
                .service(get_security_status).service(toggle_under_attack).service(toggle_lockdown).service(get_db_status)
                .service(list_redis_mirrors).service(add_redis_mirror).service(toggle_load_balancer).service(reroll_key)
                .service(wipe_database).service(restart_server).service(get_smtp_config).service(update_smtp_config).service(get_logs)
                .service(fs::Files::new("/.well-known/acme-challenge", "./storage/acme-webroot/.well-known/acme-challenge"))
                .service(fs::Files::new("/console", "./").index_file("test_app.html"))
                .default_service(web::to(|| async { HttpResponse::NotFound().body("Standalone Emulator: Route not found") }))
        }
    };

    let main_server = HttpServer::new(factory.clone())
        .bind((config.host.clone(), config.port))?
        .run();

    let p80_server = HttpServer::new(factory)
        .bind((config.host.clone(), 80));

    log::info!("Starting servers...");
    match p80_server {
        Ok(s) => {
            log::info!("Standard Web Port (80) is active");
            tokio::select! {
                res = main_server => res,
                res = s.run() => res,
            }
        },
        Err(e) => {
            log::warn!("Standard Web Port (80) failed: {}. Running on primary port only.", e);
            main_server.await
        }
    }
}
