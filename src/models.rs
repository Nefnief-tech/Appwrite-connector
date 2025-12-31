use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AppwriteRequest {
    // This allows accepting any JSON object
    #[serde(flatten)]
    pub payload: serde_json::Value,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct StoredData {
    pub id: Uuid,
    pub user_id: String,
    pub encrypted_content: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ApiResponse {
    pub id: Uuid,
    pub status: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct AuthRequest {
    pub username: String,
    pub password: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct AuthResponse {
    pub user_id: String,
    pub username: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SystemStats {
    pub total_records: i64,
    pub total_users: i64,
    pub total_roles: i64,
    pub total_requests: usize,
    pub under_attack: bool,
    pub load_balancer_mode: bool,
}

#[derive(Serialize, Deserialize, Debug, sqlx::FromRow)]
pub struct UserSummary {
    pub id: String,
    pub username: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub status: bool,
}

#[derive(Serialize, Deserialize, Debug, sqlx::FromRow)]
pub struct DataSummary {
    pub id: Uuid,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct UserProfile {
    pub user_id: String,
    pub roles: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct MessageResponse {
    pub message: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RoleDefinition {
    pub name: String,
    pub permissions: Vec<String>, // e.g., ["data:read", "data:write", "profile:manage"]
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DatabaseConfig {
    pub name: String,
    pub url: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AppwriteUser {
    #[serde(rename = "$id")]
    pub id: String,
    #[serde(rename = "$createdAt")]
    pub created_at: String,
    #[serde(rename = "$updatedAt")]
    pub updated_at: String,
    pub name: String,
    pub email: String,
    pub status: bool,
    pub emailVerification: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AppwriteSession {
    #[serde(rename = "$id")]
    pub id: String,
    #[serde(rename = "$createdAt")]
    pub created_at: String,
    #[serde(rename = "userId")]
    pub user_id: String,
    pub expire: String,
    pub provider: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AppwriteDocument {
    #[serde(rename = "$id")]
    pub id: String,
    #[serde(rename = "$collectionId")]
    pub collection_id: String,
    #[serde(rename = "$databaseId")]
    pub database_id: String,
    #[serde(rename = "$createdAt")]
    pub created_at: String,
    #[serde(rename = "$updatedAt")]
    pub updated_at: String,
    #[serde(flatten)]
    pub data: serde_json::Value,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AppwriteDocumentList {
    pub total: i64,
    pub documents: Vec<AppwriteDocument>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AppwriteRealtimeEvent {
    pub events: Vec<String>,
    pub channels: Vec<String>,
    pub timestamp: String,
    pub payload: serde_json::Value,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DatabaseStatus {
    pub name: String,
    pub url: String,
    pub online: bool,
    pub is_mirror: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SecurityStatus {
    pub under_attack: bool,
    pub load_balancer_mode: bool,
    pub redis_mirrors_count: usize,
}

#[derive(Serialize, Deserialize, Debug, Clone, sqlx::FromRow)]
pub struct S3Config {
    pub provider: String, // 's3' or 'local'
    pub bucket: String,
    pub region: String,
    pub access_key: String,
    pub secret_key: String,
    pub endpoint: Option<String>,
    pub enabled: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone, sqlx::FromRow)]
pub struct FileMetadata {
    #[serde(rename = "$id")]
    pub id: String,
    pub name: String,
    pub mime_type: String,
    pub size_bytes: i64,
    pub user_id: String,
    #[serde(rename = "$createdAt")]
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Serialize, Deserialize, Debug, Clone, sqlx::FromRow)]
pub struct SmtpConfig {
    pub host: String,
    pub port: i32,
    pub username: String,
    pub password: String,
    pub from_email: String,
    pub enabled: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct LogEntry {
    pub timestamp: String,
    pub level: String,
    pub message: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, sqlx::FromRow)]
pub struct AppwriteFunction {
    #[serde(rename = "$id")]
    pub id: String,
    #[serde(rename = "$createdAt")]
    pub created_at: chrono::DateTime<chrono::Utc>,
    #[serde(rename = "$updatedAt")]
    pub updated_at: chrono::DateTime<chrono::Utc>,
    pub name: String,
    pub runtime: String, // e.g., "node-18.0", "python-3.10"
    pub enabled: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone, sqlx::FromRow)]
pub struct AppwriteExecution {
    #[serde(rename = "$id")]
    pub id: String,
    #[serde(rename = "functionId")]
    pub function_id: String,
    #[serde(rename = "$createdAt")]
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub status: String, // "waiting", "processing", "completed", "failed"
    #[serde(rename = "stdout")]
    pub stdout: String,
    #[serde(rename = "stderr")]
    pub stderr: String,
    pub duration: f64,
    #[serde(rename = "statusCode")]
    pub status_code: i32,
}

#[derive(Serialize, Deserialize, Debug, Clone, sqlx::FromRow)]
pub struct AppwriteWebsite {
    #[serde(rename = "$id")]
    pub id: String,
    #[serde(rename = "$createdAt")]
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub name: String,
    pub domain: Option<String>,
    pub enabled: bool,
    #[serde(rename = "containerId")]
    pub container_id: Option<String>,
    pub port: Option<i32>,
}

#[derive(Serialize, Deserialize, Debug, Clone, sqlx::FromRow)]
pub struct TrafficLog {
    pub id: i32,
    pub website_id: String,
    pub ip: String,
    pub method: String,
    pub path: String,
    pub status_code: i32,
    pub latency_ms: i64,
    pub bytes_sent: i64,
    pub created_at: chrono::DateTime<chrono::Utc>,
}
