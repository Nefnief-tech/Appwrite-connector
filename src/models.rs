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
