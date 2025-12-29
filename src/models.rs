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
pub struct DatabaseStatus {
    pub name: String,
    pub url: String,
    pub online: bool,
    pub is_mirror: bool,
}
