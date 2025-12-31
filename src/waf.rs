use actix_web::{
    dev::{Service, ServiceRequest, ServiceResponse, Transform},
    Error, HttpResponse, body::EitherBody, web, http::header
};
use futures_util::future::{ok, Ready, LocalBoxFuture};
use std::task::{Context, Poll};
use log::{warn, info};
use sqlx::{Pool, Postgres, Row};
use std::sync::atomic::Ordering;
use crate::db::AppState;

pub struct Waf {
    pub db: Pool<Postgres>,
}

impl<S, B> Transform<S, ServiceRequest> for Waf
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    type InitError = ();
    type Transform = WafMiddleware<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ok(WafMiddleware {
            service: std::sync::Arc::new(service),
            db: self.db.clone(),
        })
    }
}

pub struct WafMiddleware<S> {
    service: std::sync::Arc<S>,
    db: Pool<Postgres>,
}

impl<S, B> Service<ServiceRequest> for WafMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.service.poll_ready(cx)
    }

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let db = self.db.clone();
        let service = self.service.clone();
        
        let host = req.headers().get("host").and_then(|h| h.to_str().ok()).unwrap_or("").to_string();
        let path = req.path().to_string();
        let query = req.query_string().to_string();
        let ip = req.peer_addr().map(|a| a.to_string()).unwrap_or_else(|| "unknown".into());
        
        let state = req.app_data::<web::Data<AppState>>().unwrap().clone();

        Box::pin(async move {
            // 0. Domain Mapping & Redirect
            // If the host is a custom domain, redirect to the site subpath
            if !host.contains("localhost") && !host.contains("127.0.0.1") {
                let website_match = sqlx::query("SELECT id FROM websites WHERE domain = $1 AND enabled = TRUE")
                    .bind(&host)
                    .fetch_optional(&db)
                    .await
                    .ok()
                    .flatten();

                if let Some(row) = website_match {
                    let site_id: String = row.get("id");
                    info!("Redirecting domain {} to website {}", host, site_id);
                    let target = if query.is_empty() {
                        format!("/sites/{}{}", site_id, path)
                    } else {
                        format!("/sites/{}{}?{}", site_id, path, query)
                    };
                    
                    let (req_parts, _payload) = req.into_parts();
                    let res = HttpResponse::TemporaryRedirect()
                        .insert_header((header::LOCATION, target))
                        .finish();
                    return Ok(ServiceResponse::new(req_parts, res).map_into_right_body());
                }
            }

            // 1. Global Lockdown Check
            if state.lockdown_mode.load(Ordering::SeqCst) {
                let referer = req.headers().get("referer").and_then(|h| h.to_str().ok()).unwrap_or("");
                let origin = req.headers().get("origin").and_then(|h| h.to_str().ok()).unwrap_or("");
                
                let is_from_console = path == "/console" || referer.contains("/console") || origin.contains("/console");
                let is_admin_route = path.starts_with("/admin");
                let is_ping = path == "/v1/ping" || path == "/favicon.ico";

                if !(is_from_console || is_admin_route || is_ping) {
                    warn!("WAF: Blocked external traffic to {} during Lockdown from {}", path, ip);
                    let (req_parts, _payload) = req.into_parts();
                    let res = HttpResponse::ServiceUnavailable().body("System Lockdown Active.");
                    return Ok(ServiceResponse::new(req_parts, res).map_into_right_body());
                }
            }

            // 2. Path Traversal Protection
            if path.contains("..") || path.contains("//") {
                warn!("WAF: Blocked potential path traversal from {}", ip);
                let _ = sqlx::query("INSERT INTO waf_logs (ip, path, violation) VALUES ($1, $2, $3)")
                    .bind(&ip).bind(&path).bind("Path Traversal").execute(&db).await;
                let (req_parts, _payload) = req.into_parts();
                let res = HttpResponse::Forbidden().body("Security Violation (Path)");
                return Ok(ServiceResponse::new(req_parts, res).map_into_right_body());
            }

            // 3. Attack Patterns
            let patterns = ["<script", "javascript:", "union select", "drop table", "--"];
            let combined = format!("{} {}", path, query).to_lowercase();
            for pattern in patterns {
                if combined.contains(pattern) {
                    warn!("WAF: Blocked attack pattern '{}' from {}", pattern, ip);
                    let _ = sqlx::query("INSERT INTO waf_logs (ip, path, violation) VALUES ($1, $2, $3)")
                        .bind(&ip).bind(&path).bind(format!("Pattern: {}", pattern)).execute(&db).await;
                    let (req_parts, _payload) = req.into_parts();
                    let res = HttpResponse::Forbidden().body("Security Violation (Pattern)");
                    return Ok(ServiceResponse::new(req_parts, res).map_into_right_body());
                }
            }

            // Forward to next service
            let res = service.call(req).await?;
            Ok(res.map_into_left_body())
        })
    }
}