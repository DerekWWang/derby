use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use serde_json::json;
use sqlx::sqlite::SqlitePool;

mod contracts;
mod models;
use contracts::Contract;
use models::CreateContractRequest;

#[derive(Debug)]
enum ApiError {
    NotFound,
    InvalidInput(String),
    InternalServerError,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        match self {
            ApiError::NotFound => (StatusCode::NOT_FOUND, "Resource not found").into_response(),
            ApiError::InvalidInput(msg) => {
                (StatusCode::BAD_REQUEST, format!("Invalid input: {}", msg)).into_response()
            }
            ApiError::InternalServerError => {
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error").into_response()
            }
        }
    }
}

async fn health_check() -> impl IntoResponse {
    Json(json!({
        "status": "ok",
        "message": "Service is running"
    }))
}

pub async fn get_all_contracts(
    State(pool): State<SqlitePool>,
) -> Result<Json<Vec<Contract>>, (StatusCode, String)> {
    
    // Using query_as! (compile-time checked) to map results directly to our struct
    let contracts = sqlx::query_as!(
        Contract,
        "SELECT id, contract_name, client_name, total_value, status, created_at FROM contracts"
    )
    .fetch_all(&pool)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(contracts))
}

#[tokio::main]
async fn main() {
    println!("Hello, world!");
    let pool = SqlitePool::connect("sqlite:database.db?mode=rwc").await.unwrap();
    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .expect("Failed to run migrations");

    let app = Router::new()
        .route("/health", get(health_check))
        .route("/contracts", get(get_all_contracts))    
        .with_state(pool);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000")
        .await
        .expect("Failed to bind to address");

    println!("Server running on http://localhost:3000");

    axum::serve(listener, app).await.unwrap();
}
