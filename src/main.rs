use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use serde_json::json;
use sqlx::sqlite::SqlitePool;
use tower_http::cors::{CorsLayer, Any};

mod contracts;
mod models;
use contracts::Contract;
use models::{CreateContractRequest, CreateOrderRequest};

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

fn check_wallet() -> bool {
    // Placeholder logic for wallet check
    true
}

pub async fn get_all_contracts(
    State(pool): State<SqlitePool>,
) -> Result<Json<Vec<Contract>>, (StatusCode, String)> {
    
    // Using query_as! (compile-time checked) to map results directly to our struct
    let contracts = sqlx::query_as!(
        Contract,
        "SELECT id, m_id, c_id, total_amount, rules, timestamp, closing_timestamp, state FROM contracts"
    )
    .fetch_all(&pool)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    println!("Fetched {} contracts", contracts.len());
    Ok(Json(contracts))
}

pub async fn create_contract(
    State(pool): State<SqlitePool>,
    Json(payload): Json<CreateContractRequest>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, String)> {
    let id = uuid::Uuid::new_v4().to_string();
    let now = chrono::Utc::now().timestamp();
    
    // Calculate initial total_amount from creator's bet
    let initial_amount = payload.initial_amount.unwrap_or(0);
    
    let _new_contract = sqlx::query!(
        "INSERT INTO contracts (id, m_id, c_id, rules, total_amount, timestamp, closing_timestamp, state) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        id,
        payload.m_id,
        payload.c_id,
        payload.rules,
        initial_amount,
        now,
        payload.closing_timestamp,
        0i64, // initial state: 0=Open
    )
    .execute(&pool)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // If creator provided an initial bet, create an order for it
    if let (Some(side), Some(amount)) = (payload.initial_side, payload.initial_amount) {
        if amount > 0 {
            let side_int: i64 = match side {
                contracts::Side::Yes => 0,
                contracts::Side::No => 1,
            };
            sqlx::query!(
                "INSERT INTO orders (u_id, contract_id, side, amount, timestamp) VALUES (?, ?, ?, ?, ?)",
                payload.c_id,
                id,
                side_int,
                amount,
                now,
            )
            .execute(&pool)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        }
    }

    println!("Contract created with ID: {}", id);
    Ok((StatusCode::CREATED, Json(json!({"message": "Contract created successfully", "id": id}))))
}

pub async fn create_order(
    State(pool): State<SqlitePool>,
    Json(payload): Json<CreateOrderRequest>
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, String)> {
    let now = chrono::Utc::now().timestamp();
    let side_int: i64 = match payload.side {
        contracts::Side::Yes => 0,
        contracts::Side::No => 1,
    };
    let _new_order = sqlx::query!(
        "INSERT INTO orders (u_id, contract_id, side, amount, timestamp) VALUES (?, ?, ?, ?, ?)",
        payload.u_id,
        payload.contract_id,
        side_int,
        payload.amount,
        now,
    )
    .execute(&pool)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // Update the contract's total_amount by adding this order's amount
    let result = sqlx::query!(
        r#"
        UPDATE contracts 
        SET 
            total_amount = total_amount + ?
        WHERE id = ?
        "#,
        payload.amount,
        payload.contract_id
    )
    .execute(&pool)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    if result.rows_affected() == 0 {
        return Err((StatusCode::NOT_FOUND, "Contract not found".to_string()));
    }

    println!("Order created and contract updated successfully.");
    Ok((StatusCode::CREATED, Json(json!({"message": "Order created successfully"}))))
}

#[tokio::main]
async fn main() {
    println!("Hello, world!");
    let pool = SqlitePool::connect("sqlite:database.db?mode=rwc").await.unwrap();
    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .expect("Failed to run migrations");

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    let app = Router::new()
        .route("/health", get(health_check))
        .route("/contracts", get(get_all_contracts).post(create_contract))
        .route("/orders", axum::routing::post(create_order))
        .layer(cors)
        .with_state(pool);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000")
        .await
        .expect("Failed to bind to address");

    println!("Server running on http://localhost:3000");

    axum::serve(listener, app).await.unwrap();
}
