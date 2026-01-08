use axum::{
    extract::{State, Path},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get,
    Json, Router, RequestPartsExt,
    http::{header, Request},
    middleware::Next,
};
use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};

use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use rand_core::OsRng;

use serde_json::json;
use sqlx::sqlite::SqlitePool;
use tower_http::cors::{CorsLayer, Any};

mod contracts;
mod models;
mod oai;
use contracts::Contract;
use models::{CreateContractRequest, CreateOrderRequest, RegisterUserRequest, LoginUserRequest};

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

pub fn hash_password(password: &str) -> String {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    argon2.hash_password(password.as_bytes(), &salt)
        .expect("Failed to hash password")
        .to_string()
}

const JWT_SECRET: &[u8] = b"secret"; // In production, use environment variable

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    sub: String,
    exp: usize,
}

impl<S> FromRequestParts<S> for Claims
where
    S: Send + Sync,
{
    type Rejection = (StatusCode, Json<serde_json::Value>);

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let auth_header = parts
            .headers
            .get(header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .ok_or((
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": "Missing Authorization header"})),
            ))?;

        if !auth_header.starts_with("Bearer ") {
            return Err((
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": "Invalid Authorization header"})),
            ));
        }

        let token = &auth_header[7..];

        let token_data = decode::<Claims>(
            token,
            &DecodingKey::from_secret(JWT_SECRET),
            &Validation::default(),
        )
        .map_err(|_| (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "Invalid token"})),
        ))?;

        Ok(token_data.claims)
    }
}

pub async fn login_user(State(pool): State<SqlitePool>, Json(payload): Json<LoginUserRequest>) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    let user_record = sqlx::query!(
        "SELECT id, password_hash FROM users WHERE username = ?",
        payload.username
    )
    .fetch_optional(&pool)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e.to_string()}))))?;

    let user = user_record.ok_or((StatusCode::UNAUTHORIZED, Json(json!({"error": "Invalid credentials"}))))?;

    let parsed_hash = PasswordHash::new(&user.password_hash)
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "Failed to parse password hash"}))))?;
    
    Argon2::default()
        .verify_password(payload.password.as_bytes(), &parsed_hash)
        .map_err(|_| (StatusCode::UNAUTHORIZED, Json(json!({"error": "Invalid credentials"}))))?;

    let expiration = chrono::Utc::now()
        .checked_add_signed(chrono::Duration::hours(24))
        .expect("valid timestamp")
        .timestamp() as usize;

    let claims = Claims {
        sub: user.id.clone(),
        exp: expiration,
    };

    let token = encode(&Header::default(), &claims, &EncodingKey::from_secret(JWT_SECRET))
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "Token creation failed"}))))?;

    Ok((StatusCode::OK, Json(json!({
        "message": "Login successful",
        "user_id": user.id,
        "token": token
    }))))
}

pub async fn register_user(
    State(pool): State<SqlitePool>,
    Json(payload): Json<RegisterUserRequest>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    let hashed_password = hash_password(&payload.password);
    let id = uuid::Uuid::new_v4().to_string();

    let now = chrono::Utc::now().timestamp();
    let _new_user = sqlx::query!(
        "INSERT INTO users (id, username, password_hash, created_at) VALUES (?, ?, ?, ?)",
        id,
        payload.username,
        hashed_password,
        now,
    )
    .execute(&pool)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e.to_string()}))))?;

    let _new_wallet = sqlx::query!(
        "INSERT INTO wallets (user_id, current_amount) VALUES (?, ?)",
        id,
        200i64, // initial wallet amount
    )
    .execute(&pool)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e.to_string()}))))?;

    let expiration = chrono::Utc::now()
        .checked_add_signed(chrono::Duration::hours(24))
        .expect("valid timestamp")
        .timestamp() as usize;

    let claims = Claims {
        sub: id.clone(),
        exp: expiration,
    };

    let token = encode(&Header::default(), &claims, &EncodingKey::from_secret(JWT_SECRET))
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "Token creation failed"}))))?;

    println!("User created with ID: {}", id);
    Ok((StatusCode::CREATED, Json(json!({
        "message": "User created successfully",
        "id": id,
        "token": token
    }))))
}

pub async fn check_wallet(State(pool): State<SqlitePool>, amount: i64, user_id: &String) -> bool {
    let wallet_record = sqlx::query!(
        "SELECT current_amount FROM wallets WHERE user_id = ?",
        user_id
    )
    .fetch_one(&pool)
    .await;

    match wallet_record {
        Ok(record) => record.current_amount >= amount,
        Err(_) => false,
    }
}

pub async fn get_wallet_amount(State(pool): State<SqlitePool>, user_id: &String) -> Result<i64, sqlx::Error> {
    let wallet_record = sqlx::query!(
        "SELECT current_amount FROM wallets WHERE user_id = ?",
        user_id
    )
    .fetch_one(&pool)
    .await?;

    Ok(wallet_record.current_amount)
}

pub async fn get_wallet_balance(
    State(pool): State<SqlitePool>,
    Path(user_id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    match get_wallet_amount(State(pool), &user_id).await {
        Ok(amount) => Ok(Json(json!({ "user_id": user_id, "amount": amount }))),
        Err(_) => Err((StatusCode::NOT_FOUND, Json(json!({ "error": "Wallet not found" })))),
    }
}

pub async fn deduct_funds(pool: &SqlitePool, amount: i64, user_id: &String) -> Result<bool, sqlx::Error> {
    let result = sqlx::query!(
        "UPDATE wallets SET current_amount = current_amount - ? WHERE user_id = ? AND current_amount >= ?",
        amount,
        user_id,
        amount
    )
    .execute(pool)
    .await?;

    Ok(result.rows_affected() > 0)
}

pub async fn get_all_contracts(
    State(pool): State<SqlitePool>,
) -> Result<Json<Vec<Contract>>, (StatusCode, Json<serde_json::Value>)> {
    
    // Using query_as! (compile-time checked) to map results directly to our struct
    let contracts = sqlx::query_as!(
        Contract,
        "SELECT id, m_id, c_id, total_amount, rules, timestamp, closing_timestamp, state FROM contracts"
    )
    .fetch_all(&pool)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e.to_string()}))))?;

    println!("Fetched {} contracts", contracts.len());
    Ok(Json(contracts))
}

pub async fn create_contract(
    State(pool): State<SqlitePool>,
    claims: Claims,
    Json(payload): Json<CreateContractRequest>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    let id = uuid::Uuid::new_v4().to_string();
    let now = chrono::Utc::now().timestamp();

    if let Some(closing) = payload.closing_timestamp.checked_sub(now) {
        if closing < 3600 {
            return Err((StatusCode::BAD_REQUEST, Json(json!({"error": "Closing timestamp must be at least 1 hour in the future"}))));
        }
    } else {
        return Err((StatusCode::BAD_REQUEST, Json(json!({"error": "Closing timestamp must be in the future"}))));
    }
    
    // Calculate initial total_amount from creator's bet
    let creator = claims.sub; // Use authenticated user ID
    let initial_amount = payload.initial_amount.unwrap_or(0);
    
    if initial_amount > 0 {
        let deducted = deduct_funds(&pool, initial_amount, &creator)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e.to_string()}))))?;
            
        if !deducted {
            return Err((StatusCode::BAD_REQUEST, Json(json!({"error": "Insufficient funds in wallet"}))));
        }
    }
    
    let _new_contract = sqlx::query!(
        "INSERT INTO contracts (id, m_id, c_id, rules, total_amount, timestamp, closing_timestamp, state) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        id,
        payload.m_id,
        creator,
        payload.rules,
        initial_amount,
        now,
        payload.closing_timestamp,
        0i64, // initial state: 0=Open
    )
    .execute(&pool)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e.to_string()}))))?;

    // If creator provided an initial bet, create an order for it
    if let (Some(side), Some(amount)) = (payload.initial_side, payload.initial_amount) {
        if amount > 0 {
            let side_int: i64 = match side {
                contracts::Side::Yes => 0,
                contracts::Side::No => 1,
            };
            sqlx::query!(
                "INSERT INTO orders (u_id, contract_id, side, amount, timestamp) VALUES (?, ?, ?, ?, ?)",
                creator,
                id,
                side_int,
                amount,
                now,
            )
            .execute(&pool)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e.to_string()}))))?;
        }
    }

    println!("Contract created with ID: {}", id);
    Ok((StatusCode::CREATED, Json(json!({"message": "Contract created successfully", "id": id}))))
}

pub async fn create_order(
    State(pool): State<SqlitePool>,
    claims: Claims,
    Json(payload): Json<CreateOrderRequest>
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    let now = chrono::Utc::now().timestamp();
    
    // Deduct funds
    let deducted = deduct_funds(&pool, payload.amount, &claims.sub)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e.to_string()}))))?;

    if !deducted {
         return Err((StatusCode::BAD_REQUEST, Json(json!({"error": "Insufficient funds"}))));
    }

    let side_int: i64 = match payload.side {
        contracts::Side::Yes => 0,
        contracts::Side::No => 1,
    };
    let _new_order = sqlx::query!(
        "INSERT INTO orders (u_id, contract_id, side, amount, timestamp) VALUES (?, ?, ?, ?, ?)",
        claims.sub,
        payload.contract_id,
        side_int,
        payload.amount,
        now,
    )
    .execute(&pool)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e.to_string()}))))?;

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
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e.to_string()}))))?;

    if result.rows_affected() == 0 {
        return Err((StatusCode::NOT_FOUND, Json(json!({"error": "Contract not found"}))));
    }

    println!("Order created and contract updated successfully.");
    Ok((StatusCode::CREATED, Json(json!({"message": "Order created successfully"}))))
}

pub async fn augment_contract_with_oai(contract_rules: &str) -> Result<String, Box<dyn std::error::Error>> {
    let prompt = format!(
        "Analyze the following betting pool context and generate a detailed contract that minimizes future disputes:\n\n{}",
        contract_rules
    );

    let response = oai::openai_query(&prompt).await?;
    Ok(response)
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
        .route("/register", axum::routing::post(register_user))
        .route("/login", axum::routing::post(login_user))
        .route("/wallet/{user_id}", get(get_wallet_balance))
        .route("")
        .layer(cors)
        .with_state(pool);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000")
        .await
        .expect("Failed to bind to address");

    println!("Server running on http://localhost:3000");

    axum::serve(listener, app).await.unwrap();
}
