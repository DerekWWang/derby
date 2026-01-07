use serde::Deserialize;
use crate::contracts::Side;

#[derive(Deserialize)]
pub struct CreateContractRequest {
    pub m_id: String,
    pub c_id: Option<String>,
    pub rules: String,
    pub closing_timestamp: i64,
    // Creator's initial bet (optional)
    pub initial_side: Option<Side>,
    pub initial_amount: Option<i64>,
}

#[derive(Deserialize)]
pub struct CreateOrderRequest {
    pub u_id: Option<String>,
    pub contract_id: String,
    pub side: Side,
    pub amount: i64,
}

#[derive(Deserialize)]
pub struct RegisterUserRequest {
    pub username: String,
    pub password: String,
}

#[derive(Deserialize)]
pub struct LoginUserRequest {
    pub username: String,
    pub password: String,
}