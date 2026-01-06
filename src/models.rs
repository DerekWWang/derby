use serde::Deserialize;
use crate::contracts::Side;

#[derive(Deserialize)]
pub struct CreateContractRequest {
    pub m_id: String,
    pub c_id: String,
    pub rules: String,
    pub closing_timestamp: i64,
}

#[derive(Deserialize)]
pub struct CreateOrderRequest {
    pub u_id: String,
    pub contract_id: String,
    pub side: Side,
    pub amount: i64,
}