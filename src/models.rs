use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Deserialize)]
pub struct CreateContractRequest {
    m_id: String,
    c_id: Uuid,
    rules: String,
}

#[derive(Deserialize)]
pub struct CreateOrderRequest {
    pub u_id: Uuid,
    pub contract_id: Uuid,
    pub side: Side,
    pub amount: u64,
}