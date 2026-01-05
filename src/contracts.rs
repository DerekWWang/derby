use serde::Serialize;
use uuid::Uuid;

#[derive(Serialize)]
pub enum Side { Yes, No }

#[derive(Serialize)]
pub enum ContractState { Open, Filled, Cancelled }

#[derive(Serialize)]
pub struct Contract {
    pub id: Uuid,
    pub m_id: String,
    pub c_id: Uuid, // creator id
    pub total_amount: u64,
    pub rules: String,
    pub timestamp: i64,
    pub closing_timestamp: i64,
    pub state: ContractState,
}

pub struct Order {
    pub u_id: Uuid,
    pub contract_id: Uuid,
    pub side: Side,
    pub amount: u64,
    pub timestamp: i64,
}

