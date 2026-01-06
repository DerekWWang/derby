use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum Side { Yes, No }

#[derive(Serialize, Debug, Clone)]
pub enum ContractState { Open, Filled, Cancelled }

#[derive(Serialize)]
pub struct Contract {
    pub id: String,
    pub m_id: String,
    pub c_id: String, // creator id
    pub total_amount: i64,
    pub rules: String,
    pub timestamp: i64,
    pub closing_timestamp: i64,
    pub state: i64, // 0=Open, 1=Filled, 2=Cancelled
}

pub struct Order {
    pub u_id: String,
    pub contract_id: String,
    pub side: Side,
    pub amount: u64,
    pub timestamp: i64,
}

