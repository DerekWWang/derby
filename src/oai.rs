use reqwest::header::{HeaderMap, AUTHORIZATION, CONTENT_TYPE};
use reqwest::Client;
use std::env;
use serde_derive::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
struct OAIRequest {
    model: String,
    messages: Vec<Message>,
}

#[derive(Debug, Deserialize)]
struct OAIResponse {
    choices: Vec<Choice>,
}

#[derive(Debug, Deserialize)]
struct Choice {
    message: Message,
}

#[derive(Serialize, Deserialize, Debug)]
struct Message {
    role: String,
    content: String,
}

const URI: &str = "https://api.openai.com/v1/chat/completions";
const MODEL: &str = "gpt-3.5-turbo";

pub async fn openai_query(text: &str) -> Result<String, Box<dyn std::error::Error>> {
    let oai_token = env::var("OPENAI_API").expect("OPENAI_API must be set");

    // Setup of HTTP Client
    let client = Client::new();

    let mut headers = HeaderMap::new();
    headers.insert(CONTENT_TYPE, "application/json".parse().unwrap());
    headers.insert(
        AUTHORIZATION,
        format!("Bearer {}", oai_token).parse().unwrap(),
    );

    let prompt_message: Message = Message {
        role: String::from("system"),
        content: String::from("You are a contract analyst, your goals are to intake certain context about a betting pool and analyze it. Once you have analyzed the context, generate and return a detailed contract that allows for little argumentation when being resolved in the future.\n\n"),
    };

    let req = OAIRequest {
        model: String::from(MODEL),
        messages: vec![
            prompt_message,
            Message {
                role: String::from("user"),
                content: String::from(text),
            },
        ],
    };

    let res = client
        .post(URI)
        .headers(headers)
        .json(&req)
        .send()
        .await?
        .json::<OAIResponse>()
        .await?;

    let message = res.choices.last().ok_or("No choices returned")?.message.content.clone();

    Ok(message)
}
