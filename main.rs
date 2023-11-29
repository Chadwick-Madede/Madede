use actix_web::{web, App, HttpServer, HttpResponse, HttpRequest};
use jsonwebtoken::{encode, decode, Header, Algorithm, Validation, EncodingKey, DecodingKey};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    exp: usize,
}

struct AppState {
    secret_key: String,
    users: HashMap<String, Vec<Transaction>>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Transaction {
    amount: f64,
    description: String,
}

#[derive(Debug, Deserialize)]
struct AddTransaction {
    amount: f64,
    description: String,
}

async fn login(data: web::Json<LoginData>, state: web::Data<AppState>) -> HttpResponse {
    // Check the username and password (you would usually check against a database)
    if data.username == "user123" && data.password == "password123" {
        // Generate a JWT token
        let claims = Claims {
            sub: data.username.clone(),
            exp: (chrono::Utc::now() + chrono::Duration::hours(1)).timestamp() as usize,
        };
        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(state.secret_key.as_ref()),
        )
            .unwrap();

        // Return the token
        HttpResponse::Ok().json(token)
    } else {
        // Invalid credentials
        HttpResponse::Unauthorized().body("Invalid username or password")
    }
}

async fn add_transaction(
    data: web::Json<AddTransaction>,
    req: HttpRequest,
    state: web::Data<AppState>,
) -> HttpResponse {
    // Verify the user's token
    match req.headers().get("authorization") {
        Some(auth_header) => {
            let token = auth_header.to_str().unwrap().trim_start_matches("Bearer ");
            let claims = decode::<Claims>(
                token,
                &DecodingKey::from_secret(state.secret_key.as_ref()),
                &Validation::default(),
            );
            if let Ok(claims) = claims {
                // Add the transaction to the user's account
                let username = claims.claims.sub;
                let transaction = Transaction {
                    amount: data.amount,
                    description: data.description.clone(),
                };
                state.users.entry(username).or_insert(vec![]).push(transaction);

                // Return success
                HttpResponse::Ok().body("Transaction added successfully")
            } else {
                // Invalid token
                HttpResponse::Unauthorized().body("Invalid token")
            }
        }
        None => HttpResponse::Unauthorized().body("Token not provided"),
    }
}

async fn get_transactions(
    req: HttpRequest,
    state: web::Data<AppState>,
) -> HttpResponse {
    // Verify the user's token
    match req.headers().get("authorization") {
        Some(auth_header) => {
            let token = auth_header.to_str().unwrap().trim_start_matches("Bearer ");
            let claims = decode::<Claims>(
                token,
                &DecodingKey::from_secret(state.secret_key.as_ref()),
                &Validation::default(),
            );
            if let Ok(claims) = claims {
                // Get the user's transactions
                let username = claims.claims.sub;
                if let Some(transactions) = state.users.get(&username) {
                    return HttpResponse::Ok().json(transactions);
                }
            }

            // Invalid token or user not found
            HttpResponse::Unauthorized().body("Invalid token or user not found")
        }
        None => HttpResponse::Unauthorized().body("Token not provided"),
    }
}

#[derive(Debug, Deserialize)]
struct LoginData {
    username: String,
    password: String,
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Set a secret key for encoding and decoding JWT tokens
    let secret_key = "your_secret_key".to_string();

    // Create the App with state
    let app_state = web::Data::new(AppState {
        secret_key: secret_key.clone(),
        users: HashMap::new(),
    });

    // Start the HTTP server
    HttpServer::new(move || {
        App::new()
            .app_data(app_state.clone())
            .route("/login", web::post().to(login))
            .route("/transactions", web::get().to(get_transactions))
            .route("/transactions", web::post().to(add_transaction))
    })
        .bind("127.0.0.1:8080")?}