use ring::{aead, pbkdf2, rand, hmac};
use ring::digest;
use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod};
use hyper::{Body, Request, Response, Server};
use hyper::service::{make_service_fn, service_fn};
use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use rand::SecureRandom;
use tokio::task;

type UserId = String;
type EncryptedMessage = Vec<u8>;

#[derive(Clone)]
struct User {
    password_hash: Vec<u8>,
    encryption_key: Vec<u8>,
}

struct AppState {
    users: Mutex<HashMap<UserId, User>>,
    messages: Mutex<HashMap<UserId, Vec<EncryptedMessage>>>,
}

impl AppState {
    fn new() -> Self {
        AppState {
            users: Mutex::new(HashMap::new()),
            messages: Mutex::new(HashMap::new()),
        }
    }
}

// Key generation for encryption
fn generate_encryption_key() -> Vec<u8> {
    let rng = rand::SystemRandom::new();
    let mut key = vec![0u8; 32]; // 256-bit key
    rng.fill(&mut key).unwrap();
    key
}

// Hash a password using PBKDF2
fn hash_password(password: &str) -> Vec<u8> {
    let salt = b"some_salt"; // Salt should be unique per user
    let mut hash = vec![0u8; digest::SHA256_OUTPUT_LEN];
    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA256,
        std::num::NonZeroU32::new(100_000).unwrap(),
        salt,
        password.as_bytes(),
        &mut hash,
    );
    hash
}

// Encrypt a message using AES-GCM
fn encrypt_message(key: &[u8], message: &str) -> Vec<u8> {
    let sealing_key = aead::UnboundKey::new(&aead::AES_256_GCM, key).unwrap();
    let mut nonce = vec![0u8; 12]; // AES-GCM nonce size
    rand::SystemRandom::new().fill(&mut nonce).unwrap();
    
    let nonce = aead::Nonce::assume_unique_for_key(nonce);
    let sealing_key = aead::LessSafeKey::new(sealing_key);

    let mut message_bytes = message.as_bytes().to_vec();
    message_bytes.resize(message_bytes.len() + aead::AES_256_GCM.tag_len(), 0);
    
    sealing_key.seal_in_place_append_tag(nonce, aead::Aad::empty(), &mut message_bytes).unwrap();
    message_bytes
}

// Decrypt a message using AES-GCM
fn decrypt_message(key: &[u8], ciphertext: &[u8]) -> Result<String, aead::Unspecified> {
    let opening_key = aead::UnboundKey::new(&aead::AES_256_GCM, key).unwrap();
    let opening_key = aead::LessSafeKey::new(opening_key);
    
    let nonce = aead::Nonce::assume_unique_for_key(vec![0u8; 12]); // Replace with actual nonce used during encryption

    let mut ciphertext = ciphertext.to_vec();
    let decrypted_data = opening_key.open_in_place(nonce, aead::Aad::empty(), &mut ciphertext)?;
    Ok(String::from_utf8_lossy(decrypted_data).into_owned())
}

// HTTP handlers
async fn register(req: Request<Body>, state: Arc<AppState>) -> Result<Response<Body>, hyper::Error> {
    // Parse the request and register the user
    let user_id = "user1".to_string(); // Get from the request
    let password = "password123"; // Get from the request

    let password_hash = hash_password(password);
    let encryption_key = generate_encryption_key();

    let user = User {
        password_hash,
        encryption_key,
    };

    state.users.lock().unwrap().insert(user_id.clone(), user);
    Ok(Response::new(Body::from("User registered")))
}

async fn send_message(req: Request<Body>, state: Arc<AppState>) -> Result<Response<Body>, hyper::Error> {
    // Extract the message and recipient from the request
    let recipient_id = "user2".to_string(); // Get from the request
    let message = "Hello, secure world!".to_string(); // Get from the request

    let users = state.users.lock().unwrap();
    if let Some(user) = users.get(&recipient_id) {
        let encrypted_message = encrypt_message(&user.encryption_key, &message);
        state.messages.lock().unwrap().entry(recipient_id).or_default().push(encrypted_message);
        Ok(Response::new(Body::from("Message sent")))
    } else {
        Ok(Response::new(Body::from("Recipient not found")))
    }
}

async fn receive_messages(req: Request<Body>, state: Arc<AppState>) -> Result<Response<Body>, hyper::Error> {
    let user_id = "user2".to_string(); // Get from the request

    let users = state.users.lock().unwrap();
    let messages = state.messages.lock().unwrap();

    if let Some(user) = users.get(&user_id) {
        if let Some(encrypted_messages) = messages.get(&user_id) {
            let mut decrypted_messages = Vec::new();
            for encrypted_message in encrypted_messages {
                if let Ok(decrypted_message) = decrypt_message(&user.encryption_key, encrypted_message) {
                    decrypted_messages.push(decrypted_message);
                }
            }
            Ok(Response::new(Body::from(format!("Messages: {:?}", decrypted_messages))))
        } else {
            Ok(Response::new(Body::from("No messages")))
        }
    } else {
        Ok(Response::new(Body::from("User not found")))
    }
}

// HTTPS setup with certificate validation
fn create_https_server(app_state: Arc<AppState>) -> SslAcceptor {
    let mut acceptor = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();
    acceptor.set_private_key_file("key.pem", SslFiletype::PEM).unwrap();
    acceptor.set_certificate_chain_file("cert.pem").unwrap();
    acceptor
}

#[tokio::main]
async fn main() {
    let state = Arc::new(AppState::new());

    let make_svc = make_service_fn(|_conn| {
        let state = state.clone();
        async {
            Ok::<_, hyper::Error>(service_fn(move |req| {
                let state = state.clone();
                match req.uri().path() {
                    "/register" => register(req, state),
                    "/send_message" => send_message(req, state),
                    "/receive_messages" => receive_messages(req, state),
                    _ => async { Ok(Response::new(Body::from("Not found"))) },
                }
            }))
        }
    });

    let acceptor = create_https_server(state.clone());

    let server = Server::builder(hyper::server::accept::from_std(acceptor.build().unwrap()))
        .serve(make_svc);

    println!("Running on https://127.0.0.1:443");
    if let Err(e) = server.await {
        eprintln!("server error: {}", e);
    }
}
