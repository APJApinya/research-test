use bcrypt::{hash, verify};
use rand::Rng;
use aes_gcm::{Aes256Gcm, Key, Nonce}; // AES-GCM for encryption/decryption
use aes_gcm::aead::{Aead, NewAead};
use pbkdf2::{pbkdf2};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use hyper::{Body, Request, Response, Server};
use hyper::service::{make_service_fn, service_fn};
use hyper_tls::HttpsConnector;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::net::TcpListener;

type HmacSha256 = Hmac<Sha256>;

// Simulating database
struct AppState {
    users: Mutex<HashMap<String, User>>,
}

struct User {
    hashed_password: String,
    encryption_key: Vec<u8>,
    message_count: usize,
}

impl User {
    fn new(password: &str) -> Self {
        let hashed_password = hash(password, 4).unwrap();

        // Generating symmetric key using PBKDF2
        let mut salt = [0u8; 16];
        rand::thread_rng().fill(&mut salt);
        let mut encryption_key = [0u8; 32];
        pbkdf2::<HmacSha256>(password.as_bytes(), &salt, 10000, &mut encryption_key);

        User {
            hashed_password,
            encryption_key: encryption_key.to_vec(),
            message_count: 0,
        }
    }

    fn rotate_key(&mut self, password: &str) {
        // Rotate encryption key
        let mut salt = [0u8; 16];
        rand::thread_rng().fill(&mut salt);
        let mut new_key = [0u8; 32];
        pbkdf2::<HmacSha256>(password.as_bytes(), &salt, 10000, &mut new_key);
        self.encryption_key = new_key.to_vec();
    }
}

#[tokio::main]
async fn main() {
    let app_state = Arc::new(AppState {
        users: Mutex::new(HashMap::new()),
    });

    let make_svc = make_service_fn(|_conn| {
        let app_state = app_state.clone();
        async {
            Ok::<_, hyper::Error>(service_fn(move |req| {
                handle_request(req, app_state.clone())
            }))
        }
    });

    let addr = ([127, 0, 0, 1], 3000).into();
    let server = Server::bind(&addr).serve(make_svc);

    println!("Listening on https://{}", addr);
    if let Err(e) = server.await {
        eprintln!("server error: {}", e);
    }
}

async fn handle_request(
    req: Request<Body>,
    state: Arc<AppState>,
) -> Result<Response<Body>, hyper::Error> {
    let path = req.uri().path();
    match (req.method(), path) {
        (&hyper::Method::POST, "/register") => {
            let whole_body = hyper::body::to_bytes(req.into_body()).await?;
            let body: serde_json::Value = serde_json::from_slice(&whole_body).unwrap();
            let username = body["username"].as_str().unwrap();
            let password = body["password"].as_str().unwrap();

            let mut users = state.users.lock().unwrap();
            if users.contains_key(username) {
                return Ok(Response::new(Body::from("User already exists")));
            }

            let user = User::new(password);
            users.insert(username.to_string(), user);
            Ok(Response::new(Body::from("User registered successfully")))
        }
        (&hyper::Method::POST, "/send_message") => {
            let whole_body = hyper::body::to_bytes(req.into_body()).await?;
            let body: serde_json::Value = serde_json::from_slice(&whole_body).unwrap();
            let username = body["username"].as_str().unwrap();
            let password = body["password"].as_str().unwrap();
            let message = body["message"].as_str().unwrap();

            let mut users = state.users.lock().unwrap();
            if let Some(user) = users.get_mut(username) {
                if verify(password, &user.hashed_password).unwrap() {
                    // Encrypt message using AES-GCM
                    let key = Key::from_slice(&user.encryption_key);
                    let cipher = Aes256Gcm::new(key);
                    let nonce = Nonce::from_slice(&rand::thread_rng().gen::<[u8; 12]>());

                    match cipher.encrypt(nonce, message.as_ref()) {
                        Ok(ciphertext) => {
                            user.message_count += 1;

                            // Rotate key after 10 messages
                            if user.message_count >= 10 {
                                user.rotate_key(password);
                                user.message_count = 0;
                            }

                            Ok(Response::new(Body::from(base64::encode(ciphertext))))
                        }
                        Err(_) => Ok(Response::new(Body::from("Encryption error"))),
                    }
                } else {
                    Ok(Response::new(Body::from("Invalid password")))
                }
            } else {
                Ok(Response::new(Body::from("User not found")))
            }
        }
        _ => Ok(Response::new(Body::from("Not Found"))),
    }
}
