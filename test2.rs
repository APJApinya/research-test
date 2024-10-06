use aes_gcm::{Aes256Gcm, Key, Nonce}; // AES-GCM implementation
use aes_gcm::aead::{Aead, NewAead};
use hyper::{Body, Request, Response, Server};
use hyper::service::{make_service_fn, service_fn};
use hyper_tls::HttpsConnector;
use pbkdf2::pbkdf2;
use rand::Rng;
use ring::hmac;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;

type Db = Arc<Mutex<HashMap<String, User>>>;

const PBKDF2_ITERATIONS: u32 = 100_000;

#[derive(Serialize, Deserialize, Clone)]
struct User {
    username: String,
    password_hash: Vec<u8>,
    encryption_key: Vec<u8>,
    message_count: u32,
}

#[tokio::main]
async fn main() {
    let db: Db = Arc::new(Mutex::new(HashMap::new()));
    let make_svc = make_service_fn(|_conn| {
        let db = db.clone();
        async {
            Ok::<_, hyper::Error>(service_fn(move |req| {
                let db = db.clone();
                router(req, db)
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

async fn router(req: Request<Body>, db: Db) -> Result<Response<Body>, hyper::Error> {
    match (req.method(), req.uri().path()) {
        (&hyper::Method::POST, "/register") => {
            let whole_body = hyper::body::to_bytes(req.into_body()).await?;
            let user: User = serde_json::from_slice(&whole_body).unwrap();
            register_user(user, db).await;
            Ok(Response::new(Body::from("User registered successfully")))
        }
        (&hyper::Method::POST, "/send_message") => {
            let whole_body = hyper::body::to_bytes(req.into_body()).await?;
            let msg_request: MessageRequest = serde_json::from_slice(&whole_body).unwrap();
            let response = send_message(msg_request, db).await;
            Ok(Response::new(Body::from(response)))
        }
        _ => Ok(Response::new(Body::from("Not Found"))),
    }
}

#[derive(Serialize, Deserialize)]
struct MessageRequest {
    username: String,
    message: String,
}

async fn register_user(user: User, db: Db) {
    let salt = rand::thread_rng().gen::<[u8; 16]>();
    let mut password_hash = vec![0u8; 32];
    pbkdf2::<hmac::Hmac<ring::digest::Sha256>>(
        user.password_hash.as_slice(),
        &salt,
        PBKDF2_ITERATIONS,
        &mut password_hash,
    );

    let encryption_key = rand::thread_rng().gen::<[u8; 32]>().to_vec();

    let user = User {
        username: user.username,
        password_hash,
        encryption_key,
        message_count: 0,
    };

    db.lock().unwrap().insert(user.username.clone(), user);
}

async fn send_message(req: MessageRequest, db: Db) -> String {
    let db = db.lock().unwrap();
    if let Some(user) = db.get(&req.username) {
        let encryption_key = Key::from_slice(&user.encryption_key);
        let cipher = Aes256Gcm::new(encryption_key);

        let nonce = Nonce::from_slice(&rand::thread_rng().gen::<[u8; 12]>());

        match cipher.encrypt(nonce, req.message.as_bytes()) {
            Ok(ciphertext) => {
                let response = base64::encode(&ciphertext);
                response
            }
            Err(_) => "Encryption failed".to_string(),
        }
    } else {
        "User not found".to_string()
    }
}
