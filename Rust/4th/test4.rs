use bcrypt::{hash, verify};
use ring::{pbkdf2, rand::SystemRandom, rand::SecureRandom};
use aes_gcm::{Aes256Gcm, Key, Nonce}; // AES-GCM with 256-bit keys
use aes_gcm::aead::{Aead, NewAead};
use rand::Rng;
use hyper::{Server, Request, Response, Body, Method};
use hyper::service::{make_service_fn, service_fn};
use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

type Db = Arc<Mutex<HashMap<String, User>>>;

const PBKDF2_ITER: u32 = 100_000;

#[derive(Clone, Serialize, Deserialize)]
struct User {
    username: String,
    hashed_password: String,
    encryption_key: Vec<u8>, // Symmetric key for message encryption
    message_count: u32,
}

impl User {
    fn new(username: String, password: String) -> Self {
        let hashed_password = hash(&password, 4).unwrap();
        
        // Generate symmetric key using PBKDF2
        let salt = b"unique_salt";
        let mut encryption_key = [0u8; 32];
        pbkdf2::derive(
            pbkdf2::PBKDF2_HMAC_SHA256,
            PBKDF2_ITER,
            salt,
            password.as_bytes(),
            &mut encryption_key,
        );

        User {
            username,
            hashed_password,
            encryption_key: encryption_key.to_vec(),
            message_count: 0,
        }
    }
}

async fn handle_request(req: Request<Body>, db: Db) -> Result<Response<Body>, hyper::Error> {
    match (req.method(), req.uri().path()) {
        (&Method::POST, "/register") => {
            let whole_body = hyper::body::to_bytes(req.into_body()).await?;
            let new_user: User = serde_json::from_slice(&whole_body).unwrap();

            let mut db_lock = db.lock().unwrap();
            if db_lock.contains_key(&new_user.username) {
                return Ok(Response::new(Body::from("User already exists")));
            }

            db_lock.insert(new_user.username.clone(), new_user);
            Ok(Response::new(Body::from("User registered successfully")))
        }
        (&Method::POST, "/send_message") => {
            let whole_body = hyper::body::to_bytes(req.into_body()).await?;
            let data: HashMap<String, String> = serde_json::from_slice(&whole_body).unwrap();

            let username = data.get("username").unwrap();
            let message = data.get("message").unwrap();

            let mut db_lock = db.lock().unwrap();
            let user = db_lock.get_mut(username).unwrap();

            // Key rotation logic after 10 messages
            if user.message_count >= 10 {
                let new_key = generate_key();
                user.encryption_key = new_key;
                user.message_count = 0;
            }

            // Encrypt the message using AES-GCM
            let key = Key::from_slice(&user.encryption_key);
            let cipher = Aes256Gcm::new(key);

            let mut iv = [0u8; 12];
            SystemRandom::new().fill(&mut iv).unwrap();
            let nonce = Nonce::from_slice(&iv);

            let ciphertext = cipher.encrypt(nonce, message.as_bytes()).expect("encryption failure!");
            
            user.message_count += 1;

            Ok(Response::new(Body::from(format!("Encrypted Message: {:?}", ciphertext))))
        }
        _ => Ok(Response::new(Body::from("Route not found"))),
    }
}

fn generate_key() -> Vec<u8> {
    let mut key = [0u8; 32];
    SystemRandom::new().fill(&mut key).unwrap();
    key.to_vec()
}

#[tokio::main]
async fn main() {
    let db: Db = Arc::new(Mutex::new(HashMap::new()));

    let make_svc = make_service_fn(|_conn| {
        let db = db.clone();
        async {
            Ok::<_, hyper::Error>(service_fn(move |req| {
                handle_request(req, db.clone())
            }))
        }
    });

    let addr = ([127, 0, 0, 1], 8080).into();
    let server = Server::bind(&addr).serve(make_svc);

    println!("Listening on http://{}", addr);

    if let Err(e) = server.await {
        eprintln!("server error: {}", e);
    }
}
