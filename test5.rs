use actix_web::{web, App, HttpResponse, HttpServer, Responder, post};
use ring::{rand, pbkdf2, digest, aead};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Mutex;
use std::num::NonZeroU32;

type Db = Mutex<HashMap<String, User>>;

const PBKDF2_ITERATIONS: NonZeroU32 = NonZeroU32::new(100_000).unwrap();

#[derive(Debug, Clone, Serialize, Deserialize)]
struct User {
    username: String,
    password_hash: Vec<u8>,
    encryption_key: Vec<u8>,
    message_count: usize,
}

#[derive(Debug, Clone, Deserialize)]
struct RegisterData {
    username: String,
    password: String,
}

#[derive(Debug, Clone, Deserialize)]
struct MessageData {
    sender: String,
    recipient: String,
    message: String,
}

#[post("/register")]
async fn register(data: web::Json<RegisterData>, db: web::Data<Db>) -> impl Responder {
    let salt = rand::generate::<[u8; 16]>(rand::SystemRandom::new()).unwrap();
    let mut password_hash = [0u8; digest::SHA256_OUTPUT_LEN];
    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA256,
        PBKDF2_ITERATIONS,
        salt.as_ref(),
        data.password.as_bytes(),
        &mut password_hash,
    );

    let key = rand::generate::<[u8; 32]>(rand::SystemRandom::new()).unwrap();
    let user = User {
        username: data.username.clone(),
        password_hash: password_hash.to_vec(),
        encryption_key: key.expose().to_vec(),
        message_count: 0,
    };

    let mut db = db.lock().unwrap();
    db.insert(data.username.clone(), user);

    HttpResponse::Ok().json("User registered successfully")
}

#[post("/send_message")]
async fn send_message(data: web::Json<MessageData>, db: web::Data<Db>) -> impl Responder {
    let mut db = db.lock().unwrap();
    if let Some(sender) = db.get_mut(&data.sender) {
        // Check key rotation policy
        if sender.message_count >= 10 {
            sender.encryption_key = rand::generate::<[u8; 32]>(rand::SystemRandom::new()).unwrap().expose().to_vec();
            sender.message_count = 0;
        }

        // Encrypt the message using AES-GCM
        let key = aead::UnboundKey::new(&aead::AES_256_GCM, &sender.encryption_key).unwrap();
        let nonce = rand::generate::<[u8; 12]>(rand::SystemRandom::new()).unwrap();
        let nonce_sequence = aead::Nonce::try_assume_unique_for_key(nonce.expose()).unwrap();

        let mut sealing_key = aead::SealingKey::new(key, nonce_sequence);
        let mut in_out = data.message.clone().into_bytes();
        in_out.extend_from_slice(&[0u8; aead::AES_256_GCM.tag_len()]);
        sealing_key.seal_in_place_append_tag(aead::Aad::empty(), &mut in_out).unwrap();

        // Increase the message count and respond
        sender.message_count += 1;
        HttpResponse::Ok().json(format!("Encrypted message: {:?}", in_out))
    } else {
        HttpResponse::BadRequest().body("Sender not found")
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let db: Db = Mutex::new(HashMap::new());

    // Set up the HTTPS server with rustls (a self-signed certificate would be used here)
    let config = {
        use rustls::{Certificate, PrivateKey, ServerConfig};
        use std::fs::File;
        use std::io::BufReader;

        let cert_file = &mut BufReader::new(File::open("cert.pem").unwrap());
        let key_file = &mut BufReader::new(File::open("key.pem").unwrap());
        let cert_chain = rustls_pemfile::certs(cert_file).unwrap()
            .into_iter().map(Certificate).collect();
        let key = rustls_pemfile::pkcs8_private_keys(key_file).unwrap()
            .into_iter().map(PrivateKey).next().unwrap();

        let mut config = ServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
            .with_single_cert(cert_chain, key)
            .unwrap();
        config
    };

    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(db.clone()))
            .service(register)
            .service(send_message)
    })
    .bind_rustls("127.0.0.1:8443", config)?
    .run()
    .await
}
