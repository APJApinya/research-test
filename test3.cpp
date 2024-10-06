#include <openssl/evp.h>
#include <openssl/rand.h>
#include <cpprest/http_client.h>
#include <cpprest/uri.h>
#include <cpprest/json.h>
#include <iostream>
#include <string>
#include <map>
#include <mutex>

// Mock Database for Storing User Data (For demonstration purposes)
std::map<std::string, std::string> userDatabase; // stores username and hashed password
std::map<std::string, std::vector<unsigned char>> userKeys; // stores username and encryption key
std::mutex dbMutex; // mutex for thread-safe access

#define ITERATION_COUNT 10000 // PBKDF2 iteration count
#define KEY_LENGTH 32 // Length of AES encryption key
#define IV_LENGTH 12 // Length of AES-GCM IV

// Function to perform PBKDF2 hash
std::vector<unsigned char> pbkdf2_hash(const std::string& password, const std::string& salt) {
    std::vector<unsigned char> hash(KEY_LENGTH);
    PKCS5_PBKDF2_HMAC(password.c_str(), password.size(), 
                      reinterpret_cast<const unsigned char*>(salt.c_str()), salt.size(),
                      ITERATION_COUNT, EVP_sha256(), KEY_LENGTH, hash.data());
    return hash;
}

// Generate a secure random key
std::vector<unsigned char> generate_secure_key() {
    std::vector<unsigned char> key(KEY_LENGTH);
    if (RAND_bytes(key.data(), KEY_LENGTH) != 1) {
        throw std::runtime_error("Random key generation failed");
    }
    return key;
}

// Generate secure random IV
std::vector<unsigned char> generate_secure_iv() {
    std::vector<unsigned char> iv(IV_LENGTH);
    if (RAND_bytes(iv.data(), IV_LENGTH) != 1) {
        throw std::runtime_error("Random IV generation failed");
    }
    return iv;
}

// AES-GCM Encryption
std::vector<unsigned char> aes_gcm_encrypt(const std::vector<unsigned char>& key, 
                                           const std::vector<unsigned char>& iv, 
                                           const std::string& plaintext) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    std::vector<unsigned char> ciphertext(plaintext.size() + EVP_GCM_TLS_TAG_LEN);

    if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key.data(), iv.data())) {
        throw std::runtime_error("Encryption init failed");
    }

    int len;
    if (!EVP_EncryptUpdate(ctx, ciphertext.data(), &len, 
                           reinterpret_cast<const unsigned char*>(plaintext.c_str()), plaintext.size())) {
        throw std::runtime_error("Encryption update failed");
    }

    EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len);
    EVP_CIPHER_CTX_free(ctx);
    return ciphertext;
}

// Register User
bool register_user(const std::string& username, const std::string& password) {
    std::lock_guard<std::mutex> lock(dbMutex);
    if (userDatabase.find(username) != userDatabase.end()) {
        return false; // User already exists
    }

    std::string salt = "unique_salt"; // Replace with random salt generation logic
    auto hashedPassword = pbkdf2_hash(password, salt);
    userDatabase[username] = std::string(hashedPassword.begin(), hashedPassword.end());

    auto userKey = generate_secure_key();
    userKeys[username] = userKey;

    return true;
}

// Send Message
std::vector<unsigned char> send_message(const std::string& username, const std::string& message) {
    std::lock_guard<std::mutex> lock(dbMutex);
    if (userKeys.find(username) == userKeys.end()) {
        throw std::runtime_error("User not found");
    }

    auto key = userKeys[username];
    auto iv = generate_secure_iv();
    return aes_gcm_encrypt(key, iv, message);
}

// HTTPS client example (for secure communication)
void communicate_with_server(const std::string& server_url, const std::string& message) {
    using namespace web::http;
    using namespace web::http::client;

    http_client client(U(server_url));

    uri_builder builder(U("/sendMessage"));
    builder.append_query(U("message"), U(message));

    client.request(methods::POST, builder.to_string())
        .then([](http_response response) {
            if (response.status_code() == status_codes::OK) {
                std::cout << "Message successfully sent to server." << std::endl;
            } else {
                std::cerr << "Error: " << response.status_code() << std::endl;
            }
        }).wait();
}

int main() {
    // Example Usage
    try {
        // User registration
        std::string username = "alice";
        std::string password = "password123";
        if (register_user(username, password)) {
            std::cout << "User registered successfully!" << std::endl;
        } else {
            std::cout << "User already exists." << std::endl;
        }

        // User sends a message
        std::string message = "Hello, this is a secure message!";
        auto encryptedMessage = send_message(username, message);
        std::cout << "Message encrypted and ready for transmission." << std::endl;

        // HTTPS communication with server
        std::string server_url = "https://secure-messaging-server.com";
        communicate_with_server(server_url, "Encrypted message to server");

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }

    return 0;
}
