#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <boost/asio.hpp>
#include <boost/beast.hpp>
#include <iostream>
#include <map>
#include <string>
#include <vector>

// User data structure
struct User {
    std::string username;
    std::vector<unsigned char> password_hash; // Hashed password
    unsigned char encryption_key[32];         // Symmetric key for message encryption
    int message_count = 0;
};

// Database simulation for users
std::map<std::string, User> users_db;

// PBKDF2 function to hash passwords
std::vector<unsigned char> pbkdf2_hash(const std::string& password, const unsigned char* salt, int iterations, int key_len) {
    std::vector<unsigned char> hash(key_len);
    PKCS5_PBKDF2_HMAC(password.c_str(), password.size(), salt, 16, iterations, EVP_sha256(), key_len, hash.data());
    return hash;
}

// Generate symmetric key for encryption
void generate_key(unsigned char* key, size_t length) {
    RAND_bytes(key, length);
}

// AES-GCM Encryption function
bool aes_gcm_encrypt(const unsigned char* plaintext, int plaintext_len, const unsigned char* key,
                     unsigned char* ciphertext, unsigned char* iv, int iv_len, unsigned char* tag) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;

    // Generate IV
    RAND_bytes(iv, iv_len);

    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL);
    EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv);

    int len;
    EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len);
    EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag);

    EVP_CIPHER_CTX_free(ctx);
    return true;
}

// User registration function
void register_user(const std::string& username, const std::string& password) {
    unsigned char salt[16];
    RAND_bytes(salt, sizeof(salt));

    // Hash the password using PBKDF2
    std::vector<unsigned char> password_hash = pbkdf2_hash(password, salt, 10000, 32);

    // Generate symmetric encryption key
    unsigned char encryption_key[32];
    generate_key(encryption_key, sizeof(encryption_key));

    // Store user information
    users_db[username] = {username, password_hash, {}, 0};
    memcpy(users_db[username].encryption_key, encryption_key, 32);
    
    std::cout << "User registered: " << username << std::endl;
}

// Function to handle message sending
void send_message(const std::string& sender, const std::string& recipient, const std::string& message) {
    if (users_db.find(sender) == users_db.end() || users_db.find(recipient) == users_db.end()) {
        std::cerr << "Error: Invalid user.\n";
        return;
    }

    User& sender_user = users_db[sender];
    User& recipient_user = users_db[recipient];

    // Perform key rotation if message count is 10
    if (sender_user.message_count == 10) {
        generate_key(sender_user.encryption_key, 32);
        sender_user.message_count = 0;
        std::cout << "Encryption key rotated for user: " << sender << std::endl;
    }

    // Encrypt the message using AES-GCM
    unsigned char iv[12];
    unsigned char ciphertext[1024];
    unsigned char tag[16];
    bool success = aes_gcm_encrypt(reinterpret_cast<const unsigned char*>(message.c_str()), message.size(),
                                   sender_user.encryption_key, ciphertext, iv, sizeof(iv), tag);

    if (success) {
        // Simulate storing encrypted message (in reality, this would be sent to the recipient over HTTPS)
        sender_user.message_count++;
        std::cout << "Message sent from " << sender << " to " << recipient << " successfully." << std::endl;
    } else {
        std::cerr << "Error: Message encryption failed.\n";
    }
}

int main() {
    // Register users
    register_user("alice", "securepassword1");
    register_user("bob", "securepassword2");

    // Send encrypted messages
    send_message("alice", "bob", "Hello Bob!");
    send_message("alice", "bob", "How are you?");
    send_message("alice", "bob", "This is a secure message.");

    return 0;
}
