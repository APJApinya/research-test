#include <iostream>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/pem.h>
#include <string>
#include <unordered_map>

// User data structure
struct User {
    std::string username;
    std::string hashedPassword;
    unsigned char encryptionKey[32]; // Symmetric key for message encryption
};

// In-memory user database
std::unordered_map<std::string, User> userDatabase;

// Generate a secure random key for encryption
void generateSymmetricKey(unsigned char *key, int keySize) {
    RAND_bytes(key, keySize);
}

// Hash a password using PBKDF2
std::string hashPassword(const std::string &password, unsigned char *salt, int saltLength) {
    unsigned char hash[32]; // SHA-256 output is 32 bytes
    PKCS5_PBKDF2_HMAC(password.c_str(), password.length(), salt, saltLength, 10000, EVP_sha256(), 32, hash);
    return std::string(reinterpret_cast<char *>(hash), 32);
}

// Encrypt message using AES-GCM
std::string encryptMessage(const std::string &message, const unsigned char *key) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    unsigned char iv[12];
    unsigned char ciphertext[1024];
    unsigned char tag[16];
    int len, ciphertextLen;

    // Generate a secure random IV
    RAND_bytes(iv, sizeof(iv));

    // Initialize AES-GCM encryption
    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, sizeof(iv), nullptr);
    EVP_EncryptInit_ex(ctx, nullptr, nullptr, key, iv);

    // Encrypt message
    EVP_EncryptUpdate(ctx, ciphertext, &len, reinterpret_cast<const unsigned char *>(message.c_str()), message.length());
    ciphertextLen = len;

    // Finalize encryption
    EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
    ciphertextLen += len;

    // Get the authentication tag
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, sizeof(tag), tag);

    EVP_CIPHER_CTX_free(ctx);

    // Construct a string including the IV, tag, and ciphertext for easy transmission
    return std::string(reinterpret_cast<char *>(iv), sizeof(iv)) +
           std::string(reinterpret_cast<char *>(tag), sizeof(tag)) +
           std::string(reinterpret_cast<char *>(ciphertext), ciphertextLen);
}

// Register a user
void registerUser(const std::string &username, const std::string &password) {
    unsigned char salt[16];
    RAND_bytes(salt, sizeof(salt));
    std::string hashedPassword = hashPassword(password, salt, sizeof(salt));

    unsigned char encryptionKey[32];
    generateSymmetricKey(encryptionKey, sizeof(encryptionKey));

    userDatabase[username] = User{username, hashedPassword, {}};
    memcpy(userDatabase[username].encryptionKey, encryptionKey, sizeof(encryptionKey));
}

// Simulate sending a message
void sendMessage(const std::string &sender, const std::string &receiver, const std::string &message) {
    if (userDatabase.find(receiver) == userDatabase.end()) {
        std::cout << "Receiver not found.\n";
        return;
    }

    // Encrypt the message using the receiver's key
    std::string encryptedMessage = encryptMessage(message, userDatabase[receiver].encryptionKey);
    std::cout << "Encrypted message sent to " << receiver << ": " << encryptedMessage << "\n";
}

int main() {
    // Register two users
    registerUser("Alice", "secure_password_1");
    registerUser("Bob", "secure_password_2");

    // Alice sends a secure message to Bob
    sendMessage("Alice", "Bob", "Hello Bob, this is a secure message.");

    return 0;
}
