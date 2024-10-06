#include <iostream>
#include <string>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#define SALT_LENGTH 16
#define HASH_ITERATIONS 10000
#define AES_KEY_LENGTH 32
#define IV_LENGTH 12
#define TAG_LENGTH 16

using namespace std;

struct User {
    string username;
    unsigned char salt[SALT_LENGTH];
    unsigned char password_hash[SHA256_DIGEST_LENGTH];
    unsigned char encryption_key[AES_KEY_LENGTH];
    int message_count;
};

// Simulated user database
User user_db[10];
int user_count = 0;

// Function to hash password using PBKDF2
void hashPassword(const string& password, unsigned char* salt, unsigned char* hash) {
    RAND_bytes(salt, SALT_LENGTH);
    PKCS5_PBKDF2_HMAC_SHA1(password.c_str(), password.length(), salt, SALT_LENGTH, HASH_ITERATIONS, SHA256_DIGEST_LENGTH, hash);
}

// Function to generate AES key for the user
void generateAESKey(unsigned char* key) {
    RAND_bytes(key, AES_KEY_LENGTH);
}

// Encrypt message with AES-GCM
bool encryptMessage(const string& plaintext, const unsigned char* key, unsigned char* ciphertext, unsigned char* iv, unsigned char* tag) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;

    RAND_bytes(iv, IV_LENGTH);
    if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) return false;

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_LENGTH, NULL);
    if (!EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv)) return false;

    int len;
    if (!EVP_EncryptUpdate(ctx, ciphertext, &len, reinterpret_cast<const unsigned char*>(plaintext.c_str()), plaintext.size())) return false;

    int ciphertext_len = len;
    if (!EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) return false;

    ciphertext_len += len;
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_LENGTH, tag);
    EVP_CIPHER_CTX_free(ctx);

    return true;
}

// User registration
void registerUser(const string& username, const string& password) {
    User new_user;
    new_user.username = username;
    new_user.message_count = 0;

    hashPassword(password, new_user.salt, new_user.password_hash);
    generateAESKey(new_user.encryption_key);

    user_db[user_count++] = new_user;

    cout << "User " << username << " registered successfully." << endl;
}

// User login (authenticate password)
bool loginUser(const string& username, const string& password) {
    for (int i = 0; i < user_count; ++i) {
        if (user_db[i].username == username) {
            unsigned char test_hash[SHA256_DIGEST_LENGTH];
            PKCS5_PBKDF2_HMAC_SHA1(password.c_str(), password.length(), user_db[i].salt, SALT_LENGTH, HASH_ITERATIONS, SHA256_DIGEST_LENGTH, test_hash);

            if (memcmp(test_hash, user_db[i].password_hash, SHA256_DIGEST_LENGTH) == 0) {
                cout << "Login successful." << endl;
                return true;
            }
        }
    }
    cout << "Invalid username or password." << endl;
    return false;
}

// Send encrypted message
void sendMessage(const string& sender, const string& recipient, const string& message) {
    User* sender_user = nullptr;
    User* recipient_user = nullptr;

    // Find sender and recipient in the database
    for (int i = 0; i < user_count; ++i) {
        if (user_db[i].username == sender) {
            sender_user = &user_db[i];
        }
        if (user_db[i].username == recipient) {
            recipient_user = &user_db[i];
        }
    }

    if (!sender_user || !recipient_user) {
        cout << "Sender or recipient not found." << endl;
        return;
    }

    // Encrypt message
    unsigned char iv[IV_LENGTH];
    unsigned char tag[TAG_LENGTH];
    unsigned char ciphertext[1024];

    if (encryptMessage(message, sender_user->encryption_key, ciphertext, iv, tag)) {
        cout << "Message sent to " << recipient << ": " << endl;
        cout << "Ciphertext: " << ciphertext << endl;

        // Key rotation after 10 messages
        sender_user->message_count++;
        if (sender_user->message_count >= 10) {
            generateAESKey(sender_user->encryption_key);
            sender_user->message_count = 0;
            cout << "Encryption key rotated for " << sender << endl;
        }
    } else {
        cout << "Failed to encrypt message." << endl;
    }
}

int main() {
    // Register users
    registerUser("alice", "password123");
    registerUser("bob", "securepassword");

    // Login users
    if (loginUser("alice", "password123")) {
        // Send message
        sendMessage("alice", "bob", "Hello Bob, this is a secure message!");
    }

    return 0;
}
