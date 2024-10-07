#include <iostream>
#include <string>
#include <sqlite3.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#define SALT_LENGTH 16
#define KEY_LENGTH 32
#define IV_LENGTH 12
#define TAG_LENGTH 16

using namespace std;

// Utility functions for hex encoding/decoding
string bytesToHex(const unsigned char* bytes, size_t length) {
    string hex;
    char buf[3];
    for (size_t i = 0; i < length; i++) {
        snprintf(buf, sizeof(buf), "%02x", bytes[i]);
        hex += buf;
    }
    return hex;
}

void hexToBytes(const string& hex, unsigned char* bytes) {
    for (size_t i = 0; i < hex.length(); i += 2) {
        string byteString = hex.substr(i, 2);
        bytes[i / 2] = (unsigned char) strtol(byteString.c_str(), nullptr, 16);
    }
}

// Function to hash password using PBKDF2
string hashPassword(const string& password, unsigned char* salt) {
    unsigned char key[KEY_LENGTH];
    PKCS5_PBKDF2_HMAC(password.c_str(), password.length(), salt, SALT_LENGTH, 10000, EVP_sha256(), KEY_LENGTH, key);
    return bytesToHex(key, KEY_LENGTH);
}

// Function to generate random bytes
void generateRandomBytes(unsigned char* buffer, size_t length) {
    RAND_bytes(buffer, length);
}

// Function to encrypt a message
string encryptMessage(const string& plaintext, const unsigned char* key, string& ivHex, string& tagHex) {
    unsigned char iv[IV_LENGTH];
    generateRandomBytes(iv, IV_LENGTH);
    ivHex = bytesToHex(iv, IV_LENGTH);

    unsigned char ciphertext[plaintext.length() + AES_BLOCK_SIZE];
    int len;
    int ciphertext_len;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_LENGTH, nullptr);
    EVP_EncryptInit_ex(ctx, nullptr, nullptr, key, iv);

    EVP_EncryptUpdate(ctx, nullptr, &len, nullptr, plaintext.length());
    EVP_EncryptUpdate(ctx, ciphertext, &len, (unsigned char*)plaintext.c_str(), plaintext.length());
    ciphertext_len = len;

    unsigned char tag[TAG_LENGTH];
    EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
    ciphertext_len += len;
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_LENGTH, tag);

    tagHex = bytesToHex(tag, TAG_LENGTH);
    EVP_CIPHER_CTX_free(ctx);

    return bytesToHex(ciphertext, ciphertext_len);
}

// Function to decrypt a message
string decryptMessage(const string& ciphertextHex, const unsigned char* key, const string& ivHex, const string& tagHex) {
    unsigned char iv[IV_LENGTH];
    hexToBytes(ivHex, iv);

    unsigned char tag[TAG_LENGTH];
    hexToBytes(tagHex, tag);

    size_t ciphertext_len = ciphertextHex.length() / 2;
    unsigned char ciphertext[ciphertext_len];
    hexToBytes(ciphertextHex, ciphertext);

    unsigned char plaintext[ciphertext_len];
    int len;
    int plaintext_len;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_LENGTH, nullptr);
    EVP_DecryptInit_ex(ctx, nullptr, nullptr, key, iv);

    EVP_DecryptUpdate(ctx, nullptr, &len, nullptr, ciphertext_len);
    EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len);
    plaintext_len = len;

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_LENGTH, (void*)tag);

    if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) > 0) {
        plaintext_len += len;
        EVP_CIPHER_CTX_free(ctx);
        return string((char*)plaintext, plaintext_len);
    } else {
        EVP_CIPHER_CTX_free(ctx);
        throw runtime_error("Decryption failed");
    }
}

int main() {
    sqlite3* db;
    char* errMsg = 0;

    // Open the SQLite database
    if (sqlite3_open("secure_messaging.db", &db)) {
        cerr << "Error opening SQLite database: " << sqlite3_errmsg(db) << endl;
        return 1;
    }

    // Create users table
    const char* createUsersTable = "CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, password TEXT, salt TEXT);";
    if (sqlite3_exec(db, createUsersTable, nullptr, nullptr, &errMsg) != SQLITE_OK) {
        cerr << "Error creating users table: " << errMsg << endl;
        sqlite3_free(errMsg);
    }

    // Create messages table
    const char* createMessagesTable = "CREATE TABLE IF NOT EXISTS messages (sender TEXT, recipient TEXT, message TEXT, iv TEXT, tag TEXT);";
    if (sqlite3_exec(db, createMessagesTable, nullptr, nullptr, &errMsg) != SQLITE_OK) {
        cerr << "Error creating messages table: " << errMsg << endl;
        sqlite3_free(errMsg);
    }

    // Register a new user
    string username, password;
    cout << "Enter username for registration: ";
    cin >> username;
    cout << "Enter password: ";
    cin >> password;

    unsigned char salt[SALT_LENGTH];
    generateRandomBytes(salt, SALT_LENGTH);
    string saltHex = bytesToHex(salt, SALT_LENGTH);
    string hashedPassword = hashPassword(password, salt);

    string sql = "INSERT INTO users (username, password, salt) VALUES ('" + username + "', '" + hashedPassword + "', '" + saltHex + "');";
    if (sqlite3_exec(db, sql.c_str(), nullptr, nullptr, &errMsg) != SQLITE_OK) {
        cerr << "Error inserting user: " << errMsg << endl;
        sqlite3_free(errMsg);
    } else {
        cout << "User registered successfully!" << endl;
    }

    // Log in a user
    string loginUsername, loginPassword;
    cout << "Enter username to login: ";
    cin >> loginUsername;
    cout << "Enter password: ";
    cin >> loginPassword;

    sqlite3_stmt* stmt;
    sql = "SELECT password, salt FROM users WHERE username = ?;";
    if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, loginUsername.c_str(), -1, SQLITE_STATIC);
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            string storedPassword = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
            string storedSaltHex = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));

            unsigned char storedSalt[SALT_LENGTH];
            hexToBytes(storedSaltHex, storedSalt);
            string hashedInputPassword = hashPassword(loginPassword, storedSalt);

            if (hashedInputPassword == storedPassword) {
                cout << "Login successful!" << endl;

                // Send a message
                string recipient, message;
                cout << "Enter recipient username: ";
                cin >> recipient;
                cout << "Enter message: ";
                cin.ignore();
                getline(cin, message);

                // Encrypt the message
                unsigned char key[KEY_LENGTH];
                generateRandomBytes(key, KEY_LENGTH);

                string ivHex, tagHex;
                string encryptedMessage = encryptMessage(message, key, ivHex, tagHex);

                // Store the encrypted message
                sql = "INSERT INTO messages (sender, recipient, message, iv, tag) VALUES ('" + loginUsername + "', '" + recipient + "', '" + encryptedMessage + "', '" + ivHex + "', '" + tagHex + "');";
                if (sqlite3_exec(db, sql.c_str(), nullptr, nullptr, &errMsg) != SQLITE_OK) {
                    cerr << "Error inserting message: " << errMsg << endl;
                    sqlite3_free(errMsg);
                } else {
                    cout << "Message sent successfully!" << endl;
                }

            } else {
                cout << "Invalid password!" << endl;
            }
        } else {
            cout << "User not found!" << endl;
        }
        sqlite3_finalize(stmt);
    }

    sqlite3_close(db);
    return 0;
}
