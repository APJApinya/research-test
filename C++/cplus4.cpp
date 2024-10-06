#include <iostream>
#include <string>
#include <unordered_map>
#include <sqlite3.h>
#include <cryptopp/aes.h>
#include <cryptopp/filters.h>
#include <cryptopp/modes.h>
#include <cryptopp/hex.h>
#include <cryptopp/secblock.h>

// Database management (for simplicity, SQLite is used as in-memory)
sqlite3* db;

bool initDatabase() {
    int rc = sqlite3_open(":memory:", &db);
    if (rc) {
        std::cerr << "Can't open database: " << sqlite3_errmsg(db) << std::endl;
        return false;
    }
    
    const char* createTableSQL = R"(
        CREATE TABLE users (
            id INTEGER PRIMARY KEY,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL
        );
    )";
    
    char* errorMsg;
    rc = sqlite3_exec(db, createTableSQL, 0, 0, &errorMsg);
    if (rc != SQLITE_OK) {
        std::cerr << "SQL error: " << errorMsg << std::endl;
        sqlite3_free(errorMsg);
        return false;
    }
    return true;
}

bool registerUser(const std::string& username, const std::string& password) {
    const char* insertSQL = "INSERT INTO users (username, password) VALUES (?, ?)";
    sqlite3_stmt* stmt;
    
    sqlite3_prepare_v2(db, insertSQL, -1, &stmt, nullptr);
    sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, password.c_str(), -1, SQLITE_STATIC);
    
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    
    if (rc == SQLITE_DONE) {
        return true;
    } else {
        std::cerr << "Failed to register user. Username might be taken." << std::endl;
        return false;
    }
}

bool authenticateUser(const std::string& username, const std::string& password) {
    const char* selectSQL = "SELECT password FROM users WHERE username = ?";
    sqlite3_stmt* stmt;
    
    sqlite3_prepare_v2(db, selectSQL, -1, &stmt, nullptr);
    sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_STATIC);
    
    int rc = sqlite3_step(stmt);
    bool authenticated = false;
    if (rc == SQLITE_ROW) {
        std::string dbPassword = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        if (dbPassword == password) {
            authenticated = true;
        }
    }
    sqlite3_finalize(stmt);
    return authenticated;
}

// Encryption / Decryption Utility Functions
std::string encryptMessage(const std::string& key, const std::string& message) {
    CryptoPP::SecByteBlock keyBlock(reinterpret_cast<const unsigned char*>(key.data()), key.size());
    std::string cipherText;

    CryptoPP::ECB_Mode<CryptoPP::AES>::Encryption encryption;
    encryption.SetKey(keyBlock, keyBlock.size());

    CryptoPP::StringSource ss(message, true,
        new CryptoPP::StreamTransformationFilter(encryption,
            new CryptoPP::StringSink(cipherText)
        )
    );

    return cipherText;
}

std::string decryptMessage(const std::string& key, const std::string& cipherText) {
    CryptoPP::SecByteBlock keyBlock(reinterpret_cast<const unsigned char*>(key.data()), key.size());
    std::string recoveredText;

    CryptoPP::ECB_Mode<CryptoPP::AES>::Decryption decryption;
    decryption.SetKey(keyBlock, keyBlock.size());

    CryptoPP::StringSource ss(cipherText, true,
        new CryptoPP::StreamTransformationFilter(decryption,
            new CryptoPP::StringSink(recoveredText)
        )
    );

    return recoveredText;
}

int main() {
    if (!initDatabase()) {
        return 1;
    }

    int option;
    std::string username, password;

    while (true) {
        std::cout << "1. Register\n2. Login\n3. Send Message\n4. Exit\nChoose an option: ";
        std::cin >> option;

        switch (option) {
            case 1: {
                std::cout << "Enter username: ";
                std::cin >> username;
                std::cout << "Enter password: ";
                std::cin >> password;

                if (registerUser(username, password)) {
                    std::cout << "Registration successful!" << std::endl;
                } else {
                    std::cout << "Registration failed." << std::endl;
                }
                break;
            }
            case 2: {
                std::cout << "Enter username: ";
                std::cin >> username;
                std::cout << "Enter password: ";
                std::cin >> password;

                if (authenticateUser(username, password)) {
                    std::cout << "Login successful!" << std::endl;
                } else {
                    std::cout << "Login failed. Invalid credentials." << std::endl;
                }
                break;
            }
            case 3: {
                std::string recipient, message, key;
                std::cout << "Enter recipient username: ";
                std::cin >> recipient;
                std::cout << "Enter encryption key: ";
                std::cin >> key; // Note: In practice, this should be securely derived and stored.
                std::cout << "Enter message: ";
                std::cin.ignore(); // Clear newline left in buffer
                std::getline(std::cin, message);

                // Encrypt message
                std::string encryptedMessage = encryptMessage(key, message);
                std::cout << "Encrypted Message: " << encryptedMessage << std::endl;

                // Simulate recipient decrypting the message
                std::string decryptedMessage = decryptMessage(key, encryptedMessage);
                std::cout << "Decrypted Message: " << decryptedMessage << std::endl;
                break;
            }
            case 4:
                sqlite3_close(db);
                return 0;
            default:
                std::cout << "Invalid option. Try again." << std::endl;
        }
    }

    return 0;
}
