#include <iostream>
#include <string>
#include <sqlite3.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>

sqlite3* db;

bool executeSQL(const std::string& sql) {
    char* errMsg = nullptr;
    int rc = sqlite3_exec(db, sql.c_str(), nullptr, nullptr, &errMsg);
    if (rc != SQLITE_OK) {
        std::cerr << "SQL error: " << errMsg << std::endl;
        sqlite3_free(errMsg);
        return false;
    }
    return true;
}

void initializeDatabase() {
    int rc = sqlite3_open("secure_messaging.db", &db);
    if (rc) {
        std::cerr << "Can't open database: " << sqlite3_errmsg(db) << std::endl;
        exit(1);
    }
    
    // Create user table
    std::string createUsersTable = "CREATE TABLE IF NOT EXISTS users ("
                                   "username TEXT PRIMARY KEY, "
                                   "password TEXT);";
    executeSQL(createUsersTable);

    // Create messages table
    std::string createMessagesTable = "CREATE TABLE IF NOT EXISTS messages ("
                                      "recipient TEXT, "
                                      "encrypted_message TEXT);";
    executeSQL(createMessagesTable);
}

bool registerUser(const std::string& username, const std::string& password) {
    std::string sql = "INSERT INTO users (username, password) VALUES ('" + username + "', '" + password + "');";
    return executeSQL(sql);
}

bool loginUser(const std::string& username, const std::string& password) {
    std::string sql = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "';";
    sqlite3_stmt* stmt;

    int rc = sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        std::cerr << "Failed to prepare statement." << std::endl;
        return false;
    }

    bool loggedIn = false;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        loggedIn = true;
    }

    sqlite3_finalize(stmt);
    return loggedIn;
}

RSA* generateRSAKeyPair() {
    RSA* rsa = RSA_generate_key(2048, RSA_F4, nullptr, nullptr);
    return rsa;
}

std::string rsaEncrypt(RSA* key, const std::string& message) {
    std::string encrypted;
    encrypted.resize(RSA_size(key));

    int result = RSA_public_encrypt(message.size(),
                                    reinterpret_cast<const unsigned char*>(message.c_str()),
                                    reinterpret_cast<unsigned char*>(&encrypted[0]),
                                    key,
                                    RSA_PKCS1_OAEP_PADDING);

    if (result == -1) {
        char* err = (char*)malloc(130);
        ERR_load_crypto_strings();
        ERR_error_string(ERR_get_error(), err);
        std::cerr << "Encryption error: " << err << std::endl;
        free(err);
        return "";
    }
    return encrypted;
}

std::string rsaDecrypt(RSA* key, const std::string& encryptedMessage) {
    std::string decrypted;
    decrypted.resize(RSA_size(key));

    int result = RSA_private_decrypt(encryptedMessage.size(),
                                     reinterpret_cast<const unsigned char*>(encryptedMessage.c_str()),
                                     reinterpret_cast<unsigned char*>(&decrypted[0]),
                                     key,
                                     RSA_PKCS1_OAEP_PADDING);

    if (result == -1) {
        char* err = (char*)malloc(130);
        ERR_load_crypto_strings();
        ERR_error_string(ERR_get_error(), err);
        std::cerr << "Decryption error: " << err << std::endl;
        free(err);
        return "";
    }
    return decrypted;
}

void sendMessage(const std::string& recipient, RSA* publicKey, const std::string& message) {
    std::string encryptedMessage = rsaEncrypt(publicKey, message);
    if (encryptedMessage.empty()) {
        std::cerr << "Failed to encrypt message." << std::endl;
        return;
    }

    std::string sql = "INSERT INTO messages (recipient, encrypted_message) VALUES ('" + recipient + "', '" + encryptedMessage + "');";
    executeSQL(sql);
}

void readMessages(const std::string& username, RSA* privateKey) {
    std::string sql = "SELECT encrypted_message FROM messages WHERE recipient = '" + username + "';";
    sqlite3_stmt* stmt;

    int rc = sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        std::cerr << "Failed to prepare statement." << std::endl;
        return;
    }

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        std::string encryptedMessage = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        std::string decryptedMessage = rsaDecrypt(privateKey, encryptedMessage);
        std::cout << "Message: " << decryptedMessage << std::endl;
    }

    sqlite3_finalize(stmt);
}

int main() {
    initializeDatabase();

    std::string command;
    while (true) {
        std::cout << "Enter command (register, login, send, read, exit): ";
        std::cin >> command;

        if (command == "register") {
            std::string username, password;
            std::cout << "Enter username: ";
            std::cin >> username;
            std::cout << "Enter password: ";
            std::cin >> password;

            if (registerUser(username, password)) {
                std::cout << "User registered successfully." << std::endl;
            } else {
                std::cout << "Failed to register user." << std::endl;
            }

        } else if (command == "login") {
            std::string username, password;
            std::cout << "Enter username: ";
            std::cin >> username;
            std::cout << "Enter password: ";
            std::cin >> password;

            if (loginUser(username, password)) {
                std::cout << "Login successful." << std::endl;

                RSA* rsaKeyPair = generateRSAKeyPair();
                while (true) {
                    std::cout << "Enter command (send, read, logout): ";
                    std::string subCommand;
                    std::cin >> subCommand;

                    if (subCommand == "send") {
                        std::string recipient, message;
                        std::cout << "Enter recipient: ";
                        std::cin >> recipient;
                        std::cin.ignore(); // to ignore the newline character left in the buffer
                        std::cout << "Enter message: ";
                        std::getline(std::cin, message);

                        sendMessage(recipient, rsaKeyPair, message);
                    } else if (subCommand == "read") {
                        readMessages(username, rsaKeyPair);
                    } else if (subCommand == "logout") {
                        std::cout << "Logged out." << std::endl;
                        break;
                    }
                }

            } else {
                std::cout << "Login failed." << std::endl;
            }

        } else if (command == "exit") {
            break;
        }
    }

    sqlite3_close(db);
    return 0;
}
