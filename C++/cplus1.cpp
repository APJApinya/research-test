#include <iostream>
#include <fstream>
#include <unordered_map>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <string.h>

#define SALT_SIZE 16
#define KEY_SIZE 32

using namespace std;

unordered_map<string, string> users;

void registerUser(const string &username, const string &password);
bool loginUser(const string &username, const string &password);
string hashPassword(const string &password, unsigned char *salt);
bool encryptMessage(const string &plaintext, const string &key, string &ciphertext);
bool decryptMessage(const string &ciphertext, const string &key, string &plaintext);
void sendMessage(const string &sender, const string &recipient, const string &message);

int main() {
    int choice;
    string username, password, recipient, message;

    while (true) {
        cout << "1. Register\n2. Login\n3. Exit\nEnter choice: ";
        cin >> choice;

        if (choice == 1) {
            cout << "Enter username: ";
            cin >> username;
            cout << "Enter password: ";
            cin >> password;

            registerUser(username, password);
        } else if (choice == 2) {
            cout << "Enter username: ";
            cin >> username;
            cout << "Enter password: ";
            cin >> password;

            if (loginUser(username, password)) {
                cout << "Login successful!\n";

                cout << "Enter recipient: ";
                cin >> recipient;
                cout << "Enter message to send: ";
                cin.ignore();
                getline(cin, message);

                sendMessage(username, recipient, message);
            } else {
                cout << "Invalid username or password.\n";
            }
        } else if (choice == 3) {
            break;
        } else {
            cout << "Invalid choice.\n";
        }
    }

    return 0;
}

void registerUser(const string &username, const string &password) {
    unsigned char salt[SALT_SIZE];
    RAND_bytes(salt, sizeof(salt));

    string hashedPassword = hashPassword(password, salt);

    ofstream db("users.db", ios::app);
    db << username << " " << hashedPassword << " " << string((char *)salt, SALT_SIZE) << endl;
    db.close();

    cout << "User registered successfully!\n";
}

bool loginUser(const string &username, const string &password) {
    ifstream db("users.db");
    string dbUsername, dbHashedPassword, dbSalt;
    while (db >> dbUsername >> dbHashedPassword >> dbSalt) {
        if (dbUsername == username) {
            unsigned char salt[SALT_SIZE];
            memcpy(salt, dbSalt.c_str(), SALT_SIZE);
            string hashedPassword = hashPassword(password, salt);
            return hashedPassword == dbHashedPassword;
        }
    }
    return false;
}

string hashPassword(const string &password, unsigned char *salt) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, salt, SALT_SIZE);
    SHA256_Update(&sha256, password.c_str(), password.size());
    SHA256_Final(hash, &sha256);

    return string((char *)hash, SHA256_DIGEST_LENGTH);
}

bool encryptMessage(const string &plaintext, const string &key, string &ciphertext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;

    unsigned char iv[EVP_MAX_IV_LENGTH];
    RAND_bytes(iv, sizeof(iv));

    unsigned char outbuf[plaintext.size() + EVP_MAX_BLOCK_LENGTH];
    int outlen;

    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, (unsigned char *)key.c_str(), iv);
    EVP_EncryptUpdate(ctx, outbuf, &outlen, (unsigned char *)plaintext.c_str(), plaintext.size());

    int tmplen;
    EVP_EncryptFinal_ex(ctx, outbuf + outlen, &tmplen);
    outlen += tmplen;

    ciphertext = string((char *)iv, EVP_MAX_IV_LENGTH) + string((char *)outbuf, outlen);
    EVP_CIPHER_CTX_free(ctx);
    return true;
}

bool decryptMessage(const string &ciphertext, const string &key, string &plaintext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;

    unsigned char iv[EVP_MAX_IV_LENGTH];
    memcpy(iv, ciphertext.c_str(), EVP_MAX_IV_LENGTH);

    unsigned char outbuf[ciphertext.size()];
    int outlen;

    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, (unsigned char *)key.c_str(), iv);
    EVP_DecryptUpdate(ctx, outbuf, &outlen, (unsigned char *)(ciphertext.c_str() + EVP_MAX_IV_LENGTH), ciphertext.size() - EVP_MAX_IV_LENGTH);

    int tmplen;
    EVP_DecryptFinal_ex(ctx, outbuf + outlen, &tmplen);
    outlen += tmplen;

    plaintext = string((char *)outbuf, outlen);
    EVP_CIPHER_CTX_free(ctx);
    return true;
}

void sendMessage(const string &sender, const string &recipient, const string &message) {
    string key = "some_shared_secret_key_32bytes"; // Ideally, use a key exchange mechanism

    string ciphertext;
    if (encryptMessage(message, key, ciphertext)) {
        ofstream msgDb("messages.db", ios::app);
        msgDb << recipient << " " << ciphertext << endl;
        msgDb.close();
        cout << "Message sent successfully!\n";
    } else {
        cout << "Failed to encrypt the message.\n";
    }
}
