#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/hmac.h>
#include <iostream>
#include <string>
#include <unordered_map>
#include <vector>

class SecureMessagingApp {
public:
    SecureMessagingApp() {
        // Initialize SSL
        SSL_load_error_strings();
        OpenSSL_add_ssl_algorithms();
    }

    ~SecureMessagingApp() {
        // Cleanup
        EVP_cleanup();
    }

    void registerUser(const std::string& username, const std::string& password) {
        unsigned char salt[16];
        RAND_bytes(salt, sizeof(salt));

        // Derive key using PBKDF2
        unsigned char key[32];
        PKCS5_PBKDF2_HMAC(password.c_str(), password.length(), salt, sizeof(salt), 10000, EVP_sha256(), sizeof(key), key);

        users[username] = User(username, std::vector<unsigned char>(key, key + sizeof(key)), std::vector<unsigned char>(salt, salt + sizeof(salt)));

        std::cout << "User " << username << " registered successfully." << std::endl;
    }

    bool loginUser(const std::string& username, const std::string& password) {
        if (users.find(username) == users.end()) {
            std::cout << "User not found." << std::endl;
            return false;
        }

        User& user = users[username];
        unsigned char key[32];
        PKCS5_PBKDF2_HMAC(password.c_str(), password.length(), user.salt.data(), user.salt.size(), 10000, EVP_sha256(), sizeof(key), key);

        if (std::equal(key, key + sizeof(key), user.key.begin())) {
            std::cout << "User " << username << " logged in successfully." << std::endl;
            return true;
        } else {
            std::cout << "Invalid password." << std::endl;
            return false;
        }
    }

    void sendMessage(const std::string& sender, const std::string& recipient, const std::string& message) {
        if (users.find(sender) == users.end() || users.find(recipient) == users.end()) {
            std::cout << "Sender or recipient not found." << std::endl;
            return;
        }

        User& user = users[sender];

        // Rotate key after 10 messages
        if (user.messageCount >= 10) {
            rotateKey(user);
        }

        // Generate random IV
        unsigned char iv[12];
        RAND_bytes(iv, sizeof(iv));

        // Encrypt the message using AES-GCM
        unsigned char ciphertext[1024];
        int len;
        unsigned char tag[16];

        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
        EVP_EncryptInit_ex(ctx, NULL, NULL, user.key.data(), iv);
        EVP_EncryptUpdate(ctx, NULL, &len, iv, sizeof(iv));
        EVP_EncryptUpdate(ctx, ciphertext, &len, (unsigned char*)message.c_str(), message.length());
        EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, sizeof(tag), tag);

        EVP_CIPHER_CTX_free(ctx);

        users[recipient].inbox.push_back(EncryptedMessage(std::vector<unsigned char>(ciphertext, ciphertext + sizeof(ciphertext)),
                                                          std::vector<unsigned char>(iv, iv + sizeof(iv)),
                                                          std::vector<unsigned char>(tag, tag + sizeof(tag))));

        user.messageCount++;

        std::cout << "Message sent from " << sender << " to " << recipient << "." << std::endl;
    }

private:
    struct EncryptedMessage {
        std::vector<unsigned char> ciphertext;
        std::vector<unsigned char> iv;
        std::vector<unsigned char> tag;

        EncryptedMessage(std::vector<unsigned char> ct, std::vector<unsigned char> i, std::vector<unsigned char> t)
            : ciphertext(std::move(ct)), iv(std::move(i)), tag(std::move(t)) {}
    };

    struct User {
        std::string username;
        std::vector<unsigned char> key;
        std::vector<unsigned char> salt;
        std::vector<EncryptedMessage> inbox;
        int messageCount;

        User(std::string uname, std::vector<unsigned char> k, std::vector<unsigned char> s)
            : username(std::move(uname)), key(std::move(k)), salt(std::move(s)), messageCount(0) {}
    };

    std::unordered_map<std::string, User> users;

    void rotateKey(User& user) {
        unsigned char newKey[32];
        RAND_bytes(newKey, sizeof(newKey));
        user.key.assign(newKey, newKey + sizeof(newKey));
        user.messageCount = 0;

        std::cout << "Key rotated for user " << user.username << "." << std::endl;
    }
};

int main() {
    SecureMessagingApp app;

    app.registerUser("alice", "password123");
    app.registerUser("bob", "securepassword");

    if (app.loginUser("alice", "password123")) {
        app.sendMessage("alice", "bob", "Hello Bob!");
    }

    return 0;
}
