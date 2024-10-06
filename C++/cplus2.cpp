#include <iostream>
#include <string>
#include <unordered_map>
#include <openssl/evp.h>
#include <openssl/rand.h>


class User {
public:
    std::string username;
    std::string password_hash; // For simplicity, we're just using the password as plaintext (which should not be done in practice).

    User(std::string uname, std::string pword) : username(uname), password_hash(pword) {}
};

std::unordered_map<std::string, User> users;

bool registerUser(const std::string &username, const std::string &password) {
    if (users.find(username) != users.end()) {
        std::cout << "Username already exists.\n";
        return false;
    }
    users[username] = User(username, password);
    return true;
}

bool loginUser(const std::string &username, const std::string &password) {
    if (users.find(username) != users.end() && users[username].password_hash == password) {
        std::cout << "Login successful.\n";
        return true;
    } else {
        std::cout << "Invalid credentials.\n";
        return false;
    }
}

void handleErrors() {
    ERR_print_errors_fp(stderr);
    abort();
}

bool encryptMessage(const std::string &plaintext, unsigned char *key, unsigned char *iv, std::string &ciphertext) {
    EVP_CIPHER_CTX *ctx;

    int len;
    int ciphertext_len;

    unsigned char ciphertext_buf[128];

    if (!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv) != 1) handleErrors();

    if (EVP_EncryptUpdate(ctx, ciphertext_buf, &len, (unsigned char *)plaintext.c_str(), plaintext.length()) != 1) handleErrors();
    ciphertext_len = len;

    if (EVP_EncryptFinal_ex(ctx, ciphertext_buf + len, &len) != 1) handleErrors();
    ciphertext_len += len;

    ciphertext = std::string((char*)ciphertext_buf, ciphertext_len);

    EVP_CIPHER_CTX_free(ctx);

    return true;
}

bool decryptMessage(const std::string &ciphertext, unsigned char *key, unsigned char *iv, std::string &plaintext) {
    EVP_CIPHER_CTX *ctx;

    int len;
    int plaintext_len;

    unsigned char plaintext_buf[128];

    if (!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv) != 1) handleErrors();

    if (EVP_DecryptUpdate(ctx, plaintext_buf, &len, (unsigned char *)ciphertext.c_str(), ciphertext.length()) != 1) handleErrors();
    plaintext_len = len;

    if (EVP_DecryptFinal_ex(ctx, plaintext_buf + len, &len) != 1) handleErrors();
    plaintext_len += len;

    plaintext = std::string((char*)plaintext_buf, plaintext_len);

    EVP_CIPHER_CTX_free(ctx);

    return true;
}

void sendMessage(const std::string &sender, const std::string &recipient, const std::string &message) {
    if (users.find(recipient) == users.end()) {
        std::cout << "Recipient not found.\n";
        return;
    }

    unsigned char key[32];
    unsigned char iv[12];

    if (!RAND_bytes(key, sizeof(key)) || !RAND_bytes(iv, sizeof(iv))) {
        std::cerr << "Random generation failed.\n";
        return;
    }

    std::string encryptedMessage;
    if (encryptMessage(message, key, iv, encryptedMessage)) {
        std::cout << "Message sent to " << recipient << " (encrypted).\n";
        // Here, you would store the encrypted message in a database and associate it with the recipient.
    }
}

int main() {
    std::string username, password, recipient, message;

    std::cout << "Register a new user\n";
    std::cout << "Username: ";
    std::cin >> username;
    std::cout << "Password: ";
    std::cin >> password;

    if (registerUser(username, password)) {
        std::cout << "Registration successful.\n";
    }

    std::cout << "\nLogin\n";
    std::cout << "Username: ";
    std::cin >> username;
    std::cout << "Password: ";
    std::cin >> password;

    if (loginUser(username, password)) {
        std::cout << "\nSend a message\n";
        std::cout << "Recipient: ";
        std::cin >> recipient;
        std::cin.ignore();
        std::cout << "Message: ";
        std::getline(std::cin, message);

        sendMessage(username, recipient, message);
    }

    return 0;
}
