#include <iostream>
#include <string>
#include <unordered_map>
#include <cryptopp/sha.h>
#include <cryptopp/pwdbased.h>
#include <cryptopp/osrng.h>
#include <cryptopp/aes.h>
#include <cryptopp/gcm.h>
#include <cpprest/http_client.h>
#include <cpprest/uri.h>
#include <cpprest/http_listener.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

using namespace std;
using namespace CryptoPP;
using namespace web;
using namespace web::http;
using namespace web::http::client;

// Database mockup for storing user information
unordered_map<string, pair<string, string>> userDatabase; // username -> (salt, hashed_password)
unordered_map<string, string> userKeys; // username -> current AES key

// Helper functions for password hashing
string hashPasswordWithPBKDF2(const string& password, const string& salt) {
    SecByteBlock derived(32);
    PKCS5_PBKDF2_HMAC<SHA256> pbkdf;
    pbkdf.DeriveKey(derived, derived.size(), 0,
                    (byte*)password.data(), password.size(),
                    (byte*)salt.data(), salt.size(), 10000);
    return string((char*)derived.data(), derived.size());
}

string generateSalt() {
    AutoSeededRandomPool rng;
    byte salt[16];
    rng.GenerateBlock(salt, sizeof(salt));
    return string((char*)salt, sizeof(salt));
}

// User Registration
void registerUser(const string& username, const string& password) {
    if (userDatabase.find(username) != userDatabase.end()) {
        cout << "User already exists." << endl;
        return;
    }
    string salt = generateSalt();
    string hashedPassword = hashPasswordWithPBKDF2(password, salt);
    userDatabase[username] = {salt, hashedPassword};

    // Generate an AES key for the user for message encryption
    SecByteBlock aesKey(AES::DEFAULT_KEYLENGTH);
    AutoSeededRandomPool prng;
    prng.GenerateBlock(aesKey, aesKey.size());
    userKeys[username] = string((char*)aesKey.data(), aesKey.size());

    cout << "User registered successfully." << endl;
}

// User Login
bool loginUser(const string& username, const string& password) {
    auto it = userDatabase.find(username);
    if (it == userDatabase.end()) {
        cout << "User does not exist." << endl;
        return false;
    }
    string salt = it->second.first;
    string hashedPassword = hashPasswordWithPBKDF2(password, salt);

    if (hashedPassword == it->second.second) {
        cout << "Login successful." << endl;
        return true;
    } else {
        cout << "Invalid credentials." << endl;
        return false;
    }
}

// AES-GCM Encryption
string encryptMessage(const string& plaintext, const string& key, string& iv) {
    GCM<AES>::Encryption encryption;
    AutoSeededRandomPool prng;
    
    byte ivBytes[AES::BLOCKSIZE];
    prng.GenerateBlock(ivBytes, sizeof(ivBytes));
    iv = string((char*)ivBytes, sizeof(ivBytes));
    
    encryption.SetKeyWithIV((byte*)key.data(), key.size(), ivBytes, sizeof(ivBytes));

    string cipher;
    StringSource ss1(plaintext, true, 
        new AuthenticatedEncryptionFilter(encryption,
            new StringSink(cipher)
        )
    );

    return cipher;
}

// Send Encrypted Message via HTTPS
void sendEncryptedMessage(const string& recipient, const string& message, const string& sender) {
    if (userDatabase.find(recipient) == userDatabase.end()) {
        cout << "Recipient does not exist." << endl;
        return;
    }

    // Encrypt the message
    string iv;
    string encryptedMessage = encryptMessage(message, userKeys[sender], iv);

    // HTTP client setup
    http_client client(U("https://secure.messaging.service"));

    // Create the message with encryption
    json::value postData;
    postData[U("sender")] = json::value::string(U(sender));
    postData[U("recipient")] = json::value::string(U(recipient));
    postData[U("message")] = json::value::string(U(encryptedMessage));
    postData[U("iv")] = json::value::string(U(iv));

    // Send the message
    client.request(methods::POST, U("/send_message"), postData)
        .then([](http_response response) {
            if (response.status_code() == status_codes::OK) {
                cout << "Message sent successfully." << endl;
            } else {
                cout << "Failed to send message. Status code: " << response.status_code() << endl;
            }
        }).wait();
}

// SSL Client Certificate Verification
void initializeSSL() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

void cleanupSSL() {
    EVP_cleanup();
}

int main() {
    // Initialize SSL
    initializeSSL();

    string username, password;

    // Register user
    cout << "Register - Enter username: ";
    cin >> username;
    cout << "Enter password: ";
    cin >> password;
    registerUser(username, password);

    // Login user
    cout << "\nLogin - Enter username: ";
    cin >> username;
    cout << "Enter password: ";
    cin >> password;
    if (loginUser(username, password)) {
        // Send a message
        string recipient, message;
        cout << "\nEnter recipient username: ";
        cin >> recipient;
        cout << "Enter message: ";
        cin.ignore();
        getline(cin, message);

        sendEncryptedMessage(recipient, message, username);
    }

    // Clean up SSL
    cleanupSSL();
    
    return 0;
}
