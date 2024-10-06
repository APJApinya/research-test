#include <iostream>
#include <unordered_map>
#include <string>
#include <cryptopp/aes.h>
#include <cryptopp/filters.h>
#include <cryptopp/modes.h>
#include <cryptopp/osrng.h>
#include <cryptopp/hex.h>

using namespace CryptoPP;
using namespace std;

struct User {
    string username;
    string hashedPassword;
    string encryptionKey; // Each user has their own unique encryption key.
};

unordered_map<string, User> usersDatabase;
unordered_map<string, string> messagesDatabase;

// Hash function to hash passwords (this is for demonstration purposes, PBKDF2 or another strong algorithm should be used in practice)
string hashPassword(const string& password) {
    string hashedPassword;
    SHA256 hash;
    StringSource ss(password, true, new HashFilter(hash, new HexEncoder(new StringSink(hashedPassword))));
    return hashedPassword;
}

// User Registration
bool registerUser(const string& username, const string& password) {
    if (usersDatabase.find(username) != usersDatabase.end()) {
        cout << "User already exists." << endl;
        return false;
    }

    AutoSeededRandomPool prng;
    SecByteBlock key(AES::DEFAULT_KEYLENGTH);
    prng.GenerateBlock(key, key.size());

    string keyHex;
    StringSource(key, key.size(), true, new HexEncoder(new StringSink(keyHex)));

    User newUser = {username, hashPassword(password), keyHex};
    usersDatabase[username] = newUser;

    cout << "User registered successfully!" << endl;
    return true;
}

// User Login
bool loginUser(const string& username, const string& password) {
    if (usersDatabase.find(username) == usersDatabase.end()) {
        cout << "User does not exist." << endl;
        return false;
    }

    if (usersDatabase[username].hashedPassword == hashPassword(password)) {
        cout << "Login successful!" << endl;
        return true;
    } else {
        cout << "Invalid password." << endl;
        return false;
    }
}

// Encrypt Message
string encryptMessage(const string& plainText, const string& keyHex) {
    SecByteBlock key((const byte*)keyHex.data(), keyHex.size() / 2);
    AutoSeededRandomPool prng;

    byte iv[AES::BLOCKSIZE];
    prng.GenerateBlock(iv, sizeof(iv));

    string cipherText;
    try {
        CBC_Mode<AES>::Encryption encryption;
        encryption.SetKeyWithIV(key, key.size(), iv);

        StringSource(plainText, true,
            new StreamTransformationFilter(encryption,
                new StringSink(cipherText)
            ) // StreamTransformationFilter
        ); // StringSource
    } catch (const Exception& e) {
        cerr << e.what() << endl;
        exit(1);
    }

    string ivHex;
    StringSource(iv, sizeof(iv), true, new HexEncoder(new StringSink(ivHex)));
    return ivHex + cipherText; // Return IV + ciphertext to decrypt properly.
}

// Decrypt Message
string decryptMessage(const string& cipherText, const string& keyHex) {
    SecByteBlock key((const byte*)keyHex.data(), keyHex.size() / 2);

    string ivHex = cipherText.substr(0, AES::BLOCKSIZE * 2);
    string actualCipherText = cipherText.substr(AES::BLOCKSIZE * 2);

    string iv;
    StringSource(ivHex, true, new HexDecoder(new StringSink(iv)));

    string decryptedText;
    try {
        CBC_Mode<AES>::Decryption decryption;
        decryption.SetKeyWithIV(key, key.size(), (byte*)iv.data());

        StringSource(actualCipherText, true,
            new StreamTransformationFilter(decryption,
                new StringSink(decryptedText)
            ) // StreamTransformationFilter
        ); // StringSource
    } catch (const Exception& e) {
        cerr << e.what() << endl;
        exit(1);
    }

    return decryptedText;
}

// Send Message
void sendMessage(const string& sender, const string& recipient, const string& message) {
    if (usersDatabase.find(recipient) == usersDatabase.end()) {
        cout << "Recipient does not exist." << endl;
        return;
    }

    string encryptedMessage = encryptMessage(message, usersDatabase[recipient].encryptionKey);
    messagesDatabase[recipient] = encryptedMessage;

    cout << "Message sent successfully!" << endl;
}

// Read Message
void readMessage(const string& username) {
    if (messagesDatabase.find(username) == messagesDatabase.end()) {
        cout << "No messages found." << endl;
        return;
    }

    string encryptedMessage = messagesDatabase[username];
    string decryptedMessage = decryptMessage(encryptedMessage, usersDatabase[username].encryptionKey);

    cout << "Message: " << decryptedMessage << endl;
}

// Main Function
int main() {
    int choice;
    string username, password, recipient, message;

    while (true) {
        cout << "\n1. Register\n2. Login\n3. Send Message\n4. Read Message\n5. Exit\n";
        cout << "Enter your choice: ";
        cin >> choice;

        switch (choice) {
            case 1:
                cout << "Enter username: ";
                cin >> username;
                cout << "Enter password: ";
                cin >> password;
                registerUser(username, password);
                break;

            case 2:
                cout << "Enter username: ";
                cin >> username;
                cout << "Enter password: ";
                cin >> password;
                loginUser(username, password);
                break;

            case 3:
                cout << "Enter your username: ";
                cin >> username;
                cout << "Enter recipient username: ";
                cin >> recipient;
                cout << "Enter message: ";
                cin.ignore();
                getline(cin, message);
                sendMessage(username, recipient, message);
                break;

            case 4:
                cout << "Enter your username: ";
                cin >> username;
                readMessage(username);
                break;

            case 5:
                return 0;

            default:
                cout << "Invalid choice." << endl;
        }
    }

    return 0;
}
