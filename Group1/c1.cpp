#include <iostream>
#include <unordered_map>
#include <string>
#include <vector>

using namespace std;

// Struct to represent a user.
struct User {
    string username;
    string password;
};

// Struct to represent a message.
struct Message {
    string sender;
    string recipient;
    string content;
};

// In-memory storage for users and messages.
unordered_map<string, User> users;
vector<Message> messages;

// Function to register a new user.
void registerUser() {
    string username, password;

    cout << "Enter a new username: ";
    cin >> username;

    // Check if username already exists.
    if (users.find(username) != users.end()) {
        cout << "Username already exists. Please choose a different username.\n";
        return;
    }

    cout << "Enter a password: ";
    cin >> password;

    // Store the new user.
    users[username] = User{username, password};
    cout << "User registered successfully!\n";
}

// Function to login an existing user.
bool loginUser(string &loggedInUser) {
    string username, password;

    cout << "Enter your username: ";
    cin >> username;

    // Check if the user exists.
    if (users.find(username) == users.end()) {
        cout << "User not found.\n";
        return false;
    }

    cout << "Enter your password: ";
    cin >> password;

    // Verify password.
    if (users[username].password == password) {
        loggedInUser = username;
        cout << "Login successful!\n";
        return true;
    } else {
        cout << "Incorrect password.\n";
        return false;
    }
}

// Function to send a message.
void sendMessage(const string &sender) {
    string recipient, content;

    cout << "Enter the recipient's username: ";
    cin >> recipient;

    // Check if the recipient exists.
    if (users.find(recipient) == users.end()) {
        cout << "Recipient not found.\n";
        return;
    }

    cout << "Enter your message: ";
    cin.ignore();  // Ignore leftover newline character.
    getline(cin, content);

    // Store the message.
    messages.push_back(Message{sender, recipient, content});
    cout << "Message sent successfully!\n";
}

// Function to view messages for a logged-in user.
void viewMessages(const string &loggedInUser) {
    cout << "Messages for " << loggedInUser << ":\n";
    bool hasMessages = false;

    // Iterate through all messages to find those addressed to the logged-in user.
    for (const auto &msg : messages) {
        if (msg.recipient == loggedInUser) {
            cout << "From " << msg.sender << ": " << msg.content << "\n";
            hasMessages = true;
        }
    }

    if (!hasMessages) {
        cout << "No messages.\n";
    }
}

int main() {
    string loggedInUser;
    int choice;

    while (true) {
        cout << "\n--- Menu ---\n";
        cout << "1. Register\n";
        cout << "2. Login\n";
        cout << "3. Send Message\n";
        cout << "4. View Messages\n";
        cout << "5. Exit\n";
        cout << "Enter your choice: ";
        cin >> choice;

        switch (choice) {
            case 1:
                registerUser();
                break;
            case 2:
                if (loginUser(loggedInUser)) {
                    cout << "Welcome, " << loggedInUser << "!\n";
                }
                break;
            case 3:
                if (!loggedInUser.empty()) {
                    sendMessage(loggedInUser);
                } else {
                    cout << "You need to login first.\n";
                }
                break;
            case 4:
                if (!loggedInUser.empty()) {
                    viewMessages(loggedInUser);
                } else {
                    cout << "You need to login first.\n";
                }
                break;
            case 5:
                cout << "Exiting...\n";
                return 0;
            default:
                cout << "Invalid choice. Please try again.\n";
        }
    }

    return 0;
}
