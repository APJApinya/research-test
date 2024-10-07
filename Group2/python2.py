import bcrypt
import sqlite3
from cryptography.fernet import Fernet
import os

# Database setup
conn = sqlite3.connect('secure_messaging.db')
c = conn.cursor()

# Create users table
c.execute('''
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash BLOB NOT NULL,
    encryption_key BLOB NOT NULL
)
''')

# Create messages table
c.execute('''
CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sender_id INTEGER,
    recipient_id INTEGER,
    message BLOB,
    FOREIGN KEY(sender_id) REFERENCES users(id),
    FOREIGN KEY(recipient_id) REFERENCES users(id)
)
''')

conn.commit()

# Helper function to retrieve user data by username
def get_user_by_username(username):
    c.execute('SELECT * FROM users WHERE username = ?', (username,))
    return c.fetchone()

# Registration function
def register_user():
    username = input("Enter a username: ")
    if get_user_by_username(username):
        print("Username already exists. Please choose another.")
        return

    password = input("Enter a password: ").encode('utf-8')
    password_hash = bcrypt.hashpw(password, bcrypt.gensalt())

    # Generate encryption key for the user
    encryption_key = Fernet.generate_key()

    # Store user in the database
    c.execute('INSERT INTO users (username, password_hash, encryption_key) VALUES (?, ?, ?)',
              (username, password_hash, encryption_key))
    conn.commit()

    print("User registered successfully.")

# Login function
def login_user():
    username = input("Enter your username: ")
    user = get_user_by_username(username)

    if not user:
        print("User does not exist.")
        return None

    password = input("Enter your password: ").encode('utf-8')

    if bcrypt.checkpw(password, user[2]):
        print("Login successful.")
        return user
    else:
        print("Incorrect password.")
        return None

# Send a message to another user
def send_message(sender):
    recipient_username = input("Enter the recipient's username: ")
    recipient = get_user_by_username(recipient_username)

    if not recipient:
        print("Recipient does not exist.")
        return

    message = input("Enter the message to send: ").encode('utf-8')

    # Encrypt the message using the recipient's encryption key
    recipient_key = Fernet(recipient[3])
    encrypted_message = recipient_key.encrypt(message)

    # Store the message in the database
    c.execute('INSERT INTO messages (sender_id, recipient_id, message) VALUES (?, ?, ?)',
              (sender[0], recipient[0], encrypted_message))
    conn.commit()

    print("Message sent successfully.")

# Retrieve messages for the authenticated user
def view_messages(user):
    c.execute('SELECT sender_id, message FROM messages WHERE recipient_id = ?', (user[0],))
    messages = c.fetchall()

    if not messages:
        print("No messages found.")
        return

    print("Your messages:")
    for sender_id, encrypted_message in messages:
        # Decrypt the message
        sender = c.execute('SELECT username FROM users WHERE id = ?', (sender_id,)).fetchone()
        f = Fernet(user[3])
        decrypted_message = f.decrypt(encrypted_message).decode('utf-8')
        print(f"From {sender[0]}: {decrypted_message}")

# Main program loop
def main():
    while True:
        print("\nSecure Messaging App")
        print("1. Register")
        print("2. Login")
        print("3. Quit")

        choice = input("Enter your choice: ")

        if choice == '1':
            register_user()
        elif choice == '2':
            user = login_user()
            if user:
                while True:
                    print("\n1. Send a message")
                    print("2. View messages")
                    print("3. Logout")

                    user_choice = input("Enter your choice: ")

                    if user_choice == '1':
                        send_message(user)
                    elif user_choice == '2':
                        view_messages(user)
                    elif user_choice == '3':
                        break
                    else:
                        print("Invalid choice. Please try again.")
        elif choice == '3':
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == '__main__':
    main()
