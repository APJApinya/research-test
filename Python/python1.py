import bcrypt
import sqlite3
from cryptography.fernet import Fernet

# Initialize in-memory SQLite database
conn = sqlite3.connect(":memory:")
c = conn.cursor()

# Create tables for users and messages
c.execute('''CREATE TABLE users (username TEXT PRIMARY KEY, password_hash TEXT, encryption_key TEXT)''')
c.execute('''CREATE TABLE messages (sender TEXT, recipient TEXT, message TEXT)''')

class SecureMessagingApp:
    def __init__(self):
        self.current_user = None

    def register(self, username, password):
        # Check if user already exists
        c.execute("SELECT * FROM users WHERE username = ?", (username,))
        if c.fetchone():
            print("User already exists.")
            return
        
        # Hash the password
        password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt())

        # Generate encryption key for user
        encryption_key = Fernet.generate_key()

        # Insert user into database
        c.execute("INSERT INTO users (username, password_hash, encryption_key) VALUES (?, ?, ?)", 
                  (username, password_hash, encryption_key))
        conn.commit()
        print(f"User '{username}' registered successfully!")

    def login(self, username, password):
        # Retrieve user data
        c.execute("SELECT password_hash FROM users WHERE username = ?", (username,))
        user = c.fetchone()
        if not user:
            print("User not found.")
            return False
        
        password_hash = user[0]
        if bcrypt.checkpw(password.encode(), password_hash):
            self.current_user = username
            print(f"User '{username}' logged in successfully!")
            return True
        else:
            print("Invalid password.")
            return False

    def send_message(self, recipient, message):
        if not self.current_user:
            print("Please login first.")
            return

        # Retrieve recipient's encryption key
        c.execute("SELECT encryption_key FROM users WHERE username = ?", (recipient,))
        user = c.fetchone()
        if not user:
            print("Recipient not found.")
            return

        recipient_key = user[0]
        fernet = Fernet(recipient_key)

        # Encrypt the message
        encrypted_message = fernet.encrypt(message.encode())

        # Store the message
        c.execute("INSERT INTO messages (sender, recipient, message) VALUES (?, ?, ?)",
                  (self.current_user, recipient, encrypted_message))
        conn.commit()
        print(f"Message sent to '{recipient}'.")

    def read_messages(self):
        if not self.current_user:
            print("Please login first.")
            return

        # Retrieve user's encryption key
        c.execute("SELECT encryption_key FROM users WHERE username = ?", (self.current_user,))
        user = c.fetchone()
        if not user:
            print("User not found.")
            return

        user_key = user[0]
        fernet = Fernet(user_key)

        # Retrieve messages for the current user
        c.execute("SELECT sender, message FROM messages WHERE recipient = ?", (self.current_user,))
        messages = c.fetchall()

        if not messages:
            print("No messages found.")
            return

        print("Your messages:")
        for sender, encrypted_message in messages:
            # Decrypt the message
            decrypted_message = fernet.decrypt(encrypted_message).decode()
            print(f"From {sender}: {decrypted_message}")

# Example usage:
app = SecureMessagingApp()

# Register users
app.register("alice", "password123")
app.register("bob", "securepassword")

# Login as Alice
app.login("alice", "password123")

# Alice sends a message to Bob
app.send_message("bob", "Hello, Bob! How are you?")

# Login as Bob
app.login("bob", "securepassword")

# Bob reads messages
app.read_messages()
