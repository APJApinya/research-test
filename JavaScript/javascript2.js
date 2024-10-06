const express = require("express");
const bcrypt = require("bcrypt");
const crypto = require("crypto");
const bodyParser = require("body-parser");
const { v4: uuidv4 } = require("uuid");

const app = express();
app.use(bodyParser.json());

// In-memory storage for demo purposes
const users = {};
const messages = {};

// Helper functions for encryption
function generateKey() {
    return crypto.randomBytes(32);
}

function encryptMessage(key, message) {
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
    let encrypted = cipher.update(message, "utf8", "hex");
    encrypted += cipher.final("hex");
    const tag = cipher.getAuthTag().toString("hex");
    return {
        encryptedMessage: encrypted,
        iv: iv.toString("hex"),
        tag: tag,
    };
}

function decryptMessage(key, encryptedMessage, iv, tag) {
    const decipher = crypto.createDecipheriv("aes-256-gcm", key, Buffer.from(iv, "hex"));
    decipher.setAuthTag(Buffer.from(tag, "hex"));
    let decrypted = decipher.update(encryptedMessage, "hex", "utf8");
    decrypted += decipher.final("utf8");
    return decrypted;
}

// Register user
app.post("/register", async (req, res) => {
    const { username, password } = req.body;
    if (users[username]) {
        return res.status(400).json({ message: "User already exists" });
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    const encryptionKey = generateKey(); // Each user has their own key for message encryption
    users[username] = {
        password: hashedPassword,
        encryptionKey: encryptionKey,
    };
    res.status(201).json({ message: "User registered successfully" });
});

// Login user
app.post("/login", async (req, res) => {
    const { username, password } = req.body;
    const user = users[username];
    if (!user) {
        return res.status(400).json({ message: "User does not exist" });
    }
    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
        return res.status(401).json({ message: "Invalid credentials" });
    }
    res.status(200).json({ message: "Login successful" });
});

// Send message
app.post("/send", (req, res) => {
    const { sender, recipient, message } = req.body;

    if (!users[sender] || !users[recipient]) {
        return res.status(400).json({ message: "Sender or recipient does not exist" });
    }

    const recipientKey = users[recipient].encryptionKey;
    const encryptedMessage = encryptMessage(recipientKey, message);

    const messageId = uuidv4();
    messages[messageId] = {
        sender: sender,
        recipient: recipient,
        encryptedMessage: encryptedMessage,
    };

    res.status(200).json({ message: "Message sent successfully", messageId: messageId });
});

// Receive message
app.get("/receive/:username/:messageId", (req, res) => {
    const { username, messageId } = req.params;

    if (!users[username]) {
        return res.status(400).json({ message: "User does not exist" });
    }

    const messageData = messages[messageId];
    if (!messageData || messageData.recipient !== username) {
        return res.status(404).json({ message: "Message not found or unauthorized access" });
    }

    const recipientKey = users[username].encryptionKey;
    const { encryptedMessage, iv, tag } = messageData.encryptedMessage;

    try {
        const decryptedMessage = decryptMessage(recipientKey, encryptedMessage, iv, tag);
        res.status(200).json({ message: decryptedMessage });
    } catch (error) {
        res.status(500).json({ message: "Failed to decrypt message" });
    }
});

// Start server
app.listen(3000, () => {
    console.log("Server is running on port 3000");
});
