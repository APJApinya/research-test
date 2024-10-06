const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

const app = express();
app.use(express.json());

const PORT = 3000;
const SECRET_KEY = "supersecretkey"; // Used for JWT signing
const ENCRYPTION_KEY = crypto.randomBytes(32); // 32 bytes for AES-256

// Connect to MongoDB
mongoose.connect('mongodb://localhost:27017/secure-messaging', { useNewUrlParser: true, useUnifiedTopology: true });

// User Schema
const userSchema = new mongoose.Schema({
    username: String,
    password: String,
});

const User = mongoose.model('User', userSchema);

// Middleware for authentication
const authenticateToken = (req, res, next) => {
    const token = req.header('Authorization')?.split(' ')[1];
    if (!token) return res.sendStatus(401);
    
    jwt.verify(token, SECRET_KEY, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
};

// User registration
app.post('/register', async (req, res) => {
    const { username, password } = req.body;

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ username, password: hashedPassword });

    try {
        await newUser.save();
        res.status(201).send('User Registered');
    } catch (error) {
        res.status(500).send('Error registering user');
    }
});

// User login
app.post('/login', async (req, res) => {
    const { username, password } = req.body;

    const user = await User.findOne({ username });
    if (!user) return res.status(400).send('User not found');

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) return res.status(401).send('Incorrect password');

    const token = jwt.sign({ username }, SECRET_KEY, { expiresIn: '1h' });
    res.json({ token });
});

// Send an encrypted message to another user
app.post('/send-message', authenticateToken, async (req, res) => {
    const { recipientUsername, message } = req.body;

    const recipient = await User.findOne({ username: recipientUsername });
    if (!recipient) return res.status(400).send('Recipient not found');

    const iv = crypto.randomBytes(16); // Generate random IV
    const cipher = crypto.createCipheriv('aes-256-gcm', ENCRYPTION_KEY, iv);

    let encryptedMessage = cipher.update(message, 'utf-8', 'hex');
    encryptedMessage += cipher.final('hex');
    const authTag = cipher.getAuthTag().toString('hex');

    const storedMessage = {
        sender: req.user.username,
        recipient: recipient.username,
        iv: iv.toString('hex'),
        authTag: authTag,
        encryptedMessage: encryptedMessage,
    };

    // Store `storedMessage` in your database, for now we just log it
    console.log(storedMessage);

    res.status(200).send('Message sent securely');
});

// Decrypt message for recipient
app.post('/decrypt-message', authenticateToken, async (req, res) => {
    const { iv, encryptedMessage, authTag } = req.body;

    const decipher = crypto.createDecipheriv('aes-256-gcm', ENCRYPTION_KEY, Buffer.from(iv, 'hex'));
    decipher.setAuthTag(Buffer.from(authTag, 'hex'));

    try {
        let decryptedMessage = decipher.update(encryptedMessage, 'hex', 'utf-8');
        decryptedMessage += decipher.final('utf-8');
        res.status(200).send({ decryptedMessage });
    } catch (error) {
        res.status(400).send('Failed to decrypt message');
    }
});

app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});
