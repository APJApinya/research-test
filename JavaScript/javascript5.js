const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const bodyParser = require('body-parser');
const crypto = require('crypto');
require('dotenv').config();

const app = express();
app.use(bodyParser.json());

// Connect to MongoDB
mongoose.connect('mongodb://localhost:27017/secureMessagingApp', { useNewUrlParser: true, useUnifiedTopology: true });

// User Schema
const userSchema = new mongoose.Schema({
  username: { type: String, unique: true, required: true },
  password: { type: String, required: true },
  publicKey: { type: String },
  privateKey: { type: String },
});

const User = mongoose.model('User', userSchema);

// Register User
app.post('/register', async (req, res) => {
  try {
    const { username, password } = req.body;

    // Hash the password with bcrypt
    const hashedPassword = await bcrypt.hash(password, 10);
    
    // Generate key pair (public and private key) for encryption/decryption
    const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
      modulusLength: 2048,
    });

    const newUser = new User({
      username,
      password: hashedPassword,
      publicKey: publicKey.export({ type: 'pkcs1', format: 'pem' }),
      privateKey: privateKey.export({ type: 'pkcs1', format: 'pem' }),
    });

    await newUser.save();
    res.status(201).send('User registered successfully!');
  } catch (err) {
    res.status(500).send('Error registering user!');
  }
});

// Login User
app.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = await User.findOne({ username });

    if (!user) {
      return res.status(404).send('User not found!');
    }

    const passwordMatch = await bcrypt.compare(password, user.password);

    if (!passwordMatch) {
      return res.status(401).send('Invalid credentials!');
    }

    res.status(200).send('User authenticated successfully!');
  } catch (err) {
    res.status(500).send('Error logging in!');
  }
});

// Send Encrypted Message
app.post('/send-message', async (req, res) => {
  try {
    const { senderUsername, recipientUsername, message } = req.body;

    // Find the recipient
    const recipient = await User.findOne({ username: recipientUsername });

    if (!recipient) {
      return res.status(404).send('Recipient not found!');
    }

    // Encrypt the message using recipient's public key
    const encryptedMessage = crypto.publicEncrypt(
      {
        key: recipient.publicKey,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: "sha256",
      },
      Buffer.from(message)
    );

    res.status(200).send({ encryptedMessage: encryptedMessage.toString('base64') });
  } catch (err) {
    res.status(500).send('Error sending message!');
  }
});

// Receive and Decrypt Message
app.post('/receive-message', async (req, res) => {
  try {
    const { recipientUsername, encryptedMessage } = req.body;

    // Find the recipient
    const recipient = await User.findOne({ username: recipientUsername });

    if (!recipient) {
      return res.status(404).send('Recipient not found!');
    }

    // Decrypt the message using recipient's private key
    const decryptedMessage = crypto.privateDecrypt(
      {
        key: recipient.privateKey,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: "sha256",
      },
      Buffer.from(encryptedMessage, 'base64')
    );

    res.status(200).send({ message: decryptedMessage.toString() });
  } catch (err) {
    res.status(500).send('Error receiving message!');
  }
});

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
