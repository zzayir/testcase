const express = require("express");
const mongoose = require("mongoose");
const bodyParser = require("body-parser");
const path = require("path");
const os = require("os");
const crypto = require("crypto");
const app = express();
app.use(express.json()); // This is required to parse JSON data
const cors = require('cors');
app.use(cors());
const twilio = require('twilio');
const bcrypt = require('bcryptjs');
const router = express.Router();

// ========== NFC STREAM FOR CLIENT LISTENING ==========
const nfcClients = new Map(); // Add this at the top of server.js (global)


app.get('/nfc-stream/:username', (req, res) => {
  const username = req.params.username;
  const isManager = req.query.isManager === "true"; // Grab from query string

  const key = `${isManager}:${username}`;

  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');

  res.write(`event: ping\ndata: connected\n\n`);
  nfcClients.set(key, res);

  req.on('close', () => {
    nfcClients.delete(key);
  });
});


const dotenv = require('dotenv');

dotenv.config();
require('dotenv').config();

// MongoDB connection URI
const mongoURI = "mongodb+srv://zzayir21:rifah5657@cluster21.7c8bhzd.mongodb.net/loginDB?retryWrites=true&w=majority";

// Connect to MongoDB
mongoose.connect(mongoURI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  serverSelectionTimeoutMS: 5000,
})
  .then(() => console.log("✅ Connected to MongoDB Atlas"))
  .catch(err => {
    console.error("❌ MongoDB connection error:", err);
    process.exit(1);
  });

// Enhanced User Schema with authentication data
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  email: { type: String, required: true},
  password: { type: String, required: true },
  mobileNumber: { type: String, required: true },
  authData: {
    aesKey: { type: String},
    expectedText: { type: String},
    allowedSerial: { type: String},
    securityKeys: {
      deactivateKey: { type: String},
      activateKey: { type: String}
    }
  }
});

const User = mongoose.model("User", userSchema);

// Enhanced Manager Schema (in 'employee' collection)
const managerSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  email: { type: String, required: true},
  password: { type: String, required: true },
  mobileNumber: { type: String, required: true },
  authData: {
    aesKey: { type: String},
    expectedText: { type: String},
    allowedSerial: { type: String},
    securityKeys: {
      deactivateKey: { type: String},
      activateKey: { type: String}
    }
  }
});

const Manager = mongoose.model("Manager", managerSchema, "employee");

// Middleware
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, "public")));

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ success: false, message: "Something went wrong!" });
});

// ===== LOGIN ROUTES =====

// Login endpoint (User)
app.post("/login", async (req, res, next) => {
  try {
    const { username, password } = req.body;
    
    if (!username || !password) {
      return res.status(400).json({ 
        success: false,
        message: "Username and password are required" 
      });
    }

    const user = await User.findOne({ username, password });

    if (!user) {
      return res.status(401).json({ 
        success: false,
        message: "Invalid credentials" 
      });
    }

    res.json({
      success: true,
      message: "Login successful",
      username: user.username,
      authData: user.authData
    });

  } catch (error) {
    next(error);
  }
});

// Login endpoint (Manager)
app.post("/manager-login", async (req, res, next) => {
  try {
    const { username, password } = req.body;
    
    if (!username || !password) {
      return res.status(400).json({ 
        success: false,
        message: "Username and password are required" 
      });
    }

    const manager = await Manager.findOne({ username, password });

    if (!manager) {
      return res.status(401).json({ 
        success: false,
        message: "Invalid credentials" 
      });
    }

    res.json({
      success: true,
      message: "Login successful",
      username: manager.username,
      authData: manager.authData
    });

  } catch (error) {
    next(error);
  }
});

// ===== NFC AUTHENTICATION ROUTE =====

function decryptNFCData(encryptedBase64, aesKeyHex) {
  try {
    const aesKey = Buffer.from(aesKeyHex, 'hex');
    const combined = Buffer.from(encryptedBase64, 'base64');
    const iv = combined.slice(0, 16);
    const encrypted = combined.slice(16);

    const decipher = crypto.createDecipheriv('aes-256-cbc', aesKey, iv);
    decipher.setAutoPadding(true); // Let Node.js handle PKCS7

    let decrypted = decipher.update(encrypted);
    decrypted = Buffer.concat([decrypted, decipher.final()]);

    return decrypted.toString('utf-8');
  } catch (error) {
    console.error('❌ Decryption failed:', error.message);
    return null;
  }
}


// Modified NFC auth endpoint
app.post("/api/nfc-auth", async (req, res, next) => {
  console.log("Request received for NFC Auth", req.body);
  try {
    const { encryptedData, serial, username, isManager } = req.body;
    
    if (!encryptedData || !serial || !username) {
      console.log("❌ Missing required fields");
      return res.status(400).json({ 
        success: false, 
        message: "Missing required fields" 
      });
    }

    const Model = isManager ? Manager : User;
    const account = await Model.findOne({ username });

    if (!account) {
      console.log("❌ User not found");
      return res.status(404).json({ 
        success: false, 
        message: "User not found" 
      });
    }

    // Normalize serial numbers for comparison
    const normalizeSerial = (serial) => serial ? serial.replace(/:/g, "").toUpperCase() : "";
    const normalizedInput = normalizeSerial(serial);
    const normalizedAllowed = normalizeSerial(account.authData.allowedSerial);

    console.log("Input Serial:", normalizedInput);
    console.log("Stored Serial:", normalizedAllowed);

    // Serial number validation
    if (normalizedInput !== normalizedAllowed) {
      console.log("❌ Invalid Serial Number");
      return res.status(403).json({ 
        success: false, 
        message: "Access denied: Invalid NFC device" 
      });
    }

    // Perform decryption
    const decryptedText = decryptNFCData(encryptedData, account.authData.aesKey);

    console.log("🔓 Decrypted NFC Text:", decryptedText);
    console.log("✅ Expected Text:", account.authData.expectedText);

    if (!decryptedText) {
      console.log("❌ Decryption failed");
      return res.status(400).json({ 
        success: false, 
        message: "Decryption failed" 
      });
    }

    // Verify decrypted text matches expected text
    if (decryptedText === account.authData.expectedText) {
      console.log("✅ Access Granted");
      return res.json({ 
        success: true, 
        message: "Access granted",
        isManager: isManager
      });
    } else {
      console.log("❌ Access Denied: Text Mismatch");
      return res.status(403).json({ 
        success: false, 
        message: "Access denied: Invalid NFC data" 
      });
    }

  } catch (err) {
    console.error("🔥 Server Error:", err);
    next(err);
  }
});

// ===== BACKUP CODE ROUTES =====
app.post("/api/verify-backup-code", async (req, res, next) => {
  try {
    const { username, code, isManager } = req.body;
    
    if (!username || !code) {
      return res.status(400).json({ 
        success: false, 
        message: "Username and code are required" 
      });
    }

    const Model = isManager ? Manager : User;
    const account = await Model.findOne({ username });

    if (!account) {
      return res.status(404).json({ 
        success: false, 
        message: "User not found" 
      });
    }

    // Check if code exists in backup codes
    const isValidCode = account.authData.backupCodes.includes(code);

    if (isValidCode) {
      return res.json({ 
        success: true, 
        message: "Backup code verified" 
      });
    } else {
      return res.status(403).json({ 
        success: false, 
        message: "Invalid backup code" 
      });
    }

  } catch (err) {
    next(err);
  }
});

app.post("/api/mark-backup-code-used", async (req, res, next) => {
  try {
    const { username, code, isManager } = req.body;
    
    if (!username || !code) {
      return res.status(400).json({ 
        success: false, 
        message: "Username and code are required" 
      });
    }

    const Model = isManager ? Manager : User;
    const account = await Model.findOne({ username });

    if (!account) {
      return res.status(404).json({ 
        success: false, 
        message: "User not found" 
      });
    }

    // Remove the used backup code
    const updatedBackupCodes = account.authData.backupCodes.filter(c => c !== code);
    
    await Model.updateOne(
      { username },
      { $set: { "authData.backupCodes": updatedBackupCodes } }
    );

    res.json({ 
      success: true, 
      message: "Backup code marked as used" 
    });

  } catch (err) {
    next(err);
  }
});

// ===== SECURITY KEY ROUTES =====
app.post("/api/verify-security-key", async (req, res, next) => {
  try {
    const { username, key, keyType, isManager } = req.body;
    
    if (!username || !key || !keyType) {
      return res.status(400).json({ 
        success: false, 
        message: "Missing required fields" 
      });
    }

    const Model = isManager ? Manager : User;
    const account = await Model.findOne({ username });

    if (!account) {
      return res.status(404).json({ 
        success: false, 
        message: "User not found" 
      });
    }

    // Check the security key
    const isValidKey = account.authData.securityKeys[keyType] === key;

    if (isValidKey) {
      return res.json({ 
        success: true, 
        message: "Security key verified" 
      });
    } else {
      return res.status(403).json({ 
        success: false, 
        message: "Invalid security key" 
      });
    }

  } catch (err) {
    next(err);
  }
});

// ===== AUTHENTICATOR MANAGEMENT ROUTES =====
app.post("/api/activate-authenticator", async (req, res, next) => {
  try {
    const { username, isManager } = req.body;
    
    if (!username) {
      return res.status(400).json({ 
        success: false, 
        message: "Username is required" 
      });
    }

    // In a real application, implement actual activation logic here
    // For now, just return success
    
    res.json({ 
      success: true, 
      message: "Authenticator activated successfully" 
    });

  } catch (err) {
    next(err);
  }
});

app.post("/api/deactivate-authenticator", async (req, res, next) => {
  try {
    const { username, isManager } = req.body;
    
    if (!username) {
      return res.status(400).json({ 
        success: false, 
        message: "Username is required" 
      });
    }

    // In a real application, implement actual deactivation logic here
    // For now, just return success
    
    res.json({ 
      success: true, 
      message: "Authenticator deactivated successfully" 
    });

  } catch (err) {
    next(err);
  }
});

// ALLOGIN OTP CODE START
const otpStore = new Map(); // Using Map instead of object for better performance and methods

// Generate 6-digit OTP
const generateOTP = () => Math.floor(100000 + Math.random() * 900000).toString();

// Route to send OTP
app.post('/send-otp', async (req, res) => {
  const { username, password } = req.body;

  // Input validation
  if (!username || !password) {
    return res.status(400).json({ 
      success: false, 
      message: 'Username and password are required' 
    });
  }

  try {
    const user = await User.findOne({ username }).select('+password +mobileNumber');
    if (!user) {
      return res.status(401).json({ 
        success: false, 
        message: 'Invalid credentials' 
      });
    }

    // Compare passwords (assuming plain text comparison - in production use bcrypt)
    if (user.password !== password) {
      return res.status(401).json({ 
        success: false, 
        message: 'Invalid credentials' 
      });
    }

    // Validate mobile number
    if (!user.mobileNumber) {
      return res.status(400).json({ 
        success: false, 
        message: 'No mobile number registered for this user' 
      });
    }

    const otp = generateOTP();
    const phone = user.mobileNumber;

    // In production, you would actually send the SMS
    if (process.env.NODE_ENV === 'production') {
      const client = require('twilio')(
        process.env.TWILIO_ACCOUNT_SID, 
        process.env.TWILIO_AUTH_TOKEN
      );
      
      await client.messages.create({
        body: `Tetra Techies: Your OTP is ${otp}. Use it to verify your identity. This code is confidential—never share it with anyone.`,
        from: process.env.TWILIO_PHONE_NUMBER,
        to: phone
      });
    } else {
      // In development, just log the OTP
      console.log(`[DEV] OTP for ${phone}: ${otp}`);
    }

    // Store OTP with expiration (5 minutes)
    otpStore.set(phone, {
      otp,
      expiresAt: Date.now() + 300000, // 5 minutes in milliseconds
      attempts: 0 // Track failed attempts
    });

    // Set timeout to auto-clear OTP after expiration
    setTimeout(() => {
      if (otpStore.get(phone)?.otp === otp) {
        otpStore.delete(phone);
      }
    }, 300000);

    console.log(`✅ OTP sent to ${phone}`);
    return res.json({ 
      success: true, 
      message: 'OTP sent successfully' 
    });

  } catch (error) {
    console.error('❌ Error sending OTP:', error);
    return res.status(500).json({ 
      success: false, 
      message: 'Failed to send OTP. Please try again.' 
    });
  }
});

// Route to verify OTP
app.post('/verify-otp', async (req, res) => {
  const { username, otp } = req.body;

  // Input validation
  if (!username || !otp) {
    return res.status(400).json({ 
      valid: false, 
      message: 'Username and OTP are required' 
    });
  }

  try {
    const user = await User.findOne({ username }).select('+mobileNumber');
    if (!user) {
      return res.status(400).json({ 
        valid: false, 
        message: 'User not found' 
      });
    }

    const phone = user.mobileNumber;
    if (!phone) {
      return res.status(400).json({ 
        valid: false, 
        message: 'No mobile number registered for this user' 
      });
    }

    const record = otpStore.get(phone);
    if (!record) {
      return res.status(400).json({ 
        valid: false, 
        message: 'No OTP request found. Please request a new OTP.' 
      });
    }

    // Check attempts
    if (record.attempts >= 3) {
      otpStore.delete(phone);
      return res.status(429).json({ 
        valid: false, 
        message: 'Too many attempts. Please request a new OTP.' 
      });
    }

    // Check expiration
    if (Date.now() > record.expiresAt) {
      otpStore.delete(phone);
      return res.status(400).json({ 
        valid: false, 
        message: 'OTP expired. Please request a new OTP.' 
      });
    }

    // Verify OTP
    if (record.otp !== otp) {
      // Increment failed attempts
      record.attempts += 1;
      otpStore.set(phone, record);
      
      return res.status(400).json({ 
        valid: false, 
        message: 'Invalid OTP',
        attemptsLeft: 3 - record.attempts
      });
    }

    // Successful verification
    otpStore.delete(phone); // OTP is one-time use
    
    return res.json({ 
      valid: true, 
      message: 'OTP verified successfully' 
    });

  } catch (error) {
    console.error('❌ Error verifying OTP:', error);
    return res.status(500).json({ 
      valid: false, 
      message: 'Server error during OTP verification' 
    });
  }
});
// ALLOGIN OTP CODE END

// ====== HELPER: Get Local IP ======
function getLocalIP() {
  try {
    const interfaces = os.networkInterfaces();
    for (let name in interfaces) {
      for (let iface of interfaces[name]) {
        if (iface.family === "IPv4" && !iface.internal) {
          return iface.address;
        }
      }
    }
    return "localhost";
  } catch (err) {
    console.error("Error getting local IP:", err);
    return "localhost";
  }
}

// ====== REGISTER.HTML CODE START ======

const otpMap = new Map();

// Improved username check with error handling
app.post('/api/check-username', async (req, res) => {
  try {
    if (!req.body.username) {
      return res.status(400).json({ error: "Username is required" });
    }
    const user = await User.findOne({ username: req.body.username });
    res.json({ available: !user });
  } catch (err) {
    console.error("Error checking username:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// Improved OTP sending with validation
app.post('/api/send-otp', async (req, res) => {
  try {
    const { mobileNumber } = req.body;
    if (!mobileNumber) {
      return res.status(400).json({ error: "Mobile number is required" });
    }

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    otpMap.set(mobileNumber, otp);

    const client = twilio(process.env.TWILIO_SID, process.env.TWILIO_AUTH_TOKEN);
    await client.messages.create({
      body: `Your OTP is ${otp}`,
      to: mobileNumber,
      from: process.env.TWILIO_PHONE
    });

    res.json({ success: true });
  } catch (err) {
    console.error("Error sending OTP:", err);
    res.status(500).json({ error: "Failed to send OTP" });
  }
});

// Improved OTP verification
app.post('/api/verify-otp', (req, res) => {
  try {
    const { mobileNumber, otp } = req.body;
    if (!mobileNumber || !otp) {
      return res.status(400).json({ error: "Mobile number and OTP are required" });
    }

    const storedOTP = otpMap.get(mobileNumber);
    const isValid = storedOTP === otp;
    
    if (isValid) {
      otpMap.delete(mobileNumber); // Clear OTP after successful verification
    }
    
    res.json({ verified: isValid });
  } catch (err) {
    console.error("Error verifying OTP:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// Improved registration endpoint
app.post('/api/register', async (req, res) => {
  try {
    const { username, email, password, mobileNumber, authData } = req.body;

    // Input validation
    if (!username || !email || !password || !mobileNumber) {
      return res.status(400).json({ error: "All fields are required" });
    }

    if (password.length < 8) {
      return res.status(400).json({ error: "Password must be at least 8 characters" });
    }

    const userData = {
      username,
      email,
      password: password, // Storing plain password
      mobileNumber
    };

    // Add authData if provided
    if (authData) {
      userData.authData = authData;
    }

    const newUser = new User(userData);
    await newUser.save();
    
    res.status(201).json({ 
      message: "User registered successfully",
      user: {
        username: newUser.username,
        email: newUser.email,
        mobileNumber: newUser.mobileNumber,
        hasNFC: !!newUser.authData
      }
    });

  } catch (err) {
    console.error("Registration error:", err);
    
    if (err.code === 11000) {
      const field = Object.keys(err.keyPattern)[0];
      return res.status(400).json({ 
        error: `${field} already exists` 
      });
    }
    
    res.status(500).json({ error: "Registration failed" });
  }
});


// ======= REGISTER.HTML CODE END ======

// ====== AUTH VIA MOBILE START ======
// Replace your current Twilio initialization with this:
const accountSid = process.env.TWILIO_ACCOUNT_SID;
const authToken = process.env.TWILIO_AUTH_TOKEN;

if (!accountSid || !authToken) {
  console.error("❌ Twilio credentials missing! Check your .env file");
  process.exit(1);
}

const twilioClient = require('twilio')(accountSid, authToken, {
  lazyLoading: true // Better performance
});

// Verify Twilio client is working
(async () => {
  try {
    await twilioClient.messages.list({limit: 1});
    console.log("✅ Twilio client initialized successfully");
  } catch (err) {
    console.error("❌ Twilio initialization failed:", err.message);
    process.exit(1);
  }
})();

// In your server.js
app.post('/send-nfc-link', async (req, res) => {
  try {
      const { username, isManager } = req.body;
      
      // Validate input
      if (!username) {
          return res.status(400).json({ 
              success: false,
              message: "Username is required" 
          });
      }

      // Find user
      const Model = isManager ? Manager : User;
      const user = await Model.findOne({ username });
      
      if (!user) {
          return res.status(404).json({ 
              success: false,
              message: "User not found" 
          });
      }

      // Validate mobile number
      const mobileNumber = user.mobileNumber?.trim();
      if (!mobileNumber) {
          return res.status(400).json({ 
              success: false,
              message: "No mobile number registered" 
          });
      }

      // Format number (ensure E.164 format)
      let formattedNumber = mobileNumber;
      if (!mobileNumber.startsWith('+')) {
          formattedNumber = `+91${mobileNumber.replace(/\D/g, '')}`; // Default to India (+91)
      }

      // Generate secure token and link
      const token = crypto.randomBytes(32).toString('hex');
      const roleCode = isManager ? 574940 : 842537; // 2 = manager, 1 = user
      const nfcLink = `${req.protocol}://${req.get('host')}/app.html?username=${encodeURIComponent(username)}&role=${roleCode}&token=${token}`;


      // Verify Twilio client is ready
      if (!twilioClient) {
          throw new Error('Twilio client not initialized');
      }

      // Send SMS
      const message = await twilioClient.messages.create({
          body: `Your NFC Authentication Link: ${nfcLink}`,
          from: process.env.TWILIO_PHONE_NUMBER,
          to: formattedNumber
      });

      console.log(`SMS sent to ${formattedNumber} (SID: ${message.sid})`);
      
      return res.json({ 
          success: true, 
          message: "NFC authentication link sent to your mobile" 
      });

  } catch (error) {
      console.error("SMS Error:", {
          code: error.code,
          message: error.message,
          stack: error.stack
      });

      return res.status(500).json({ 
          success: false,
          message: "Failed to send NFC link",
          error: process.env.NODE_ENV === 'development' ? error.message : undefined
      });
  }
});

app.post('/receive-nfc-data', (req, res) => {
  const { serial, data, username, isManager } = req.body;

  const key = `${isManager}:${username}`;
  const client = nfcClients.get(key);

  if (client) {
    const payload = JSON.stringify({ serial, data, isManager });
    client.write(`event: nfc\ndata: ${payload}\n\n`);
    return res.json({ success: true, message: "Data forwarded to frontend" });
  }

  res.status(404).json({ success: false, message: "No active frontend found for user" });
});




// ====== AUTH VIA MOBILE END ======


// ====== MOBILE AUTH REGISTER START ======

// Replace the existing mobile auth endpoints with these:

// Mobile Auth Sessions Storage
const mobileAuthSessions = new Map();

// Initiate Mobile Authentication
app.post('/api/initiate-mobile-auth', async (req, res) => {
  try {
    const { username, mobileNumber, email } = req.body;

    // Validate input
    if (!username || !mobileNumber || !email) {
      return res.status(400).json({ 
        success: false,
        error: 'All fields are required' 
      });
    }

    // Generate token (valid for 15 minutes)
    const token = crypto.randomBytes(32).toString('hex');
    const expiresAt = Date.now() + 15 * 60 * 1000;

    // Store session
    mobileAuthSessions.set(username, { 
      token, 
      expiresAt,
      mobileNumber
    });

    // Generate authentication link
    const authLink = `${req.protocol}://${req.get('host')}/res-webapp.html?username=${username}&token=${token}`;

    // Send SMS via Twilio
    const message = await twilioClient.messages.create({
      body: `Complete your NFC registration: ${authLink}`,
      from: process.env.TWILIO_PHONE_NUMBER,
      to: mobileNumber
    });

    console.log(`SMS sent to ${mobileNumber} (SID: ${message.sid})`);

    res.json({ 
      success: true,
      message: 'Authentication SMS sent successfully'
    });

  } catch (error) {
    console.error('Mobile auth initiation error:', error);
    res.status(500).json({ 
      success: false,
      error: 'Failed to initiate mobile authentication',
      details: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// Complete Mobile Authentication
// Enhanced Complete Mobile Auth Endpoint
// Enhanced Complete Mobile Auth Endpoint
app.post('/api/complete-mobile-auth', async (req, res) => {
  try {
    const { username, token, authData } = req.body;

    console.log('Received auth completion request:', { username, token, authData });

    // Validate input
    if (!username || !token || !authData) {
      console.log('Missing required fields');
      return res.status(400).json({ 
        success: false,
        error: 'Missing required fields' 
      });
    }

    // Verify token
    const session = mobileAuthSessions.get(username);
    if (!session || session.token !== token) {
      console.log('Invalid or expired token');
      return res.status(401).json({ 
        success: false,
        error: 'Invalid or expired token' 
      });
    }

    if (Date.now() > session.expiresAt) {
      console.log('Token expired');
      return res.status(401).json({ 
        success: false,
        error: 'Token expired' 
      });
    }

    // Convert serial number if needed
    if (authData.allowedSerial && Array.isArray(authData.allowedSerial)) {
      authData.allowedSerial = authData.allowedSerial.join(',');
    }

    // Update user with NFC data
    const updatedUser = await User.findOneAndUpdate(
      { username },
      { $set: { authData } },
      { new: true }
    );

    if (!updatedUser) {
      console.log('User not found');
      return res.status(404).json({
        success: false,
        error: 'User not found'
      });
    }

    // Clear the session
    mobileAuthSessions.delete(username);

    console.log('Mobile authentication completed successfully for:', username);
    res.json({ 
      success: true,
      message: 'Mobile authentication completed successfully'
    });

  } catch (error) {
    console.error('Mobile auth completion error:', error);
    res.status(500).json({ 
      success: false,
      error: 'Failed to complete mobile authentication',
      details: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// Check Auth Status
app.get('/api/check-auth-status', async (req, res) => {
  try {
    const { username } = req.query;
    
    if (!username) {
      return res.status(400).json({ 
        success: false,
        error: 'Username is required' 
      });
    }

    // Check if user has completed NFC registration
    const user = await User.findOne({ username });
    
    if (!user) {
      return res.status(404).json({
        success: false,
        error: 'User not found'
      });
    }

    res.json({ 
      success: true,
      completed: !!user.authData
    });

  } catch (error) {
    console.error('Auth status check error:', error);
    res.status(500).json({ 
      success: false,
      error: 'Failed to check authentication status'
    });
  }
});

// Add this endpoint to verify user exists
app.get('/api/verify-user', async (req, res) => {
  try {
    const { username } = req.query;
    
    let user = await User.findOne({ username });
    if (!user) {
      user = await Manager.findOne({ username });
      if (!user) {
        return res.status(404).json({ exists: false });
      }
    }
    
    res.json({ exists: true });
  } catch (err) {
    res.status(500).json({ error: 'Verification failed' });
  }
});

// ====== MOBILE AUTH REGISTER END ======

// ====== START SERVER ======
const PORT = process.env.PORT || 3010;
const server = app.listen(PORT, "0.0.0.0", () => {
  const localIP = getLocalIP();
  console.log(`\n✅ Server running at:`);
  console.log(`👉 PC:     http://localhost:${PORT}`);
  console.log(`👉 Mobile: http://${localIP}:${PORT}\n`);
});

// Handle unhandled promise rejections
process.on("unhandledRejection", (err) => {
  console.error("Unhandled Rejection:", err);
  server.close(() => process.exit(1));
});

// Handle uncaught exceptions
process.on("uncaughtException", (err) => {
  console.error("Uncaught Exception:", err);
  server.close(() => process.exit(1));
});



