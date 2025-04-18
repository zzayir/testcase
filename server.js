const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const mongoose = require('mongoose');
const twilio = require('twilio');
const bcrypt = require('bcryptjs');
require('dotenv').config();
const app = express();

// Configure CORS
app.use(cors({
  origin: process.env.ALLOWED_ORIGIN || 'http://localhost:3000',
  methods: ['GET', 'POST'],
  allowedHeaders: ['Content-Type']
}));

app.use(bodyParser.json());
const path = require('path');
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.json());

const mongoURI = "mongodb+srv://zzayir21:rifah5657@cluster21.7c8bhzd.mongodb.net/loginDB?retryWrites=true&w=majority";

// Connect to MongoDB with better error handling and connection options
mongoose.connect(mongoURI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  connectTimeoutMS: 5000,
  socketTimeoutMS: 30000
})
.then(() => console.log('MongoDB connected successfully'))
.catch(err => {
  console.error('MongoDB connection error:', err);
  process.exit(1);
});

// Update the userSchema to make authData optional
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  mobileNumber: { type: String, required: true, unique: true },
  authData: {
    aesKey: { type: String },
    expectedText: { type: String },
    allowedSerial: { type: String },
    encryptedText: { type: String }
  }
}, { timestamps: true });

const User = mongoose.model('User', userSchema);

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

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = new User({
      username,
      email,
      password: hashedPassword,
      mobileNumber,
      authData: authData || null
    });

    await newUser.save();
    
    res.status(201).json({ 
      message: "User registered successfully",
      user: {
        username: newUser.username,
        email: newUser.email,
        mobileNumber: newUser.mobileNumber
      }
    });

  } catch (err) {
    console.error("Registration error:", err);
    
    if (err.code === 11000) {
      // MongoDB duplicate key error
      const field = Object.keys(err.keyPattern)[0];
      return res.status(400).json({ 
        error: `${field} already exists` 
      });
    }
    
    res.status(500).json({ error: "Registration failed" });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
