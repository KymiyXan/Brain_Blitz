const mongoose = require('mongoose');
const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const User = require('../models/User');
const auth = require('../middleware/auth');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const otpExpiry = process.env.OTP_EXPIRY * 60 * 1000;

async function sendOTPToUser(userId, otp) {
  const user = await User.findById(userId);
  if (!user || !user.email) throw new Error('User email not found');

  const transporter = nodemailer.createTransport({
    service: 'Gmail',
    auth: {
      user: process.env.EMAIL_USER, // Your email
      pass: process.env.EMAIL_PASS  // Your email password or app password
    }
  });

  const mailOptions = {
    from: process.env.EMAIL_USER,
    to: user.email,
    subject: 'Your OTP Code',
    text: `Your OTP code is: ${otp}. It expires in 5 minutes.`
  };

  await transporter.sendMail(mailOptions);
};

async function generateAndSendOTP(userId) {
  const otp = crypto.randomInt(100000, 999999).toString(); // Generates a 6-digit OTP
  const otpExpires = Date.now() + 5 * 60 * 1000; // OTP valid for 5 minutes

  // Store OTP in the database (assuming your User model has `otp` and `otpExpires`)
  await User.findByIdAndUpdate(userId, { otp, otpExpires });

  // Send OTP to user (Example: Send via email or SMS)
  await sendOTPToUser(userId, otp);

  return otp;
};

const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  username: { type: String, unique: true, required: true },
  email: { type: String, unique: true, required: true },
  password: { type: String, required: true },
  age: { type: Number, required: true },
  friends: [{ type: mongoose.Schema.Types.ObjectId, ref: '../models/User' }]
});

module.exports = mongoose.model('../models/User', userSchema);

// Logger middleware
const logAction = (action, user) => {
  const timestamp = new Date().toISOString();
  console.log(`[${timestamp}] ${action} - User: ${user}`);
};

const registerLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10, // Limit each IP to 10 requests per window
  message: 'Too many registration attempts, please try again later'
});
/*
// Register
router.post('/register', registerLimiter, async (req, res) => {
  const { name, username, email, password, age } = req.body;
  try {
    // Input validation
    if (!name || !username || !email || !password || !age) {
      logAction('Registration failed - missing fields', email || 'Unknown');
      return res.status(400).send('All fields are required');
    }

    // Normalize input
    const normalizedEmail = email.toLowerCase();
    const normalizedUsername = username.toLowerCase();

    // Check if the email or username already exists
    const existingUser = await User.findOne({
      $or: [{ email: normalizedEmail }, { username: normalizedUsername }]
    });
    if (existingUser) {
      logAction('Registration failed - email or username already exists', normalizedEmail);
      return res.status(400).send('Email or username already in use');
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create and save the user
    const user = new User({
      name,
      username: normalizedUsername,
      email: normalizedEmail,
      password: hashedPassword,
      age
    });

    await user.save();
    logAction('Registered', normalizedUsername);
    res.status(201).send('User registered successfully');
  } catch (error) {
    // Handle duplicate key error (MongoDB error code 11000)
    if (error.code === 11000) {
      logAction('Registration failed - duplicate key', email || 'Unknown');
      return res.status(400).send('Email or username already in use');
    }
    logAction('Registration failed - server error', email || 'Unknown');
    res.status(500).send('Server error');
  }
});
*/

router.get('/', (req, res) => {
  res.render('../views/index.ejs');
});

router.get('/register', (req, res) => {
  res.render('../views/register.ejs');
});

// Register
router.post('/register', registerLimiter, async (req, res) => {
  const { name, username, email, password, age } = req.body;
  try {
    if (!name || !username || !email || !password || !age) {
      logAction('Registration failed - missing fields', email || 'Unknown');
      return res.status(400).send('All fields are required');
    }

    const normalizedEmail = email.toLowerCase();
    const normalizedUsername = username.toLowerCase();

    // Check if email or username already exists
    const existingUser = await User.findOne({
      $or: [{ email: normalizedEmail }, { username: normalizedUsername }]
    });
    if (existingUser) {
      logAction('Registration failed - email or username already exists', normalizedEmail);
      return res.status(400).send('Email or username already in use');
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create and save the user
    const user = new User({
      name,
      username: normalizedUsername,
      email: normalizedEmail,
      password: hashedPassword,
      age
    });

    await user.save();

    // Generate JWT token
    const token = jwt.sign(
      { userId: user._id, username: user.username },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );

    logAction('Registered', normalizedUsername);
    res.status(201).json({ message: 'User registered successfully', token });
  } catch (error) {
    if (error.code === 11000) {
      logAction('Registration failed - duplicate key', email || 'Unknown');
      return res.status(400).send('Email or username already in use');
    }
    logAction('Registration failed - server error', email || 'Unknown');
    res.status(500).send('Server error');
  }
});


router.get('/login', (req, res) => {
  res.render('../views/login.ejs');
});

/*
// Login
router.post('/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await User.findOne({ email: email.toLowerCase() });
    if (!user) {
      logAction('Login failed - invalid email', email);
      return res.status(400).send('Invalid credentials');
    }
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      logAction('Login failed - invalid password', email);
      return res.status(400).send('Invalid credentials');
    }
    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });
    logAction('Logged in', email);
    res.json({ token });
  } catch (error) {
    logAction('Login failed - server error', email);
    res.status(500).send('Server error');
  }
});
*/
// Login
router.post('/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await User.findOne({ email: email.toLowerCase() });
    if (!user) {
      logAction('Login failed - invalid email', email);
      return res.status(400).send('Invalid credentials');
    }
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      logAction('Login failed - invalid password', email);
      return res.status(400).send('Invalid credentials');
    }

    // Generate JWT token
    const token = jwt.sign(
      { userId: user._id, username: user.username },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );

    logAction('Logged in', email);
    res.json({ message: 'Login successful', token });
  } catch (error) {
    logAction('Login failed - server error', email);
    res.status(500).send('Server error');
  }
});

// Forget Password
router.post('/forgot-password', async (req, res) => {
  const { email, newPassword } = req.body;
  try {
    const user = await User.findOne({ email: email.toLowerCase() });
    if (!user) {
      logAction('Password reset failed - user not found', email);
      return res.status(400).send('User not found');
    }
    user.password = await bcrypt.hash(newPassword, 10);
    await user.save();
    logAction('Password reset', email);
    res.send('Password updated');
  } catch (error) {
    logAction('Password reset failed - server error', email);
    res.status(500).send('Server error');
  }
});

// View Profile (Public)
router.get('/profile/:username', async (req, res) => {
  try {
    const user = await User.findOne({ username: req.params.username.toLowerCase() }).select('-password').populate('friends', 'username');
    if (!user) {
      logAction('Profile view failed - user not found', req.params.username);
      return res.status(404).send('User not found');
    }

    // Calculate total score and total questions right
    const totalScore = user.scores.reduce((acc, scoreEntry) => acc + scoreEntry.score, 0);
    const totalQuestionsRight = user.scores.reduce((acc, scoreEntry) => acc + scoreEntry.questions_right, 0);

    const userProfile = {
      ...user.toObject(),
      totalScore,
      totalQuestionsRight,
      friendsCount: user.friends.length,
      friends: user.friends.map(friend => friend.username)
    };

    logAction('Viewed profile', req.params.username);
    res.json(userProfile);
  } catch (error) {
    logAction('Profile view failed - server error', req.params.username);
    res.status(500).send('Server error');
  }
});

// Add Friend (Public)
router.post('/add-friend', async (req, res) => {
  const { username, friendUsername } = req.body;
  try {
    const user = await User.findOne({ username: username.toLowerCase() });
    const friend = await User.findOne({ username: friendUsername.toLowerCase() });

    if (!friend) {
      logAction('Add friend failed - friend not found', username);
      return res.status(404).send('Friend not found');
    }

    if (user.friends.includes(friend._id)) {
      return res.status(400).send('Friend already added');
    }

    user.friends.push(friend._id);
    await user.save();

    logAction('Added friend', friendUsername);
    res.send('Friend added');
  } catch (error) {
    logAction('Add friend failed - server error', username);
    res.status(500).send('Server error');
  }
});

// Remove Friend (Auth required)
router.post('/remove-friend', auth, async (req, res) => {
  const { friendUsername } = req.body;
  try {
    const user = await User.findById(req.user.userId);
    const friend = await User.findOne({ username: friendUsername.toLowerCase() });

    if (!friend) {
      logAction('Remove friend failed - friend not found', req.user.userId);
      return res.status(404).send('Friend not found');
    }

    user.friends = user.friends.filter(friendId => friendId.toString() !== friend._id.toString());
    await user.save();

    logAction('Removed friend', friendUsername);
    res.send('Friend removed');
  } catch (error) {
    logAction('Remove friend failed - server error', req.user.userId);
    res.status(500).send('Server error');
  }
});

// View Friends' Scores (Public)
// router.get('/friends-scores/:username', async (req, res) => {
//   try {
//     const user = await User.findOne({ username: req.params.username.toLowerCase() }).populate('friends', 'username scores');
//     if (!user) {
//       logAction('View friends scores failed - user not found', req.params.username);
//       return res.status(404).send('User not found');
//     }

//     const friendsScores = user.friends.map(friend => ({
//       username: friend.username,
//       scores: friend.scores.map(score => ({
//         category: score.category,
//         score: score.score,
//         questions_right: score.questions_right
//       }))
//     }));

//     res.json(friendsScores);
//   } catch (error) {
//     logAction('View friends scores failed - server error', req.params.username);
//     res.status(500).send('Server error');
//   }
// });

// Logout (No token required)
router.post('/logout', (req, res) => {
  logAction('Logged out', 'Anonymous');
  res.send('User logged out');
});

// Update User (Auth required)
router.put('/update', auth, async (req, res) => {
  const { name, username, email } = req.body;
  try {
    const user = await User.findById(req.user.userId);
    if (!user) {
      logAction('Update failed - user not found', req.user.userId);
      return res.status(404).send('User not found');
    }

    if (name) user.name = name;
    if (username) user.username = username.toLowerCase();
    if (email) user.email = email.toLowerCase();

    await user.save();
    logAction('Updated profile', req.user.userId);
    res.send('User updated');
  } catch (error) {
    logAction('Update failed - server error', req.user.userId);
    res.status(500).send('Server error');
  }
});

// Delete User (Admin required)
router.delete('/delete/:userId', auth, async (req, res) => {
  if (req.user.role !== 'admin') {
    logAction('Delete failed - insufficient permissions', req.user.userId);
    return res.status(403).send('Access denied');
  }

  const { userId } = req.params;
  try {
    const user = await User.findByIdAndDelete(userId);
    if (!user) {
      logAction('Delete failed - user not found', userId);
      return res.status(404).send('User not found');
    }
    logAction('Deleted user', userId);
    res.send('User deleted');
  } catch (error) {
    logAction('Delete failed - server error', userId);
    res.status(500).send('Server error');
  }
});

// Delete Own Account (Auth required)
router.delete('/delete', auth, async (req, res) => {
  try {
    const user = await User.findByIdAndDelete(req.user.userId);
    if (!user) {
      logAction('Delete own account failed - user not found', req.user.userId);
      return res.status(404).send('User not found');
    }
    logAction('Deleted own account', req.user.userId);
    res.send('Account deleted');
  } catch (error) {
    logAction('Delete own account failed - server error', req.user.userId);
    res.status(500).send('Server error');
  }
});

module.exports = router;
