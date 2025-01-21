const jwt = require('jsonwebtoken');
const User = require('../models/User');

// In-memory rate limiting store
const rateLimitStore = new Map();
const RATE_LIMIT_WINDOW_MS = 15 * 60 * 1000; // 15 minutes
const MAX_REQUESTS_PER_WINDOW = 10; // Maximum requests per token per window

module.exports = async function (req, res, next) {
  const token = req.header('Authorization');
  if (!token) {
    return res.status(401).send('Access denied');
  }

  try {
    const jwtToken = token.split(' ')[1]; // Extract the token
    const decoded = jwt.verify(jwtToken, process.env.JWT_SECRET);
    req.user = decoded;

    // Rate limiting logic
    const now = Date.now();
    const userId = req.user.userId;

    // Check and update rate limiting data
    const userRequests = rateLimitStore.get(userId) || [];
    const filteredRequests = userRequests.filter(
      (timestamp) => now - timestamp < RATE_LIMIT_WINDOW_MS
    );

    // Update the store
    filteredRequests.push(now);
    rateLimitStore.set(userId, filteredRequests);

    // Check if the user has exceeded the limit
    if (filteredRequests.length > MAX_REQUESTS_PER_WINDOW) {
      return res.status(429).send('Too many requests. Please try again later.');
    }

    // Validate the user from the database
    const user = await User.findById(userId);
    if (!user) {
      return res.status(401).send('Access denied');
    }

    req.user.role = user.role; // Assuming role is a field in your user model
    next();
  } catch (error) {
    res.status(400).send('Invalid token');
  }
};

/*
module.exports = async function (req, res, next) {
  try {
    // Get token from Authorization header
    const authHeader = req.header('Authorization');
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ message: 'Access denied. No token provided.' });
    }

    // Extract token
    const token = authHeader.split(' ')[1];

    // Verify token
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded; // Contains userId & role if stored in token

    // Fetch user to validate OTP
    const user = await User.findById(req.user.userId);
    if (!user) {
      return res.status(401).json({ message: 'User not found' });
    }

    // OTP verification (assuming OTP is stored in user model and expires after a short time)
    if (!user.otp || user.otp !== req.header('X-OTP')) {
      return res.status(403).json({ message: 'Invalid or expired OTP' });
    }

    next();
  } catch (error) {
    res.status(400).json({ message: 'Invalid token', error: error.message });
  }
};
*/ 
