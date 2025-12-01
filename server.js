const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const { v4: uuidv4 } = require('uuid');
const rateLimit = require('express-rate-limit');
const { Telegraf } = require('telegraf');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());

// Rate limiter for auth routes
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10,
  message: { error: 'Too many attempts, try again later.' }
});

// In-memory storage (use DB in production)
let users = [];
let resetCodes = new Map(); // not used now, but reserved
const activeBots = new Map();

// One-time activation nonces: nonce → userId (expires in 10 min)
const ACTIVATION_NONCES = new Map();

// JWT Secret (use environment variable in production)
const JWT_SECRET = process.env.JWT_SECRET || 'pX9kL2mN7qR4tV8wE3zA6bC9dF1gH5jJ0nP2sT5uY8iO3lK6mN9pQ2rE5tW8xZ';

const isValidEmail = (email) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);

// ========================
// AUTH MIDDLEWARE
// ========================
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers.authorization;
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) return res.status(401).json({ error: 'Access token required' });

  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) return res.status(403).json({ error: 'Invalid or expired token' });
    req.user = decoded;
    next();
  });
};

// ========================
// LAUNCH USER BOT WITH NONCE SUPPORT
// ========================
function launchUserBot(user, activationNonce = null) {
  // Stop existing bot if running (prevents duplicates)
  if (activeBots.has(user.id)) {
    activeBots.get(user.id).stop();
    activeBots.delete(user.id);
  }

  if (!user.telegramBotToken) return;

  const bot = new Telegraf(user.telegramBotToken);

  bot.start(async (ctx) => {
    const payload = ctx.startPayload || '';
    const chatId = ctx.chat.id.toString();

    let isValidActivation = false;

    // Activation via secure deep link
    if (activationNonce && payload === `activate_${activationNonce}`) {
      if (ACTIVATION_NONCES.get(activationNonce) === user.id) {
        ACTIVATION_NONCES.delete(activationNonce);
        isValidActivation = true;
      }
    }

    // Allow manual /start if already connected
    if (user.isTelegramConnected) {
      isValidActivation = true;
    }

    if (isValidActivation && !user.isTelegramConnected) {
      user.telegramChatId = chatId;
      user.isTelegramConnected = true;

      await ctx.replyWithHTML(`
<b>Sendm 2FA Activated Successfully!</b>

Account: <code>${user.email}</code>
You will now receive password reset codes here.

<i>Keep this chat open • Never share your bot token</i>
      `);

      console.log(`2FA activated: \( {user.email} | Chat ID: \){chatId}`);
    } else if (user.isTelegramConnected && chatId === user.telegramChatId) {
      await ctx.replyWithHTML(`
<b>Sendm • Already Active</b>

Your 2FA is connected and ready.
Use /status to check connection.
      `);
    } else {
      await ctx.replyWithHTML(`
<b>Invalid or expired activation link</b>

Please generate a new link from your Sendm dashboard.
      `);
    }
  });

  bot.command('status', (ctx) => {
    if (ctx.chat.id.toString() !== user.telegramChatId) {
      return ctx.reply('This bot is linked to a different account.');
    }

    ctx.replyWithHTML(`
<b>Sendm Status</b>
Account: <code>${user.email}</code>
2FA Status: <b>${user.isTelegramConnected ? 'Active • Connected' : 'Not Connected'}</b>
Chat ID: <code>${user.telegramChatId || '—'}</code>
    `);
  });

  // Launch bot (polling — works great on Render, Heroku, etc.)
  bot.launch();
  activeBots.set(user.id, bot);

  console.log(`Bot launched for \( {user.email} (@ \){user.telegramBotToken.split(':')[0]}...)`);
}

// ========================
// ROUTES
// ========================

// Register
app.post('/api/auth/register', authLimiter, async (req, res) => {
  try {
    const { fullName, email, password } = req.body;
    if (!fullName || !email || !password) return res.status(400).json({ error: 'All fields required' });
    if (!isValidEmail(email)) return res.status(400).json({ error: 'Invalid email' });
    if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });

    if (users.find(u => u.email === email.toLowerCase())) {
      return res.status(409).json({ error: 'Email already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 12);
    const newUser = {
      id: uuidv4(),
      fullName,
      email: email.toLowerCase(),
      password: hashedPassword,
      createdAt: new Date().toISOString(),
      telegramBotToken: null,
      telegramChatId: null,
      isTelegramConnected: false
    };

    users.push(newUser);

    const token = jwt.sign({ userId: newUser.id, email: newUser.email }, JWT_SECRET, { expiresIn: '7d' });

    res.status(201).json({
      success: true,
      message: 'Account created successfully!',
      token,
      user: { id: newUser.id, fullName, email: newUser.email, isTelegramConnected: false }
    });
  } catch (err) {
    console.error('Register error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Login
app.post('/api/auth/login', authLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = users.find(u => u.email === email.toLowerCase());

    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    const token = jwt.sign({ userId: user.id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });

    res.json({
      success: true,
      token,
      user: {
        id: user.id,
        fullName: user.fullName,
        email: user.email,
        isTelegramConnected: user.isTelegramConnected
      }
    });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Get current user
app.get('/api/auth/me', authenticateToken, (req, res) => {
  const user = users.find(u => u.id === req.user.userId);
  if (!user) return res.status(404).json({ error: 'User not found' });

  res.json({
    user: {
      id: user.id,
      fullName: user.fullName,
      email: user.email,
      isTelegramConnected: user.isTelegramConnected
    }
  });
});

// CONNECT TELEGRAM BOT + RETURN ACTIVATION LINK
app.post('/api/auth/connect-telegram', authenticateToken, async (req, res) => {
  const { botToken } = req.body;

  if (!botToken || typeof botToken !== 'string') {
    return res.status(400).json({ error: 'Bot token is required' });
  }

  const token = botToken.trim();

  try {
    const response = await fetch(`https://api.telegram.org/bot${token}/getMe`);
    if (!response.ok) throw new Error('Invalid response');
    const data = await response.json();

    if (!data.ok || !data.result?.is_bot) {
      return res.status(400).json({ error: 'Invalid bot token. Create a bot via @BotFather' });
    }

    const botUsername = data.result.username;
    const user = users.find(u => u.id === req.user.userId);
    if (!user) return res.status(404).json({ error: 'User not found' });

    // Stop any previous bot instance
    if (activeBots.has(user.id)) {
      activeBots.get(user.id).stop();
      activeBots.delete(user.id);
    }

    // Save token, reset connection
    user.telegramBotToken = token;
    user.isTelegramConnected = false;
    user.telegramChatId = null;

    // Generate one-time secure nonce
    const nonce = crypto.randomBytes(20).toString('hex');
    ACTIVATION_NONCES.set(nonce, user.id);

    // Expire nonce after 10 minutes
    setTimeout(() => ACTIVATION_NONCES.delete(nonce), 10 * 60 * 1000);

    // Launch bot with activation support
    launchUserBot(user, nonce);

    // CORRECT & WORKING deep link
    const startLink = `https://t.me/\( {botUsername}?start=activate_ \){nonce}`;

    console.log(`Activation link generated → \( {user.email} → https://t.me/ \){botUsername}`);

    res.json({
      success: true,
      message: 'Bot connected! Click the link below to activate 2FA',
      botUsername: `@${botUsername}`,
      startLink,
      instructions: 'Tap the link → Press "START" → Your account will be activated instantly'
    });

  } catch (err) {
    console.error('Bot connection failed:', err.message);
    res.status(500).json({ error: 'Failed to connect bot. Check token and try again.' });
  }
});

// Check activation status (for frontend polling)
app.get('/api/auth/bot-status', authenticateToken, (req, res) => {
  const user = users.find(u => u.id === req.user.userId);
  if (!user) return res.status(404).json({ error: 'User not found' });

  res.json({
    activated: user.isTelegramConnected === true,
    chatId: user.telegramChatId || null
  });
});

// Optional: Disconnect Telegram (extra feature)
app.post('/api/auth/disconnect-telegram', authenticateToken, (req, res) => {
  const user = users.find(u => u.id === req.user.userId);
  if (!user) return res.status(404).json({ error: 'User not found' });

  if (activeBots.has(user.id)) {
    activeBots.get(user.id).stop();
    activeBots.delete(user.id);
  }

  user.telegramBotToken = null;
  user.telegramChatId = null;
  user.isTelegramConnected = false;

  res.json({ success: true, message: 'Telegram disconnected successfully' });
});

// Start server
app.listen(PORT, '0.0.0.0', () => {
  console.log(`Sendm 2FA Backend Running on port ${PORT}`);
  console.log(`https://sendm.onrender.com`);
});

module.exports = app;
