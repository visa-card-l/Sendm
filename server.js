const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const { v4: uuidv4 } = require('uuid');
const rateLimit = require('express-rate-limit');
const { Telegraf } = require('telegraf');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());

// Rate limiting for auth routes
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10,
  message: { error: 'Too many attempts, try again later.' }
});

// In-memory storage (replace with DB in production)
let users = [];
const activeBots = new Map();

const JWT_SECRET = process.env.JWT_SECRET || 'super-secret-jwt-key-change-in-prod';

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
// LAUNCH USER'S BOT
// ========================
function launchUserBot(user) {
  // Stop existing bot if running
  if (activeBots.has(user.id)) {
    activeBots.get(user.id).stop();
    activeBots.delete(user.id);
  }

  const bot = new Telegraf(user.telegramBotToken);

  bot.start(async (ctx) => {
    const payload = ctx.startPayload || '';
    const chatId = ctx.chat.id.toString();

    // Correct payload = user's UUID
    if (payload === user.id) {
      if (user.isTelegramConnected && user.telegramChatId === chatId) {
        return ctx.replyWithHTML('Already connected!');
      }

      user.telegramChatId = chatId;
      user.isTelegramConnected = true;

      await ctx.replyWithHTML(`
<b>Sendm 2FA Connected Successfully!</b>

You will now receive login codes here.

<i>Keep this chat private • Never share your bot</i>
      `);
      console.log(`2FA connected: \( {user.email} → \){chatId}`);
      return;
    }

    // Wrong or no payload
    if (user.isTelegramConnected) {
      await ctx.replyWithHTML(`
<b>Sendm • Already Connected</b>
Account: <code>${user.email}</code>
      `);
    } else {
      await ctx.replyWithHTML('Open the link from the Sendm app to connect your account.');
    }
  });

  bot.command('status', (ctx) => {
    ctx.replyWithHTML(`
<b>Sendm Status</b>
Account: <code>${user.email}</code>
2FA: <b>${user.isTelegramConnected ? 'Active' : 'Not Connected'}</b>
    `);
  });

  bot.catch((err) => console.error(`Bot error [${user.email}]:`, err));
  bot.launch();
  activeBots.set(user.id, bot);
  console.log(`Bot launched for \( {user.email} @ \){bot.botInfo?.username}`);
}

// ========================
// ROUTES
// ========================

app.post('/api/auth/register', authLimiter, async (req, res) => {
  try {
    const { fullName, email, password } = req.body;
    if (!fullName || !email || !password)
      return res.status(400).json({ error: 'All fields required' });
    if (!isValidEmail(email))
      return res.status(400).json({ error: 'Invalid email' });
    if (password.length < 6)
      return res.status(400).json({ error: 'Password too short' });

    if (users.find(u => u.email === email.toLowerCase())) {
      return res.status(409).json({ error: 'Email already exists' });
    }

    const hashed = await bcrypt.hash(password, 12);
    const newUser = {
      id: uuidv4(),
      fullName,
      email: email.toLowerCase(),
      password: hashed,
      createdAt: new Date().toISOString(),
      telegramBotToken: null,
      telegramChatId: null,
      isTelegramConnected: false
    };

    users.push(newUser);

    const token = jwt.sign(
      { userId: newUser.id, email: newUser.email },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.status(201).json({
      success: true,
      token,
      user: {
        id: newUser.id,
        fullName,
        email: newUser.email,
        isTelegramConnected: false
      }
    });
  } catch (err) {
    console.error('Register error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/auth/login', authLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = users.find(u => u.email === email.toLowerCase());

    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const token = jwt.sign(
      { userId: user.id, email: user.email },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

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

// CORRECT DEEP LINK — THIS IS THE FIXED ONE
app.post('/api/auth/connect-telegram', authenticateToken, async (req, res) => {
  const { botToken } = req.body;
  if (!botToken || typeof botToken !== 'string') {
    return res.status(400).json({ error: 'Bot token required' });
  }

  const token = botToken.trim();

  try {
    const response = await fetch(`https://api.telegram.org/bot${token}/getMe`);
    const data = await response.json();

    if (!response.ok || !data.ok || !data.result?.username) {
      return res.status(400).json({ error: 'Invalid bot token' });
    }

    const botUsername = data.result.username;

    const user = users.find(u => u.id === req.user.userId);
    if (!user) return res.status(404).json({ error: 'User not found' });

    user.telegramBotToken = token;
    user.isTelegramConnected = false;
    user.telegramChatId = null;

    // Restart bot with new token
    launchUserBot(user);

    // THIS IS NOW 100% CORRECT
    const startLink = `https://t.me/\( {botUsername}?start= \){user.id}`;

    res.json({
      success: true,
      message: 'Tap to connect',
      botUsername: `@${botUsername}`,
      startLink
    });

    console.log(`Deep link generated → \( {user.email}: \){startLink}`);
  } catch (err) {
    console.error('Telegram connect error:', err);
    res.status(500).json({ error: 'Failed to connect bot' });
  }
});

app.get('/api/auth/bot-status', authenticateToken, (req, res) => {
  const user = users.find(u => u.id === req.user.userId);
  if (!user) return res.status(404).json({ error: 'User not found' });

  res.json({
    activated: user.isTelegramConnected,
    chatId: user.telegramChatId || null
  });
});

// Start server
app.listen(PORT, () => {
  console.log(`Sendm 2FA Server running on http://localhost:${PORT}`);
});

module.exports = app;
