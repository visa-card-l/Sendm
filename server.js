const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const { v4: uuidv4 } = require('uuid');
const rateLimit = require('express-rate-limit');
const { Telegraf } = require('telegraf');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10,
  message: { error: 'Too many attempts, try again later.' }
});

// In-memory storage
let users = [];
let resetCodes = new Map(); // email → { code, expiresAt }
const activeBots = new Map(); // userId → bot instance

// Your JWT secret (in production use process.env.JWT_SECRET)
const JWT_SECRET = process.env.JWT_SECRET || 'pX9kL2mN7qR4tV8wE3zA6bC9dF1gH5jJ0nP2sT5uY8iO3lK6mN9pQ2rE5tW8xZ';

const isValidEmail = (email) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);

// ========================
// AUTHENTICATION MIDDLEWARE (MOVED UP HERE!
// ========================
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers.authorization;
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) return res.status(401).json({ error: 'Access token required' });

  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) return res.status(403).json({ error: 'Invalid or expired token' });
    req.user = decoded; // { userId, email }
    next();
  });
};

// ========================
// TELEGRAM BOT HELPERS
// ========================
function launchUserBot(user) {
  if (!user.telegramBotToken || activeBots.has(user.id)) return;

  const bot = new Telegraf(user.telegramBotToken);

  bot.start(async (ctx) => {
    const chatId = ctx.chat.id.toString();
    user.telegramChatId = chatId;
    user.isTelegramConnected = true;

    await ctx.replyWithHTML(`
<b>Sendm 2FA Activated!</b>

You will now receive password reset codes here.
<i>Never share your bot token with anyone.</i>
    `);

    console.log(`Telegram 2FA activated for ${user.email}`);
  });

  bot.command('status', (ctx) => {
    ctx.replyWithHTML(`
<b>Sendm Status</b>
Account: <code>${user.email}</code>
2FA: <b>${user.isTelegramConnected ? 'Active' : 'Not connected'}</b>
    `);
  });

  bot.launch();
  activeBots.set(user.id, bot);
  console.log(`Bot launched for ${user.email}`);
}

// ========================
// ROUTES
// ========================

app.post('/api/auth/register', authLimiter, async (req, res) => {
  try {
    const { fullName, email, password } = req.body;
    if (!fullName || !email || !password) return res.status(400).json({ error: 'All fields required' });
    if (!isValidEmail(email)) return res.status(400).json({ error: 'Invalid email format' });
    if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });

    if (users.find(u => u.email === email.toLowerCase())) {
      return res.status(409).json({ error: 'Email already registered' });
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

    const token = jwt.sign(
      { userId: newUser.id, email: newUser.email },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.status(201).json({
      success: true,
      message: 'Account created successfully',
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
      return res.status(401).json({ error: 'Invalid email or password' });
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

app.post('/api/auth/connect-telegram', authenticateToken, async (req, res) => {
  const { botToken } = req.body;
  const user = users.find(u => u.id === req.user.userId);

  if (!botToken) return res.status(400).json({ error: 'Bot token is required' });

  try {
    const testBot = new Telegraf(botToken);
    const me = await testBot.telegram.getMe();
    testBot.stop();

    user.telegramBotToken = botToken;
    user.isTelegramConnected = false; // becomes true after /start

    launchUserBot(user);

    res.json({
      success: true,
      message: 'Bot connected! Open @"${me.username}" and press /start to activate 2FA.',
      botUsername: `@${me.username}`
    });
  } catch (err) {
    console.error('Invalid bot token:', err.message);
    res.status(400).json({ error: 'Invalid bot token. Create one with @BotFather' });
  }
});

app.post('/api/auth/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;
    if (!isValidEmail(email)) return res.status(400).json({ error: 'Valid email required' });

    const user = users.find(u => u.email === email.toLowerCase());
    if (!user) return res.status(404).json({ error: 'No account found' });

    if (!user.telegramBotToken || !user.telegramChatId) {
      return res.status(400).json({
        error: 'Telegram 2FA not connected',
        message: 'Connect your bot in the dashboard first'
      });
    }

    const code = Math.floor(100000 + Math.random() * 900000).toString();
    const expiresAt = Date.now() + 10 * 60 * 1000; // 10 min
    resetCodes.set(user.email, { code, expiresAt });

    const bot = activeBots.get(user.id);
    if (bot) {
      await bot.telegram.sendMessage(user.telegramChatId, `
*Sendm Password Reset Code*

Your code: *${code}*

Valid for 10 minutes.
      `.trim(), { parse_mode: 'Markdown' });
    }

    console.log(`Reset code sent to \( {user.email}: \){code}`);
    res.json({ success: true, message: 'Check your Telegram bot for the code' });
  } catch (err) {
    console.error('Forgot password error:', err);
    res.status(500).json({ error: 'Failed to send code' });
  }
});

app.post('/api/auth/reset-password', async (req, res) => {
  const { email, code, newPassword } = req.body;

  const stored = resetCodes.get(email.toLowerCase());
  if (!stored || stored.expiresAt < Date.now() || stored.code !== code) {
    return res.status(400).json({ error: 'Invalid or expired code' });
  }

  const user = users.find(u => u.email === email.toLowerCase());
  if (!user) return res.status(404).json({ error: 'User not found' });

  user.password = await bcrypt.hash(newPassword, 12);
  resetCodes.delete(email.toLowerCase());

  res.json({ success: true, message: 'Password reset successful' });
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

// ========================
// START SERVER
// ========================
app.listen(PORT, '0.0.0.0', () => {
  console.log(`Sendm Auth Backend running on port ${PORT}`);
  console.log(`URL: https://your-app.onrender.com`);
});

module.exports = app;
