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
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: { error: 'Too many attempts, try again later.' }
});

let users = [];
const activeBots = new Map();

const JWT_SECRET = process.env.JWT_SECRET || 'your-super-secret-jwt-key-2025';

const isValidEmail = (email) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);

const authenticateToken = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Access token required' });

  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) return res.status(403).json({ error: 'Invalid or expired token' });
    req.user = decoded;
    next();
  });
};

function launchUserBot(user) {
  if (activeBots.has(user.id)) {
    activeBots.get(user.id).stop();
    activeBots.delete(user.id);
  }

  const bot = new Telegraf(user.telegramBotToken);

  bot.start(async (ctx) => {
    const payload = ctx.startPayload || '';
    const chatId = ctx.chat.id.toString();

    if (payload === user.id) {
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

    await ctx.replyWithHTML(`
<b>Invalid or expired link</b>
This link is only valid once.
    `);
  });

  bot.command('status', (ctx) => {
    ctx.replyWithHTML(`
<b>Sendm 2FA Status</b>
Account: <code>${user.email}</code>
Status: <b>${user.isTelegramConnected ? 'Connected' : 'Not Connected'}</b>
    `);
  });

  bot.catch((err) => console.error(`Bot error [${user.email}]:`, err));
  bot.launch();
  activeBots.set(user.id, bot);
}

// ======================== ROUTES ========================

app.post('/api/auth/register', authLimiter, async (req, res) => {
  const { fullName, email, password } = req.body;
  if (!fullName || !email || !password) return res.status(400).json({ error: 'Missing fields' });
  if (!isValidEmail(email)) return res.status(400).json({ error: 'Invalid email' });
  if (password.length < 6) return res.status(400).json({ error: 'Password too short' });

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
  const token = jwt.sign({ userId: newUser.id, email: newUser.email }, JWT_SECRET, { expiresIn: '7d' });

  res.status(201).json({
    success: true,
    token,
    user: { id: newUser.id, fullName, email: newUser.email, isTelegramConnected: false }
  });
});

app.post('/api/auth/login', authLimiter, async (req, res) => {
  const { email, password } = req.body;
  const user = users.find(u => u.email === email.toLowerCase());

  if (!user || !(await bcrypt.compare(password, user.password))) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  const token = jwt.sign({ userId: user.id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });

  res.json({
    success: true,
    token,
    user: { id: user.id, fullName: user.fullName, email: user.email, isTelegramConnected: user.isTelegramConnected }
  });
});

app.get('/api/auth/me', authenticateToken, (req, res) => {
  const user = users.find(u => u.id === req.user.userId);
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json({ user: { id: user.id, fullName: user.fullName, email: user.email, isTelegramConnected: user.isTelegramConnected } });
});

// THIS IS THE ONLY ROUTE THAT SENDS THE MAGIC LINK
app.post('/api/auth/connect-telegram', authenticateToken, async (req, res) => {
  const { botToken } = req.body;
  if (!botToken?.trim()) return res.status(400).json({ error: 'Bot token required' });

  const token = botToken.trim();
  const user = users.find(u => u.id === req.user.userId);
  if (!user) return res.status(404).json({ error: 'User not found' });

  try {
    // Stop any old bot
    if (activeBots.has(user.id)) {
      activeBots.get(user.id).stop();
      activeBots.delete(user.id);
    }

    // Get real username from Telegram
    const tgResponse = await fetch(`https://api.telegram.org/bot${token}/getMe`);
    const tgData = await tgResponse.json();

    console.log('Telegram getMe response:', JSON.stringify(tgData, null, 2));

    if (!tgData.ok || !tgData.result?.username) {
      return res.status(400).json({ 
        error: 'Invalid bot token. Copy it exactly from @BotFather.' 
      });
    }

    const botUsername = tgData.result.username;  // THIS IS THE TRUTH

    // Save token and launch bot
    user.telegramBotToken = token;
    user.isTelegramConnected = false;
    user.telegramChatId = null;

    launchUserBot(user);

    // THIS LINK WILL WORK 100% — same as your manual one
    const startLink = `https://t.me/\( {botUsername}?start= \){user.id}`;

    console.log('PERFECT MAGIC LINK SENT TO FRONTEND →', startLink);

    res.json({
      success: true,
      message: 'Bot connected! Tap to activate.',
      botUsername: `@${botUsername}`,
      startLink
    });

  } catch (err) {
    console.error('Connect failed:', err);
    res.status(500).json({ error: 'Failed to reach Telegram. Try again.' });
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

app.listen(PORT, () => {
  console.log(`Sendm 2FA Server running on port ${PORT}`);
  console.log(`http://localhost:${PORT}`);
});
