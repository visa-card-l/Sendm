const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const { v4: uuidv4 } = require('uuid');
const rateLimit = require('express-rate-limit');
const { Telegraf } = require('telegraf');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// === CONFIG ===
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.static('public')); // for future static files
app.use(cors({
  origin: ['http://localhost:3000', 'https://sendmi.onrender.com'],
  credentials: true
}));
app.use(express.json());

// === SECURITY ===
const JWT_SECRET = process.env.JWT_SECRET || 'sendm2fa_ultra_secure_jwt_2025!@#$%^&*()_+-=9876543210zyxwvutsrqponmlkjihgfedcba';
const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 10, message: { error: 'Too many attempts' } });

// === IN-MEMORY STORAGE ===
let users = [];
const activeBots = new Map();
const resetTokens = new Map();

// === DEFAULT EDITOR HTML ===
const defaultEditorHTML = `
<h2 class="editable" contenteditable="true">Get 50% Off Your First Order</h2>
<p class="editable" contenteditable="true">Limited time offer! Join thousands of happy customers and start saving today.</p>

<div class="image-container">
  <img src="https://picsum.photos/600/400" alt="Hero" class="landing-image" id="landingImage">
  <br>
  <button class="add-image-btn" id="heroImageBtn">Add / Change Image</button>
</div>

<div class="cta-wrapper">
  <a href="#" class="cta-button editable" contenteditable="true" id="ctaButton">Claim Your Discount Now</a>
</div>

<button class="add-block-btn" id="addBlockBtn">
  <i class="fas fa-plus-circle" style="margin-right:10px;"></i>Add New Block
</button>`.trim();

// === HELPERS ===
const isValidEmail = (email) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);

function generate2FACode() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

async function send2FACodeViaBot(user, code) {
  if (!user.isTelegramConnected || !user.telegramChatId || !activeBots.has(user.id)) return false;
  const bot = activeBots.get(user.id);
  try {
    await bot.telegram.sendMessage(user.telegramChatId, `
Security Alert – Password Reset

Your 6-digit code:

<b>${code}</b>

Valid for 10 minutes.
    `.trim(), { parse_mode: 'HTML' });
    return true;
  } catch (err) {
    console.error(`Failed to send code to ${user.email}:`, err.message);
    return false;
  }
}

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

You will now receive login & recovery codes here.

<i>Keep this chat private • Never share your bot</i>
      `);
      console.log(`2FA Connected: \( {user.email} → \){chatId}`);
    } else {
      await ctx.replyWithHTML(`<b>Invalid or expired link</b>\nThis link can only be used once.`);
    }
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

// === MIDDLEWARE ===
const authenticateToken = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Access token required' });

  jwt.verify(token, JWT_SECRET, (err, newborn) => {
    if (err) return res.status(403).json({ error: 'Invalid or expired token' });
    req.user = newborn;
    next();
  });
};

// === ROUTES ===
app.post('/api/auth/register', authLimiter, async (req, res) => {
  const { fullName, email, password } = req.body;
  if (!fullName || !email || !password) return res.status(400).json({ error: 'All fields required' });
  if (!isValidEmail(email)) return res.status(400).json({ error: 'Invalid email' });
  if (password.length < 6) return res.status(400).json({ error: 'Password too short' });
  if (users.find(u => u.email === email.toLowerCase())) return res.status(409).json({ error: 'Email already exists' });

  const hashed = await bcrypt.hash(password, 12);
  const newUser = {
    id: uuidv4(),
    fullName,
    email: email.toLowerCase(),
    password: hashed,
    createdAt: new Date().toISOString(),
    telegramBotToken: null,
    telegramChatId: null,
    isTelegramConnected: false,
    landingConfig: null
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
  if (!user || !(await bcrypt.compare(password, user.password)))
    return res.status(401).json({ error: 'Invalid credentials' });

  const token = jwt.sign({ userId: user.id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });

  res.json({
    success: true,
    token,
    user: { id: user.id, fullName: user.fullName, email: user.email, isTelegramConnected: user.isTelegramConnected }
  });
});

// EDITOR: Load config
app.get('/api/editor/load', authenticateToken, (req, res) => {
  const user = users.find(u => u.id === req.user.userId);
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json({ html: user.landingConfig || defaultEditorHTML });
});

// EDITOR: Save config
app.post('/api/editor/save', authenticateToken, (req, res) => {
  const { html } = req.body;
  const user = users.find(u => u.id === req.user.userId);
  if (!user) return res.status(404).json({ error: 'User not found' });

  user.landingConfig = html.trim();
  res.json({ success: true, message: 'Saved' });
});

// Serve Live Editor (EJS)
app.get('/editor', authenticateToken, (req, res) => {
  const user = users.find(u => u.id === req.user.userId);
  if (!user) return res.redirect('/login');

  res.render('editor', {
    config: user.landingConfig || defaultEditorHTML,
    apiUrl: 'https://sendm.onrender.com/api/editor'
  });
});

// Simple login page (optional)
app.get('/login', (req, res) => {
  res.send(`
    <h2>Login to Sendm</h2>
    <form action="/api/auth/login" method="POST">
      <input type="email" name="email" placeholder="Email" required /><br><br>
      <input type="password" name="password" placeholder="Password" required /><br><br>
      <button type="submit">Login</button>
    </form>
    <p><a href="/register">Register</a></p>
    <script>
      const form = document.querySelector('form');
      form.onsubmit = async (e) => {
        e.preventDefault();
        const res = await fetch(form.action, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(Object.fromEntries(new FormData(form)))
        });
        const data = await res.json();
        if (data.token) {
          localStorage.setItem('jwt', data.token);
          window.location.href = '/editor';
        } else {
          alert('Login failed');
        }
      };
    </script>
  `);
});

app.get('/', (req, res) => {
  res.send(`<h1>Sendm 2FA + Editor Live at <a href="https://sendm.onrender.com/editor">/editor</a></h1>`);
});

// === START SERVER ===
app.listen(PORT, () => {
  console.log(`Sendm Live Editor Running → https://sendm.onrender.com/editor`);
  console.log(`API: https://sendm.onrender.com/api/editor`);
});
