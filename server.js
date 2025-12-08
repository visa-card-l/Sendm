const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const { v4: uuidv4 } = require('uuid');
const rateLimit = require('express-rate-limit');
const { Telegraf } = require('telegraf');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;
const IS_PRODUCTION = process.env.NODE_ENV === 'production';
app.set('trust proxy', 1);

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.static('public'));
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

const JWT_SECRET = 'sendm2fa_ultra_secure_jwt_2025!@#$%^&*()_+-=9876543210zyxwvutsrqponmlkjihgfedcba';
const authLimiter = rateLimit({ windowMs: 15*60*1000, max: 10, message: { error: 'Too many attempts' }});

let users = [];
const activeBots = new Map();
const landingPages = new Map();

const isValidEmail = (email) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);

function launchUserBot(user) {
  if (activeBots.has(user.id)) {
    activeBots.get(user.id).stop();
    activeBots.delete(user.id);
  }
  const bot = new Telegraf(user.telegramBotToken);
  bot.start(async (ctx) => {
    const payload = ctx.startPayload || '';
    if (payload === user.id) {
      user.telegramChatId = ctx.chat.id.toString();
      user.isTelegramConnected = true;
      await ctx.replyWithHTML('<b>Sendm 2FA Connected!</b>\nKeep this chat private.');
      console.log('2FA Connected:', user.email);
    } else {
      await ctx.replyWithHTML('<b>Invalid link</b>');
    }
  });
  bot.catch(err => console.error('Bot error:', err));
  bot.launch();
  activeBots.set(user.id, bot);
}

const authenticateToken = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1] || req.query.token;
  if (!token) return res.status(401).json({ error: 'Token required' });
  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) return res.status(403).json({ error: 'Invalid token' });
    req.user = decoded;
    next();
  });
};

function getFullUrl(req, path = '') {
  const protocol = IS_PRODUCTION ? 'https' : req.protocol;
  const host = req.get('host') || 'localhost:' + PORT;
  return protocol + '://' + host + path;
}

// === AUTH ROUTES ===
app.post('/api/auth/register', authLimiter, async (req, res) => {
  const { fullName, email, password } = req.body;
  if (!fullName || !email || !password) return res.status(400).json({ error: 'All fields required' });
  if (!isValidEmail(email)) return res.status(400).json({ error: 'Invalid email' });
  if (password.length < 6) return res.status(400).json({ error: 'Password too short' });
  if (users.find(u => u.email === email.toLowerCase())) return res.status(409).json({ error: 'Email exists' });

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
  res.status(201).json({ success: true, token, user: { id: newUser.id, fullName, email: newUser.email, isTelegramConnected: false }});
});

app.post('/api/auth/login', authLimiter, async (req, res) => {
  const { email, password } = req.body;
  const user = users.find(u => u.email === email.toLowerCase());
  if (!user || !(await bcrypt.compare(password, user.password))) return res.status(401).json({ error: 'Invalid credentials' });
  const token = jwt.sign({ userId: user.id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ success: true, token, user: { id: user.id, fullName: user.fullName, email: user.email, isTelegramConnected: user.isTelegramConnected }});
});

app.get('/api/auth/me', authenticateToken, (req, res) => {
  const user = users.find(u => u.id === req.user.userId);
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json({ user: { id: user.id, fullName: user.fullName, email: user.email, isTelegramConnected: user.isTelegramConnected }});
});

// === TELEGRAM 2FA ===
app.post('/api/auth/connect-telegram', authenticateToken, async (req, res) => {
  const { botToken } = req.body;
  if (!botToken?.trim()) return res.status(400).json({ error: 'Bot token required' });
  const token = botToken.trim();
  const user = users.find(u => u.id === req.user.userId);
  if (!user) return res.status(404).json({ error: 'User not found' });
  try {
    if (activeBots.has(user.id)) activeBots.get(user.id).stop();
    const response = await fetch('https://api.telegram.org/bot' + token + '/getMe');
    const data = await response.json();
    if (!data.ok) return res.status(400).json({ error: 'Invalid bot token' });
    const username = data.result.username.replace(/^@/, '');
    user.telegramBotToken = token;
    user.isTelegramConnected = false;
    user.telegramChatId = null;
    launchUserBot(user);
    res.json({ success: true, startLink: 'https://t.me/' + username + '?start=' + user.id });
  } catch { res.status(500).json({ error: 'Failed to connect' }); }
});

app.post('/api/auth/disconnect-telegram', authenticateToken, (req, res) => {
  const user = users.find(u => u.id === req.user.userId);
  if (!user) return res.status(404).json({ error: 'User not found' });
  if (activeBots.has(user.id)) activeBots.get(user.id).stop();
  user.telegramBotToken = null; user.telegramChatId = null; user.isTelegramConnected = false;
  res.json({ success: true });
});

// === LANDING PAGES ===
app.get('/api/pages', authenticateToken, (req, res) => {
  const pages = Array.from(landingPages.entries())
    .filter(([_, p]) => p.userId === req.user.userId)
    .map(([id, p]) => ({ shortId: id, title: p.title, url: getFullUrl(req, '/p/' + id) }));
  res.json({ pages });
});

app.post('/api/pages/save', authenticateToken, (req, res) => {
  const { shortId, title, config } = req.body;
  if (!title || !config || !Array.isArray(config.blocks)) return res.status(400).json({ error: 'Invalid data' });
  const id = shortId || uuidv4().slice(0, 8);
  landingPages.set(id, {
    userId: req.user.userId,
    title: String(title).trim(),
    config: { blocks: config.blocks },
    updatedAt: new Date().toISOString()
  });
  res.json({ success: true, shortId: id, url: getFullUrl(req, '/p/' + id) });
});

app.get('/p/:shortId', (req, res) => {
  const page = landingPages.get(req.params.shortId);
  if (!page || !page.config || !Array.isArray(page.config.blocks)) return res.status(404).render('404');
  res.render('landing', { title: page.title || 'Page', blocks: page.config.blocks });
});

// === REAL-LOOKING SSR TEMPLATE (NO EDITOR TRASH) ===
const landingTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title><%= title %></title>
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css"/>
  <style>
    :root{--primary:#1564C0;--primary-light:#3485e5;--gray-600:#6c757d;--gray-800:#343a40;}
    *{margin:0;padding:0;box-sizing:border-box;}
    body{font-family:'Segoe UI',Arial,sans-serif;background:#f0f4f8;padding:40px 20px;line-height:1.6;min-height:100vh;display:flex;align-items:center;justify-content:center;}
    .wrapper{max-width:580px;width:100%;margin:0 auto;background:white;border-radius:20px;overflow:hidden;box-shadow:0 20px 60px rgba(0,0,0,0.15);padding:50px 40px;text-align:center;}
    h1,h2,h3,h4,h5,h6{margin:20px 0;font-weight:700;color:var(--gray-800);}
    h1{font-size:42px;} h2{font-size:34px;} p{font-size:17px;color:var(--gray-600);margin-bottom:32px;line-height:1.7;}
    .landing-image{max-width:100%;border-radius:14px;box-shadow:0 10px 30px rgba(0,0,0,0.12);margin:40px 0;}
    .cta-button{display:inline-block;padding:18px 50px;font-size:18px;font-weight:600;background:var(--primary);color:white;border:none;border-radius:14px;text-decoration:none;box-shadow:0 10px 30px rgba(21,100,192,0.35);transition:all .3s;cursor:pointer;}
    .cta-button:hover{background:var(--primary-light);transform:translateY(-3px);}
    .form-block{padding:32px;background:#f9fbff;border-radius:16px;margin:40px 0;text-align:center;}
    .form-block input,.form-block button{width:100%;padding:16px;margin:10px 0;border-radius:10px;border:1px solid #ddd;font-size:16px;}
    .form-block button{background:var(--primary);color:white;border:none;font-weight:600;cursor:pointer;}
    .form-block button:hover{background:var(--primary-light);}
  </style>
</head>
<body>
  <div class="wrapper">
    <% blocks.forEach(block => { %>
      <% if (block.type === 'text') { %>
        <<%= block.tag || 'p' %>><%- block.content %></<%= block.tag || 'p' %>>
      <% } else if (block.type === 'image') { %>
        <img src="<%= block.src %>" alt="Image" class="landing-image">
      <% } else if (block.type === 'button') { %>
        <a href="<%= block.href || '#' %>" target="_blank" class="cta-button"><%= block.text || 'Click Here' %></a>
      <% } else if (block.type === 'form') { %>
        <div class="form-block"><%- block.html %></div>
      <% } %>
    <% }); %>
  </div>
</body>
</html>`;

const notFoundTemplate = `<!DOCTYPE html><html><head><title>404</title></head><body style="font-family:sans-serif;text-align:center;padding:100px;background:#f8f9fa;"><h1>404</h1><p>Not found</p></body></html>`;

if (!fs.existsSync(path.join(__dirname, 'views'))) fs.mkdirSync(path.join(__dirname, 'views'), { recursive: true });
if (!fs.existsSync(path.join(__dirname, 'public'))) fs.mkdirSync(path.join(__dirname, 'public'), { recursive: true });
if (!fs.existsSync(path.join(__dirname, 'views', 'landing.ejs'))) {
  fs.writeFileSync(path.join(__dirname, 'views', 'landing.ejs'), landingTemplate);
  fs.writeFileSync(path.join(__dirname, 'views', '404.ejs'), notFoundTemplate);
}

app.use((req, res) => res.status(404).render('404'));

app.listen(PORT, () => {
  console.log('SENDM LIVE — PORT ' + PORT);
  console.log('Editor: https://your-static.com/editor.html?token=xxx');
  console.log('Pages:  https://your-domain.onrender.com/p/xxxxxx');
});
