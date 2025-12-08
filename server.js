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
const resetTokens = new Map();
const landingPages = new Map();

const isValidEmail = (email) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);

function generate2FACode() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

async function send2FACodeViaBot(user, code) {
  if (!user.isTelegramConnected || !user.telegramChatId || !activeBots.has(user.id)) return false;
  const bot = activeBots.get(user.id);
  try {
    await bot.telegram.sendMessage(user.telegramChatId,
      'Security Alert – Password Reset\n\n' +
      'Your 6-digit code:\n\n' +
      '<b>' + code + '</b>\n\n' +
      'Valid for 10 minutes.'
    , { parse_mode: 'HTML' });
    return true;
  } catch (err) {
    console.error('Failed to send code to ' + user.email + ':', err.message);
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
      await ctx.replyWithHTML('<b>Sendm 2FA Connected Successfully!</b>\n\nYou will now receive codes here.\n\n<i>Keep this chat private • Never share your bot</i>');
      console.log('2FA Connected: ' + user.email + ' → ' + chatId);
    } else {
      await ctx.replyWithHTML('<b>Invalid or expired link</b>');
    }
  });
  bot.command('status', (ctx) => {
    ctx.replyWithHTML('<b>Sendm 2FA Status</b>\nAccount: <code>' + user.email + '</code>\nStatus: <b>' + (user.isTelegramConnected ? 'Connected' : 'Not Connected') + '</b>');
  });
  bot.catch((err) => console.error('Bot error [' + user.email + ']:', err));
  bot.launch();
  activeBots.set(user.id, bot);
}

const authenticateToken = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1] || req.query.token;
  if (!token) return res.status(401).json({ error: 'Access token required' });
  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) return res.status(403).json({ error: 'Invalid or expired token' });
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
    isTelegramConnected: false
  };
  users.push(newUser);
  const token = jwt.sign({ userId: newUser.id, email: newUser.email }, JWT_SECRET, { expiresIn: '7d' });
  res.status(201).json({ success: true, token, user: { id: newUser.id, fullName, email: newUser.email, isTelegramConnected: false }});
});

app.post('/api/auth/login', authLimiter, async (req, res) => {
  const { email, password } = req.body;
  const user = users.find(u => u.email === email.toLowerCase());
  if (!user(filepath) || !(await bcrypt.compare(password, user.password))) return res.status(401).json({ error: 'Invalid credentials' });
  const token = jwt.sign({ userId: user.id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ success: true, token, user: { id: user.id, fullName: user.fullName, email: user.email, isTelegramConnected: user.isTelegramConnected }});
});

app.get('/api/auth/me', authenticateToken, (req, res) => {
  const user = users.find(u => u.id === req.user.userId);
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json({ user: { id: user.id, fullName: user.fullName, email: user.email, isTelegramConnected: user.isTelegramConnected }});
});

// === TELEGRAM 2FA ROUTES ===
app.post('/api/auth/connect-telegram', authenticateToken, async (req, res) => {
  const { botToken } = req.body;
  if (!botToken?.trim()) return res.status(400).json({ error: 'Bot token required' });
  const token = botToken.trim();
<<<<<<< Updated upstream
  const user = users.find(u => u.id === req.user.userId);
  if (!user) return res.status(404).json({ error: 'User not found' });
  try {
    if (activeBots.has(user.id)) { activeBots.get(user.id).stop(); activeBots.delete(user.id); }
    const response = await fetch('https://api.telegram.org/bot' + token + '/getMe');
    const data = await response.json();
    if (!data.ok || !data.result?.username) return res.status(400).json({ error: 'Invalid bot token' });
    const botUsername = data.result.username.replace(/^@/, '');
    user.telegramBotToken = token;
    user.isTelegramConnected = false;
    user.telegramChatId = null;
    launchUserBot(user);
    const startLink = 'https://t.me/' + botUsername + '?start=' + user.id;
    res.json({ success: true, message: 'Bot connected! Tap to activate.', botUsername: '@' + botUsername, startLink });
  } catch (err) {
    res.status(500).json({ error: 'Failed to connect to Telegram' });
  }
});

app.post('/api/auth/change-bot-token', authenticateToken, async (req, res) => {
  const { newBotToken } = req.body;
  if (!newBotToken?.trim()) return res.status(400).json({ error: 'New bot token required' });
  const token = newBotToken.trim();
  const user = users.find(u => u.id === req.user.userId);
  if (!user) return res.status(404).json({ error: 'User not found' });
  try {
    if (activeBots.has(user.id)) { activeBots.get(user.id).stop(); activeBots.delete(user.id); }
    const response = await fetch('https://api.telegram.org/bot' + token + '/getMe');
    const data = await response.json();
    if (!data.ok || !data.result?.username) return res.status(400).json({ error: 'Invalid bot token' });
    const botUsername = data.result.username.replace(/^@/, '');
    user.telegramBotToken = token;
    user.isTelegramConnected = false;
    user.telegramChatId = null;
    launchUserBot(user);
    const startLink = 'https://t.me/' + botUsername + '?start=' + user.id;
    res.json({ success: true, message: 'Bot token changed!', botUsername: '@' + botUsername, startLink });
  } catch (err) {
    res.status(500).json({ error: 'Failed to validate new token' });
  }
});

app.post('/api/auth/disconnect-telegram', authenticateToken, (req, res) => {
  const user = users.find(u => u.id === req.user.userId);
  if (!user) return res.status(404).json({ error: 'User not found' });
  if (activeBots.has(user.id)) { activeBots.get(user.id).stop(); activeBots.delete(user.id); }
  user.telegramBotToken = null; user.telegramChatId = null; user.isTelegramConnected = false;
  res.json({ success: true, message: 'Bot disconnected', isTelegramConnected: false });
});

app.get('/api/auth/bot-status', authenticateToken, (req, res) => {
  const user = users.find(u => u.id === req.user.userId);
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json({ activated: user.isTelegramConnected, chatId: user.telegramChatId || null });
});

// === LANDING PAGES API ===
app.get('/api/pages', authenticateToken, (req, res) => {
  const userPages = Array.from(landingPages.entries())
    .filter(([_, p]) => p.userId === req.user.userId)
    .map(([id, p]) => ({ shortId: id, title: p.title, createdAt: p.createdAt, updatedAt: p.updatedAt, url: getFullUrl(req, '/p/' + id) }));
  res.json({ pages: userPages });
});

app.post('/api/pages/save', authenticateToken, (req, res) => {
  const { shortId, title, config } = req.body;

  if (!title || !config || !Array.isArray(config.blocks)) {
    return res.status(400).json({ error: 'Invalid data: title + blocks array required' });
  }

  const finalShortId = shortId || uuidv4().slice(0, 8);
  const now = new Date().toISOString();

  landingPages.set(finalShortId, {
    userId: req.user.userId,
    title: String(title).trim(),
    config: { blocks: config.blocks },
    createdAt: landingPages.get(finalShortId)?.createdAt || now,
    updatedAt: now
  });

  res.json({
    success: true,
    shortId: finalShortId,
    url: getFullUrl(req, '/p/' + finalShortId)
  });
});

app.post('/api/pages/delete', authenticateToken, (req, res) => {
  const { shortId } = req.body;
  const page = landingPages.get(shortId);
  if (!page || page.userId !== req.user.userId) return res.status(404).json({ error: 'Not found' });
  landingPages.delete(shortId);
  res.json({ success: true });
});

// === PERFECT CLEAN LANDING PAGE (NO EDITOR UI) ===
app.get('/p/:shortId', (req, res) => {
  const page = landingPages.get(req.params.shortId);
  if (!page || !page.config || !Array.isArray(page.config.blocks)) return res.status(404).render('404');
  res.render('landing', { title: page.title || 'Special Offer', blocks: page.config.blocks });
});

// === SSR TEMPLATES ===
const viewsDir = path.join(__dirname, 'views');
const publicDir = path.join(__dirname, 'public');
if (!fs.existsSync(viewsDir)) fs.mkdirSync(viewsDir, { recursive: true });
if (!fs.existsSync(publicDir)) fs.mkdirSync(publicDir, { recursive: true });

const landingTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title><%= title %></title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet">
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css"/>
  <style>
    :root{
      --primary:#1564C0;
      --primary-light:#3485e5;
      --gray-600:#6c757d;
      --gray-800:#343a40;
    }
    *{margin:0;padding:0;box-sizing:border-box;}
    body{
      font-family:'Inter',sans-serif;
      background:#f0f4f8;
      padding:40px 20px;
      line-height:1.7;
      color:#333;
    }
    .wrapper{
      max-width:580px;
      margin:0 auto;
      background:white;
      border-radius:20px;
      overflow:hidden;
      box-shadow:0 20px 60px rgba(0,0,0,0.15);
      padding:50px 40px;
      text-align:center;
    }
    h1{font-size:42px;font-weight:800;color:var(--gray-800);margin-bottom:20px;}
    h2{font-size:36px;font-weight:700;margin:30px 0 16px;}
    h3{font-size:28px;font-weight:700;margin:24px 0 12px;}
    p{font-size:18px;color:var(--gray-600);margin-bottom:28px;}
    .landing-image{
      max-width:100%;
      height:auto;
      border-radius:16px;
      box-shadow:0 15px 40px rgba(0,0,0,0.15);
      margin:40px 0;
    }
    .cta-button{
      display:inline-block;
      padding:18px 50px;
      font-size:19px;
      font-weight:700;
      background:var(--primary);
      color:white !important;
      text-decoration:none;
      border-radius:14px;
      box-shadow:0 12px 35px rgba(21,100,192,0.4);
      transition:all .3s;
      margin:20px 10px;
    }
    .cta-button:hover{
      background:var(--primary-light);
      transform:translateY(-4px);
      box-shadow:0 20px 50px rgba(21,100,192,0.5);
    }
    .form-block{
      background:#f8faff;
      padding:40px 32px;
      border-radius:16px;
      margin:48px 0;
      border:1px solid #e3e8ff;
    }
    .form-block input,
    .form-block textarea,
    .form-block button{
      width:100%;
      padding:16px 20px;
      margin:12px 0;
      border-radius:12px;
      border:1px solid #d1d8ff;
      font-size:16px;
    }
    .form-block button{
      background:var(--primary);
      color:white;
      border:none;
      font-weight:700;
      cursor:pointer;
      font-size:18px;
    }
    .form-block button:hover{
      background:var(--primary-light);
    }
    .footer{
      margin-top:60px;
      padding-top:30px;
      border-top:1px solid #eee;
      color:#999;
      font-size:14px;
    }
    @media(max-width:640px){
      .wrapper{padding:40px 24px;}
      h1{font-size:36px;}
      h2{font-size:30px;}
    }
  </style>
</head>
<body>
<div class="wrapper">
  <% blocks.forEach(block => { %>
    <% if (block.type === 'text') { %>
      <<%= block.tag || 'p' %> style="font-size:<%= block.tag==='h1'?'42px':block.tag==='h2'?'36px':block.tag==='h3'?'28px':'18px' %>;font-weight:<%= block.tag?.startsWith('h')?'700':'400' %>;margin:28px 0;">
        <%- block.content %>
      </<%= block.tag || 'p' %>>
    <% } %>
    <% if (block.type === 'image') { %>
      <img src="<%= block.src %>" alt="Offer" class="landing-image" loading="lazy">
    <% } %>
    <% if (block.type === 'button') { %>
      <a href="<%= block.href && block.href !== '#' ? block.href : 'javascript:void(0)' %>" 
         target="_blank" 
         class="cta-button">
        <%= block.text || 'Click Here' %>
      </a>
    <% } %>
    <% if (block.type === 'form') { %>
      <div class="form-block">
        <%- block.html %>
      </div>
    <% } %>
  <% }); %>
</div>
<div class="footer">
  © <%= new Date().getFullYear() %> All rights reserved.
</div>
</body>
</html>`;

const notFoundTemplate = `<!DOCTYPE html><html><head><title>404</title></head><body style="font-family:sans-serif;text-align:center;padding:100px;background:#f8f9fa;"><h1>404</h1><p>Page not found</p></body></html>`;

if (!fs.existsSync(path.join(viewsDir, 'landing.ejs'))) {
  fs.writeFileSync(path.join(viewsDir, 'landing.ejs'), landingTemplate);
  fs.writeFileSync(path.join(viewsDir, '404.ejs'), notFoundTemplate);
  console.log('SSR templates created');
}

app.use((req, res) => res.status(404).render('404'));

app.listen(PORT, () => {
  console.log('SENDM SSR SERVER LIVE on port ' + PORT);
  console.log('Editor: https://your-static-site.com/editor.html?token=your_jwt');
  console.log('Pages:  https://your-domain.onrender.com/p/shortid');
});
