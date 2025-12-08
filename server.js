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
const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 10, message: { error: 'Too many attempts' } });

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
    if (ctx.startPayload === user.id) {
      user.telegramChatId = ctx.chat.id.toString();
      user.isTelegramConnected = true;
      await ctx.replyWithHTML('<b>Sendm 2FA Connected!</b>\nYou will receive codes here.');
    }
  });
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
  const host = req.get('host');
  return protocol + '://' + host + path;
}

// === AUTH ===
app.post('/api/auth/register', authLimiter, async (req, res) => {
  const { fullName, email, password } = req.body;
  if (!fullName || !email || !password || password.length < 6 || !isValidEmail(email)) {
    return res.status(400).json({ error: 'Invalid input' });
  }
  if (users.find(u => u.email === email.toLowerCase())) {
    return res.status(409).json({ error: 'Email exists' });
  }
  const user = {
    id: uuidv4(),
    fullName,
    email: email.toLowerCase(),
    password: await bcrypt.hash(password, 12),
    telegramBotToken: null,
    telegramChatId: null,
    isTelegramConnected: false,
    createdAt: new Date().toISOString()
  };
  users.push(user);
  const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ success: true, token, user: { id: user.id, fullName, email: user.email } });
});

app.post('/api/auth/login', authLimiter, async (req, res) => {
  const { email, password } = req.body;
  const user = users.find(u => u.email === email.toLowerCase());
  if (!user || !(await bcrypt.compare(password, user.password))) {
    return res.status(401).json({ error: 'Wrong credentials' });
  }
  const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ success: true, token });
});

// === TELEGRAM 2FA ===
app.post('/api/auth/connect-telegram', authenticateToken, async (req, res) => {
  const { botToken } = req.body;
  if (!botToken?.trim()) return res.status(400).json({ error: 'Token required' });
  const user = users.find(u => u.id === req.user.userId);
  if (!user) return res.status(404).json({ error: 'User not found' });

  try {
    const info = await fetch(`https://api.telegram.org/bot${botToken}/getMe`).then(r => r.json());
    if (!info.ok) return res.status(400).json({ error: 'Invalid bot token' });

    user.telegramBotToken = botToken.trim();
    user.isTelegramConnected = false;
    user.telegramChatId = null;
    launchUserBot(user);

    const link = `https://t.me/\( {info.result.username}?start= \){user.id}`;
    res.json({ success: true, startLink: link });
  } catch {
    res.status(500).json({ error: 'Failed to connect' });
  }
});

// === PAGES API ===
app.get('/api/pages', authenticateToken, (req, res) => {
  const pages = Array.from(landingPages.entries())
    .filter(([_, p]) => p.userId === req.user.userId)
    .map(([id, p]) => ({ shortId: id, title: p.title, url: getFullUrl(req, '/p/' + id) }));
  res.json({ pages });
});

app.post('/api/pages/save', authenticateToken, (req, res) => {
  const { shortId, title, config } = req.body;
  if (!title || !config?.blocks || !Array.isArray(config.blocks)) {
    return res.status(400).json({ error: 'Invalid data' });
  }

  const id = shortId || uuidv4().slice(0, 8);
  landingPages.set(id, {
    userId: req.user.userId,
    title: title.trim(),
    config: { blocks: config.blocks },
    updatedAt: new Date().toISOString()
  });

  res.json({ success: true, shortId: id, url: getFullUrl(req, '/p/' + id) });
});

app.post('/api/pages/delete', authenticateToken, (req, res) => {
  const { shortId } = req.body;
  const page = landingPages.get(shortId);
  if (page && page.userId === req.user.userId) landingPages.delete(shortId);
  res.json({ success: true });
});

// === FINAL LANDING PAGE - 100% CLEAN, REAL LOOKING ===
app.get('/p/:shortId', (req, res) => {
  const page = landingPages.get(req.params.shortId);
  if (!page) return res.status(404).render('404');
  res.render('landing', { title: page.title, blocks: page.config.blocks });
});

// === TEMPLATES ===
const viewsDir = path.join(__dirname, 'views');
if (!fs.existsSync(viewsDir)) fs.mkdirSync(viewsDir, { recursive: true });

// THIS IS THE ONLY THING THAT MATTERS — PURE, CLEAN, PROFESSIONAL LANDING PAGE
const landingTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title><%- title %></title>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700;800&display=swap" rel="stylesheet">
  <style>
    * { margin:0; padding:0; box-sizing:border-box; }
    body { font-family:'Inter',sans-serif; background:#f5f7ff; color:#1a1a1a; line-height:1.6; padding:30px 15px; }
    .container { max-width:560px; margin:0 auto; background:#fff; border-radius:24px; overflow:hidden; box-shadow:0 20px 60px rgba(0,0,0,0.12); }
    .content { padding:60px 40px; text-align:center; }
    h1 { font-size:42px; font-weight:800; margin-bottom:20px; color:#1e293b; }
    h2 { font-size:34px; font-weight:700; margin:30px 0 16px; }
    p { font-size:18px; color:#64748b; margin-bottom:24px; }
    .img { width:100%; border-radius:16px; margin:40px 0; box-shadow:0 15px 35px rgba(0,0,0,0.1); }
    .btn { display:inline-block; padding:18px 48px; margin:15px; background:#1564c0; color:white; text-decoration:none; border-radius:12px; font-weight:700; font-size:18px; box-shadow:0 10px 30px rgba(21,100,192,0.4); transition:all .3s; }
    .btn:hover { background:#3485e5; transform:translateY(-4px); box-shadow:0 20px 40px rgba(21,100,192,0.5); }
    .form { background:#f8faff; padding:40px; border-radius:16px; margin:40px 0; }
    .form input, .form textarea { width:100%; padding:16px; margin:10px 0; border:1px solid #ddd; border-radius:10px; font-size:16px; }
    .form button { width:100%; padding:16px; background:#1564c0; color:white; border:none; border-radius:10px; font-weight:700; font-size:17px; cursor:pointer; }
    .form button:hover { background:#3485e5; }
    .footer { text-align:center; padding:30px; color:#94a3b8; font-size:14px; }
    @media(max-width:640px){ .content{padding:40px 24px;} h1{font-size:36px;} }
  </style>
</head>
<body>
<div class="container">
  <div class="content">
    <% blocks.forEach(b => { %>
      <% if(b.type==='text') { %>
        <<%- b.tag || 'p' %> style="font-size:<%- b.tag==='h1'?'42px':b.tag==='h2'?'34px':'18px' %>;font-weight:<%- b.tag?.startsWith('h')?'700':'400' %>;margin:24px 0;">
          <%- b.content %>
        </<%- b.tag || 'p' %>>
      <% } else if(b.type==='image') { %>
        <img src="<%- b.src %>" alt="" class="img">
      <% } else if(b.type==='button') { %>
        <a href="<%- b.href && b.href!=='#' ? b.href : 'javascript:void(0)' %>" target="_blank" class="btn">
          <%- b.text || 'Click Here' %>
        </a>
      <% } else if(b.type==='form') { %>
        <div class="form"><%- b.html %></div>
      <% } %>
    <% }) %>
  </div>
</div>
<div class="footer">© ${new Date().getFullYear()} All rights reserved.</div>
</body>
</html>`;

const notFoundTemplate = `<!DOCTYPE html><html><head><title>Not Found</title></head><body style="font-family:sans-serif;text-align:center;padding:100px;background:#f8f9fa;"><h1>404</h1><p>Page not found</p></body></html>`;

if (!fs.existsSync(path.join(viewsDir, 'landing.ejs'))) {
  fs.writeFileSync(path.join(viewsDir, 'landing.ejs'), landingTemplate);
  fs.writeFileSync(path.join(viewsDir, '404.ejs'), notFoundTemplate);
  console.log('Templates created');
}

app.use((req, res) => res.status(404).render('404'));

app.listen(PORT, () => {
  console.log(`SENDM LIVE → http://localhost:${PORT}`);
  console.log(`Final pages → http://localhost:${PORT}/p/yourid`);
});
