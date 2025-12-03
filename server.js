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

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.static('public'));
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// === STORAGE & SECURITY ===
const JWT_SECRET = 'sendm2fa_ultra_secure_jwt_2025!@#$%^&*()_+-=9876543210zyxwvutsrqponmlkjihgfedcba';
const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 10, message: { error: 'Too many attempts' } });

let users = [];
const activeBots = new Map();
const resetTokens = new Map();
const landingPages = new Map(); // shortId → page data

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
  const token = req.headers.authorization?.split(' ')[1] || req.query.token;
  if (!token) return res.status(401).json({ error: 'Access token required' });

  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) return res.status(403).json({ error: 'Invalid or expired token' });
    req.user = decoded;
    next();
  });
};

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

app.get('/api/auth/me', authenticateToken, (req, res) => {
  const user = users.find(u => u.id === req.user.userId);
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json({ user: { id: user.id, fullName: user.fullName, email: user.email, isTelegramConnected: user.isTelegramConnected } });
});

app.post('/api/auth/connect-telegram', authenticateToken, async (req, res) => {
  const { botToken } = req.body;
  if (!botToken?.trim()) return res.status(400).json({ error: 'Bot token required' });

  const token = botToken.trim();
  const user = users.find(u => u.id === req.user.userId);
  if (!user) return res.status(404).json({ error: 'User not found' });

  try {
    if (activeBots.has(user.id)) {
      activeBots.get(user.id).stop();
      activeBots.delete(user.id);
    }

    const response = await fetch(`https://api.telegram.org/bot${token}/getMe`);
    const data = await response.json();

    if (!data.ok || !data.result?.username)
      return res.status(400).json({ error: 'Invalid bot token or no username set' });

    const botUsername = data.result.username.replace(/^@/, '');

    user.telegramBotToken = token;
    user.isTelegramConnected = false;
    user.telegramChatId = null;

    launchUserBot(user);

    const startLink = 'https://t.me/' + botUsername + '?start=' + user.id;

    res.json({
      success: true,
      message: 'Bot connected! Tap to activate.',
      botUsername: '@' + botUsername,
      startLink
    });
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
    if (activeBots.has(user.id)) {
      activeBots.get(user.id).stop();
      activeBots.delete(user.id);
    }

    const response = await fetch(`https://api.telegram.org/bot${token}/getMe`);
    const data = await response.json();

    if (!data.ok || !data.result?.username)
      return res.status(400).json({ error: 'Invalid bot token' });

    const botUsername = data.result.username.replace(/^@/, '');

    user.telegramBotToken = token;
    user.isTelegramConnected = false;
    user.telegramChatId = null;

    launchUserBot(user);

    const startLink = 'https://t.me/' + botUsername + '?start=' + user.id;

    res.json({
      success: true,
      message: 'Bot token changed! Click link to activate.',
      botUsername: '@' + botUsername,
      startLink
    });
  } catch (err) {
    res.status(500).json({ error: 'Failed to validate new token' });
  }
});

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

  res.json({
    success: true,
    message: 'Bot disconnected and token deleted',
    isTelegramConnected: false
  });
});

app.get('/api/auth/bot-status', authenticateToken, (req, res) => {
  const user = users.find(u => u.id === req.user.userId);
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json({ activated: user.isTelegramConnected, chatId: user.telegramChatId || null });
});

app.post('/api/auth/forgot-password', async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: 'Email required' });

  const user = users.find(u => u.email === email.toLowerCase());
  if (!user) return res.json({ success: true, message: 'If account exists, code was sent.' });

  if (!user.isTelegramConnected) {
    return res.status(400).json({ error: 'Telegram 2FA not connected.' });
  }

  const code = generate2FACode();
  const resetToken = uuidv4();
  const expiresAt = Date.now() + 10 * 60 * 1000;

  resetTokens.set(resetToken, { userId: user.id, code, expiresAt });

  const sent = await send2FACodeViaBot(user, code);
  if (!sent) return res.status(500).json({ error: 'Failed to send code' });

  res.json({ success: true, message: 'Code sent!', resetToken });
});

app.post('/api/auth/verify-reset-code', (req, res) => {
  const { resetToken, code } = req.body;
  if (!resetToken || !code) return res.status(400).json({ error: 'Token and code required' });

  const entry = resetTokens.get(resetToken);
  if (!entry || Date.now() > entry.expiresAt) {
    resetTokens.delete(resetToken);
    return res.status(400).json({ error: 'Invalid or expired code' });
  }

  if (entry.code !== code.trim()) {
    return res.status(400).json({ error: 'Wrong code' });
  }

  res.json({ success: true, message: 'Verified', userId: entry.userId });
});

app.post('/api/auth/reset-password', (req, res) => {
  const { resetToken, newPassword } = req.body;
  if (!resetToken || !newPassword || newPassword.length < 6)
    return res.status(400).json({ error: 'Valid token and password required' });

  const entry = resetTokens.get(resetToken);
  if (!entry || Date.now() > entry.expiresAt) {
    resetTokens.delete(resetToken);
    return res.status(400).json({ error: 'Invalid session' });
  }

  const user = users.find(u => u.id === entry.userId);
  if (!user) return res.status(404).json({ error: 'User not found' });

  user.password = bcrypt.hashSync(newPassword, 12);
  resetTokens.delete(resetToken);

  res.json({ success: true, message: 'Password reset successful' });
});

// === LANDING PAGE API ===
app.get('/api/pages', authenticateToken, (req, res) => {
  const userPages = Array.from(landingPages.entries())
    .filter(([_, page]) => page.userId === req.user.userId)
    .map(([shortId, page]) => ({
      shortId,
      title: page.title,
      createdAt: page.createdAt,
      updatedAt: page.updatedAt,
      url: `\( {req.protocol}:// \){req.get('host')}/p/${shortId}`
    }));
  res.json({ pages: userPages });
});

app.post('/api/pages/save', authenticateToken, (req, res) => {
  const { shortId, title, config } = req.body;
  if (!title || !config) return res.status(400).json({ error: 'Title and config required' });

  const finalShortId = shortId || uuidv4().slice(0, 8);
  const now = new Date().toISOString();

  landingPages.set(finalShortId, {
    userId: req.user.userId,
    title: title.trim(),
    config,
    createdAt: landingPages.get(finalShortId)?.createdAt || now,
    updatedAt: now
  });

  res.json({
    success: true,
    shortId: finalShortId,
    url: `\( {req.protocol}:// \){req.get('host')}/p/${finalShortId}`
  });
});

app.post('/api/pages/delete', authenticateToken, (req, res) => {
  const { shortId } = req.body;
  const page = landingPages.get(shortId);
  if (!page || page.userId !== req.user.userId)
    return res.status(404).json({ error: 'Page not found' });

  landingPages.delete(shortId);
  res.json({ success: true });
});

app.get('/p/:shortId', (req, res) => {
  const page = landingPages.get(req.params.shortId);
  if (!page) return res.status(404).render('404');
  res.render('landing', { title: page.title, config: JSON.stringify(page.config) });
});

// === AUTO-CREATE VIEWS ===
const viewsDir = path.join(__dirname, 'views');
if (!fs.existsSync(viewsDir)) fs.mkdirSync(viewsDir, { recursive: true });
if (!fs.existsSync(path.join(__dirname, 'public'))) fs.mkdirSync(path.join(__dirname, 'public'), { recursive: true });

const landingTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title><%= title %></title>
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css"/>
  <style>
    :root{--primary:#1564C0;--primary-light:#3485e5;--gray-600:#6c757d;--gray-800:#343a40;}
    *{margin:0;padding:0;box-sizing:border-box;}
    body{font-family:'Segoe UI',Arial,sans-serif;background:#f0f4f8;padding:40px 20px;line-height:1.6;}
    .wrapper{max-width:580px;margin:0 auto;background:white;border-radius:20px;overflow:hidden;box-shadow:0 15px 45px rgba(0,0,0,0.15);padding:44px 40px;text-align:center;}
    h2{font-size:34px;font-weight:700;color:var(--gray-800);margin-bottom:16px;}
    p{font-size:17px;color:var(--gray-600);margin-bottom:32px;}
    .landing-image{max-width:100%;border-radius:14px;box-shadow:0 10px 30px rgba(0,0,0,0.12);margin:40px 0;}
    .cta-button{display:inline-block;padding:18px 50px;font-size:18px;font-weight:600;background:var(--primary);color:white;border:none;border-radius:14px;text-decoration:none;box-shadow:0 10px 30px rgba(21,100,192,0.35);transition:all .3s;}
    .cta-button:hover{background:var(--primary-light);transform:translateY(-3px);}
    .form-block{padding:32px;background:#f9fbff;border-radius:16px;margin:40px 0;}
    .form-block input,.form-block button{width:100%;padding:16px;margin:10px 0;border-radius:10px;border:1px solid #ddd;}
    .form-block button{background:var(--primary);color:white;border:none;font-weight:600;cursor:pointer;}
  </style>
</head>
<body>
  <div class="wrapper" id="landingRoot"></div>
  <script>
    const config = <%= config %>;
    const root = document.getElementById('landingRoot');
    config.blocks.forEach(b => {
      if (b.type==='text'){const el=document.createElement(b.tag||'p');el.innerHTML=b.content;root.appendChild(el);}
      if (b.type==='image'){const div=document.createElement('div');div.style.textAlign='center';const img=document.createElement('img');img.src=b.src;img.className='landing-image';div.appendChild(img);root.appendChild(div);}
      if (b.type==='button'){const a=document.createElement('a');a.href=b.href;a.className='cta-button';a.textContent=b.text;a.target='_blank';root.appendChild(a);}
      if (b.type==='form'){const div=document.createElement('div');div.className='form-block';div.innerHTML=b.html;root.appendChild(div);}
    });
  </script>
</body>
</html>`;

const notFoundTemplate = `<!DOCTYPE html><html><head><title>404</title></head><body style="font-family:sans-serif;text-align:center;padding:100px;background:#f8f9fa;"><h1>404</h1><p>Page not found</p></body></html>`;

if (!fs.existsSync(path.join(viewsDir, 'landing.ejs'))) {
  fs.writeFileSync(path.join(viewsDir, 'landing.ejs'), landingTemplate);
  fs.writeFileSync(path.join(viewsDir, '404.ejs'), notFoundTemplate);
  console.log('Created EJS templates');
}

app.use((req, res) => res.status(404).render('404'));

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
  console.log(`Published pages → /p/shortid`);
});
