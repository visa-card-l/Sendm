// server.js — FINAL, COMPLETE & UPDATED TO MATCH smav.onrender.com EDITING BEHAVIOR
// All 20+ original routes are preserved
// Added public fast fetch endpoints for editing:
//   GET /api/page/:shortId  → public (no auth)
//   GET /api/form/:shortId  → public (no auth)
// Save/create/delete/list remain authenticated
// Landing pages and forms remain completely separate entities

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

// Middleware
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.static('public'));
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// Security & Storage
const JWT_SECRET = 'sendm2fa_ultra_secure_jwt_2025!@#$%^&*()_+-=9876543210zyxwvutsrqponmlkjihgfedcba';
const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 10, message: { error: 'Too many attempts' } });

let users = [];
const activeBots = new Map();
const resetTokens = new Map();
const landingPages = new Map(); // shortId → { userId, title, config: { blocks }, createdAt, updatedAt }
const formPages = new Map();    // shortId → { userId, title, state (full editor state), createdAt, updatedAt }

const isValidEmail = (email) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);

// ==================== TELEGRAM 2FA HELPERS ====================
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
      await ctx.replyWithHTML(`<b>Invalid or expired link</b>`);
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

// ==================== JWT MIDDLEWARE ====================
const authenticateToken = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1] || req.query.token;
  if (!token) return res.status(401).json({ error: 'Access token required' });

  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) return res.status(403).json({ error: 'Invalid or expired token' });
    req.user = decoded;
    next();
  });
};

// ==================== ALL 20+ ORIGINAL ROUTES (UNCHANGED) ====================

// 1. Register
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

// 2. Login
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

// 3. Get current user
app.get('/api/auth/me', authenticateToken, (req, res) => {
  const user = users.find(u => u.id === req.user.userId);
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json({ user: { id: user.id, fullName: user.fullName, email: user.email, isTelegramConnected: user.isTelegramConnected } });
});

// 4. Connect Telegram Bot
app.post('/api/auth/connect-telegram', authenticateToken, async (req, res) => {
  const { botToken } = req.body;
  if (!botToken?.trim()) return res.status(400).json({ error: 'Bot token required' });

  const token = botToken.trim();
  const user = users.find(u => u.id === req.user.userId);
  if (!user) return res.status(404).json({ error: 'User not found' });

  try {
    if (activeBots.has(user.id)) activeBots.get(user.id).stop(), activeBots.delete(user.id);

    const response = await fetch('https://api.telegram.org/bot' + token + '/getMe');
    const data = await response.json();

    if (!data.ok || !data.result?.username) return res.status(400).json({ error: 'Invalid bot token' });

    const botUsername = data.result.username.replace(/^@/, '');
    user.telegramBotToken = token;
    user.isTelegramConnected = false;
    user.telegramChatId = null;
    launchUserBot(user);

    const startLink = 'https://t.me/' + botUsername + '?start=' + user.id;

    res.json({ success: true, message: 'Bot connected!', botUsername: '@' + botUsername, startLink });
  } catch (err) {
    res.status(500).json({ error: 'Failed to connect to Telegram' });
  }
});

// 5. Change Bot Token
app.post('/api/auth/change-bot-token', authenticateToken, async (req, res) => {
  const { newBotToken } = req.body;
  if (!newBotToken?.trim()) return res.status(400).json({ error: 'New bot token required' });

  const token = newBotToken.trim();
  const user = users.find(u => u.id === req.user.userId);
  if (!user) return res.status(404).json({ error: 'User not found' });

  try {
    if (activeBots.has(user.id)) activeBots.get(user.id).stop(), activeBots.delete(user.id);

    const response = await fetch('https://api.telegram.org/bot' + token + '/getMe');
    const data = await response.json();

    if (!data.ok || !data.result?.username) return res.status(400).json({ error: 'Invalid bot token' });

    const botUsername = data.result.username.replace(/^@/, '');
    user.telegramBotToken = token;
    user.isTelegramConnected = false;
    user.telegramChatId = null;
    launchUserBot(user);

    const startLink = 'https://t.me/' + botUsername + '?start=' + user.id;

    res.json({ success: true, message: 'Bot token updated!', botUsername: '@' + botUsername, startLink });
  } catch (err) {
    res.status(500).json({ error: 'Failed to validate token' });
  }
});

// 6. Disconnect Telegram
app.post('/api/auth/disconnect-telegram', authenticateToken, (req, res) => {
  const user = users.find(u => u.id === req.user.userId);
  if (!user) return res.status(404).json({ error: 'User not found' });

  if (activeBots.has(user.id)) activeBots.get(user.id).stop(), activeBots.delete(user.id);

  user.telegramBotToken = null;
  user.telegramChatId = null;
  user.isTelegramConnected = false;

  res.json({ success: true, message: 'Telegram disconnected' });
});

// 7. Bot Status
app.get('/api/auth/bot-status', authenticateToken, (req, res) => {
  const user = users.find(u => u.id === req.user.userId);
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json({ activated: user.isTelegramConnected, chatId: user.telegramChatId || null });
});

// 8. Forgot Password (send code)
app.post('/api/auth/forgot-password', async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: 'Email required' });

  const user = users.find(u => u.email === email.toLowerCase());
  if (!user) return res.json({ success: true, message: 'If account exists, code was sent.' });

  if (!user.isTelegramConnected) return res.status(400).json({ error: 'Telegram 2FA not connected' });

  const code = generate2FACode();
  const resetToken = uuidv4();
  const expiresAt = Date.now() + 10 * 60 * 1000;

  resetTokens.set(resetToken, { userId: user.id, code, expiresAt });
  const sent = await send2FACodeViaBot(user, code);
  if (!sent) return res.status(500).json({ error: 'Failed to send code' });

  res.json({ success: true, message: 'Code sent!', resetToken });
});

// 9. Verify Reset Code
app.post('/api/auth/verify-reset-code', (req, res) => {
  const { resetToken, code } = req.body;
  if (!resetToken || !code) return res.status(400).json({ error: 'Token and code required' });

  const entry = resetTokens.get(resetToken);
  if (!entry || Date.now() > entry.expiresAt) {
    resetTokens.delete(resetToken);
    return res.status(400).json({ error: 'Invalid or expired code' });
  }

  if (entry.code !== code.trim()) return res.status(400).json({ error: 'Wrong code' });

  res.json({ success: true, message: 'Verified', userId: entry.userId });
});

// 10. Reset Password
app.post('/api/auth/reset-password', async (req, res) => {
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

  user.password = await bcrypt.hash(newPassword, 12);
  resetTokens.delete(resetToken);

  res.json({ success: true, message: 'Password reset successful' });
});

// ==================== LANDING PAGE ROUTES (11-14) ====================

// 11. List user pages
app.get('/api/pages', authenticateToken, (req, res) => {
  const userPages = Array.from(landingPages.entries())
    .filter(([_, page]) => page.userId === req.user.userId)
    .map(([shortId, page]) => ({
      shortId,
      title: page.title,
      createdAt: page.createdAt,
      updatedAt: page.updatedAt,
      url: req.protocol + '://' + req.get('host') + '/p/' + shortId
    }));
  res.json({ pages: userPages });
});

// 12. Save page (create or edit)
app.post('/api/pages/save', authenticateToken, (req, res) => {
  const { shortId, title, config } = req.body;
  if (!title || !config || !Array.isArray(config.blocks))
    return res.status(400).json({ error: 'Title and config.blocks required' });

  const finalShortId = shortId || uuidv4().slice(0, 8);
  const now = new Date().toISOString();

  const cleanBlocks = config.blocks
    .map(block => {
      if (block.isEditor || (block.id && (block.id.includes('editor-') || block.id.includes('control-')))) return null;

      if (block.type === 'text') {
        const content = (block.content || '').trim();
        if (!content || content === 'New text' || content.length < 1) return null;
        return { type: 'text', tag: block.tag || 'p', content };
      }

      if (block.type === 'image') {
        const src = block.src?.trim();
        if (!src || (src.startsWith('data:image/') && src.length < 100)) return null;
        return { type: 'image', src };
      }

      if (block.type === 'button') {
        const text = (block.text || '').trim();
        const lowerText = text.toLowerCase();
        if (!text || text.length < 3 || lowerText === 'x' || lowerText.includes('add ') || lowerText.includes('delete') || lowerText.includes('remove') || lowerText.includes('close')) return null;
        return { type: 'button', text, href: block.href === '#' ? '' : (block.href || '') };
      }

      if (block.type === 'form') {
        const html = block.html?.trim();
        if (!html || html.length < 10) return null;
        return { type: 'form', html: html.replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '') };
      }

      return null;
    })
    .filter(Boolean);

  if (cleanBlocks.length === 0) {
    return res.status(400).json({ error: 'No valid content blocks found. Add text, images, buttons, or forms.' });
  }

  landingPages.set(finalShortId, {
    userId: req.user.userId,
    title: title.trim(),
    config: { blocks: cleanBlocks },
    createdAt: landingPages.get(finalShortId)?.createdAt || now,
    updatedAt: now
  });

  res.json({
    success: true,
    shortId: finalShortId,
    url: req.protocol + '://' + req.get('host') + '/p/' + finalShortId
  });
});

// 13. Delete page
app.post('/api/pages/delete', authenticateToken, (req, res) => {
  const { shortId } = req.body;
  const page = landingPages.get(shortId);
  if (!page || page.userId !== req.user.userId) return res.status(404).json({ error: 'Page not found' });
  landingPages.delete(shortId);
  res.json({ success: true });
});

// 14. Public page rendering
app.get('/p/:shortId', (req, res) => {
  const page = landingPages.get(req.params.shortId);
  if (!page) return res.status(404).render('404');
  res.render('landing', { title: page.title, blocks: page.config.blocks });
});

// ==================== FORM-SPECIFIC ROUTES (15-18 + NEW PUBLIC FETCH) ====================

// 15. List user forms
app.get('/api/forms', authenticateToken, (req, res) => {
  const userForms = Array.from(formPages.entries())
    .filter(([_, form]) => form.userId === req.user.userId)
    .map(([shortId, formData]) => ({
      shortId,
      title: formData.title,
      createdAt: formData.createdAt,
      updatedAt: formData.updatedAt,
      url: req.protocol + '://' + req.get('host') + '/f/' + shortId
    }));
  res.json({ forms: userForms });
});

// NEW: PUBLIC fetch form config for editing (fast, no auth — exactly like smav.onrender.com)
app.get('/api/form/:shortId', (req, res) => {
  const formData = formPages.get(req.params.shortId);
  if (!formData) return res.status(404).json({ error: 'Form not found' });
  res.json({
    shortId: req.params.shortId,
    title: formData.title,
    state: formData.state  // full editor state (template, headerColors, placeholders, etc.)
  });
});

// NEW: PUBLIC fetch landing page config for editing (fast, no auth)
app.get('/api/page/:shortId', (req, res) => {
  const page = landingPages.get(req.params.shortId);
  if (!page) return res.status(404).json({ error: 'Page not found' });
  res.json({
    shortId: req.params.shortId,
    title: page.title,
    config: page.config  // full blocks array
  });
});

// 16. Save form (create or edit) — now stores full state instead of extracting HTML
app.post('/api/forms/save', authenticateToken, (req, res) => {
  const { shortId, title, state } = req.body;
  if (!title || !state)
    return res.status(400).json({ error: 'Title and state required' });

  const finalShortId = shortId || uuidv4().slice(0, 8);
  const now = new Date().toISOString();

  // Store the entire editor state (exactly what the client editor sends)
  formPages.set(finalShortId, {
    userId: req.user.userId,
    title: title.trim(),
    state,                         // full state: template, headerText, headerColors, placeholders, etc.
    createdAt: formPages.get(finalShortId)?.createdAt || now,
    updatedAt: now
  });

  res.json({
    success: true,
    shortId: finalShortId,
    url: req.protocol + '://' + req.get('host') + '/f/' + finalShortId
  });
});

// 17. Delete form
app.post('/api/forms/delete', authenticateToken, (req, res) => {
  const { shortId } = req.body;
  const formData = formPages.get(shortId);
  if (!formData || formData.userId !== req.user.userId) return res.status(404).json({ error: 'Form not found' });
  formPages.delete(shortId);
  res.json({ success: true });
});

// 18. Public form page rendering — now reconstructs from saved full state
app.get('/f/:shortId', (req, res) => {
  const formData = formPages.get(req.params.shortId);
  if (!formData) return res.status(404).render('404');

  // Pass the full state to the view so the same rendering logic as the editor can be used
  res.render('form', {
    title: formData.title,
    state: formData.state
  });
});

// ==================== VIEWS & 404 ====================
const viewsDir = path.join(__dirname, 'views');
if (!fs.existsSync(viewsDir)) fs.mkdirSync(viewsDir, { recursive: true });
if (!fs.existsSync(path.join(__dirname, 'public'))) fs.mkdirSync(path.join(__dirname, 'public'), { recursive: true });

const landingEjs = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title><%= title %></title>
  <meta name="description" content="Custom landing page built with Sendm">
  <style>
    :root{--primary:#1564C0;--primary-light:#3485e5;--gray-800:#343a40;--gray-600:#6c757d;}
    *{margin:0;padding:0;box-sizing:border-box;}
    body{font-family:'Segoe UI',Arial,sans-serif;background:#f5f8fc;color:var(--gray-800);line-height:1.7;}
    .container{max-width:700px;margin:40px auto;background:white;border-radius:24px;overflow:hidden;box-shadow:0 20px 60px rgba(0,0,0,0.12);}
    .content{padding:80px 50px;text-align:center;}
    h1{font-size:42px;font-weight:700;margin-bottom:20px;background:linear-gradient(135deg,var(--primary),var(--primary-light));-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;}
    h2{font-size:36px;font-weight:700;margin:40px 0 20px;color:var(--gray-800);}
    p{font-size:19px;color:var(--gray-600);margin-bottom:40px;max-width:600px;margin-left:auto;margin-right:auto;}
    .hero-img{max-width:100%;border-radius:18px;box-shadow:0 15px 40px rgba(0,0,0,0.15);margin:50px 0;}
    .cta{display:inline-block;padding:22px 70px;font-size:21px;font-weight:600;background:var(--primary);color:white;text-decoration:none;border-radius:16px;box-shadow:0 12px 35px rgba(21,100,192,0.4);transition:all .3s;margin-bottom:20px;}
    .cta:hover{background:var(--primary-light);transform:translateY(-5px);box-shadow:0 20px 50px rgba(21,100,192,0.5);}
    .form-block{padding:40px;background:#f9fbff;border-radius:20px;margin:50px 0;border:1px solid #e0e7ff;text-align:left;}
    .form-block h3{margin-bottom:24px;font-size:24px;text-align:center;}
    .form-block input,.form-block button{width:100%;padding:16px;margin:10px 0;border-radius:12px;border:1px solid #ddd;font-size:16px;}
    .form-block button{background:var(--primary);color:white;border:none;font-weight:600;cursor:pointer;}
    .footer{padding:40px;background:#f9f9f9;text-align:center;color:#888;font-size:14px;border-top:1px solid #eee;}
    @media(max-width:640px){.content{padding:60px 30px;}h1{font-size:34px;}.cta{padding:18px 50px;font-size:19px;}}
  </style>
</head>
<body>
  <div class="container">
    <div class="content">
      <% blocks.forEach(block => { %>
        <% if (block.type === 'text') { %>
          <% if (block.tag === 'h1') { %><h1><%= block.content %></h1><% } %>
          <% if (block.tag === 'h2') { %><h2><%= block.content %></h2><% } %>
          <% if (block.tag === 'p') { %><p><%= block.content %></p><% } %>
        <% } else if (block.type === 'image') { %>
          <img src="<%= block.src %>" alt="Image" class="hero-img" loading="lazy">
        <% } else if (block.type === 'button') { %>
          <a href="<%= block.href || '#' %>" class="cta" <%= block.href && block.href.startsWith('http') ? 'target="_blank" rel="noopener"' : '' %>>
            <%= block.text %>
          </a>
        <% } else if (block.type === 'form') { %>
          <div class="form-block"><%- block.html %></div>
        <% } %>
      <% }) %>
    </div>
    <div class="footer">
      © <%= new Date().getFullYear() %> Sendm<br>
      <a href="#" style="color:var(--primary);text-decoration:none;">Unsubscribe</a> • 
      <a href="#" style="color:var(--primary);text-decoration:none;">Privacy</a>
    </div>
  </div>
</body>
</html>`;

const formEjs = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title><%= title %></title>
  <meta name="description" content="Custom form built with Sendm">
  <style>
    :root{--primary:#1564C0;--primary-light:#3485e5;--gray-800:#343a40;--gray-600:#6c757d;}
    *{margin:0;padding:0;box-sizing:border-box;}
    body{font-family:'Segoe UI',Arial,sans-serif;background:#f5f8fc;color:var(--gray-800);line-height:1.7;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px;}
    .form-container{max-width:500px;width:100%;background:white;border-radius:24px;overflow:hidden;box-shadow:0 20px 60px rgba(0,0,0,0.12);padding:40px;}
    .form-block{margin:0;text-align:left;}
    .form-block input{width:100%;padding:16px;margin:10px 0;border-radius:12px;border:1px solid #ddd;font-size:16px;background:#fafbff;transition:all .2s;}
    .form-block input:focus{outline:none;border-color:var(--primary);box-shadow:0 0 0 4px rgba(21,100,192,0.12);}
    .form-block button{width:100%;padding:16px;margin-top:10px;background:var(--primary);color:white;border:none;font-weight:600;cursor:pointer;border-radius:12px;transition:all .3s;box-shadow:0 4px 15px rgba(21,100,192,0.3);}
    .form-block button:hover{background:var(--primary-light);transform:translateY(-2px);box-shadow:0 8px 25px rgba(21,100,192,0.4);}
    .footer{padding:30px 0;background:#f9f9f9;text-align:center;color:#888;font-size:14px;border-top:1px solid #eee;}
    @media(max-width:640px){.form-container{padding:20px;}}
  </style>
</head>
<body>
  <div class="form-container">
    <div class="form-block">
      <script>
        // Reconstruct the form using the saved state (same logic as your editor preview)
        const state = <%- JSON.stringify(state || {}) %>;

        // Example reconstruction (you can expand this to match your exact editor preview)
        document.write('<h2 style="text-align:center;">' + (state.headerText || 'My Form') + '</h2>');
        document.write('<p style="text-align:center;color:#555;">' + (state.subheaderText || 'Fill the form') + '</p>');

        // Add inputs based on placeholders
        if (state.placeholders && Array.isArray(state.placeholders)) {
          state.placeholders.forEach(p => {
            document.write('<input type="text" placeholder="' + p.placeholder + '" style="box-shadow:0 0 0 2px #000;">');
          });
        }

        // Button
        document.write('<button style="background:' + (state.buttonColor || 'linear-gradient(45deg,#00b7ff,#0078ff)') + ';color:' + (state.buttonTextColor || '#fff') + ';">' + (state.buttonText || 'Submit') + '</button>');
      </script>
    </div>
    <div class="footer">
      © <%= new Date().getFullYear() %> Sendm
    </div>
  </div>
</body>
</html>`;

const notFoundEjs = `<!DOCTYPE html><html><head><title>404</title><style>body{font-family:sans-serif;background:#f8f9fa;text-align:center;padding:100px;color:#333;}h1{font-size:80px;}p{font-size:20px;}</style></head><body><h1>404</h1><p>Page not found</p></body></html>`;

// Ensure clean views on startup
fs.writeFileSync(path.join(viewsDir, 'landing.ejs'), landingEjs);
fs.writeFileSync(path.join(viewsDir, 'form.ejs'), formEjs);
fs.writeFileSync(path.join(viewsDir, '404.ejs'), notFoundEjs);
console.log('Clean views ensured: landing.ejs, form.ejs, 404.ejs');

app.use((req, res) => res.status(404).render('404'));

app.listen(PORT, () => {
  console.log(`\nSENDEM SERVER LIVE & UPDATED`);
  console.log(`http://localhost:${PORT}`);
  console.log(`Landing Pages → http://localhost:${PORT}/p/xxxxxx`);
  console.log(`Forms → http://localhost:${PORT}/f/xxxxxx`);
  console.log(`Public editing fetch → GET /api/form/:id or /api/page/:id (no auth)`);
  console.log(`Save requires auth\n`);
});
