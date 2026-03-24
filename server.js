require('dotenv').config();
const express    = require('express');
const http       = require('http');
const { Server } = require('socket.io');
const mongoose   = require('mongoose');
const bcrypt     = require('bcrypt');
const session    = require('express-session');
const MongoStore = require('connect-mongo');
const nodemailer = require('nodemailer');
const cors       = require('cors');

// ─────────────────────────────────────────
// App setup
// ─────────────────────────────────────────
const app    = express();
const server = http.createServer(app);

const FRONTEND_URL = process.env.FRONTEND_URL || 'http://localhost:5500';

const io = new Server(server, {
  cors: { origin: FRONTEND_URL, credentials: true, methods: ['GET','POST'] }
});

// ─────────────────────────────────────────
// MongoDB Schemas
// ─────────────────────────────────────────
const userSchema = new mongoose.Schema({
  username:     { type: String, required: true, unique: true, trim: true },
  email:        { type: String, required: true, lowercase: true, trim: true },
  passwordHash: { type: String, required: true },
  joinedAt:     { type: Date, default: Date.now },
  profile: {
    color:       { type: String, default: '' },
    handle:      { type: String, default: '' },
    bio:         { type: String, default: '' },
    status:      { type: String, default: 'online' },
    avatarUrl:   { type: String, default: null },
    avatarEmoji: { type: String, default: '' },
    bannerUrl:   { type: String, default: null },
  }
});

const messageSchema = new mongoose.Schema({
  msgId:             { type: String, required: true, unique: true },
  room:              { type: String, required: true, index: true },
  author:            { type: String, required: true },
  authorColor:       String,
  authorHandle:      String,
  authorAvatarUrl:   String,
  authorAvatarEmoji: String,
  type:              { type: String, default: 'text' },
  text:              String,
  url:               String,
  dur:               Number,
  reactions:         { type: Object, default: {} },
  replyTo:           Object,
  system:            Boolean,
  time:              String,
  createdAt:         { type: Date, default: Date.now }
});

const otpSchema = new mongoose.Schema({
  username:  { type: String, required: true },
  otp:       { type: String, required: true },
  expiresAt: { type: Date, required: true },
  verified:  { type: Boolean, default: false }
});
otpSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

const User    = mongoose.model('User',    userSchema);
const Message = mongoose.model('Message', messageSchema);
const OTP     = mongoose.model('OTP',     otpSchema);

// ─────────────────────────────────────────
// Middleware
// ─────────────────────────────────────────
app.use(express.json({ limit: '12mb' })); // allow base64 image uploads

app.use(cors({
  origin: FRONTEND_URL,
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type']
}));

const sessionMiddleware = session({
  secret:            process.env.SESSION_SECRET || 'rooms-dev-secret-change-me',
  resave:            false,
  saveUninitialized: false,
  store: MongoStore.create({
    mongoUrl:     process.env.MONGODB_URI,
    ttl:          30 * 24 * 60 * 60, // 30 days
    autoRemove:   'native'
  }),
  cookie: {
    secure:   process.env.NODE_ENV === 'production',
    httpOnly: true,
    sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
    maxAge:   30 * 24 * 60 * 60 * 1000 // 30 days
  }
});

app.use(sessionMiddleware);

// Share express-session with Socket.io
io.use((socket, next) => {
  sessionMiddleware(socket.request, {}, next);
});

// ─────────────────────────────────────────
// Email (Gmail App Password)
// ─────────────────────────────────────────
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.GMAIL_USER,
    pass: process.env.GMAIL_APP_PASSWORD
  }
});

function generateOTP() {
  return String(Math.floor(100000 + Math.random() * 900000));
}

async function sendOTPEmail(to, otp, username) {
  await transporter.sendMail({
    from:    `"Rooms Chat" <${process.env.GMAIL_USER}>`,
    to,
    subject: '🔐 Your Rooms Password Reset Code',
    html: `
<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"/></head>
<body style="margin:0;padding:0;background:#F7F5F0;font-family:'Helvetica Neue',Helvetica,Arial,sans-serif">
  <table width="100%" cellpadding="0" cellspacing="0">
    <tr><td align="center" style="padding:40px 20px">
      <table width="440" cellpadding="0" cellspacing="0" style="background:#fff;border-radius:20px;overflow:hidden;box-shadow:0 8px 40px rgba(0,0,0,.1)">
        <tr>
          <td style="background:linear-gradient(135deg,#D4522A,#7C3AED);padding:32px;text-align:center">
            <span style="font-size:32px">🔒</span>
            <h1 style="color:#fff;font-size:22px;margin:8px 0 0;letter-spacing:-0.5px">Password Reset</h1>
          </td>
        </tr>
        <tr>
          <td style="padding:32px">
            <p style="color:#1A1A18;font-size:15px;margin:0 0 12px">Hi <strong>${username}</strong>,</p>
            <p style="color:#7A7670;font-size:14px;line-height:1.6;margin:0 0 24px">
              We received a request to reset your password. Use the code below to continue.
              This code expires in <strong>15 minutes</strong>.
            </p>
            <div style="background:#FFF8F6;border:2px dashed #D4522A;border-radius:14px;padding:24px;text-align:center;margin-bottom:24px">
              <p style="color:#A8A49D;font-size:11px;letter-spacing:1.5px;text-transform:uppercase;margin:0 0 8px;font-weight:600">YOUR VERIFICATION CODE</p>
              <div style="font-size:42px;font-weight:800;letter-spacing:10px;color:#D4522A;font-family:monospace;line-height:1">${otp}</div>
            </div>
            <p style="color:#A8A49D;font-size:12px;line-height:1.6;margin:0">
              If you didn't request this, you can safely ignore this email — your account is still secure.
            </p>
          </td>
        </tr>
        <tr>
          <td style="background:#F7F5F0;padding:16px 32px;text-align:center">
            <p style="color:#A8A49D;font-size:11px;margin:0">Rooms Chat · This is an automated message</p>
          </td>
        </tr>
      </table>
    </td></tr>
  </table>
</body>
</html>`
  });
}

// ─────────────────────────────────────────
// Auth Middleware
// ─────────────────────────────────────────
function requireAuth(req, res, next) {
  if (!req.session.username) {
    return res.status(401).json({ error: 'Not authenticated' });
  }
  next();
}

// ─────────────────────────────────────────
// REST Routes
// ─────────────────────────────────────────

// Health check (Render pings this to keep the service warm)
app.get('/api/health', (req, res) => res.json({ ok: true, ts: Date.now() }));

// Get current session / user
app.get('/api/session', async (req, res) => {
  if (!req.session.username) return res.json({ user: null });
  try {
    const user = await User.findOne({ username: req.session.username }).lean();
    if (!user) { req.session.destroy(() => {}); return res.json({ user: null }); }
    return res.json({
      user: {
        username: user.username,
        email:    user.email,
        joinedAt: user.joinedAt,
        profile:  user.profile
      }
    });
  } catch (e) {
    console.error('/api/session error:', e);
    return res.status(500).json({ error: 'Server error' });
  }
});

// Register
app.post('/api/register', async (req, res) => {
  try {
    const { username, email, password } = req.body;

    // Validation
    if (!username || !email || !password)
      return res.status(400).json({ error: 'All fields required' });
    if (username.length < 2 || username.length > 24)
      return res.status(400).json({ error: 'Username must be 2–24 characters' });
    if (!/^[a-zA-Z0-9_ .'-]+$/.test(username))
      return res.status(400).json({ error: 'Username has invalid characters' });
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))
      return res.status(400).json({ error: 'Enter a valid email address' });
    if (password.length < 6)
      return res.status(400).json({ error: 'Password must be at least 6 characters' });

    const exists = await User.findOne({ username });
    if (exists) return res.status(409).json({ error: 'Username already taken' });

    const passwordHash = await bcrypt.hash(password, 12);
    const handle = '@' + username.toLowerCase().replace(/\s+/g, '');

    const user = await User.create({
      username, email, passwordHash,
      joinedAt: new Date(),
      profile: { color: '', handle, bio: '', status: 'online', avatarUrl: null, avatarEmoji: '' }
    });

    req.session.username = username;
    return res.json({
      user: { username, email, joinedAt: user.joinedAt, profile: user.profile }
    });
  } catch (e) {
    console.error('/api/register error:', e);
    return res.status(500).json({ error: 'Server error' });
  }
});

// Login
app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password)
      return res.status(400).json({ error: 'Username and password are required' });

    const user = await User.findOne({ username }).lean();
    if (!user) return res.status(401).json({ error: 'Account not found' });

    const match = await bcrypt.compare(password, user.passwordHash);
    if (!match) return res.status(401).json({ error: 'Incorrect password' });

    req.session.username = username;
    return res.json({
      user: { username, email: user.email, joinedAt: user.joinedAt, profile: user.profile }
    });
  } catch (e) {
    console.error('/api/login error:', e);
    return res.status(500).json({ error: 'Server error' });
  }
});

// Logout
app.post('/api/logout', (req, res) => {
  req.session.destroy(() => {});
  res.json({ ok: true });
});

// Update profile
app.put('/api/profile', requireAuth, async (req, res) => {
  try {
    const { color, handle, bio, status, avatarUrl, avatarEmoji, bannerUrl } = req.body;
    const user = await User.findOne({ username: req.session.username });
    if (!user) return res.status(404).json({ error: 'User not found' });

    user.profile = { color, handle, bio, status, avatarUrl, avatarEmoji, bannerUrl };
    await user.save();
    return res.json({ ok: true, profile: user.profile });
  } catch (e) {
    console.error('/api/profile error:', e);
    return res.status(500).json({ error: 'Server error' });
  }
});

// ── Forgot password: Step 1 — find account & send OTP email ──
app.post('/api/forgot-password', async (req, res) => {
  try {
    const { username } = req.body;
    if (!username) return res.status(400).json({ error: 'Username is required' });

    const user = await User.findOne({ username }).lean();
    if (!user) return res.status(404).json({ error: 'No account found with that username' });

    // Generate a fresh OTP (delete any existing)
    await OTP.deleteMany({ username });
    const otp       = generateOTP();
    const expiresAt = new Date(Date.now() + 15 * 60 * 1000); // 15 min
    await OTP.create({ username, otp, expiresAt });

    // Send email
    await sendOTPEmail(user.email, otp, username);

    // Return masked email (e.g. "jo***@gmail.com")
    const parts  = user.email.split('@');
    const masked = parts[0].slice(0, 2) + '***@' + parts[1];

    return res.json({ masked });
  } catch (e) {
    console.error('/api/forgot-password error:', e);
    return res.status(500).json({
      error: 'Failed to send email. Check your Gmail App Password in server config.'
    });
  }
});

// ── Forgot password: Step 2 — verify OTP ──
app.post('/api/verify-otp', async (req, res) => {
  try {
    const { username, otp } = req.body;
    const record = await OTP.findOne({ username });
    if (!record)              return res.status(400).json({ error: 'No OTP found. Request a new code.' });
    if (new Date() > record.expiresAt) return res.status(400).json({ error: 'Code expired. Request a new one.' });
    if (record.otp !== otp)   return res.status(400).json({ error: 'Incorrect code. Check your email.' });

    record.verified = true;
    await record.save();
    return res.json({ ok: true });
  } catch (e) {
    console.error('/api/verify-otp error:', e);
    return res.status(500).json({ error: 'Server error' });
  }
});

// ── Forgot password: Step 3 — reset password ──
app.post('/api/reset-password', async (req, res) => {
  try {
    const { username, otp, newPassword } = req.body;
    if (!newPassword || newPassword.length < 6)
      return res.status(400).json({ error: 'Password must be at least 6 characters' });

    const record = await OTP.findOne({ username });
    if (!record || !record.verified || record.otp !== otp || new Date() > record.expiresAt)
      return res.status(400).json({ error: 'Invalid or expired code. Please start over.' });

    const passwordHash = await bcrypt.hash(newPassword, 12);
    await User.updateOne({ username }, { passwordHash });
    await OTP.deleteMany({ username });

    const user = await User.findOne({ username }).lean();
    req.session.username = username;
    return res.json({
      user: { username, email: user.email, joinedAt: user.joinedAt, profile: user.profile }
    });
  } catch (e) {
    console.error('/api/reset-password error:', e);
    return res.status(500).json({ error: 'Server error' });
  }
});

// Get messages for a room (last 150)
app.get('/api/messages/:room', requireAuth, async (req, res) => {
  try {
    const messages = await Message
      .find({ room: req.params.room })
      .sort({ createdAt: 1 })
      .limit(150)
      .lean();
    return res.json({ messages });
  } catch (e) {
    console.error('/api/messages error:', e);
    return res.status(500).json({ error: 'Server error' });
  }
});

// ─────────────────────────────────────────
// Socket.io — Real-time
// ─────────────────────────────────────────
const activeUsers = new Map(); // socketId → { username, room }

io.on('connection', (socket) => {
  const username = socket.request.session?.username;
  if (!username) {
    socket.disconnect();
    return;
  }

  console.log(`[socket] ${username} connected (${socket.id})`);
  activeUsers.set(socket.id, { username, room: 'general' });

  // ── Join a room ──
  socket.on('join_room', (room) => {
    const prev = activeUsers.get(socket.id)?.room;
    if (prev && prev !== room) {
      socket.leave(prev);
      io.to(prev).emit('presence_update', getPresence(prev));
    }
    socket.join(room);
    activeUsers.get(socket.id).room = room;
    io.to(room).emit('presence_update', getPresence(room));
  });

  // ── Send a message ──
  socket.on('send_message', async ({ room, msg }) => {
    try {
      // Save to DB
      await Message.create({
        msgId:             msg.id,
        room,
        author:            username,
        authorColor:       msg.color,
        authorHandle:      msg.handle,
        authorAvatarUrl:   msg.avatarUrl,
        authorAvatarEmoji: msg.avatarEmoji,
        type:              msg.type || 'text',
        text:              msg.text,
        url:               msg.url,
        dur:               msg.dur,
        reactions:         msg.reactions || {},
        replyTo:           msg.replyTo,
        system:            msg.system,
        time:              msg.time
      });
      // Broadcast to everyone else in the room (sender already has it locally)
      socket.to(room).emit('message', { room, msg });
    } catch (e) {
      // Duplicate ID or other error — skip silently
      if (e.code !== 11000) console.error('[socket] send_message error:', e);
    }
  });

  // ── System messages (join/leave announcements etc.) ──
  socket.on('system_message', async ({ room, msg }) => {
    try {
      await Message.create({ msgId: msg.id, room, author: 'system', type: 'text', text: msg.text, system: true, time: msg.time });
      socket.to(room).emit('message', { room, msg });
    } catch (e) { /* ignore duplicates */ }
  });

  // ── Typing indicator ──
  socket.on('typing', ({ room, name }) => {
    socket.to(room).emit('typing', { name });
  });

  // ── New room created ──
  socket.on('new_room', ({ name, topic }) => {
    socket.broadcast.emit('new_room', { name, topic });
  });

  // ── Reaction ──
  socket.on('reaction', ({ room, msgId, emoji, count, mine }) => {
    socket.to(room).emit('reaction', { msgId, emoji, count, mine });
    // Update DB reactions
    Message.findOne({ msgId }).then(msg => {
      if (!msg) return;
      if (!msg.reactions) msg.reactions = {};
      msg.reactions[emoji] = { count, mine: false };
      msg.markModified('reactions');
      msg.save().catch(() => {});
    });
  });

  // ── Profile update ──
  socket.on('profile_update', (data) => {
    socket.broadcast.emit('profile_update', data);
  });

  // ── Disconnect ──
  socket.on('disconnect', () => {
    const room = activeUsers.get(socket.id)?.room;
    activeUsers.delete(socket.id);
    if (room) io.to(room).emit('presence_update', getPresence(room));
    console.log(`[socket] ${username} disconnected`);
  });
});

function getPresence(room) {
  const users = [];
  for (const [, data] of activeUsers) {
    if (data.room === room) users.push(data.username);
  }
  return users;
}

// ─────────────────────────────────────────
// Start server
// ─────────────────────────────────────────
const PORT = process.env.PORT || 4000;

mongoose
  .connect(process.env.MONGODB_URI)
  .then(() => {
    console.log('✅ MongoDB connected');
    server.listen(PORT, () => {
      console.log(`✅ Server running on port ${PORT}`);
      console.log(`   Frontend allowed: ${FRONTEND_URL}`);
    });
  })
  .catch((err) => {
    console.error('❌ MongoDB connection failed:', err.message);
    process.exit(1);
  });
