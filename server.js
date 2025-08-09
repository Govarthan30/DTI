// server.js
require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const bodyParser = require("body-parser");
const nodemailer = require("nodemailer");
const crypto = require("crypto");
const qrcode = require("qrcode");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const cron = require("node-cron");

const app = express();
app.use(cors());
app.use(bodyParser.json());

// ---------- config ----------
const PORT = process.env.PORT || 5000;
const MONGO_URI = process.env.MONGO_URI;
const MAIL_USER = process.env.MAIL_USER;
const MAIL_PASS = process.env.MAIL_PASS;
const JWT_SECRET = process.env.JWT_SECRET || "change_this_secret";
const HARDWARE_KEY = process.env.HARDWARE_KEY || "change_this_hardware_key";

// check env
if (!MONGO_URI) {
  console.error("MONGO_URI is not set in .env");
  process.exit(1);
}
if (!MAIL_USER || !MAIL_PASS) {
  console.warn("MAIL_USER / MAIL_PASS not set — OTP emails will fail.");
}

// ---------- connect mongo ----------
mongoose
  .connect(MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log("MongoDB connected"))
  .catch((err) => {
    console.error("MongoDB connection error:", err);
    process.exit(1);
  });

// ---------- models ----------
const UserSchema = new mongoose.Schema({
  email: { type: String, unique: true, required: true },
  passwordHash: String,   // hashed password
  verified: { type: Boolean, default: false }, // after OTP verify
  otp: String,
  otpExpiresAt: Date,
  createdAt: { type: Date, default: Date.now },
});
const User = mongoose.model("User", UserSchema);

const OrderSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  userEmail: String,
  items: [
    {
      itemId: String,
      name: String,
      qty: Number,
      price: Number,
    },
  ],
  total: Number,
  paid: { type: Boolean, default: false },
  publicRef: { type: String, index: true, unique: true }, // shown in QR
  secretToken: String, // never shown in QR
  expiresAt: Date,
  used: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now },
});
const Order = mongoose.model("Order", OrderSchema);

// ---------- mailer ----------
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: MAIL_USER,
    pass: MAIL_PASS,
  },
});

// ---------- helpers ----------
function genSecret(len = 32) {
  return crypto.randomBytes(len).toString("hex");
}
function genRef(len = 10) {
  return crypto.randomBytes(Math.ceil(len / 2)).toString("hex").slice(0, len);
}
function nowPlusMinutes(min) {
  return new Date(Date.now() + min * 60 * 1000);
}
function authMiddleware(req, res, next) {
  const h = req.headers.authorization;
  if (!h) return res.status(401).json({ error: "Missing Authorization header" });
  const token = h.replace("Bearer ", "");
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = payload; // contains email and userId if we include it
    next();
  } catch (err) {
    return res.status(401).json({ error: "Invalid token" });
  }
}

// ---------- ROUTES ----------

// health
app.get("/", (req, res) => res.json({ ok: true }));

// 1) Signup: create user with email+password and send OTP
app.post("/api/auth/signup", async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: "email & password required" });

    const existing = await User.findOne({ email });
    if (existing) return res.status(400).json({ error: "User already exists; verify or login" });

    const passwordHash = await bcrypt.hash(password, 10);
    const otp = String(Math.floor(100000 + Math.random() * 900000));
    const otpExpiresAt = nowPlusMinutes(10);

    const user = await User.create({ email, passwordHash, otp, otpExpiresAt, verified: false });

    // send OTP email (best-effort)
    if (MAIL_USER && MAIL_PASS) {
      transporter.sendMail({
        from: MAIL_USER,
        to: email,
        subject: "QuickServe - Your OTP",
        text: `Your OTP is ${otp}. It is valid for 10 minutes.`,
      }).catch(err => console.error("sendMail error:", err));
    }

    return res.json({ message: "Signup successful, OTP sent to email (verify to activate)" });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "server error" });
  }
});

// 2) Verify OTP -> activate account & return JWT
app.post("/api/auth/verify-otp", async (req, res) => {
  try {
    const { email, otp } = req.body;
    if (!email || !otp) return res.status(400).json({ error: "email & otp required" });

    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ error: "user not found" });

    if (user.verified) {
      return res.status(400).json({ error: "user already verified; please login" });
    }

    if (!user.otp || user.otp !== otp || new Date() > user.otpExpiresAt) {
      return res.status(401).json({ error: "invalid or expired otp" });
    }

    user.verified = true;
    user.otp = null;
    user.otpExpiresAt = null;
    await user.save();

    const token = jwt.sign({ userId: user._id, email: user.email }, JWT_SECRET, { expiresIn: "1d" });
    return res.json({ token, message: "verified and logged in" });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "server error" });
  }
});

// 3) Login with email+password (requires verified)
app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: "email & password required" });

    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ error: "user not found" });

    const ok = await bcrypt.compare(password, user.passwordHash || "");
    if (!ok) return res.status(401).json({ error: "invalid credentials" });

    if (!user.verified) return res.status(403).json({ error: "email not verified; verify OTP first" });

    const token = jwt.sign({ userId: user._id, email: user.email }, JWT_SECRET, { expiresIn: "1d" });
    return res.json({ token });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "server error" });
  }
});

// 4) Send OTP again (for recovery)
app.post("/api/auth/resend-otp", async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: "email required" });

    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ error: "user not found" });

    const otp = String(Math.floor(100000 + Math.random() * 900000));
    user.otp = otp;
    user.otpExpiresAt = nowPlusMinutes(10);
    await user.save();

    if (MAIL_USER && MAIL_PASS) {
      transporter.sendMail({
        from: MAIL_USER,
        to: email,
        subject: "QuickServe - Your OTP (resend)",
        text: `Your OTP is ${otp}. It is valid for 10 minutes.`,
      }).catch(err => console.error("sendMail error:", err));
    }

    return res.json({ message: "OTP resent to email" });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "server error" });
  }
});

// 5) Create order (user must be authenticated). This marks paid = true per your flow.
app.post("/api/orders", authMiddleware, async (req, res) => {
  try {
    const userId = req.user.userId;
    const userEmail = req.user.email;
    const { items } = req.body;
    if (!items || !Array.isArray(items) || items.length === 0) {
      return res.status(400).json({ error: "items array required" });
    }

    const total = items.reduce((s, it) => s + (it.price || 0) * (it.qty || 1), 0);

    // Create secure token + public ref
    const secretToken = genSecret(32);
    let publicRef;
    // ensure unique publicRef
    do {
      publicRef = genRef(10);
    } while (await Order.findOne({ publicRef }));

    const expiresAt = nowPlusMinutes(30);

    const order = await Order.create({
      userId,
      userEmail,
      items,
      total,
      paid: true, // per your flow
      publicRef,
      secretToken,
      expiresAt,
    });

    // QR contains only the public ref JSON
    const qrPayload = JSON.stringify({ ref: publicRef });
    const qrDataUrl = await qrcode.toDataURL(qrPayload);

    return res.json({
      message: "order created",
      orderId: order._id,
      publicRef,
      qrDataUrl,
      expiresAt,
    });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "server error" });
  }
});

// 6) Get user's order history
app.get("/api/orders/history", authMiddleware, async (req, res) => {
  try {
    const userId = req.user.userId;
    const orders = await Order.find({ userId }).sort({ createdAt: -1 }).lean();
    return res.json({ orders });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "server error" });
  }
});

// 7) Get single order (user-owned)
app.get("/api/orders/:orderId", authMiddleware, async (req, res) => {
  try {
    const userId = req.user.userId;
    const { orderId } = req.params;
    const order = await Order.findById(orderId);
    if (!order) return res.status(404).json({ error: "order not found" });
    if (String(order.userId) !== String(userId)) return res.status(403).json({ error: "forbidden" });
    return res.json({ order });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "server error" });
  }
});

// 8) Hardware sync: returns active tokens (secretToken + ref + order data) — protected by HARDWARE_KEY header
app.get("/api/hardware/sync", async (req, res) => {
  try {
    const key = req.headers["x-hardware-key"];
    if (!key || key !== HARDWARE_KEY) return res.status(401).json({ error: "invalid hardware key" });

    const now = new Date();
    const tokens = await Order.find({
      used: false,
      expiresAt: { $gt: now },
    }).select("publicRef secretToken expiresAt userEmail items total createdAt").lean();

    // return tokens for hardware to cache locally
    return res.json({ tokens });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "server error" });
  }
});

// 9) Hardware redeem: validate ref + secretToken (or online verification), mark used and return order
app.post("/api/hardware/redeem", async (req, res) => {
  try {
    const { ref, secretToken } = req.body;
    if (!ref) return res.status(400).json({ error: "ref required" });

    const tokenDoc = await Order.findOne({ publicRef: ref });
    if (!tokenDoc) return res.status(404).json({ error: "ref not found" });
    if (tokenDoc.used) return res.status(409).json({ error: "token already used" });
    if (new Date() > tokenDoc.expiresAt) return res.status(410).json({ error: "token expired" });

    if (secretToken) {
      if (secretToken !== tokenDoc.secretToken) return res.status(401).json({ error: "invalid secret token" });
    } else {
      // if no secretToken provided, optionally allow (less secure) — here we require secretToken for hardware redeem
      return res.status(400).json({ error: "secretToken required" });
    }

    // mark used and respond with order details
    tokenDoc.used = true;
    await tokenDoc.save();

    return res.json({
      message: "valid",
      order: {
        id: tokenDoc._id,
        userEmail: tokenDoc.userEmail,
        items: tokenDoc.items,
        total: tokenDoc.total,
        createdAt: tokenDoc.createdAt,
      },
    });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "server error" });
  }
});

// 10) Admin export orders as CSV (basic) — no auth added here; in production add admin auth
app.get("/api/admin/export-orders", async (req, res) => {
  try {
    const orders = await Order.find().lean();
    const fields = ["_id", "userEmail", "total", "paid", "used", "createdAt", "expiresAt"];
    const csvRows = [fields.join(",")];
    orders.forEach(o => {
      const row = fields.map(f => {
        const v = o[f];
        if (v === undefined || v === null) return "";
        return typeof v === "object" ? JSON.stringify(v).replace(/"/g, '""') : String(v).replace(/"/g, '""');
      });
      csvRows.push(row.join(","));
    });
    const csv = csvRows.join("\n");
    res.header("Content-Type", "text/csv");
    res.attachment("orders.csv");
    return res.send(csv);
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "server error" });
  }
});

// ---------- cleanup cron: delete expired tokens/orders ----------
// runs every minute, deletes orders older than their expiry (or mark expired)
cron.schedule("*/1 * * * *", async () => {
  try {
    const now = new Date();
    const resDel = await Order.deleteMany({ expiresAt: { $lt: now } });
    if (resDel.deletedCount > 0) {
      console.log(`Cleanup: removed ${resDel.deletedCount} expired orders/tokens`);
    }
  } catch (err) {
    console.error("cleanup error:", err);
  }
});

// start server
app.listen(PORT, () => console.log(`Server running on ${PORT}`));
