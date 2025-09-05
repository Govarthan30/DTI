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
const fs = require("fs");
const path = require("path");
const Razorpay = require("razorpay");
const router = express.Router();
const offlineFile = path.join(process.cwd(), "offlineClaims.json");

const razorpay = new Razorpay({
  key_id: process.env.RAZORPAY_KEY_ID,
  key_secret: process.env.RAZORPAY_KEY_SECRET,
});

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
const TOKEN_SIGN_KEY = process.env.TOKEN_SIGN_KEY || "change_this_token_sign_key";

// local file path for downloadable snapshot
const TOKENS_FILE_PATH = path.join(__dirname, "tokens.json");

// check env
if (!MONGO_URI) {
  console.error("MONGO_URI is not set in .env");
  process.exit(1);
}
if (!MAIL_USER || !MAIL_PASS) {
  console.warn("MAIL_USER / MAIL_PASS not set — OTP emails will fail.");
}
if (!HARDWARE_KEY) {
  console.warn("HARDWARE_KEY not set — hardware endpoints will be insecure in prod.");
}
if (!TOKEN_SIGN_KEY) {
  console.warn("TOKEN_SIGN_KEY not set — token signatures use default key (insecure for prod).");
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
function requireHardwareKey(req, res) {
  const key = req.headers["x-hardware-key"];
  if (!key || key !== HARDWARE_KEY) {
    res.status(401).json({ error: "invalid hardware key" });
    return null;
  }
  return true;
}

// HMAC signer for a token entry (fields must match exactly on client verify)
function signTokenEntry({ publicRef, expiresAt, createdAt }) {
  const payload = `${publicRef}|${new Date(expiresAt).toISOString()}|${new Date(createdAt).toISOString()}`;
  return crypto.createHmac("sha256", TOKEN_SIGN_KEY).update(payload).digest("hex");
}

// Build the in-memory list of active token entries with signatures
async function buildActiveTokenEntries(limit = null) {
  const now = new Date();
  let q = Order.find({ used: false, expiresAt: { $gt: now } })
    .select("publicRef expiresAt createdAt userEmail items total")
    .sort({ createdAt: -1 });
  if (limit && Number.isInteger(limit) && limit > 0) q = q.limit(limit);

  const docs = await q.lean();
  return docs.map(d => {
    const entry = {
      publicRef: d.publicRef,
      // NOTE: for offline trust you can omit secretToken from snapshot.
      // If you need stronger offline auth, include a masked/hashed token.
      expiresAt: d.expiresAt,
      createdAt: d.createdAt,
      userEmail: d.userEmail,
      items: d.items,
      total: d.total,
    };
    return { ...entry, signature: signTokenEntry(entry) };
  });
}

// Write snapshot file to disk (so hardware can download)
async function updateTokensFile(limit = null) {
  const tokens = await buildActiveTokenEntries(limit);
  const snapshot = {
    generatedAt: new Date().toISOString(),
    count: tokens.length,
    tokens,
  };
  fs.writeFileSync(TOKENS_FILE_PATH, JSON.stringify(snapshot, null, 2));
  return snapshot;
}

// ---------- ROUTES ----------

// health
app.get("/", (req, res) => res.json({ ok: true }));

// 1) Signup
app.post("/api/auth/signup", async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: "email & password required" });

    const existing = await User.findOne({ email });
    if (existing) return res.status(400).json({ error: "User already exists; verify or login" });

    const passwordHash = await bcrypt.hash(password, 10);
    const otp = String(Math.floor(100000 + Math.random() * 900000));
    const otpExpiresAt = nowPlusMinutes(10);

    await User.create({ email, passwordHash, otp, otpExpiresAt, verified: false });

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

// 2) Verify OTP
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

// 3) Login
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

// 4) Resend OTP
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
console.log("=== /api/orders route hit ===");

// 5) Create order
app.post("/api/orders", authMiddleware, async (req, res) => {
  console.log("=== /api/orders route hit ===");
  console.log("User (from authMiddleware):", req.user);
  console.log("Request Body:", req.body);

  try {
    const userId = req.user.userId;
    const userEmail = req.user.email;
    const { items } = req.body;

    console.log("=== Validating request body ===");
    if (!items || !Array.isArray(items) || items.length === 0) {
      console.warn("Invalid request: items array required");
      return res.status(400).json({ error: "items array required" });
    }

    const total = items.reduce((s, it) => s + (it.price || 0) * (it.qty || 1), 0);
    console.log("=== Order total calculated:", total, "===");

    console.log("=== Generating tokens ===");
    const secretToken = genSecret(32);
    let publicRef;
    let attempts = 0;
    const maxAttempts = 5;
    do {
      publicRef = genRef(10);
      attempts++;
      if (attempts > maxAttempts) {
        console.error("Failed to generate unique publicRef after", maxAttempts, "attempts");
        return res.status(500).json({ error: "Failed to generate unique order reference" });
      }
    } while (await Order.findOne({ publicRef }).catch(err => {
       console.error("Error checking for existing publicRef:", err);
       // If DB check fails, don't proceed
       throw err;
    }));
    console.log("=== Generated unique publicRef:", publicRef, "===");

    const expiresAt = nowPlusMinutes(30);
    console.log("=== Order expires at:", expiresAt.toISOString(), "===");

    console.log("=== Creating order in DB ===");
    const order = await Order.create({
      userId,
      userEmail,
      items,
      total,
      paid: true, // Assuming paid after successful Razorpay verification (adjust if needed pre-payment)
      publicRef,
      secretToken,
      expiresAt,
    });
    console.log("=== Order created successfully, ID:", order._id, "===");

    // QR code payload
    console.log("=== Generating QR Code ===");
    const qrPayload = JSON.stringify({ ref: publicRef, token: secretToken });
    const qrDataUrl = await qrcode.toDataURL(qrPayload);
    console.log("=== QR Code generated ===");

    try {
      console.log("=== Updating tokens snapshot file ===");
      await updateTokensFile();
      console.log("=== Tokens snapshot file updated ===");
    } catch (e) {
      console.warn("Snapshot refresh failed:", e.message);
    }


    // 📧 Send mail with QR
    console.log("=== Preparing to send QR Email ===");
    console.log("User Email (userEmail):", userEmail);
    console.log("MAIL_USER env var set:", !!MAIL_USER);
    console.log("MAIL_PASS env var set (length check):", MAIL_PASS ? `Yes (${MAIL_PASS.length} chars)` : "No");

    let emailSent = false; // Flag to track email status
    if (!MAIL_USER || !MAIL_PASS) {
      console.warn("Mail credentials missing – skipping email.");
    } else {
      console.log("=== Attempting to send QR Email ===");
      try {
        // Note: transporter.verify() is often not needed on every send if connection is stable.
        // Uncomment the next two lines if you suspect SMTP connection issues.
        // await transporter.verify();
        // console.log("✅ SMTP server verified and ready");

        const mailOptions = {
          from: MAIL_USER,
          to: userEmail,
          subject: "Your QuickServe Order QR Code",
          html: `
            <p>Thank you for your order 🎉</p>
            <p>Order Ref: <b>${publicRef}</b></p>
            <p>Total: ₹${total}</p>
            <p>This QR code is valid until <b>${expiresAt.toLocaleString()}</b></p>
            <p><img src="cid:orderqr" alt="QR Code" /></p>
          `,
          attachments: [
            {
              filename: `order-${publicRef}.png`,
              content: qrDataUrl.split("base64,")[1],
              encoding: "base64",
              cid: "orderqr" // embed inline in HTML
            }
          ],
        };

        console.log("=== Mail Options Prepared ===");
        const info = await transporter.sendMail(mailOptions);
        console.log("📧 QR Mail sent successfully. Message ID:", info.messageId);
        emailSent = true; // Set flag on success

      } catch (err) {
        // **** This is the key part for debugging - ensure it logs ****
        console.error("❌ QR Mail send error:", err);
        // Depending on requirements, you might want to return an error to the client
        // if the email is critical. For now, we log and continue.
      }
    }

    // Determine final message based on email status
    const responseMessage = emailSent
      ? "order created and email sent"
      : "order created (but email with QR failed to send)";

    console.log("=== Sending final response ===");
    return res.json({
      message: responseMessage,
      orderId: order._id,
      publicRef,
      qrDataUrl, // Always send back QR data, frontend can use if email failed
      expiresAt,
    });

  } catch (err) {
    // **** CRITICAL: Make sure this outer catch logs the error ****
    console.error("=== UNHANDLED ERROR in /api/orders route:", err);
    // Send a generic error response to the client
    return res.status(500).json({ error: "Failed to create order. Please try again later." });
  }
});


console.log("=== /api/orders/history route hit ===");
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

// 8) Hardware sync (JSON, non-file) — includes signatures
app.get("/api/hardware/sync", async (req, res) => {
  try {
    if (!requireHardwareKey(req, res)) return;
    const limit = parseInt(req.query.limit || "", 10);
    const tokens = await buildActiveTokenEntries(Number.isInteger(limit) ? limit : null);
    return res.json({ generatedAt: new Date().toISOString(), tokens });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "server error" });
  }
});

// 8b) Hardware snapshot file (downloadable tokens.json)
app.get("/api/hardware/tokens-file", async (req, res) => {
  try {
    if (!requireHardwareKey(req, res)) return;
    const limit = parseInt(req.query.limit || "", 10);
    await updateTokensFile(Number.isInteger(limit) ? limit : null);
    res.download(TOKENS_FILE_PATH, "tokens.json");
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "server error" });
  }
});

// 9) Hardware redeem (online, strict) — requires secretToken
// 9) Hardware redeem (hybrid: online DB, fallback to tokens.json)
// 9) Hardware redeem (hybrid: online DB, fallback to tokens.json)
app.post("/api/hardware/redeem", async (req, res) => {
  try {
    const { ref, secretToken } = req.body;
    if (!ref) return res.status(400).json({ error: "ref required" });

    // --- Online mode (MongoDB) ---
    try {
      const tokenDoc = await Order.findOne({ publicRef: ref });
      if (tokenDoc) {
        if (tokenDoc.used) return res.status(409).json({ error: "token already used" });
        if (new Date() > tokenDoc.expiresAt) return res.status(410).json({ error: "token expired" });
        if (!secretToken || secretToken !== tokenDoc.secretToken) {
          return res.status(401).json({ error: "invalid secretToken" });
        }

        tokenDoc.used = true;
        await tokenDoc.save();
        try { await updateTokensFile(); } catch (e) {}

        // ✅ Send Thank-you mail
        if (MAIL_USER && MAIL_PASS) {
          transporter.sendMail({
            from: MAIL_USER,
            to: tokenDoc.userEmail,
            subject: "Thank You for Your Order 🎉",
            html: `
              <p>Hi ${tokenDoc.userEmail},</p>
              <p>Thank you for claiming your order. We hope you enjoy it!</p>
              <p><b>Order Ref:</b> ${tokenDoc.publicRef}</p>
              <p><b>Total:</b> ₹${tokenDoc.total}</p>
              <p>— QuickServe Team</p>
            `,
          }).catch(err => console.error("Thank-you mail error:", err));
        }

        return res.json({
          message: "valid (DB)",
          order: { id: tokenDoc._id, items: tokenDoc.items, total: tokenDoc.total }
        });
      }
    } catch (dbErr) {
      console.warn("⚠️ DB offline, falling back to JSON:", dbErr.message);
    }

    // --- Offline mode (tokens.json) ---
    if (!fs.existsSync(TOKENS_FILE_PATH)) {
      return res.status(503).json({ error: "offline snapshot not available" });
    }
    const snapshot = JSON.parse(fs.readFileSync(TOKENS_FILE_PATH));
    const token = snapshot.tokens.find(t => t.publicRef === ref);
    if (!token) return res.status(404).json({ error: "ref not found in snapshot" });
    if (new Date() > new Date(token.expiresAt)) return res.status(410).json({ error: "token expired" });

    const expectedSig = signTokenEntry(token);
    if (expectedSig !== token.signature) return res.status(401).json({ error: "signature mismatch" });

    // ✅ Send Thank-you mail (offline mode)
    if (MAIL_USER && MAIL_PASS) {
      transporter.sendMail({
        from: MAIL_USER,
        to: token.userEmail,
        subject: "Thank You for Your Order 🎉",
        html: `
          <p>Hi ${token.userEmail},</p>
          <p>Thank you for claiming your order. We hope you enjoy it!</p>
          <p><b>Order Ref:</b> ${token.publicRef}</p>
          <p><b>Total:</b> ₹${token.total}</p>
          <p>— QuickServe Team</p>
        `,
      }).catch(err => console.error("Thank-you mail error:", err));
    }

    return res.json({ message: "valid (offline json)", token });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "server error" });
  }
});

// 9b) Hardware bulk-redeem (OFFLINE SYNC) — trusts hardware key
// Body: { refs: ["ABC123", "XYZ999", ...] }
// 9b) Hardware bulk-redeem (hybrid: online DB, fallback to tokens.json)
// Path to store offline claims
const OFFLINE_CLAIMS_PATH = path.join(__dirname, "offlineClaims.json");

app.post("/api/hardware/bulk-redeem", async (req, res) => {
  try {
    if (!requireHardwareKey(req, res)) return;

    // --- Check if offline claims exist ---
    if (!fs.existsSync(OFFLINE_CLAIMS_PATH)) {
      return res.status(400).json({ error: "no offline claims to sync" });
    }
    const offlineClaims = JSON.parse(fs.readFileSync(OFFLINE_CLAIMS_PATH, "utf8"));
    if (!Array.isArray(offlineClaims) || offlineClaims.length === 0) {
      return res.status(400).json({ error: "no offline claims pending" });
    }

    const results = [];

    try {
      // --- Sync each offline claim into DB ---
      for (const claim of offlineClaims) {
        const ref = claim.ref;
        const doc = await Order.findOne({ publicRef: ref });
        if (!doc) { results.push({ ref, status: "not_found" }); continue; }
        if (doc.used) { results.push({ ref, status: "already_used" }); continue; }
        if (new Date() > doc.expiresAt) { results.push({ ref, status: "expired" }); continue; }

        // Mark redeemed
        doc.used = true;
        await doc.save();
        results.push({ ref, status: "synced" });
      }

      // ✅ Clear offline claims after syncing
      fs.writeFileSync(OFFLINE_CLAIMS_PATH, JSON.stringify([], null, 2));

      // Update tokens.json snapshot
      try { await updateTokensFile(); } catch (e) { console.warn("snapshot update failed:", e.message); }

      return res.json({ mode: "synced_to_db", results });
    } catch (dbErr) {
      console.error("❌ Bulk sync failed, DB offline:", dbErr.message);
      return res.status(503).json({ error: "DB unavailable, try again later" });
    }
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "server error" });
  }
});



// 10) Admin export orders as CSV (basic) — add admin auth in production
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

// 1) Create Razorpay Order
app.post("/api/payments/create-order", authMiddleware, async (req, res) => {
  try {
    const { amount } = req.body; // in INR (not paise)
    if (!amount) return res.status(400).json({ error: "amount required" });

    const options = {
      amount: amount * 100, // Razorpay works in paise
      currency: "INR",
      receipt: "receipt_" + Date.now(),
    };

    const order = await razorpay.orders.create(options);
    return res.json(order);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to create Razorpay order" });
  }
});

// 2) Verify Razorpay Payment
app.post("/api/payments/verify", authMiddleware, async (req, res) => {
  console.log("=== /api/payments/verify route hit ===");
  console.log("User (from authMiddleware):", req.user);
  console.log("Request Body:", req.body);

  try {
    const { razorpay_order_id, razorpay_payment_id, razorpay_signature, items } = req.body;

    if (!razorpay_order_id || !razorpay_payment_id || !razorpay_signature) {
      console.warn("Missing payment details in request body");
      return res.status(400).json({ error: "Missing payment details" });
    }

    // --- Signature Verification ---
    console.log("=== Verifying Razorpay signature ===");
    const expectedSig = crypto
      .createHmac("sha256", process.env.RAZORPAY_KEY_SECRET)
      .update(razorpay_order_id + "|" + razorpay_payment_id)
      .digest("hex");

    if (expectedSig !== razorpay_signature) {
      console.warn("Invalid Razorpay signature provided");
      return res.status(400).json({ error: "Invalid signature" });
    }
    console.log("✅ Razorpay signature verified successfully");

    // --- Order Data Processing ---
    console.log("=== Processing order data ===");
    const total = items.reduce((s, it) => s + (it.price || 0) * (it.qty || 1), 0);
    console.log("Calculated total:", total);

    const secretToken = genSecret(32);
    let publicRef;
    let attempts = 0;
    const maxAttempts = 5;
    do {
      publicRef = genRef(10);
      attempts++;
      if (attempts > maxAttempts) {
        const errorMsg = `Failed to generate unique publicRef after ${maxAttempts} attempts`;
        console.error(errorMsg);
        return res.status(500).json({ error: errorMsg });
      }
    } while (await Order.findOne({ publicRef }).catch(err => {
       console.error("Error checking for existing publicRef:", err);
       throw err; // Re-throw to be caught by the outer catch
    }));
    console.log("Generated unique publicRef:", publicRef);

    const expiresAt = nowPlusMinutes(30);
    console.log("Order expires at:", expiresAt.toISOString());

    // --- Database Order Creation ---
    console.log("=== Creating order in DB ===");
    const order = await Order.create({
      userId: req.user.userId,
      userEmail: req.user.email,
      items,
      total,
      paid: true,
      publicRef,
      secretToken,
      expiresAt,
    });
    console.log("=== Order created successfully, ID:", order._id, "===");

    // --- QR Code Generation ---
    console.log("=== Generating QR Code ===");
    const qrPayload = JSON.stringify({ ref: publicRef, token: secretToken });
    const qrDataUrl = await qrcode.toDataURL(qrPayload);
    console.log("=== QR Code generated ===");

    // --- Update Tokens File ---
    try {
      console.log("=== Updating tokens snapshot file ===");
      await updateTokensFile();
      console.log("=== Tokens snapshot file updated ===");
    } catch (e) {
      console.warn("Snapshot refresh failed:", e.message);
    }

    // --- 📧 Send Mail with QR ---
    console.log("=== Preparing to send QR Email ===");
    const userEmail = req.user.email; // Get email from authenticated user
    console.log("User Email (userEmail):", userEmail);
    console.log("MAIL_USER env var set:", !!MAIL_USER);
    console.log("MAIL_PASS env var set (length check):", MAIL_PASS ? `Yes (${MAIL_PASS.length} chars)` : "No");

    let emailSent = false;
    if (!MAIL_USER || !MAIL_PASS) {
      console.warn("Mail credentials missing – skipping email.");
    } else {
      console.log("=== Attempting to send QR Email ===");
      try {
        // await transporter.verify(); // Uncomment if needed for debugging
        // console.log("✅ SMTP server verified and ready");

        const mailOptions = {
          from: MAIL_USER,
          to: userEmail,
          subject: "Your QuickServe Order QR Code",
          html: `
            <p>Thank you for your order 🎉</p>
            <p>Order Ref: <b>${publicRef}</b></p>
            <p>Total: ₹${total}</p>
            <p>This QR code is valid until <b>${expiresAt.toLocaleString()}</b></p>
            <p><img src="cid:orderqr" alt="QR Code" /></p>
          `,
          attachments: [
            {
              filename: `order-${publicRef}.png`,
              content: qrDataUrl.split("base64,")[1],
              encoding: "base64",
              cid: "orderqr"
            }
          ],
        };

        console.log("=== Mail Options Prepared ===");
        const info = await transporter.sendMail(mailOptions);
        console.log("📧 QR Mail sent successfully. Message ID:", info.messageId);
        emailSent = true;

      } catch (err) {
        console.error("❌ QR Mail send error:", err);
        // Depending on your requirements, you might want to return an error to the client
        // if the email is critical. For now, we log the error and continue.
        // The order is created, just the email failed.
      }
    }

    const responseMessage = emailSent
      ? "Order created and email sent successfully"
      : "Order created successfully (but email failed to send)";

    console.log("=== Sending final response ===");
    // --- Send Response ---
    return res.json({
      message: responseMessage, // Include email status in response
      success: true,
      orderId: order._id,
      publicRef,
      qrDataUrl,
      expiresAt,
    });

  } catch (err) {
    console.error("=== UNHANDLED ERROR in /api/payments/verify route:", err);
    return res.status(500).json({ error: "Payment verification and order creation failed" });
  }
});

// 1) Offline Redeem
app.post("/api/hardware/offline-redeem", async (req, res) => {
  try {
    const { userId, hardwareId, credits } = req.body;

    if (!userId || !hardwareId || !credits) {
      return res.status(400).json({ error: "Missing fields" });
    }

    // Read existing offline claims
    const claims = JSON.parse(fs.readFileSync("offlineClaims.json", "utf-8") || "[]");

    // Add new claim
    claims.push({
      userId,
      hardwareId,
      credits,
      claimedAt: new Date().toISOString(),
    });

    // Save back to file
    fs.writeFileSync("offlineClaims.json", JSON.stringify(claims, null, 2));

    return res.json({
      success: true,
      message: "Claim stored offline. Will sync when online.",
    });
  } catch (error) {
    console.error("Offline Redeem Error:", error);
    return res.status(500).json({ error: "Failed to store offline claim" });
  }
});


// ---------- cleanup cron: delete expired tokens & refresh snapshot ----------
cron.schedule("*/1 * * * *", async () => {
  try {
    const now = new Date();
    const resDel = await Order.deleteMany({ expiresAt: { $lt: now } });
    if (resDel.deletedCount > 0) {
      console.log(`Cleanup: removed ${resDel.deletedCount} expired orders/tokens`);
    }
    // keep the tokens file fresh for hardware pulls
    await updateTokensFile();
  } catch (err) {
    console.error("cleanup error:", err);
  }
});

// start server
app.listen(PORT, () => console.log(`Server running on ${PORT}`));
