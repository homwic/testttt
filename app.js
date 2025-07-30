require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const path = require("path");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const cors = require("cors");
const fetch = require("node-fetch");
const axios = require("axios");
const { Resend } = require("resend");
const User = require("./models/User");
const apiKeyAuth = require("./middleware/apiKeyAuth");
const https = require("https");

const ipv4Agent = new https.Agent({ family: 4 });// Sudah diperbaiki

const resend = new Resend(process.env.RESEND_API_KEY);

const app = express();
app.set("trust proxy", true);
app.use(cors());
app.use(express.json());
app.use(express.static("public"));

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});
app.get("/thankyou", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "thankyou.html"));
});
app.get("/dashboard", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "dashboard.html"));
});
app.get("/login", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "login.html"));
});
app.get("/register", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "register.html"));
});
app.get("/profile", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "profile.html"));
});


// --- Helper: Modern HTML Email Template for OTP ---
function getOtpEmailHtml(otp) {
  return `
  <div style="max-width:480px;margin:auto;background:#fff;border-radius:16px;box-shadow:0 4px 24px #007bff22;padding:32px 24px;font-family:'Segoe UI',Roboto,sans-serif;">
    <div style="text-align:center;">
      <img src="https://cdn.jsdelivr.net/gh/bonangid/public-res/logo-api-blue.png" alt="Logo" width="58" style="margin-bottom:8px"/>
      <h2 style="color:#007bff;font-size:1.6rem;margin-bottom:2px;font-weight:700;letter-spacing:1px;">Verifikasi Email Akun</h2>
      <div style="color:#444;font-size:1.04rem;margin-bottom:16px;">
        Terima kasih telah mendaftar.<br>
        Silakan masukkan kode OTP berikut untuk verifikasi akun Anda:
      </div>
      <div style="margin:26px 0 24px">
        <span style="display:inline-block;background:#f4f8ff;border-radius:10px;padding:18px 0;font-size:2.1rem;font-weight:700;letter-spacing:16px;color:#007bff;width:96%;max-width:300px;">
          <span>${otp}</span>
        </span>
      </div>
      <div style="color:#777;font-size:1.02rem;margin-bottom:18px;">
        <span>Kode OTP berlaku selama <b>10 menit</b>.</span>
      </div>
      <div style="font-size:1rem;color:#aaa;">Abaikan email ini jika Anda tidak merasa mendaftar.</div>
    </div>
    <div style="text-align:center;margin-top:24px;font-size:0.98rem;color:#95a5a6;">
      &copy; ${new Date().getFullYear()} API Demo
    </div>
  </div>
  `;
}

mongoose
  .connect(process.env.MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => console.log("MongoDB Connected!"))
  .catch((err) => console.error("MongoDB connection error:", err));

/* Register & kirim OTP via email */
app.post("/api/register", async (req, res) => {
  try {
    const { username, email, password } = req.body;
    if (!(username && email && password))
      return res
        .status(400)
        .json({ status: "error", message: "Semua field wajib diisi." });
    const uname = username.trim().toLowerCase();
    const mail = email.trim().toLowerCase();
    const exist = await User.findOne({
      $or: [{ username: uname }, { email: mail }],
    });
    if (exist)
      return res
        .status(400)
        .json({ status: "error", message: "Username/Email sudah terdaftar." });

    // Generate OTP
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const otpExpired = new Date(Date.now() + 10 * 60 * 1000); // 10 menit
    const hashed = await bcrypt.hash(password, 10);

    await User.create({
      username: uname,
      email: mail,
      password: hashed,
      isVerified: false,
      otp,
      otpExpired,
    });

    try {
      await resend.emails.send({
        from: process.env.RESEND_FROM,
        to: mail,
        subject: "Kode OTP Verifikasi Akun",
        html: getOtpEmailHtml(otp),
      });
      res.json({
        status: "ok",
        message: "Register berhasil. Cek email untuk kode OTP.",
        email: mail,
      });
    } catch (e) {
      res
        .status(500)
        .json({ status: "error", message: "Gagal kirim email OTP." });
    }
  } catch (err) {
    console.error("REGISTER ERROR:", err);
    res.status(500).json({ status: "error", message: "Gagal register." });
  }
});

/* Verifikasi OTP */
app.post("/api/verify-otp", async (req, res) => {
  const { email, otp } = req.body;
  const mail = email.trim().toLowerCase();
  const user = await User.findOne({ email: mail });
  if (!user)
    return res
      .status(404)
      .json({ status: "error", message: "User tidak ditemukan." });
  if (user.isVerified)
    return res.json({ status: "ok", message: "Akun sudah diverifikasi." });
  if (!user.otp || user.otp !== otp)
    return res.status(400).json({ status: "error", message: "OTP salah." });
  if (!user.otpExpired || user.otpExpired < new Date())
    return res
      .status(400)
      .json({ status: "error", message: "OTP sudah kadaluarsa." });

  user.isVerified = true;
  user.otp = null;
  user.otpExpired = null;
  await user.save();
  res.json({
    status: "ok",
    message: "Akun berhasil diverifikasi. Silakan login.",
  });
});

/* Login (hanya bisa jika sudah OTP verified) */
app.post("/api/login", async (req, res) => {
  const { username, password } = req.body;
  const uname = username.trim().toLowerCase();
  const user = await User.findOne({ username: uname });
  if (!user)
    return res
      .status(400)
      .json({ status: "error", message: "User tidak ditemukan." });
  if (!user.isVerified)
    return res
      .status(403)
      .json({ status: "error", message: "Akun belum diverifikasi OTP." });
  const valid = await bcrypt.compare(password, user.password);
  if (!valid)
    return res
      .status(400)
      .json({ status: "error", message: "Password salah." });
  const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, {
    expiresIn: "2d",
  });
  res.json({ status: "ok", token });
});

/* JWT Middleware */
function userAuth(req, res, next) {
  const header = req.headers["authorization"];
  if (!header)
    return res.status(401).json({ status: "error", message: "Unauthorized." });
  const token = header.split(" ")[1];
  try {
    const data = jwt.verify(token, process.env.JWT_SECRET);
    req.userId = data.id;
    next();
  } catch (err) {
    return res
      .status(401)
      .json({ status: "error", message: "Token salah/expired." });
  }
}

/* Generate API Key (ganti key saja, expired tetap) */
app.post("/api/generate-api-key", userAuth, async (req, res) => {
  try {
    const user = await User.findById(req.userId);
    if (!user)
      return res
        .status(404)
        .json({ status: "error", message: "User tidak ditemukan." });
    const newApiKey = crypto.randomBytes(16).toString("hex");
    user.apiKey = newApiKey;
    user.apiKeyStatus = "active";
    await user.save();
    res.json({
      status: "ok",
      apiKey: newApiKey,
      apiKeyExpired: user.apiKeyExpired || null,
    });
  } catch (err) {
    console.error("GENERATE API KEY ERROR:", err);
    res
      .status(500)
      .json({ status: "error", message: "Gagal generate API key." });
  }
});

/* GET user profile */
app.get("/api/me", userAuth, async (req, res) => {
  const user = await User.findById(req.userId).lean();
  if (!user)
    return res
      .status(404)
      .json({ status: "error", message: "User tidak ditemukan." });
  delete user.password;
  res.json({ status: "ok", user });
});

/* BUAT INVOICE TRIPAY (untuk pembayaran/perpanjangan API) */
app.post("/api/pay", userAuth, async (req, res) => {
  const { method } = req.body;
  const user = await User.findById(req.userId);
  if (!user)
    return res
      .status(404)
      .json({ status: "error", message: "User tidak ditemukan." });

  const merchantCode = process.env.TRIPAY_MERCHANT_CODE;
  const privateKey = process.env.TRIPAY_PRIVATE_KEY;
  const merchantRef = "ORDER" + Date.now() + user._id;
  const amount = 30000;

  const signatureBase = merchantCode + merchantRef + amount;
  const signature = crypto
    .createHmac("sha256", privateKey)
    .update(signatureBase)
    .digest("hex");

  const payload = {
    method,
    merchant_ref: merchantRef,
    merchant_code: merchantCode,
    amount,
    customer_name: user.username,
    customer_email: user.email,
    customer_phone: "08123456789",
    order_items: [
      { sku: "API001", name: "API Access", price: amount, quantity: 1 },
    ],
    callback_url: process.env.TRIPAY_CALLBACK_URL,
    return_url: `https://viu.lutifygame.biz.id/thankyou.html?ref=${merchantRef}`,
    httpsAgent: ipv4Agent,
    signature,
  };

  try {
    const tripayResp = await axios.post(
      "https://tripay.co.id/api/transaction/create",
      payload,
      { headers: { Authorization: `Bearer ${process.env.TRIPAY_API_KEY}` },
    httpsAgent: ipv4Agent, }
    );
    const invoiceData = tripayResp.data.data;
    if (!invoiceData || !invoiceData.checkout_url) {
      console.error("TRIPAY RESP:", tripayResp.data);
      return res
        .status(500)
        .json({ status: "error", message: "Invoice tidak valid dari Tripay." });
    }
    user.paymentStatus = "pending";
    user.paymentMerchantRef = merchantRef;
    user.paymentChannel = method;
    user.paymentUrl = invoiceData.checkout_url;
    user.reference = invoiceData.reference;
    await user.save();

    res.json({
      status: "ok",
      payment_url: invoiceData.checkout_url,
      merchant_ref: merchantRef,
      reference: invoiceData.reference,
      data: invoiceData,
    });
  } catch (err) {
    let msg = "Gagal membuat invoice pembayaran.";
    if (err.response && err.response.data)
      msg = JSON.stringify(err.response.data);
    console.error("TRIPAY ERROR:", err.response?.data || err.message);
    return res.status(500).json({ status: "error", message: msg });
  }
});

/* Webhook Tripay (expired diperpanjang BENAR) */
app.post("/api/tripay/webhook", express.json(), async (req, res) => {
  const callbackSignature = req.headers["x-callback-signature"] || "";
  const bodyString = JSON.stringify(req.body);
  const signature = crypto
    .createHmac("sha256", process.env.TRIPAY_PRIVATE_KEY)
    .update(bodyString)
    .digest("hex");
  if (signature !== callbackSignature)
    return res
      .status(401)
      .json({ status: "error", message: "Invalid signature" });

  const { merchant_ref, status } = req.body;
  if (status === "PAID") {
    const user = await User.findOne({ paymentMerchantRef: merchant_ref });
    if (user) {
      const key = user.apiKey || crypto.randomBytes(16).toString("hex");
      user.apiKey = key;
      user.apiKeyStatus = "active";
      let now = Date.now();
      let expired = user.apiKeyExpired
        ? new Date(user.apiKeyExpired).getTime()
        : 0;
      let base = expired > now ? expired : now;
      user.apiKeyExpired = new Date(base + 30 * 24 * 60 * 60 * 1000); // +30 hari dari expired
      user.paymentStatus = "paid";
      await user.save();
    }
  }
  if (status === "EXPIRED") {
    const user = await User.findOne({ paymentMerchantRef: merchant_ref });
    if (user) {
      user.paymentStatus = "expired";
      await user.save();
    }
  }
  res.json({ success: true });
});

/* GET detail invoice Tripay untuk halaman thankyou */
app.get("/api/invoice/detail/:merchant_ref", userAuth, async (req, res) => {
  try {
    const user = await User.findOne({
      paymentMerchantRef: req.params.merchant_ref,
    });
    if (!user)
      return res
        .status(404)
        .json({ status: "error", message: "Transaksi tidak ditemukan." });

    const tripayResp = await axios.get(
      `https://tripay.co.id/api/transaction/detail?reference=${user.reference}`,
      { headers: { Authorization: `Bearer ${process.env.TRIPAY_API_KEY}` },
    httpsAgent: ipv4Agent, }
    );
    res.json({ status: "ok", data: tripayResp.data.data });
  } catch (e) {
    res.status(500).json({
      status: "error",
      message: e.response?.data?.message || "Gagal ambil data invoice",
    });
  }
});

/* Tambah whitelist */
app.post("/api/whitelist/add", userAuth, async (req, res) => {
  const { item } = req.body;
  if (!item)
    return res
      .status(400)
      .json({ status: "error", message: "IP/domain wajib diisi." });
  const user = await User.findById(req.userId);
  if (!user.whitelist) user.whitelist = [];
  if (!user.whitelist.includes(item)) user.whitelist.push(item);
  await user.save();
  res.json({ status: "ok", whitelist: user.whitelist });
});

/* Hapus whitelist */
app.post("/api/whitelist/delete", userAuth, async (req, res) => {
  const { item } = req.body;
  if (!item)
    return res
      .status(400)
      .json({ status: "error", message: "IP/domain wajib diisi." });
  const user = await User.findById(req.userId);
  user.whitelist = user.whitelist.filter((i) => i !== item);
  await user.save();
  res.json({ status: "ok", whitelist: user.whitelist });
});

/* PROXY UTAMA (pakai apiKeyAuth middleware) */
app.get("/api/viu", apiKeyAuth, async (req, res) => {
  const username = req.query.username || "";
  const domain = req.query.domain || "";
  const password = req.query.password || "";
  const paket = req.query.paket || "1";
  if (!username || !domain || !password) {
    return res.status(400).json({
      status: "error",
      message: "Parameter kurang lengkap",
      copyright: "@LUTIFY",
    });
  }
  let phone = "";
  if (paket === "1") phone = "6281328345758";
  else if (paket === "200") phone = "6282199189441";
  else {
    return res.status(400).json({
      status: "error",
      message: "Paket tidak valid",
      copyright: "@LUTIFY",
    });
  }
  const target_api = `https://amfcode.my.id/apiviu/27juli?username=${encodeURIComponent(
    username
  )}&domain=${encodeURIComponent(domain)}&password=${encodeURIComponent(
    password
  )}&phone=${phone}`;
  try {
    const response = await fetch(target_api, {
      headers: { Authorization: "Bearer AMFCODE" },
    });
    const httpcode = response.status;
    const respText = await response.text();
    let respJson;
    try {
      respJson = JSON.parse(respText);
      respJson.copyright = "@LUTIFY";
      return res.status(httpcode).json(respJson);
    } catch (parseErr) {
      return res.status(httpcode).json({
        status: "error",
        message: "API target error / bukan JSON",
        copyright: "@LUTIFY",
      });
    }
  } catch (err) {
    return res.status(500).json({
      status: "error",
      message: "Terjadi error pada server",
      copyright: "@LUTIFY",
    });
  }
});

app.listen(7000, () => {
  console.log("Server ready: http://localhost:7000");
});
