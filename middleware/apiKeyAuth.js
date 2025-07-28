const User = require("../models/User");

module.exports = async function apiKeyAuth(req, res, next) {
  try {
    const apikey = req.query.apikey || req.headers["x-api-key"];
    if (!apikey)
      return res
        .status(401)
        .json({ status: "error", message: "API key diperlukan." });

    const user = await User.findOne({ apiKey: apikey, apiKeyStatus: "active" });
    if (!user)
      return res
        .status(403)
        .json({ status: "error", message: "API key tidak valid/aktif." });

    // Pastikan trust proxy di app.js sudah true!
    let ip = req.ip || req.connection.remoteAddress;
    if (ip.startsWith("::ffff:")) ip = ip.replace("::ffff:", "");
    if (ip === "::1") ip = "127.0.0.1";

    // Pengecekan whitelist hanya IP
    const allowIp = user.whitelist && user.whitelist.includes(ip);

    if (!allowIp) {
      return res.status(403).json({
        status: "error",
        message: "Silakan whitelist IP kamu terlebih dahulu.",
        your_ip: ip,
        cara: "Tambahkan IP public kamu di dashboard.",
      });
    }

    // Jika lolos, teruskan user
    req.userApiKey = user;
    next();
  } catch (e) {
    return res.status(500).json({ status: "error", message: "Auth error." });
  }
};
