const mongoose = require("mongoose");
const UserSchema = new mongoose.Schema({
  username: { type: String, unique: true, required: true },
  email: { type: String, unique: true, required: true },
  password: { type: String, required: true },
  apiKey: String,
  apiKeyExpired: Date,
  apiKeyStatus: {
    type: String,
    enum: ["inactive", "active"],
    default: "inactive",
  },
  whitelist: [String],
  paymentStatus: { type: String, default: "" }, // kosong saat baru daftar
  paymentMerchantRef: String,
  paymentChannel: String,
  paymentUrl: String,
  reference: String, // ← WAJIB ADA UNTUK FITUR INVOICE/THANKYOU!
  // Tambahan OTP
  isVerified: { type: Boolean, default: false },
  otp: String,
  otpExpired: Date,
});
module.exports = mongoose.model("User", UserSchema);
