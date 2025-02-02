const express = require("express");
const {
  register,
  login,
  refreshToken,
  logout,
  forgotPassword,
  resetPassword,
} = require("../controllers/authController");

const router = express.Router();

router.post("/register", register);
router.post("/login", login);
router.post("/refresh-token", refreshToken);
router.post("/logout", logout);
router.post("/forgot-password", forgotPassword); // New endpoint
router.post("/reset-password", resetPassword); // New endpoint

module.exports = router;