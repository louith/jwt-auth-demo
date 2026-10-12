const crypto = require("crypto");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const User = require("../models/user.model");
const RefreshToken = require("../models/refreshToken.model");

const REFRESH_TTL_MS = (Number(process.env.REFRESH_TOKEN_DAYS) || 7) * 24 * 60 * 60 * 1000;

// Access token: short-lived JWT, sent on every request, never stored on the server
function signToken(user) {
  return jwt.sign(
    { userId: user.id },                       // payload: keep it small, no secrets
    process.env.JWT_SECRET,                    // the server-only secret
    { expiresIn: process.env.JWT_EXPIRES_IN || "15m" }
  );
}

// Only the hash is stored, so a leaked DB can't be used to refresh sessions
const hashToken = (token) => crypto.createHash("sha256").update(token).digest("hex");

// Refresh token: random string. The user gets the real token, the DB gets the hash.
function issueRefreshToken(userId) {
  const token = crypto.randomBytes(48).toString("hex");
  RefreshToken.create({
    tokenHash: hashToken(token),
    userId,
    expiresAt: Date.now() + REFRESH_TTL_MS,
  });
  return token;
}

exports.register = async (req, res, next) => {
  try {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({ error: "Name, email and password are required" });
    }
    if (password.length < 8) {
      return res.status(400).json({ error: "Password must be at least 8 characters" });
    }
    if (User.findByEmail(email)) {
      return res.status(409).json({ error: "Email is already registered" });
    }

    const passwordHash = await bcrypt.hash(password, 10); // never store plain passwords
    User.create({ name, email, passwordHash }); //database storing logic is in the model, not here in the controller

    res.status(201).json({ message: "Account created. You can log in now." });
  } catch (err) {
    next(err);
  }
};

exports.login = async (req, res, next) => {
  try {
    const { email, password } = req.body;
    const user = User.findByEmail(email); //query thru db if existing

    // Same message for both cases so attackers can't tell which emails exist
    const valid = user && (await bcrypt.compare(password || "", user.passwordHash));
    if (!valid) {
      return res.status(401).json({ error: "Invalid email or password" });
    }

    res.json({
      accessToken: signToken(user),
      refreshToken: issueRefreshToken(user.id),
    });
  } catch (err) {
    next(err);
  }
};

// Trade a valid refresh token for a brand new pair (rotation)
exports.refresh = (req, res, next) => {
  try {
    const { refreshToken } = req.body;
    if (!refreshToken) {
      return res.status(400).json({ error: "Refresh token is required" });
    }

    // 1. Do we know this token?
    const stored = RefreshToken.findByHash(hashToken(refreshToken));
    if (!stored) {
      return res.status(401).json({ error: "Invalid refresh token" });
    }

    // 2. Already used? Someone has a copy. Kill all sessions for this user.
    if (stored.revokedAt) {
      RefreshToken.revokeAllForUser(stored.userId);
      return res.status(401).json({ error: "Refresh token reuse detected. Please log in again." });
    }

    // 3. Expired?
    if (stored.expiresAt < Date.now()) {
      return res.status(401).json({ error: "Refresh token expired" });
    }

    const user = User.findById(stored.userId);
    if (!user) return res.status(401).json({ error: "Invalid refresh token" });

    // 4. Valid: cancel the old one, issue a fresh pair
    RefreshToken.revoke(stored.tokenHash);
    res.json({
      accessToken: signToken(user),
      refreshToken: issueRefreshToken(user.id),
    });
  } catch (err) {
    next(err);
  }
};

// Real logout: cancel the refresh token on the server
exports.logout = (req, res, next) => {
  try {
    const { refreshToken } = req.body;
    if (refreshToken) RefreshToken.revoke(hashToken(refreshToken));
    res.status(204).end(); // always succeed, don't leak whether the token existed
  } catch (err) {
    next(err);
  }
};