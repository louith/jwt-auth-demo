const router = require("express").Router();
const { register, login, refresh, logout } = require("../controllers/auth.controller");

router.post("/register", register); // POST /api/auth/register
router.post("/login", login);       // POST /api/auth/login
router.post("/refresh", refresh);   // POST /api/auth/refresh
router.post("/logout", logout);     // POST /api/auth/logout

module.exports = router;