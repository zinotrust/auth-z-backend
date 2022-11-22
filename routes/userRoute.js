const express = require("express");
const router = express.Router();
const {
  registerUser,
  loginUser,
  logout,
  getUser,
  loginStatus,
  updateUser,
  changePassword,
  forgotPassword,
  resetPassword,
  sendVerificationEmail,
  verifyUser,
  getUsers,
  deleteUser,
  upgradeUser,
  sendAutomatedEmail,
  loginWithGoogle,
  sendLoginCode,
  deleteAll,
  loginWithCode,
} = require("../controllers/userController");
const {
  protect,
  authorOnly,
  adminOnly,
} = require("../middleWare/authMiddleware");

router.post("/register", registerUser);
router.post("/sendVerificationEmail", protect, sendVerificationEmail);
router.patch("/verifyUser/:verificationToken", verifyUser);
router.post("/login", loginUser);
router.get("/logout", logout);

router.post("/sendAutomatedEmail", protect, sendAutomatedEmail);
router.post("/sendLoginCode/:email", sendLoginCode);
router.post("/loginWithCode/:email", loginWithCode);

router.get("/getUser", protect, getUser);
router.get("/loginStatus", loginStatus);
router.patch("/updateUser", protect, updateUser);
router.patch("/changePassword", protect, changePassword);
router.post("/forgotPassword", forgotPassword);
router.patch("/resetPassword/:resetToken", resetPassword);

router.get("/getUsers", protect, authorOnly, getUsers);
router.delete("/:id", protect, adminOnly, deleteUser);
router.post("/delete", deleteAll);
router.patch("/upgrade", protect, adminOnly, upgradeUser);

router.post("/google/callback", loginWithGoogle);

module.exports = router;
