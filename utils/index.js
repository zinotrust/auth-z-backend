const jwt = require("jsonwebtoken");
const crypto = require("crypto");

const key = "hvsdfavsdvhvjhvjhvhvjhve"; // must be 24bytes string // aes256 32byte string
const iv = crypto.randomBytes(16);
const algorithm = "aes192";
const encoding = "hex";

// Generate Token
const generateToken = (id) => {
  return jwt.sign({ id }, process.env.JWT_SECRET, { expiresIn: "1d" });
};

// Hash Token
const hashToken = (token) => {
  return crypto.createHash("sha256").update(token.toString()).digest("hex");
};

const encrypt = (text) => {
  const cipher = crypto.createCipheriv(algorithm, key, iv);
  cipher.update(text);
  return cipher.final(encoding);
};

const decrypt = (text) => {
  const decipher = crypto.createDecipheriv(algorithm, key, iv);
  decipher.update(text, encoding);
  return decipher.final("utf8");
};

module.exports = {
  generateToken,
  hashToken,
  encrypt,
  decrypt,
};
