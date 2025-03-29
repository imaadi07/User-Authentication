// backend/app.js
require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const path = require("path");
const jwt = require("jsonwebtoken");
const User = require("./models/User");

const app = express();

// Middleware
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname, "../frontend")));

// Connect to MongoDB
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log("📦 MongoDB Connected"))
  .catch((err) => console.error("❌ MongoDB Error:", err));

// Generate JWT Token
const generateToken = (user) => {
  return jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: "2h" });
};

// Signup Route
app.post("/signup", async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).send("All fields are required");

    const userExists = await User.findOne({ username });
    if (userExists) return res.status(400).send("User already exists");

    const newUser = await User.create({ username, password });
    const token = generateToken(newUser);
    res.cookie("token", token).redirect("/dashboard.html");
  } catch (err) {
    res.status(500).send("Server Error");
  }
});

// Login Route
app.post("/login", async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = await User.findOne({ username });

    if (!user || !(await user.comparePassword(password))) {
      return res.status(401).send("Invalid credentials");
    }

    const token = generateToken(user);
    res.cookie("token", token).redirect("/dashboard.html");
  } catch (err) {
    res.status(500).send("Server Error");
  }
});

// Dashboard Authentication Middleware
const verifyToken = (req, res, next) => {
  const token = req.cookies?.token;
  if (!token) return res.redirect("/login.html");

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) return res.redirect("/login.html");
    req.user = decoded;
    next();
  });
};

// Dashboard Route
app.get("/dashboard", verifyToken, async (req, res) => {
  const user = await User.findById(req.user.id);
  res.send(`Welcome, ${user.username}!`);
});

// Start Server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Server running on http://localhost:${PORT}`));
