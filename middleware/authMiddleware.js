const asyncHandler = require("express-async-handler");
const User = require("../models/userModel");
const jwt = require("jsonwebtoken");

// Protect middleware to authenticate users
const protect = asyncHandler(async (req, res, next) => {
  try {
    const token = req.cookies.token; // Read token from cookies
    if (!token) {
      res.status(401);
      throw new Error("Not authorized, please login");
    }

    // Verify token
    const verified = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(verified.id).select("-password"); // Get user from token

    if (!user) {
      res.status(404);
      throw new Error("User not found");
    }

    req.user = user; // Attach user to request
    next();
  } catch (error) {
    res.status(401).json({ message: "Not authorized, please login" });
  }
});

// Middleware to restrict access to admins only
const adminOnly = asyncHandler(async (req, res, next) => {
  if (req.user && req.user.role === "admin") {
    next();
  } else {
    res.status(403).json({ message: "Not authorized as an admin" });
  }
});

// Middleware to restrict access to authors or admins
const authorOnly = asyncHandler(async (req, res, next) => {
  if (req.user && (req.user.role === "author" || req.user.role === "admin")) {
    next();
  } else {
    res.status(403).json({ message: "Not authorized as an author" });
  }
});

module.exports = {
  protect,
  adminOnly,
  authorOnly,
};