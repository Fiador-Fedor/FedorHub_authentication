require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const cors = require("cors");

const authRoutes = require("./routes/authRoutes");
const profileRoutes = require("./routes/profileRoutes");
const { connectDB } = require("./utils/db");

const app = express();


app.use(bodyParser.json({ limit: "5mb" }));

// Database Connection
connectDB();

// Routes
app.use("/auth", authRoutes);
app.use("/auth/profile", profileRoutes);

module.exports = app;