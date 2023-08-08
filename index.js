const express = require("express");
const app = express();
const mongoose = require("mongoose");
const bodyParser = require("body-parser");
const { AuthSchemaModel } = require("./user");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
app.use(bodyParser.json({ limit: "10mb" }));
app.use(bodyParser.urlencoded({ limit: "10mb", extended: true }));
const cors = require("cors");
require("dotenv").config();
app.use(express.json());
app.use(cors());

mongoose.connect(process.env.MONGODBSECRET);

app.post("/signup", async (req, res) => {
  const { email, pwd } = req.body;

  try {
    if (!email || !pwd) {
      return res.status(400).json({ error: "Please fill all required fields" });
    }

    if (email.indexOf("@") === -1) {
      return res.status(400).json({ error: "Invalid email" });
    }

    if (pwd.length < 8) {
      return res
        .status(400)
        .json({ error: "Password should not be less than 8 characters" });
    }

    const existingUser = await AuthSchemaModel.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ error: "Email already exists" });
    }

    const hashedPassword = await bcrypt.hash(pwd, 10);
    const user = new AuthSchemaModel({
      email,
      password: hashedPassword,
    });

    await user.save();
    res.status(200).json({ message: "User registered successfully" });
  } catch (error) {
    console.error("Failed to register user", error);
    res.status(500).json({ error: "Failed to register user" });
  }
});

app.post("/login", async (req, res) => {
  const { email, pwd } = req.body;

  try {
    if (!email || !pwd) {
      return res.status(400).json({ error: "Please fill all required fields" });
    }

    if (email.indexOf("@") === -1) {
      return res.status(400).json({ error: "Invalid email" });
    }

    if (pwd.length < 8) {
      return res
        .status(400)
        .json({ error: "Password should not be less than 8 characters" });
    }

    const user = await AuthSchemaModel.findOne({ email });
    if (!user) {
      return res.status(401).json({ error: "Invalid email or password" });
    }

    const passwordMatch = await bcrypt.compare(pwd, user.password);
    if (!passwordMatch) {
      return res.status(401).json({ error: "Invalid password" });
    }

    const token = jwt.sign(
      { userId: user._id, email: user.email },
      process.env.YOUR_SECRET_KEY,
      { expiresIn: "7200000000h" }
    );
    // localStorage.setItem('token', token);
    res.status(200).json({ message: "Login successful", token });
    console.log("login successful");
  } catch (error) {
    console.error("Failed to log in", error);
    res.status(500).json({ error: "Failed to log in" });
  }
});

const verifyToken = (req, res, next) => {
  const token = req.headers.authorization;

  if (!token) {
    return res.status(401).json({ error: "Token missing" });
  }

  try {
    const decoded = jwt.verify(
      token.split(" ")[1],
      process.env.YOUR_SECRET_KEY
    );
    req.user = decoded;
    req.user = {
      userId: decoded.userId,
      email: decoded.email,
    };
    next();
  } catch (error) {
    console.error("Failed to verify token, fetch failed", error);
    res.status(401).json({ error: "Invalid token, fetch failed" });
  }
};

app.get("/dashboard", verifyToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    const user = await AuthSchemaModel.findById(userId);

    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }
    const { email } = user;
    res.status(200).json({
      email,
    });
  } catch (error) {
    console.error("Failed to fetch dashboard", error);
    res.status(500).json({ error: "Failed to fetch dashboard" });
  }
});

app.get("/", (req, res) => {
  res.send("<p>Welcome to Skill tank assignment api.</p>");
});

const port = process.env.PORT || 3000;
app.listen(port, "0.0.0.0", () => {
  console.log(`server started at ${port}`);
});
