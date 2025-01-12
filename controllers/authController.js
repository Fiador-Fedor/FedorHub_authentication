const User = require("../models/User");
const bcrypt = require("bcrypt");
const {
  generateAccessToken,
  generateRefreshToken,
  storeRefreshToken,
  verifyToken,
  getStoredRefreshToken,
  revokeRefreshToken,
} = require("../utils/tokenManager");
const rabbitMQ = require("../utils/rabbitmq");
const keepAlive = require("../utils/keepAlive");

const notificationsServiceURL = process.env.KEEP_NOTI_ALIVE;
const axios = require('axios');

// Register new user
exports.register = async (req, res) => {
  try {
    const { username, email, password, role } = req.body;

    const allowedRoles = ["USER", "SHOP_OWNER", "ADMIN"];
    if (role && !allowedRoles.includes(role)) {
      return res.status(400).json({ message: "Invalid role specified" });
    }

    const userExists = await User.findOne({ $or: [{ username }, { email }] });
    if (userExists) {
      return res.status(400).json({ message: "Username or email already exists" });
    }

    const user = new User({
      username,
      email,
      password,
      role: role || "USER",
    });

    await user.save();
	
	// Send the first RabbitMQ message
     try {
      await rabbitMQ.sendMessage("user_data_sync", { id: user._id, username, email, role: user.role });
    } catch (mqError) {
      console.error("RabbitMQ Error (user_data_sync):", mqError.message);
    }
	
    // Use setTimeout to send the second message after a delay
    setTimeout(async () => {
      try {
        await rabbitMQ.sendMessage("auth_events", {
          type: "user_created",
          data: { userId: user._id, username, email, role: user.role },
        });
      } catch (error) {
        console.error("RabbitMQ Error (auth_events):", error.message);
      }
    }, 5000);
	
	await keepAlive(notificationsServiceURL);
	
    res.status(201).json({ message: "User registered successfully" });
  } catch (error) {
    console.error("Register Error:", error.message);
    res.status(500).json({ error: "Internal server error" });
  }
};

// Login user
exports.login = async (req, res) => {
  try {
    const { username, password } = req.body;

    const user = await User.findOne({ username });
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    const payload = { id: user._id, role: user.role };

    const accessToken = generateAccessToken(payload);
    const refreshToken = generateRefreshToken(payload);

    await storeRefreshToken(user._id.toString(), refreshToken);
	
	
    try {
      await rabbitMQ.sendMessage("auth_events", {
        type: "user_logged_in",
        data: { userId: user._id, username },
      });
    } catch (error) {
      console.error("RabbitMQ Error:", error.message);
    }
	
	let profileImageUrl = null;

    // Generate secure download URL if the user has a profileFileId
    if (user.profileFileId) {
      const authorizeResponse = await axios.get('https://api.backblazeb2.com/b2api/v3/b2_authorize_account', {
        headers: {
          Authorization: `Basic ${Buffer.from(
            `${process.env.B2_APPLICATION_KEY_ID}:${process.env.B2_APPLICATION_KEY}`
          ).toString('base64')}`,
        },
      });

      const {
        apiInfo: { storageApi },
        authorizationToken,
      } = authorizeResponse.data;

      const { downloadUrl } = storageApi;

      if (!downloadUrl || !authorizationToken) {
        throw new Error("Failed to retrieve valid Backblaze B2 configuration.");
      }

      const downloadAuthorizationResponse = await axios.post(
        `${storageApi.apiUrl}/b2api/v3/b2_get_download_authorization`,
        {
          bucketId: process.env.B2_BUCKET_ID,
          fileNamePrefix: user.profileFileId,
          validDurationInSeconds: 3600, // 1-hour validity
        },
        {
          headers: {
            Authorization: authorizationToken,
          },
        }
      );

      profileImageUrl = `${downloadUrl}/file/${process.env.B2_BUCKET_NAME}/${user.profileFileId}?Authorization=${downloadAuthorizationResponse.data.authorizationToken}`;
    }

    res.json({
      accessToken,
      refreshToken,
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        role: user.role,
		profileImage:profileImageUrl,
      },
    });
	
	await keepAlive(notificationsServiceURL);
	
  } catch (error) {
    console.error("Login Error:", error.message);
    res.status(500).json({ error: "Internal server error" });
  }
};

// Refresh token
exports.refreshToken = async (req, res) => {
  try {
    const { refreshToken } = req.body;

    if (!refreshToken) {
      return res.status(400).json({ error: "Refresh token is required" });
    }

    const decoded = verifyToken(refreshToken, process.env.JWT_REFRESH_SECRET);

    const storedToken = await getStoredRefreshToken(decoded.user_id);
    if (storedToken !== refreshToken) {
      return res.status(403).json({ error: "Invalid or expired refresh token" });
    }

    const payload = { id: decoded.user_id, role: decoded.role };

    const newAccessToken = generateAccessToken(payload);
    const newRefreshToken = generateRefreshToken(payload);

    await storeRefreshToken(decoded.user_id, newRefreshToken);

    res.json({ accessToken: newAccessToken, refreshToken: newRefreshToken });
  } catch (error) {
    console.error("Refresh Token Error:", error.message);
    res.status(403).json({ error: "Invalid or expired refresh token" });
  }
};

// Logout user
exports.logout = async (req, res) => {
  try {
    const { userId } = req.body;

    if (!userId) {
      return res.status(400).json({ error: "User ID is required" });
    }

    await revokeRefreshToken(userId);
	
	try {
      await rabbitMQ.sendMessage("auth_events", {
        type: "user_logged_out",
        data: { userId },
      });
    } catch (error) {
      console.error("RabbitMQ Error:", error.message);
    }
	
	await keepAlive(notificationsServiceURL);

    res.json({ message: "Logged out successfully" });
  } catch (error) {
    console.error("Logout Error:", error.message);
    res.status(500).json({ error: "Internal server error" });
  }
};
