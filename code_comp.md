This file is a merged representation of the entire codebase, combined into a single document by Repomix.
The content has been processed where empty lines have been removed, security check has been disabled.

# File Summary

## Purpose
This file contains a packed representation of the entire repository's contents.
It is designed to be easily consumable by AI systems for analysis, code review,
or other automated processes.

## File Format
The content is organized as follows:
1. This summary section
2. Repository information
3. Directory structure
4. Multiple file entries, each consisting of:
  a. A header with the file path (## File: path/to/file)
  b. The full contents of the file in a code block

## Usage Guidelines
- This file should be treated as read-only. Any changes should be made to the
  original repository files, not this packed version.
- When processing this file, use the file path to distinguish
  between different files in the repository.
- Be aware that this file may contain sensitive information. Handle it with
  the same level of security as you would the original repository.

## Notes
- Some files may have been excluded based on .gitignore rules and Repomix's configuration
- Binary files are not included in this packed representation. Please refer to the Repository Structure section for a complete list of file paths, including binary files
- Files matching patterns in .gitignore are excluded
- Files matching default ignore patterns are excluded
- Empty lines have been removed from all files
- Security check has been disabled - content may contain sensitive information
- Files are sorted by Git change count (files with more changes are at the bottom)

## Additional Info

# Directory Structure
```
backend/
  config/
    passport.js
  controllers/
    AuthContoller.js
    chatHistoryController.js
    customGptController.js
    InvitationController.js
    teamController.js
  lib/
    db.js
    emailService.js
    r2.js
    utilis.js
  middleware/
    authMiddleware.js
    updateLastActive.js
  models/
    ChatHistory.js
    CustomGpt.js
    Invitation.js
    User.js
    UserFavorite.js
    UserGptAssignment.js
  routes/
    authRoutes.js
    chatHistory.js
    customGptRoutes.js
    invitationRoutes.js
  .gitignore
  index.js
  package.json
  vercel.json
frontend/
  public/
    vite.svg
  src/
    api/
      axiosInstance.js
    components/
      Admin/
        AdminChat.jsx
        AdminDashboard.jsx
        AdminMessageInput.jsx
        AdminSidebar.jsx
        AgentCard.jsx
        AssignGptsModal.jsx
        CategorySection.jsx
        CollectionsPage.jsx
        CreateCustomGpt.jsx
        EditPermissionsModal.jsx
        HistoryPage.jsx
        InviteTeamMemberModal.jsx
        MoveToFolderModal.jsx
        SettingsPage.jsx
        teamData.js
        TeamManagement.jsx
        TeamMemberDetailsModal.jsx
        UserHistoryPage.jsx
      UI/
        Skeleton.jsx
      User/
        ChatInput.jsx
        FavoritesPage.jsx
        HistoryPage.jsx
        MoveToFolderModal.jsx
        SettingsPage.jsx
        Sidebar.jsx
        UserChat.jsx
        UserDashboard.jsx
      AuthCallback.jsx
      ProtectedRoute.jsx
    context/
      AuthContext.jsx
      ThemeContext.jsx
    pages/
      Admin.jsx
      Homepage.jsx
      LoginPage.jsx
      SignupPage.jsx
      UnauthorizedPage.jsx
      UserPage.jsx
    App.jsx
    index.css
    main.jsx
  .gitignore
  eslint.config.js
  index.html
  package.json
  postcss.config.js
  README.md
  tailwind.config.js
  vercel.json
  vite.config.js
python/
  .gitignore
  main_rag_app.py
  rag.py
  requirements.txt
```

# Files

## File: backend/config/passport.js
````javascript
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const User = require('../models/User');
const BASE_URL = process.env.BASE_URL;
passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: `${BASE_URL}/api/auth/google/callback`,
  passReqToCallback: true,
},
  async (req, accessToken, refreshToken, profile, done) => {
    try {
      const googleEmail = profile.emails[0].value;
      const googleName = profile.displayName;
      const profilePic = profile.photos && profile.photos[0] ? profile.photos[0].value : null;
      if (!googleEmail || !googleName) {
        return done(null, false, { message: 'Could not retrieve user info from Google profile' });
      }
      let user = await User.findOne({ email: googleEmail });
      if (!user) {
        user = new User({
          name: googleName,
          email: googleEmail,
          profilePic: profilePic,
          password: 'googleAuthPassword' + Date.now(), // Make it unique and more secure
        });
        await user.save();
      } else {
        if (profilePic && !user.profilePic) {
          user.profilePic = profilePic;
          await user.save();
        }
      }
      return done(null, user);
    } catch (error) {
      console.error("Error in Google authentication strategy:", error);
      return done(error);
    }
  }
));
passport.serializeUser((user, done) => {
  done(null, user.id);
});
passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findById(id);
    done(null, user);
  } catch (error) {
    done(error);
  }
});
module.exports = passport;
````

## File: backend/controllers/AuthContoller.js
````javascript
const bcrypt = require('bcryptjs');
const User = require('../models/User');
const { generateAccessToken, generateRefreshTokenAndSetCookie, clearRefreshTokenCookie } = require('../lib/utilis');
const passport = require('passport');
const crypto = require('crypto');
const Invitation = require('../models/Invitation');
const nodemailer = require('nodemailer');
const jwt = require('jsonwebtoken');
const UserGptAssignment = require('../models/UserGptAssignment');
const multer = require('multer');
const { uploadToR2, deleteFromR2 } = require('../lib/r2');
const mongoose = require('mongoose');
const UserFavorite = require('../models/UserFavorite');
const ChatHistory = require('../models/ChatHistory');
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || 'your-secure-encryption-key-exactly-32-b'; // Make this exactly 32 bytes
const IV_LENGTH = 16; // For AES, this is always 16 bytes
// Function to encrypt API keys
function encrypt(text) {
    try {
        // Ensure key is exactly 32 bytes
        let key = Buffer.from(ENCRYPTION_KEY);
        if (key.length !== 32) {
            const newKey = Buffer.alloc(32);
            key.copy(newKey, 0, 0, Math.min(key.length, 32));
            key = newKey;
        }
        const iv = crypto.randomBytes(IV_LENGTH);
        const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
        let encrypted = cipher.update(text);
        encrypted = Buffer.concat([encrypted, cipher.final()]);
        return iv.toString('hex') + ':' + encrypted.toString('hex');
    } catch (err) {
        console.error("Encryption error:", err);
        throw err;
    }
}
// Function to decrypt API keys
function decrypt(text) {
    try {
        // Check if the text is in the correct format
        if (!text || !text.includes(':')) {
            console.log("Invalid encrypted text format");
            return '';
        }
        let key = Buffer.from(ENCRYPTION_KEY);
        if (key.length !== 32) {
            const newKey = Buffer.alloc(32);
            key.copy(newKey, 0, 0, Math.min(key.length, 32));
            key = newKey;
        }
        const textParts = text.split(':');
        const iv = Buffer.from(textParts.shift(), 'hex');
        const encryptedText = Buffer.from(textParts.join(':'), 'hex');
        // Ensure IV is correct length
        if (iv.length !== IV_LENGTH) {
            console.log("Invalid IV length in encrypted data");
            return '';
        }
        const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
        let decrypted = decipher.update(encryptedText);
        decrypted = Buffer.concat([decrypted, decipher.final()]);
        return decrypted.toString();
    } catch (err) {
        console.error("Decryption error:", err);
        return '';
    }
}
// --- Multer setup for profile picture ---
const profilePicStorage = multer.memoryStorage();
const profilePicUpload = multer({
    storage: profilePicStorage,
    limits: { fileSize: 5 * 1024 * 1024 }, // 5MB limit for profile pics
    fileFilter: (req, file, cb) => {
        if (file.mimetype.startsWith('image/')) {
            cb(null, true);
        } else {
            cb(new Error('Not an image! Please upload an image file.'), false);
        }
    }
}).single('profileImage');
const Signup = async (req, res) => {
    const { name, email, password } = req.body;
    try {
        if (!name || !email || !password) {
            return res.status(400).json({ message: 'All fields are required' });
        }
        if (password.length < 6) {
            return res.status(400).json({ message: "Password must be at least 6 characters long" });
        }
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ message: 'User already exists' });
        }
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);
        const newUser = new User({ name, email, password: hashedPassword });
        if (newUser) {
            await newUser.save();
            res.status(201).json({
                success: true,
                message: "Signup successful. Please login."
            });
        }
        else {
            res.status(400).json({ message: 'Invalid user data' });
        }
    }
    catch (error) {
        res.status(500).json({ message: error.message });
    }
}
const Login = async (req, res) => {
    const { email, password } = req.body;
    try{
        if(!email || !password){
            return res.status(400).json({message:'All fields are required'});
        }
        const user = await User.findOne({email}).select('+password');
        if(!user){
            return res.status(400).json({message:'Invalid email or password'});
        }
        const isPasswordCorrect = await bcrypt.compare(password,user.password);
        if(!isPasswordCorrect){
            return res.status(400).json({message:'Invalid email or password'});
        }
        // Update lastActive timestamp when user logs in
        user.lastActive = new Date();
        await user.save();
        // Generate tokens
        const accessToken = generateAccessToken(user._id);
        generateRefreshTokenAndSetCookie(res, user._id);
        // Return access token and user info in the response body
        res.status(200).json({
            accessToken,
            user: {
              _id: user._id,
              name: user.name,
              email: user.email,
              profilePic: user.profilePic,
              role: user.role
            }
        });
    }
    catch(error){
        console.error("Login Error:", error);
        res.status(500).json({message: 'Server error during login.'});
    }
}
const googleAuth = passport.authenticate('google', { scope: ['profile', 'email'] });
const googleAuthCallback = (req, res, next) => {
  passport.authenticate('google', {
      failureRedirect: `${process.env.FRONTEND_URL || 'http://localhost:5173'}/login?error=google_auth_failed`,
      session: false
    }, async (err, user, info) => {
    if (err) {
        console.error("Google Auth Error:", err);
        return res.redirect(`${process.env.FRONTEND_URL || 'http://localhost:5173'}/login?error=google_auth_error`);
    }
    if (!user) {
        console.error("Google Auth Failed:", info?.message);
        return res.redirect(`${process.env.FRONTEND_URL || 'http://localhost:5173'}/login?error=${encodeURIComponent(info?.message || 'google_auth_failed')}`);
    }
    // User authenticated successfully by Google Strategy
    try {
        // Update lastActive for Google login
        user.lastActive = new Date();
        await user.save();
        // Generate tokens
        const accessToken = generateAccessToken(user._id);
        // Set secure and httpOnly flags to false for development
        generateRefreshTokenAndSetCookie(res, user._id);
        // Set additional cookie for SameSite issue (optional)
        const userData = {
            _id: user._id,
            name: user.name,
            email: user.email,
            profilePic: user.profilePic,
            role: user.role
        };
        // Redirect to a dedicated frontend callback handler page/route
        const feRedirectUrl = new URL(`${process.env.FRONTEND_URL || 'http://localhost:5173'}/auth/callback`);
        feRedirectUrl.searchParams.set('accessToken', accessToken);
        feRedirectUrl.searchParams.set('user', JSON.stringify(userData));
        // Log successful authentication
        return res.redirect(feRedirectUrl.toString());
    } catch (error) {
        console.error("Error during Google auth token generation/redirect:", error);
        return res.redirect(`${process.env.FRONTEND_URL || 'http://localhost:5173'}/login?error=processing_failed`);
    }
  })(req, res, next);
};
const Logout = async (req, res) => {
    clearRefreshTokenCookie(res);
    res.status(200).json({ message: 'Logged out successfully' });
}
const refreshTokenController = async (req, res) => {
    const refreshToken = req.cookies.refreshToken;
    if (!refreshToken) {
        return res.status(401).json({ message: 'Refresh token not found' });
    }
    try {
        // Verify the refresh token
        const decoded = jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET);
        // Optional: Check if refresh token is revoked in DB if implementing revocation
        const user = await User.findById(decoded.userId);
        if (!user) {
             return res.status(401).json({ message: 'User not found for refresh token' });
        }
        // Issue a new access token
        const newAccessToken = generateAccessToken(decoded.userId);
        // Optionally update lastActive here as well
        user.lastActive = new Date();
        await user.save();
        res.status(200).json({ accessToken: newAccessToken });
    } catch (error) {
         console.error("Refresh Token Error:", error);
         clearRefreshTokenCookie(res); // Clear invalid refresh token cookie
         if (error.name === 'JsonWebTokenError' || error.name === 'TokenExpiredError') {
             return res.status(403).json({ message: 'Invalid or expired refresh token' });
         }
         return res.status(500).json({ message: 'Server error during token refresh' });
    }
};
const getCurrentUser = async (req, res) => {
    try {
        // req.user is populated by protectRoute middleware (using access token)
        const userId = req.user._id;
        const user = await User.findOne({email: req.user.email});
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }
        // Update lastActive timestamp when user data is fetched via protected route
        user.lastActive = new Date();
        await user.save();
        res.status(200).json({
            _id: user._id,
            name: user.name,
            email: user.email,
            profilePic: user.profilePic,
            role: user.role
        });
    } catch (error) {
        console.error("Get Current User Error:", error);
        res.status(500).json({ message: 'Server error fetching user data.' });
    }
};
const getAllUsers = async (req, res) => {
    try {
        // Only admin should be able to get all users
        if (req.user.role !== 'admin') {
            return res.status(403).json({ message: 'Not authorized to access this resource' });
        }
        const users = await User.find({}).select('-password').sort({ createdAt: -1 });
        res.status(200).json({
            success: true,
            users
        });
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
};
const removeTeamMember = async (req, res) => {
    try {
        const { userId } = req.params;
        // Verify admin role
        if (req.user.role !== 'admin') {
            return res.status(403).json({ success: false, message: 'Only admins can remove team members' });
        }
        // Check if user exists
        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).json({ success: false, message: 'User not found' });
        }
        const session = await mongoose.startSession();
        try {
            await session.withTransaction(async () => {
                // Delete all associated data in parallel
                const [chatResult, gptResult, favResult, userResult] = await Promise.all([
                    ChatHistory.deleteMany({ userId }).session(session),
                    UserGptAssignment.deleteMany({ userId }).session(session),
                    UserFavorite.deleteMany({ userId }).session(session),
                    User.findByIdAndDelete(userId).session(session)
                ]);
                return res.status(200).json({
                    success: true,
                    message: 'User and all associated data removed successfully',
                    deletionResults: {
                        chatHistory: chatResult,
                        gptAssignments: gptResult,
                        favorites: favResult,
                        user: !!userResult
                    }
                });
            });
        } finally {
            session.endSession();
        }
    } catch (error) {
        console.error('Error removing team member:', error);
        return res.status(500).json({
            success: false,
            message: 'Failed to remove team member',
            error: error.message
        });
    }
};
// Create transporter
const transporter = nodemailer.createTransport({
  service: process.env.EMAIL_SERVICE || 'gmail',
  auth: {
    user: process.env.GMAIL_USERNAME,
    pass: process.env.GMAIL_PASSWORD
  }
});
// Add this new function to set user as inactive
const setInactive = async (req, res) => {
    try {
        // req.user is available thanks to protectRoute middleware
        if (!req.user || !req.user._id) {
            return res.status(401).json({ message: 'Not authorized' });
        }
        const userId = req.user._id;
        await User.findByIdAndUpdate(userId, { $set: { lastActive: null } });
        res.status(200).json({ success: true, message: 'User marked as inactive.' });
    } catch (error) {
        console.error("Error setting user inactive:", error);
        res.status(500).json({ success: false, message: 'Failed to mark user as inactive.' });
    }
};
// Get users with GPT counts in one call
const getUsersWithGptCounts = async (req, res) => {
    try {
      // Verify admin role
      if (req.user.role !== 'admin') {
        return res.status(403).json({ success: false, message: 'Not authorized' });
      }
      // Get pagination parameters
      const page = parseInt(req.query.page, 10) || 1;
      const limit = parseInt(req.query.limit, 10) || 10;
      const skip = (page - 1) * limit;
      // Execute queries in parallel
      const [total, users, assignments] = await Promise.all([
        User.countDocuments({ _id: { $ne: req.user._id } }),
        User.find({ _id: { $ne: req.user._id } })
          .select('name email role createdAt lastActive')
          .sort({ createdAt: -1 })
          .skip(skip)
          .limit(limit)
          .lean(),
        UserGptAssignment.aggregate([
          { $group: { _id: '$userId', count: { $sum: 1 } } },
        ]),
      ]);
      // Create GPT count map
      const gptCountMap = Object.fromEntries(
        assignments.map(({ _id, count }) => [_id.toString(), count])
      );
      // Add GPT counts to users
      const usersWithCounts = users.map((user) => ({
        ...user,
        gptCount: gptCountMap[user._id] || 0,
      }));
      return res.status(200).json({
        success: true,
        users: usersWithCounts,
        total,
        page,
        limit,
      });
    } catch (error) {
      console.error('Error fetching users with GPT counts:', error);
      return res.status(500).json({ success: false, message: error.message });
    }
  };
// Get a single user's GPT count
const getUserGptCount = async (req, res) => {
    try {
        const { userId } = req.params;
        // Count GPT assignments for this user
        const count = await UserGptAssignment.countDocuments({ userId });
        res.status(200).json({
            success: true,
            count
        });
    } catch (error) {
        console.error('Error fetching user GPT count:', error);
        res.status(500).json({ message: error.message });
    }
};
// Get user activity
const getUserActivity = async (req, res) => {
    try {
        const { userId } = req.params;
        // Only admin should be able to access other users' activity
        if (req.user.role !== 'admin' && req.user._id.toString() !== userId) {
            return res.status(403).json({ message: 'Not authorized to access this resource' });
        }
        return res.status(200).json({
            success: true,
            activities: []
        });
    } catch (error) {
        console.error('Error fetching user activity:', error);
        return res.status(500).json({ message: error.message });
    }
};
// Update User Profile (Name, Email)
const updateUserProfile = async (req, res) => {
    const { name, email } = req.body;
    const userId = req.user._id;
    try {
        if (!name && !email) {
            return res.status(400).json({ success: false, message: 'Please provide name or email to update.' });
        }
        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).json({ success: false, message: 'User not found.' });
        }
        if (email && email !== user.email) {
            const existingUser = await User.findOne({ email: email });
            if (existingUser) {
                return res.status(400).json({ success: false, message: 'Email address already in use.' });
            }
            user.email = email;
        }
        if (name) {
            user.name = name;
        }
        await user.save();
        const updatedUser = await User.findById(userId).select('-password');
        res.status(200).json({
            success: true,
            message: 'Profile updated successfully.',
            user: updatedUser
        });
    } catch (error) {
        console.error('Error updating user profile:', error);
        res.status(500).json({ success: false, message: 'Server error updating profile.' });
    }
};
// Upload/Update Profile Picture
const updateUserProfilePicture = async (req, res) => {
    const userId = req.user._id;
    try {
        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).json({ success: false, message: 'User not found.' });
        }
        if (!req.file) {
            return res.status(400).json({ success: false, message: 'No image file provided.' });
        }
        if (user.profilePic) {
             try {
                 if (process.env.R2_PUBLIC_URL && user.profilePic.startsWith(process.env.R2_PUBLIC_URL)) {
                     const key = user.profilePic.replace(process.env.R2_PUBLIC_URL + '/', '');
                     await deleteFromR2(key);
                 }
             } catch (deleteError) {
                 console.error("Failed to delete old profile picture, proceeding anyway:", deleteError);
             }
        }
        const { fileUrl } = await uploadToR2(
            req.file.buffer,
            req.file.originalname,
            `profile-pics/${userId}`
        );
        user.profilePic = fileUrl;
        await user.save();
        const updatedUser = await User.findById(userId).select('-password');
        res.status(200).json({
            success: true,
            message: 'Profile picture updated successfully.',
            user: updatedUser
        });
    } catch (error) {
        console.error('Error updating profile picture:', error);
         if (error.message.includes('Not an image')) {
             return res.status(400).json({ success: false, message: 'Invalid file type. Please upload an image.' });
         }
        res.status(500).json({ success: false, message: 'Server error updating profile picture.' });
    }
};
// Change Password
const changePassword = async (req, res) => {
    const { currentPassword, newPassword } = req.body;
    const userId = req.user._id;
    try {
        if (!currentPassword || !newPassword) {
            return res.status(400).json({ success: false, message: 'Please provide both current and new passwords.' });
        }
        if (newPassword.length < 6) {
            return res.status(400).json({ success: false, message: 'New password must be at least 6 characters long.' });
        }
        const user = await User.findById(userId).select('+password');
        if (!user) {
            return res.status(404).json({ success: false, message: 'User not found.' });
        }
        const isMatch = await bcrypt.compare(currentPassword, user.password);
        if (!isMatch) {
            return res.status(400).json({ success: false, message: 'Incorrect current password.' });
        }
        const salt = await bcrypt.genSalt(10);
        user.password = await bcrypt.hash(newPassword, salt);
        await user.save();
        res.status(200).json({
            success: true,
            message: 'Password updated successfully.'
        });
    } catch (error) {
        console.error('Error changing password:', error);
        res.status(500).json({ success: false, message: 'Server error changing password.' });
    }
};
// Get user's API keys
const getApiKeys = async (req, res) => {
    try {
        const user = await User.findById(req.user._id).select('+apiKeys');
        if (!user) {
            return res.status(404).json({ success: false, message: 'User not found' });
        }
        // Initialize apiKeys object if it doesn't exist
        if (!user.apiKeys) {
            return res.json({ success: true, apiKeys: {} });
        }
        // Decrypt API keys for frontend use
        const decryptedKeys = {};
        for (const [key, value] of Object.entries(user.apiKeys)) {
            if (value) {
                try {
                    decryptedKeys[key] = decrypt(value);
                    // If decryption returned empty string due to failure, consider it invalid
                    if (!decryptedKeys[key]) {
                        decryptedKeys[key] = '';
                    }
                } catch (error) {
                    console.error(`Failed to decrypt key ${key}:`, error);
                    decryptedKeys[key] = '';
                }
            } else {
                decryptedKeys[key] = '';
            }
        }
        return res.json({ success: true, apiKeys: decryptedKeys });
    } catch (error) {
        console.error('Error getting API keys:', error);
        return res.status(500).json({ success: false, message: 'Server error' });
    }
};
// Save user's API keys
const saveApiKeys = async (req, res) => {
    try {
        const { apiKeys } = req.body;
        if (!apiKeys) {
            return res.status(400).json({ success: false, message: 'No API keys provided' });
        }
        const user = await User.findById(req.user._id).select('+apiKeys');
        if (!user) {
            return res.status(404).json({ success: false, message: 'User not found' });
        }
        // Encrypt API keys for storage
        const encryptedKeys = {};
        for (const [key, value] of Object.entries(apiKeys)) {
            if (value) {
                try {
                    encryptedKeys[key] = encrypt(value);
                } catch (err) {
                    console.error(`Error encrypting ${key}:`, err);
                    throw err;
                }
            }
        }
        // Store encrypted keys
        user.apiKeys = encryptedKeys;
        await user.save();
        return res.json({ success: true, message: 'API keys saved successfully' });
    } catch (error) {
        console.error('Error saving API keys:', error);
        return res.status(500).json({ success: false, message: error.message || 'Server error' });
    }
};
// Update password 
const updatePassword = async (req, res) => {
    try {
        const { currentPassword, newPassword } = req.body;
        // Validate inputs
        if (!currentPassword || !newPassword) {
            return res.status(400).json({ success: false, message: 'All fields are required' });
        }
        // Find user
        const user = await User.findById(req.user._id).select('+password');
        if (!user) {
            return res.status(404).json({ success: false, message: 'User not found' });
        }
        // Check if current password is correct
        const isMatch = await bcrypt.compare(currentPassword, user.password);
        if (!isMatch) {
            return res.status(400).json({ success: false, message: 'Current password is incorrect' });
        }
        // Hash new password
        const salt = await bcrypt.genSalt(10);
        user.password = await bcrypt.hash(newPassword, salt);
        await user.save();
        return res.json({ success: true, message: 'Password updated successfully' });
    } catch (error) {
        console.error('Error updating password:', error);
        return res.status(500).json({ success: false, message: 'Server error' });
    }
};
// Update User Permissions
const updateUserPermissions = async (req, res) => {
    try {
        const { userId } = req.params;
        const { role, department } = req.body;
        // Verify admin role
        if (req.user.role !== 'admin') {
            return res.status(403).json({ 
                success: false, 
                message: 'Only admins can update user permissions' 
            });
        }
        // Check if user exists
        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).json({ 
                success: false, 
                message: 'User not found' 
            });
        }
        // Convert role to lowercase for database (frontend sends capitalized)
        if (role) {
            user.role = role.toLowerCase();
        }
        // Update department if provided
        if (department) {
            user.department = department;
        }
        await user.save();
        res.status(200).json({
            success: true,
            message: 'User permissions updated successfully',
            user: {
                id: user._id,
                name: user.name,
                email: user.email,
                role: user.role,
                department: user.department
            }
        });
    } catch (error) {
        console.error('Error updating user permissions:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Server error updating permissions.' 
        });
    }
};
module.exports = { Signup, Login, Logout, googleAuth, googleAuthCallback, refreshTokenController, getCurrentUser, getAllUsers,  setInactive, removeTeamMember, getUsersWithGptCounts, getUserGptCount, getUserActivity, updateUserProfile, updateUserProfilePicture, changePassword, getApiKeys, saveApiKeys, updatePassword, updateUserPermissions };
````

## File: backend/controllers/chatHistoryController.js
````javascript
const ChatHistory = require('../models/ChatHistory');
const mongoose = require('mongoose');
exports.saveMessage = async (req, res) => {
    try {
        const { userId, gptId, gptName, message, role, model } = req.body;
        if (!userId || !gptId || !message || !role) {
            return res.status(400).json({ 
                success: false, 
                message: 'Missing required fields',
                received: { hasUserId: !!userId, hasGptId: !!gptId, hasMessage: !!message, hasRole: !!role }
            });
        }
        // Find existing conversation or create new one
        let conversation = await ChatHistory.findOne({ userId, gptId });
        if (!conversation) {
            conversation = new ChatHistory({
                userId,
                gptId,
                gptName,
                model: model || 'gpt-4o-mini',
                messages: [],
                lastMessage: ''
            });
        }
        // Add new message
        conversation.messages.push({
            role,
            content: message,
            timestamp: new Date()
        });
        // Update last message (always update for display purposes)
        if (role === 'user') {
            conversation.lastMessage = message;
        }
        conversation.updatedAt = new Date();
        const savedConversation = await conversation.save();
        res.json({ 
            success: true, 
            conversation: savedConversation,
            messageCount: savedConversation.messages.length
        });
    } catch (error) {
        console.error('Error saving chat message:', error);
        res.status(500).json({ success: false, message: 'Error saving chat message', error: error.message });
    }
};
exports.getUserHistory = async (req, res) => {
    try {
        const { userId } = req.params;
        if (!userId) {
            return res.status(400).json({ success: false, message: 'User ID is required' });
        }
        const conversations = await ChatHistory.find({ userId })
            .sort({ updatedAt: -1 })
            .lean();
        // Format conversations for frontend
        const formattedConversations = conversations.map(conv => ({
            _id: conv._id,
            gptId: conv.gptId,
            gptName: conv.gptName,
            lastMessage: conv.lastMessage || (conv.messages.length > 0 ? conv.messages[conv.messages.length-1].content : ''),
            updatedAt: conv.updatedAt,
            messageCount: conv.messages.length,
            model: conv.model || 'gpt-4o-mini',
            summary: conv.summary,
            messages: conv.messages.map(msg => ({
                role: msg.role,
                content: msg.content,
                timestamp: msg.timestamp
            }))
        }));
        res.json({ success: true, conversations: formattedConversations });
    } catch (error) {
        console.error('Error fetching chat history:', error);
        res.status(500).json({ success: false, message: 'Error fetching chat history', error: error.message });
    }
};
exports.getConversation = async (req, res) => {
    try {
        const { userId, gptId } = req.params;
        if (!userId || !gptId) {
            return res.status(400).json({ success: false, message: 'User ID and GPT ID are required' });
        }
        const conversation = await ChatHistory.findOne({ userId, gptId });
        if (!conversation) {
            return res.status(404).json({ success: false, message: 'Conversation not found' });
        }
        // Format the conversation to include all message details
        const formattedConversation = {
            _id: conversation._id,
            userId: conversation.userId,
            gptId: conversation.gptId,
            gptName: conversation.gptName,
            model: conversation.model,
            summary: conversation.summary,
            lastMessage: conversation.lastMessage,
            createdAt: conversation.createdAt,
            updatedAt: conversation.updatedAt,
            messages: conversation.messages.map(msg => ({
                role: msg.role,
                content: msg.content,
                timestamp: msg.timestamp
            }))
        };
        res.json({ success: true, conversation: formattedConversation });
    } catch (error) {
        console.error('Error fetching conversation:', error);
        res.status(500).json({ success: false, message: 'Error fetching conversation', error: error.message });
    }
};
exports.deleteConversation = async (req, res) => {
    try {
        const { userId, conversationId } = req.params;
        if (!userId || !conversationId) {
            return res.status(400).json({ success: false, message: 'User ID and conversation ID are required' });
        }
        const result = await ChatHistory.findOneAndDelete({
            _id: conversationId,
            userId
        });
        if (!result) {
            return res.status(404).json({ success: false, message: 'Conversation not found' });
        }
        res.json({ success: true, message: 'Conversation deleted successfully' });
    } catch (error) {
        console.error('Error deleting conversation:', error);
        res.status(500).json({ success: false, message: 'Error deleting conversation', error: error.message });
    }
};
exports.getTeamHistory = async (req, res) => {
    try {
        // Check if the user has admin role (NOT isAdmin property)
        if (req.user.role !== 'admin') {
            return res.status(403).json({ 
                success: false, 
                message: 'Access denied. Only admins can view team history.' 
            });
        }
        // Get team's chat history (all conversations)
        const conversations = await ChatHistory.find({})
            .sort({ updatedAt: -1 })
            .populate('userId', 'name email') // Get user details
            .lean();
        // Format conversations for frontend
        const formattedConversations = conversations.map(conv => ({
            _id: conv._id,
            userId: conv.userId?._id || conv.userId,
            userName: conv.userId?.name || 'Team Member',
            userEmail: conv.userId?.email || '',
            gptId: conv.gptId,
            gptName: conv.gptName,
            lastMessage: conv.lastMessage || (conv.messages.length > 0 ? conv.messages[conv.messages.length-1].content : ''),
            updatedAt: conv.updatedAt,
            messageCount: conv.messages.length,
            model: conv.model || 'gpt-4o-mini',
            summary: conv.summary,
            messages: conv.messages.map(msg => ({
                role: msg.role,
                content: msg.content,
                timestamp: msg.timestamp
            }))
        }));
        res.json({ success: true, conversations: formattedConversations });
    } catch (error) {
        console.error('Error fetching team chat history:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Error fetching team chat history', 
            error: error.message 
        });
    }
};
exports.getAdminConversationById = async (req, res) => {
    try {
        const { conversationId } = req.params;
        if (!mongoose.Types.ObjectId.isValid(conversationId)) {
            return res.status(400).json({ success: false, message: 'Invalid Conversation ID format' });
        }
        // Find conversation by ID, populate user details if needed
        // Ensure the admin has permission via middleware (adminOnly)
        const conversation = await ChatHistory.findById(conversationId)
            .populate('userId', 'name email') // Optional: include basic user info
            .lean(); // Use lean for performance if not modifying
        if (!conversation) {
            return res.status(404).json({ success: false, message: 'Conversation not found' });
        }
        // Format messages similar to other endpoints
        const formattedConversation = {
            ...conversation,
            userName: conversation.userId?.name || 'Unknown User', // Add userName if populated
            userEmail: conversation.userId?.email || '', // Add userEmail if populated
            messages: conversation.messages.map(msg => ({
                role: msg.role,
                content: msg.content,
                timestamp: msg.timestamp
            }))
        };
        // Remove populated userId object if you only want the ID string
        // formattedConversation.userId = conversation.userId?._id || conversation.userId; 
        res.json({ success: true, conversation: formattedConversation });
    } catch (error) {
        console.error('Error fetching conversation by ID for admin:', error);
        res.status(500).json({ success: false, message: 'Error fetching conversation', error: error.message });
    }
};
````

## File: backend/controllers/customGptController.js
````javascript
const CustomGpt = require('../models/CustomGpt');
const { uploadToR2, deleteFromR2 } = require('../lib/r2');
const multer = require('multer');
const fs = require('fs');
const path = require('path');
const UserGptAssignment = require('../models/UserGptAssignment');
const User = require('../models/User');
const UserFavorite = require('../models/UserFavorite');
// Configure multer for memory storage
const storage = multer.memoryStorage();
const upload = multer({
  storage,
  limits: { fileSize: 20 * 1024 * 1024 } // 20MB limit
});
// Define specific field handlers
const handleImageUpload = upload.single('image');
const handleKnowledgeUpload = upload.array('knowledgeFiles', 5);
// New combined middleware for handling both optional fields
const handleCombinedUpload = upload.fields([
  { name: 'image', maxCount: 1 },
  { name: 'knowledgeFiles', maxCount: 5 }
]);
// Create a new custom GPT
const createCustomGpt = async (req, res) => {
  try {
    const { name, description, instructions, conversationStarter, model, capabilities } = req.body;
    // Validate required fields manually for clarity (optional but helpful)
    if (!name || !description || !instructions) {
      console.error("Validation Error: Missing required fields (name, description, instructions)");
      return res.status(400).json({ success: false, message: 'Missing required fields: name, description, instructions' });
    }
    if (!req.user?._id) {
      console.error("Auth Error: req.user._id is missing");
      return res.status(401).json({ success: false, message: 'Authentication error, user ID not found' });
    }
    let parsedCapabilities;
    try {
      parsedCapabilities = JSON.parse(capabilities || '{"webBrowsing": true}');
    } catch (parseError) {
      console.error("Error parsing capabilities JSON:", parseError);
      return res.status(400).json({ success: false, message: 'Invalid format for capabilities' });
    }
    // Create the custom GPT object
    const customGptData = {
      name,
      description,
      instructions,
      conversationStarter,
      model,
      capabilities: parsedCapabilities,
      createdBy: req.user._id,
      imageUrl: null,       // Initialize explicitly
      knowledgeFiles: []  // Initialize explicitly
    };
    const customGpt = new CustomGpt(customGptData);
    // Access files from req.files
    const imageFile = req.files?.image?.[0];
    const knowledgeUploads = req.files?.knowledgeFiles || [];
    // Upload image if provided
    if (imageFile) {
      try {
        const { fileUrl } = await uploadToR2(
          imageFile.buffer,
          imageFile.originalname,
          'images/gpt'
        );
        customGpt.imageUrl = fileUrl;
      } catch (uploadError) {
        console.error("Error during image upload to R2:", uploadError);
        // Decide if you want to stop or continue without the image
        return res.status(500).json({ success: false, message: 'Failed during image upload', error: uploadError.message });
      }
    }
    // Upload knowledge files if provided
    if (knowledgeUploads.length > 0) {
      try {
        const knowledgeFilesData = await Promise.all(
          knowledgeUploads.map(async (file) => {
            const { fileUrl } = await uploadToR2(
              file.buffer,
              file.originalname,
              'knowledge'
            );
            return {
              name: file.originalname,
              fileUrl,
              fileType: file.mimetype,
            };
          })
        );
        customGpt.knowledgeFiles = knowledgeFilesData;
      } catch (uploadError) {
        console.error("Error during knowledge file upload to R2:", uploadError);
        // Decide if you want to stop or continue without the knowledge files
        return res.status(500).json({ success: false, message: 'Failed during knowledge file upload', error: uploadError.message });
      }
    }
    // Explicitly log the save operation and force a database test
    const savedGpt = await customGpt.save();
    // DIRECT DATABASE VERIFICATION - force a fresh read from DB
    const verifyResult = await CustomGpt.findById(savedGpt._id);
    if (verifyResult) {
    } else {
      console.error("VERIFICATION FAILED: Document not found in DB after save!");
    }
    res.status(201).json({
      success: true,
      message: 'Custom GPT created successfully',
      customGpt: savedGpt
    });
  } catch (error) {
    // Log the specific error
    console.error('--- Error caught in createCustomGpt catch block ---');
    console.error("Error Name:", error.name);
    console.error("Error Message:", error.message);
    console.error("Full Error Object:", error);
    // Check for Mongoose validation errors specifically
    if (error.name === 'ValidationError') {
      // Extract cleaner validation messages
      const validationErrors = Object.values(error.errors).map(err => err.message);
      console.error("Validation Errors:", validationErrors);
      return res.status(400).json({
        success: false,
        message: 'Validation failed',
        errors: validationErrors
      });
    }
    res.status(500).json({
      success: false,
      message: 'Failed to create custom GPT',
      error: error.message // Send a generic message or specific if safe
    });
  }
};
// Get all custom GPTs for the current user
const getUserCustomGpts = async (req, res) => {
  try {
    const customGpts = await CustomGpt.find({ createdBy: req.user._id });
    res.status(200).json({
      success: true,
      customGpts
    });
  } catch (error) {
    console.error('Error fetching user custom GPTs:', error);
    return res.status(500).json({
      success: false,
      message: 'Error fetching custom GPTs'
    });
  }
};
// Get a specific custom GPT by ID
const getCustomGptById = async (req, res) => {
  try {
    // Check if id is valid before attempting to find
    if (!req.params.id || req.params.id === 'undefined') {
      return res.status(400).json({
        success: false,
        message: 'Invalid GPT ID provided'
      });
    }
    const customGpt = await CustomGpt.findById(req.params.id);
    if (!customGpt) {
      return res.status(404).json({
        success: false,
        message: 'Custom GPT not found'
      });
    }
    // Check if the user owns this GPT
    if (customGpt.createdBy.toString() !== req.user._id.toString()) {
      return res.status(403).json({
        success: false,
        message: 'Not authorized to access this custom GPT'
      });
    }
    res.status(200).json({
      success: true,
      customGpt
    });
  } catch (error) {
    console.error('Error fetching custom GPT:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch custom GPT',
      error: error.message
    });
  }
};
// Update a custom GPT
const updateCustomGpt = async (req, res) => {
  try {
    let customGpt = await CustomGpt.findById(req.params.id);
    if (!customGpt) {
      return res.status(404).json({
        success: false,
        message: 'Custom GPT not found'
      });
    }
    // Check if the user owns this GPT
    if (customGpt.createdBy.toString() !== req.user._id.toString()) {
      return res.status(403).json({
        success: false,
        message: 'Not authorized to update this custom GPT'
      });
    }
    const { name, description, instructions, conversationStarter, model, capabilities } = req.body;
    // Update basic fields
    customGpt.name = name || customGpt.name;
    customGpt.description = description || customGpt.description;
    customGpt.instructions = instructions || customGpt.instructions;
    customGpt.conversationStarter = conversationStarter ?? customGpt.conversationStarter;
    customGpt.model = model || customGpt.model;
    if (capabilities) {
      customGpt.capabilities = JSON.parse(capabilities);
    }
    // Access files from req.files (now an object)
    const imageFile = req.files?.image ? req.files.image[0] : null;
    const knowledgeUploads = req.files?.knowledgeFiles || [];
    // Upload new image if provided
    if (imageFile) {
      // Delete old image if exists
      if (customGpt.imageUrl) {
        // Extract key from imageUrl
        const key = customGpt.imageUrl.replace(process.env.R2_PUBLIC_URL + '/', '');
        await deleteFromR2(key);
      }
      const { fileUrl } = await uploadToR2(
        imageFile.buffer,
        imageFile.originalname,
        'images/gpt'
      );
      customGpt.imageUrl = fileUrl;
    }
    // Handle knowledge files if provided
    if (knowledgeUploads.length > 0) {
      // Delete old files if needed and specified in request
      if (req.body.replaceKnowledge === 'true' && customGpt.knowledgeFiles.length > 0) {
        for (const file of customGpt.knowledgeFiles) {
          const key = file.fileUrl.replace(process.env.R2_PUBLIC_URL + '/', '');
          await deleteFromR2(key);
        }
        customGpt.knowledgeFiles = [];
      }
      // Upload new files
      const newKnowledgeFilesData = await Promise.all(
        knowledgeUploads.map(async (file) => {
          const { fileUrl } = await uploadToR2(
            file.buffer,
            file.originalname,
            'knowledge'
          );
          return {
            name: file.originalname,
            fileUrl,
            fileType: file.mimetype,
          };
        })
      );
      customGpt.knowledgeFiles = [
        ...customGpt.knowledgeFiles,
        ...newKnowledgeFilesData
      ];
    }
    await customGpt.save();
    res.status(200).json({
      success: true,
      message: 'Custom GPT updated successfully',
      customGpt
    });
  } catch (error) {
    console.error('Error updating custom GPT:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to update custom GPT',
      error: error.message
    });
  }
};
// Delete a custom GPT
const deleteCustomGpt = async (req, res) => {
  try {
    const customGpt = await CustomGpt.findById(req.params.id);
    if (!customGpt) {
      return res.status(404).json({
        success: false,
        message: 'Custom GPT not found'
      });
    }
    // Check if the user owns this GPT
    if (customGpt.createdBy.toString() !== req.user._id.toString()) {
      return res.status(403).json({
        success: false,
        message: 'Not authorized to delete this custom GPT'
      });
    }
    // Delete associated files from R2
    if (customGpt.imageUrl) {
      const imageKey = customGpt.imageUrl.replace(process.env.R2_PUBLIC_URL + '/', '');
      await deleteFromR2(imageKey);
    }
    // Delete knowledge files
    for (const file of customGpt.knowledgeFiles) {
      const fileKey = file.fileUrl.replace(process.env.R2_PUBLIC_URL + '/', '');
      await deleteFromR2(fileKey);
    }
    // Delete the custom GPT from database
    await CustomGpt.findByIdAndDelete(req.params.id);
    res.status(200).json({
      success: true,
      message: 'Custom GPT deleted successfully'
    });
  } catch (error) {
    console.error('Error deleting custom GPT:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to delete custom GPT',
      error: error.message
    });
  }
};
// Delete a specific knowledge file
const deleteKnowledgeFile = async (req, res) => {
  try {
    const { id, fileIndex } = req.params;
    const customGpt = await CustomGpt.findById(id);
    if (!customGpt) {
      return res.status(404).json({
        success: false,
        message: 'Custom GPT not found'
      });
    }
    // Check if the user owns this GPT
    if (customGpt.createdBy.toString() !== req.user._id.toString()) {
      return res.status(403).json({
        success: false,
        message: 'Not authorized to modify this custom GPT'
      });
    }
    // Check if the file exists
    if (!customGpt.knowledgeFiles[fileIndex]) {
      return res.status(404).json({
        success: false,
        message: 'Knowledge file not found'
      });
    }
    // Delete the file from R2
    const fileKey = customGpt.knowledgeFiles[fileIndex].fileUrl.replace(process.env.R2_PUBLIC_URL + '/', '');
    await deleteFromR2(fileKey);
    // Remove the file from the array
    customGpt.knowledgeFiles.splice(fileIndex, 1);
    await customGpt.save();
    res.status(200).json({
      success: true,
      message: 'Knowledge file deleted successfully',
      customGpt
    });
  } catch (error) {
    console.error('Error deleting knowledge file:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to delete knowledge file',
      error: error.message
    });
  }
};
const getAllCustomGpts = async (req, res) => {
  try {
    // Only show GPTs created by the admin (current user)
    const filter = { createdBy: req.user._id };
    const customGpts = await CustomGpt.find(filter); 
    res.status(200).json({
      success: true,
      customGpts
    });
  } catch (error) {
    console.error('Error fetching all accessible custom GPTs:', error);
    return res.status(500).json({
      success: false,
      message: 'Error fetching custom GPTs'
    });
  }
};
const getUserAssignedGpts = async (req, res) => {
  try {
    const userId = req.params.userId || req.user._id;  // Allow using either parameter or current user
    // Check for assignments in UserGptAssignment collection
    const assignments = await UserGptAssignment.find({ userId }).lean();
    if (assignments.length === 0) {
      return res.status(200).json({
        success: true,
        gpts: []
      });
    }
    // Get GPT details for each assignment
    const gptIds = assignments.map(assignment => assignment.gptId);
    const gpts = await CustomGpt.find({ _id: { $in: gptIds } }).lean();
    // Add assignment dates and folder to each GPT
    const gptsWithDetails = gpts.map(gpt => {
      const assignment = assignments.find(a => a.gptId.toString() === gpt._id.toString());
      return {
        ...gpt,
        assignedAt: assignment?.createdAt || new Date(),
        folder: assignment?.folder || null
      };
    });
    // Get user's favorites to mark the favorite GPTs
    const userFavorites = await UserFavorite.find({ user: userId }).distinct('gpt');
    // Add isFavorite flag to each GPT
    const gptsWithFavorites = gptsWithDetails.map(gpt => {
      return {
        ...gpt,
        isFavorite: userFavorites.some(favId => 
          favId.toString() === gpt._id.toString()
        )
      };
    });
    return res.status(200).json({
      success: true,
      gpts: gptsWithFavorites
    });
  } catch (error) {
    console.error(`Error in getUserAssignedGpts: ${error.message}`);
    console.error(error.stack);
    return res.status(500).json({ 
      success: false, 
      message: `Failed to fetch assigned GPTs: ${error.message}`
    });
  }
};
const assignGptToUser = async (req, res) => {
  try {
    const { userId } = req.params;
    const { gptId } = req.body;
    if (req.user.role !== 'admin') {
      return res.status(403).json({
        success: false,
        message: 'Only admins can assign GPTs'
      });
    }
    const userExists = await User.exists({ _id: userId });
    if (!userExists) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }
    const gptExists = await CustomGpt.exists({ _id: gptId });
    if (!gptExists) {
      return res.status(404).json({
        success: false,
        message: 'GPT not found'
      });
    }
    // Check if assignment already exists
    const existingAssignment = await UserGptAssignment.findOne({ userId, gptId });
    if (existingAssignment) {
      return res.status(200).json({
        success: true,
        message: 'GPT is already assigned to this user'
      });
    }
    await UserGptAssignment.create({
      userId,
      gptId,
      assignedBy: req.user._id
    });
    return res.status(200).json({
      success: true,
      message: 'GPT assigned successfully'
    });
  } catch (error) {
    console.error('Error assigning GPT:', error);
    return res.status(500).json({
      success: false,
      message: 'Error assigning GPT'
    });
  }
};
const unassignGptFromUser = async (req, res) => {
  try {
    const { userId, gptId } = req.params;
    if (req.user.role !== 'admin') {
      return res.status(403).json({
        success: false,
        message: 'Only admins can unassign GPTs'
      });
    }
    const result = await UserGptAssignment.findOneAndDelete({ userId, gptId });
    if (!result) {
      return res.status(404).json({
        success: false,
        message: 'Assignment not found'
      });
    }
    return res.status(200).json({
      success: true,
      message: 'GPT unassigned successfully'
    });
  } catch (error) {
    console.error('Error unassigning GPT:', error);
    return res.status(500).json({
      success: false,
      message: 'Error unassigning GPT'
    });
  }
};
const getUserGptCount = async (req, res) => {
  try {
    // Only admins can access this
    if (req.user.role !== 'admin') {
      return res.status(403).json({
        success: false,
        message: 'Not authorized to access user GPT counts'
      });
    }
    // Get all users
    const users = await User.find().select('_id');
    const userGptCounts = {};
    users.forEach(user => {
      userGptCounts[user._id.toString()] = 0;
    });
    const assignments = await UserGptAssignment.aggregate([
      {
        $group: {
          _id: '$userId',
          count: { $sum: 1 }
        }
      }
    ]);
    assignments.forEach(assignment => {
      userGptCounts[assignment._id.toString()] = assignment.count;
    });
    return res.status(200).json({
      success: true,
      userGptCounts
    });
  } catch (error) {
    console.error('Error fetching user GPT counts:', error);
    return res.status(500).json({
      success: false,
      message: 'Error fetching user GPT counts'
    });
  }
};
// Get assigned GPT by ID
const getAssignedGptById = async (req, res) => {
  try {
    const gptId = req.params.id;
    const userId = req.user._id;
    if (!gptId || gptId === 'undefined') {
      return res.status(400).json({
        success: false,
        message: 'Invalid GPT ID provided'
      });
    }
    // First, check if this GPT is assigned to the user
    const assignment = await UserGptAssignment.findOne({
      userId: userId,
      gptId: gptId
    });
    if (!assignment) {
      return res.status(403).json({
        success: false,
        message: 'Not authorized to access this GPT or GPT not assigned to user'
      });
    }
    // If assignment exists, get the GPT details
    const customGpt = await CustomGpt.findById(gptId);
    if (!customGpt) {
      return res.status(404).json({
        success: false,
        message: 'Custom GPT not found'
      });
    }
    return res.status(200).json({
      success: true,
      customGpt
    });
  } catch (error) {
    console.error('Error fetching assigned GPT by ID:', error);
    return res.status(500).json({
      success: false,
      message: 'Error fetching assigned GPT'
    });
  }
};
// New controller function to update the folder
const updateGptFolder = async (req, res) => {
  try {
    const { id } = req.params;
    const { folder } = req.body; // folder can be a string or null/undefined
    // Validate folder name slightly (optional, prevent overly long names etc.)
    if (folder && typeof folder === 'string' && folder.length > 100) {
      return res.status(400).json({
        success: false,
        message: 'Folder name is too long (max 100 characters).'
      });
    }
    const customGpt = await CustomGpt.findById(id);
    if (!customGpt) {
      return res.status(404).json({
        success: false,
        message: 'Custom GPT not found'
      });
    }
    // Check if the user owns this GPT or is an admin (adjust authorization as needed)
    // Assuming only the creator can modify it for now
    if (customGpt.createdBy.toString() !== req.user._id.toString()) {
      // Maybe allow admins too?
      // if (customGpt.createdBy.toString() !== req.user._id.toString() && req.user.role !== 'admin') {
      return res.status(403).json({
        success: false,
        message: 'Not authorized to modify this custom GPT'
      });
    }
    // Update the folder - set to null if folder is null/empty string, otherwise use the string
    customGpt.folder = folder || null; 
    await customGpt.save();
    res.status(200).json({
      success: true,
      message: 'GPT folder updated successfully',
      customGpt: { // Send back minimal updated info if needed
        _id: customGpt._id,
        folder: customGpt.folder
      } 
    });
  } catch (error) {
    console.error('Error updating GPT folder:', error);
    // Handle potential validation errors from Mongoose if you add stricter schema rules
    if (error.name === 'ValidationError') {
      return res.status(400).json({ success: false, message: error.message });
    }
    res.status(500).json({
      success: false,
      message: 'Failed to update GPT folder',
      error: error.message
    });
  }
};
// Get user's favorite GPTs
const getUserFavorites = async (req, res) => {
    try {
        const userId = req.user._id;
        // Find all favorites for this user
        const favorites = await UserFavorite.find({ user: userId })
            .populate({
                path: 'gpt',
                // Select necessary fields, potentially removing assignedAt if it's not directly on CustomGpt
                select: 'name description model imageUrl capabilities files' 
            })
            .lean(); // Use lean for better performance
        if (!favorites.length) {
            return res.status(200).json({ success: true, gpts: [] });
        }
        // Get GPT IDs from favorites
        const gptIds = favorites.map(fav => fav.gpt._id);
        // Find the corresponding assignments to get folder info
        const assignments = await UserGptAssignment.find({ 
            userId: userId, 
            gptId: { $in: gptIds } 
        }).lean();
        // Create a map for easy lookup: gptId -> folder
        const assignmentFolderMap = assignments.reduce((map, assignment) => {
            map[assignment.gptId.toString()] = assignment.folder || null;
            return map;
        }, {});
        // Extract the GPT data and add folder info
        const gpts = favorites.map(fav => {
            const gptObject = fav.gpt; // Already a plain object due to .lean()
            gptObject.isFavorite = true;
            // Assign folder from the map, default to null if not found (shouldn't happen ideally)
            gptObject.folder = assignmentFolderMap[gptObject._id.toString()] || null; 
            // Note: You might want createdAt from the favorite record, not the GPT itself
            gptObject.createdAt = fav.createdAt; // Use favorite creation date
            return gptObject;
        });
        return res.status(200).json({
            success: true,
            gpts
        });
    } catch (error) {
        console.error('Error fetching user favorites:', error);
        return res.status(500).json({
            success: false,
            message: 'Failed to fetch favorite GPTs',
            error: error.message
        });
    }
};
// Add a GPT to user's favorites
const addToFavorites = async (req, res) => {
    try {
        const userId = req.user._id;
        const { gptId } = req.params;
        // Check if the GPT exists and is assigned to the user
        const isAssigned = await UserGptAssignment.exists({ 
            userId: userId,
            gptId: gptId
        });
        if (!isAssigned) {
            return res.status(404).json({
                success: false,
                message: 'GPT not found or not assigned to you'
            });
        }
        // Create a new favorite (the unique index will prevent duplicates)
        await UserFavorite.create({
            user: userId,
            gpt: gptId
        });
        return res.status(201).json({
            success: true,
            message: 'GPT added to favorites'
        });
    } catch (error) {
        // If it's a duplicate key error, just return success
        if (error.code === 11000) {
            return res.status(200).json({
                success: true,
                message: 'GPT is already in favorites'
            });
        }
        console.error('Error adding to favorites:', error);
        return res.status(500).json({
            success: false,
            message: 'Failed to add GPT to favorites',
            error: error.message
        });
    }
};
// Remove a GPT from user's favorites
const removeFromFavorites = async (req, res) => {
    try {
        const userId = req.user._id;
        const { gptId } = req.params;
        // Delete the favorite
        const result = await UserFavorite.deleteOne({
            user: userId,
            gpt: gptId
        });
        if (result.deletedCount === 0) {
            return res.status(404).json({
                success: false,
                message: 'GPT not found in favorites'
            });
        }
        return res.status(200).json({
            success: true,
            message: 'GPT removed from favorites'
        });
    } catch (error) {
        console.error('Error removing from favorites:', error);
        return res.status(500).json({
            success: false,
            message: 'Failed to remove GPT from favorites',
            error: error.message
        });
    }
};
// Update GPT folder for user assignment
const updateUserGptFolder = async (req, res) => {
  try {
    const userId = req.user._id;
    const { gptId } = req.params;
    const { folder } = req.body; // folder can be a string or null/undefined
    // Validate folder name slightly (optional, prevent overly long names etc.)
    if (folder && typeof folder === 'string' && folder.length > 100) {
      return res.status(400).json({
        success: false,
        message: 'Folder name is too long (max 100 characters).'
      });
    }
    // Find the assignment
    const assignment = await UserGptAssignment.findOne({ 
      userId: userId, 
      gptId: gptId 
    });
    if (!assignment) {
      return res.status(404).json({
        success: false,
        message: 'GPT assignment not found'
      });
    }
    // Update the folder - set to null if folder is null/empty string, otherwise use the string
    assignment.folder = folder || null;
    await assignment.save();
    return res.status(200).json({
      success: true,
      message: 'Folder updated successfully',
      assignment: {
        gptId: assignment.gptId,
        folder: assignment.folder
      }
    });
  } catch (error) {
    console.error('Error updating assignment folder:', error);
    return res.status(500).json({
      success: false,
      message: 'Failed to update folder',
      error: error.message
    });
  }
};
module.exports = {
  createCustomGpt,
  getUserCustomGpts,
  getCustomGptById,
  updateCustomGpt,
  deleteCustomGpt,
  deleteKnowledgeFile,
  uploadMiddleware: handleCombinedUpload,
  getAllCustomGpts,
  getUserAssignedGpts,
  assignGptToUser,
  unassignGptFromUser,
  getUserGptCount,
  getAssignedGptById,
  updateGptFolder,
  getUserFavorites,
  addToFavorites,
  removeFromFavorites,
  updateUserGptFolder
};
````

## File: backend/controllers/InvitationController.js
````javascript
const crypto = require('crypto');
const User = require('../models/User');
const Invitation = require('../models/Invitation');
const { sendEmail } = require('../lib/emailService');
const inviteTeamMember = async (req, res) => {
  try {
    const { email } = req.body;
    const role = 'employee';
    if (!req.user || req.user.role !== 'admin') {
      return res.status(403).json({ 
        success: false, 
        message: 'Only admins can send invitations' 
      });
    }
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ 
        success: false, 
        message: 'User with this email already exists' 
      });
    }
    const existingInvitation = await Invitation.findOne({ 
      email, 
      status: 'pending',
      expiresAt: { $gt: new Date() }
    });
    if (existingInvitation) {
      return res.status(400).json({ 
        success: false, 
        message: 'An invitation has already been sent to this email' 
      });
    }
    const token = crypto.randomBytes(20).toString('hex');
    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + 7); // Token valid for 7 days
    const invitation = new Invitation({
      email,
      role,
      token,
      expiresAt,
      invitedBy: req.user._id
    });
    await invitation.save();
    const inviteUrl = `${process.env.FRONTEND_URL}/register?token=${token}`;
    try {
      await sendEmail({
        to: email,
        subject: 'Invitation to join the team',
        html: `
          <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #e0e0e0; border-radius: 5px;">
            <h1 style="color: #333;">You've been invited to join the team</h1>
            <p>You've been invited by ${req.user.name}</p>
            <p>Click the button below to create your account:</p>
            <a href="${inviteUrl}" style="display: inline-block; padding: 10px 20px; background-color: #3182ce; color: white; border-radius: 5px; text-decoration: none; margin: 15px 0;">Accept Invitation</a>
            <p style="color: #666; font-size: 0.9em;">This invitation expires in 7 days.</p>
            <hr style="border: none; border-top: 1px solid #e0e0e0; margin: 20px 0;">
            <p style="color: #999; font-size: 0.8em;">If you're having trouble with the button above, copy and paste this URL into your browser: <br> ${inviteUrl}</p>
          </div>
        `
      });
      return res.status(200).json({
        success: true,
        message: 'Invitation sent successfully'
      });
    } catch (emailError) {
      await Invitation.findByIdAndDelete(invitation._id);
      console.error('Error sending invitation email:', emailError);
      return res.status(500).json({
        success: false,
        message: 'Failed to send invitation email'
      });
    }
  } catch (error) {
    console.error('Error creating invitation:', error);
    return res.status(500).json({
      success: false,
      message: 'Error creating invitation'
    });
  }
};
const getPendingInvitesCount = async (req, res) => {
  try {
    if (!req.user || req.user.role !== 'admin') {
      return res.status(403).json({ 
        success: false, 
        message: 'Only admins can view pending invitations' 
      });
    }
    const count = await Invitation.countDocuments({ 
      status: 'pending',
      expiresAt: { $gt: new Date() }
    });
    return res.status(200).json({
      success: true,
      count
    });
  } catch (error) {
    console.error('Error getting pending invites count:', error);
    return res.status(500).json({
      success: false,
      message: 'Error getting pending invites count'
    });
  }
};
const verifyInvitation = async (req, res) => {
  try {
    const { token } = req.params;
    const invitation = await Invitation.findOne({ 
      token,
      status: 'pending',
      expiresAt: { $gt: new Date() }
    });
    if (!invitation) {
      return res.status(400).json({
        success: false,
        message: 'Invalid or expired invitation'
      });
    }
    return res.status(200).json({
      success: true,
      invitation: {
        email: invitation.email,
        role: invitation.role
      }
    });
  } catch (error) {
    console.error('Error verifying invitation:', error);
    return res.status(500).json({
      success: false,
      message: 'Error verifying invitation'
    });
  }
}; 
module.exports = {
  inviteTeamMember,
  getPendingInvitesCount,
  verifyInvitation
};
````

## File: backend/controllers/teamController.js
````javascript
const User = require('../models/User');
const CustomGpt = require('../models/CustomGpt');
const UserGptAssignment = require('../models/UserGptAssignment'); // This would be a new model
const mongoose = require('mongoose');
// Get GPTs assigned to a team member
const getAssignedGpts = async (req, res) => {
    try {
        let { id } = req.params;
        // Handle case when id is not a valid ObjectId
        // For demo/sample data purposes only
        if (!mongoose.Types.ObjectId.isValid(id)) {
            return res.status(200).json({
                success: true,
                assignedGpts: [] // Return empty array for sample data
            });
        }
        // Find all assignments for this user
        const assignments = await UserGptAssignment.find({ userId: id });
        if (!assignments || assignments.length === 0) {
            return res.status(200).json({
                success: true,
                assignedGpts: []
            });
        }
        // Get the GPT details for all assigned GPTs
        const gptIds = assignments.map(assignment => assignment.gptId);
        const assignedGpts = await CustomGpt.find({ _id: { $in: gptIds } });
        res.status(200).json({
            success: true,
            assignedGpts
        });
    } catch (error) {
        console.error('Error fetching assigned GPTs:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch assigned GPTs',
            error: error.message
        });
    }
};
// Assign a GPT to a team member
const assignGpt = async (req, res) => {
    try {
        const { id } = req.params;
        const { gptId } = req.body;
        if (!gptId) {
            return res.status(400).json({
                success: false,
                message: 'GPT ID is required'
            });
        }
        // Check if GPT exists
        const gpt = await CustomGpt.findById(gptId);
        if (!gpt) {
            return res.status(404).json({
                success: false,
                message: 'GPT not found'
            });
        }
        // Check if user exists
        const user = await User.findById(id);
        if (!user) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }
        // Check if assignment already exists
        const existingAssignment = await UserGptAssignment.findOne({ userId: id, gptId });
        if (existingAssignment) {
            return res.status(400).json({
                success: false,
                message: 'GPT is already assigned to this user'
            });
        }
        // Create new assignment
        const assignment = new UserGptAssignment({
            userId: id,
            gptId,
            assignedBy: req.user._id,
            assignedAt: new Date()
        });
        await assignment.save();
        res.status(201).json({
            success: true,
            message: 'GPT assigned successfully',
            assignment
        });
    } catch (error) {
        console.error('Error assigning GPT:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to assign GPT',
            error: error.message
        });
    }
};
// Unassign a GPT from a team member
const unassignGpt = async (req, res) => {
    try {
        const { id, gptId } = req.params;
        // Find and delete the assignment
        const result = await UserGptAssignment.findOneAndDelete({ userId: id, gptId });
        if (!result) {
            return res.status(404).json({
                success: false,
                message: 'Assignment not found'
            });
        }
        res.status(200).json({
            success: true,
            message: 'GPT unassigned successfully'
        });
    } catch (error) {
        console.error('Error unassigning GPT:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to unassign GPT',
            error: error.message
        });
    }
};
module.exports = {
    getAssignedGpts,
    assignGpt,
    unassignGpt,
    // Include other team controller functions...
    getTeamMembers: async (req, res) => {
        // Implementation for getting team members
    },
    inviteTeamMember: async (req, res) => {
        // Implementation for inviting a team member
    },
    updateTeamMember: async (req, res) => {
        // Implementation for updating a team member
    },
    removeTeamMember: async (req, res) => {
        // Implementation for removing a team member
    }
};
````

## File: backend/lib/db.js
````javascript
const mongoose = require("mongoose");
// Global connection promise that can be awaited
let dbConnectionPromise = null;
const connectDB = async () => {
    // Return existing connection promise if it exists
    if (dbConnectionPromise) {
        return dbConnectionPromise;
    }
    // Create new connection promise
    dbConnectionPromise = mongoose.connect(process.env.MONGO_URI, {
        serverSelectionTimeoutMS: 30000,
        socketTimeoutMS: 45000,
        maxPoolSize: 10,
        // Remove bufferCommands: false to allow buffering
    });
    try {
        const conn = await dbConnectionPromise;        
        mongoose.connection.on('error', err => {
            console.error('MongoDB connection error:', err);
            dbConnectionPromise = null; // Reset on error
        });
        mongoose.connection.on('disconnected', () => {
            dbConnectionPromise = null; // Reset on disconnect
        });
        return conn;
    } catch (error) {
        console.error(`Error: ${error.message}`);
        process.exit(1);
    }
};
module.exports = connectDB;
````

## File: backend/lib/emailService.js
````javascript
const nodemailer = require('nodemailer');
// Create transporter
const transporter = nodemailer.createTransport({
  service: process.env.EMAIL_SERVICE || 'gmail',
  auth: {
    user: process.env.GMAIL_USERNAME,
    pass: process.env.GMAIL_PASSWORD
  }
});
/**
 * Send email
 * @param {Object} options - Email options (to, subject, html, etc.)
 * @returns {Promise}
 */
const sendEmail = async (options) => {
  const mailOptions = {
    from: process.env.EMAIL_FROM,
    to: options.to,
    subject: options.subject,
    html: options.html
  };
  try {
    const info = await transporter.sendMail(mailOptions);
    return info;
  } catch (error) {
    console.error('Error sending email:', error);
    throw error;
  }
};
module.exports = { sendEmail };
````

## File: backend/lib/r2.js
````javascript
const { S3Client, PutObjectCommand, DeleteObjectCommand } = require('@aws-sdk/client-s3');
const { v4: uuidv4 } = require('uuid');
const path = require('path');
let s3Client;
try {
    s3Client = new S3Client({
        region: 'auto',
        endpoint: `https://${process.env.R2_ACCOUNT_ID}.r2.cloudflarestorage.com`,
        credentials: {
            accessKeyId: process.env.R2_ACCESS_KEY_ID,
            secretAccessKey: process.env.R2_SECRET_ACCESS_KEY,
        },
    });
} catch (error) {
    console.error("Error initializing S3Client:", error);
    throw new Error("Failed to initialize R2 client. Check credentials."); 
}
/**
 * Upload a file to Cloudflare R2
 * @param {Buffer} fileBuffer - The file buffer
 * @param {string} fileName - Original file name
 * @param {string} folder - Folder to store the file in (e.g., 'images', 'knowledge')
 * @returns {Promise<{fileUrl: string, key: string}>} - URL and key of the uploaded file
 */
async function uploadToR2(fileBuffer, fileName, folder = '') {
    // Create a unique filename to prevent collisions
    const fileExtension = path.extname(fileName);
    const key = folder 
        ? `${folder}/${uuidv4()}${fileExtension}` 
        : `${uuidv4()}${fileExtension}`;
    // Set up the upload parameters
    const uploadParams = {
        Bucket: process.env.R2_BUCKET_NAME,
        Key: key,
        Body: fileBuffer,
        ContentType: getContentType(fileExtension),
    };
    try {
        // Upload to R2
        await s3Client.send(new PutObjectCommand(uploadParams));
        // Generate the public URL
        const fileUrl = `${process.env.R2_PUBLIC_URL}/${key}`;
        return {
            fileUrl,
            key,
        };
    } catch (error) {
        console.error('Error uploading to R2:', error);
        throw new Error('Failed to upload file to storage');
    }
}
/**
 * Delete a file from Cloudflare R2
 * @param {string} key - The file key
 * @returns {Promise<void>}
 */
async function deleteFromR2(key) {
    const deleteParams = {
        Bucket: process.env.R2_BUCKET_NAME,
        Key: key,
    };
    try {
        await s3Client.send(new DeleteObjectCommand(deleteParams));
    } catch (error) {
        console.error('Error deleting from R2:', error);
        throw new Error('Failed to delete file from storage');
    }
}
/**
 * Get content type based on file extension
 * @param {string} extension - File extension
 * @returns {string} - MIME type
 */
function getContentType(extension) {
    const contentTypes = {
        '.jpg': 'image/jpeg',
        '.jpeg': 'image/jpeg',
        '.png': 'image/png',
        '.gif': 'image/gif',
        '.pdf': 'application/pdf',
        '.doc': 'application/msword',
        '.docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        '.txt': 'text/plain',
    };
    return contentTypes[extension.toLowerCase()] || 'application/octet-stream';
}
module.exports = {
    uploadToR2,
    deleteFromR2,
};
````

## File: backend/lib/utilis.js
````javascript
const jwt = require('jsonwebtoken');
// Generates Access Token (short-lived)
const generateAccessToken = (userId) => {
    return jwt.sign({ userId }, process.env.JWT_SECRET, { expiresIn: '15m' }); // e.g., 15 minutes
};
const generateRefreshTokenAndSetCookie = (res, userId) => {
    const refreshToken = jwt.sign(
        { userId },
        process.env.REFRESH_TOKEN_SECRET,
        { expiresIn: '7d' }
    );
    // Set the cookie with more permissive settings
    res.cookie('refreshToken', refreshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production', // Only use secure in production
        sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax', // Use 'none' in production, 'lax' in development
        maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days in milliseconds
        path: '/' // Ensure cookie is available across your domain
    });
    return refreshToken;
};
// Clears the Refresh Token cookie
const clearRefreshTokenCookie = (res) => {
    res.cookie('refreshToken', '', {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: process.env.NODE_ENV === 'production' ? 'None' : 'Lax',
        path: '/api/auth/refresh',
        expires: new Date(0), // Set expiry date to the past
    });
};
module.exports = { generateAccessToken, generateRefreshTokenAndSetCookie, clearRefreshTokenCookie };
````

## File: backend/middleware/authMiddleware.js
````javascript
const jwt = require('jsonwebtoken');
const User = require('../models/User');
const connectDB = require('../lib/db');
const protectRoute = async (req, res, next) => {
    let token;
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
        token = req.headers.authorization.split(' ')[1];
    } 
    else if (req.cookies && req.cookies.token) {
        token = req.cookies.token;
    }
    if (!token) {
        return res.status(401).json({
            success: false,
            message: 'Please log in to access this resource'
        });
    }
    try {
        // Verify the token
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        // Find user by id (excluding password)
        const user = await User.findById(decoded.userId).select('-password');
        if (!user) {
            return res.status(401).json({
                success: false,
                message: 'User not found'
            });
        }
        // Add user to request object
        req.user = user;
        next();
    } catch (error) {
        console.error('JWT verification failed:', error.message);
        return res.status(401).json({
            success: false,
            message: 'Invalid or expired token. Please log in again.'
        });
    }
};
module.exports = { protectRoute };
````

## File: backend/middleware/updateLastActive.js
````javascript
const User = require('../models/User');
// Middleware to update lastActive timestamp for authenticated users
const updateLastActive = async (req, res, next) => {
    try {
        // Only update if user is authenticated
        if (req.user && req.user._id) {
            // Update the lastActive field to the current time
            await User.findByIdAndUpdate(
                req.user._id,
                { lastActive: new Date() },
                { new: true }
            );
        }
        next();
    } catch (error) {
        console.error("Error updating lastActive status:", error);
        next(); // Continue even if there's an error with the update
    }
};
module.exports = updateLastActive;
````

## File: backend/models/ChatHistory.js
````javascript
const mongoose = require('mongoose');
const messageSchema = new mongoose.Schema({
    role: {
        type: String,
        enum: ['user', 'assistant'],
        required: true
    },
    content: {
        type: String,
        required: true
    },
    timestamp: {
        type: Date,
        default: Date.now
    }
});
const chatHistorySchema = new mongoose.Schema({
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    gptId: {
        type: String,
        required: true
    },
    gptName: {
        type: String,
        required: true
    },
    messages: [messageSchema],
    lastMessage: {
        type: String,
        default: ''
    },
    model: {
        type: String,
        default: 'gpt-4o-mini' 
    },
    summary: String,
    createdAt: {
        type: Date,
        default: Date.now
    },
    updatedAt: {
        type: Date,
        default: Date.now
    }
}, {
    timestamps: true
});
// Index for efficient querying
chatHistorySchema.index({ userId: 1, gptId: 1 });
// Method to check for duplicate conversations
chatHistorySchema.statics.findOrCreateConversation = async function(userId, gptId, gptName, model) {
    let conversation = await this.findOne({ userId, gptId });
    if (!conversation) {
        conversation = new this({
            userId,
            gptId,
            gptName,
            model,
            messages: [],
            lastMessage: ''
        });
    }
    return conversation;
};
module.exports = mongoose.model('ChatHistory', chatHistorySchema);
````

## File: backend/models/CustomGpt.js
````javascript
const mongoose = require('mongoose');
const Schema = mongoose.Schema;
const CustomGptSchema = new Schema({
    name: {
        type: String,
        required: true,
        trim: true
    },
    description: {
        type: String,
        required: true,
        trim: true
    },
    instructions: {
        type: String,
        required: true,
        maxLength: 10000,
    },
    conversationStarter: {
        type: String,
        default: ""
    },
    model: {
        type: String,
        default: ""
    },
    capabilities: {
        type: Object,
        default: { webBrowsing: true }
    },
    imageUrl: {
        type: String,
        default: null
    },
    knowledgeFiles: [{
        name: String,
        fileUrl: String,
        fileType: String,
    }],
    createdBy: {
        type: Schema.Types.ObjectId,
        ref: 'User',
        required: true,
    },
    isPublic: {
        type: Boolean,
        default: false
    },
    folder: {
        type: String,
        trim: true,
        default: null
    },
    createdAt: {
        type: Date,
        default: Date.now
    }
}, { timestamps: true });
// Add logging to debug Schema registration
const CustomGpt = mongoose.model('CustomGpt', CustomGptSchema);
module.exports = CustomGpt;
````

## File: backend/models/Invitation.js
````javascript
const mongoose = require('mongoose');
const InvitationSchema = new mongoose.Schema({
  email: {
    type: String,
    required: true,
    trim: true,
    lowercase: true
  },
  role: {
    type: String,
    enum: ['admin', 'employee'],
    default: 'employee'
  },
  token: {
    type: String,
    required: true
  },
  expiresAt: {
    type: Date,
    required: true
  },
  invitedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  status: {
    type: String,
    enum: ['pending', 'accepted', 'expired'],
    default: 'pending'
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
});
InvitationSchema.index({ token: 1 });
InvitationSchema.index({ email: 1 });
module.exports = mongoose.model('Invitation', InvitationSchema);
````

## File: backend/models/User.js
````javascript
const mongoose = require('mongoose');
const Schema = mongoose.Schema;
const bcrypt = require('bcryptjs');
const userSchema = new Schema({
    name:{
        type:String,
        required:true,
    },
    email:{
        type:String,
        required:true,
        unique:true,
    },
    password:{
        type:String,
        required:true,
        select: false
    },
    role:{
        type:String,
        enum:['admin','employee'],
        default:'employee',
    },  
    department: {
        type: String,
        default: 'Not Assigned'
    },
    profilePic: {
        type: String,
        default: null
    },
    lastActive: {
        type: Date,
        default: null
    },
    assignedGpts: [{
        type: mongoose.Schema.Types.ObjectId,
        ref: 'CustomGpt'
    }],
    apiKeys: {
        type: Object,
        select: false,
        default: {}
    }
}, {timestamps:true});
// Password hash middleware
userSchema.pre('save', async function(next) {
    // Only hash the password if it's modified
    if (!this.isModified('password')) return next();
    try {
        const salt = await bcrypt.genSalt(10);
        this.password = await bcrypt.hash(this.password, salt);
        next();
    } catch (error) {
        next(error);
    }
});
const User = mongoose.model('User', userSchema);
module.exports = User;
````

## File: backend/models/UserFavorite.js
````javascript
const mongoose = require('mongoose');
const Schema = mongoose.Schema;
const userFavoriteSchema = new Schema({
    user: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    gpt: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'CustomGpt',
        required: true
    },
    folder: {
        type: String,
        default: 'Uncategorized'
    }
}, { timestamps: true });
// Add a compound index to make sure users can't favorite the same GPT twice
userFavoriteSchema.index({ user: 1, gpt: 1 }, { unique: true });
const UserFavorite = mongoose.model('UserFavorite', userFavoriteSchema);
module.exports = UserFavorite;
````

## File: backend/models/UserGptAssignment.js
````javascript
const mongoose = require('mongoose');
const UserGptAssignmentSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  gptId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'CustomGpt',
    required: true
  },
  assignedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  assignedAt: {
    type: Date,
    default: Date.now
  },
  folder: {
    type: String,
    default: 'Uncategorized'
  }
}, { timestamps: true });
UserGptAssignmentSchema.index({ userId: 1, gptId: 1 }, { unique: true });
module.exports = mongoose.model('UserGptAssignment', UserGptAssignmentSchema);
````

## File: backend/routes/authRoutes.js
````javascript
const express = require('express');
const router = express.Router();
const { Signup, Login, Logout, googleAuth, googleAuthCallback, refreshTokenController, getCurrentUser, getAllUsers, removeTeamMember, getUsersWithGptCounts, getUserGptCount, updateUserProfile, updateUserProfilePicture, changePassword, updatePassword, getApiKeys, saveApiKeys, updateUserPermissions } = require('../controllers/AuthContoller');
const passport = require('passport');
const { protectRoute } = require('../middleware/authMiddleware'); // Imports protectRoute
const multer = require('multer'); // Import multer
router.post('/signup', Signup);
router.post('/login', Login);
router.post('/logout', Logout);
router.post('/refresh', refreshTokenController);
router.get('/me', protectRoute, getCurrentUser);
router.get('/google', (req, res, next) => {
  passport.authenticate('google', {
    scope: ['profile', 'email'],
    prompt: 'consent',
    authorizingPrompt: 'select_account'
  })(req, res, next);
});
router.get('/google/callback', googleAuthCallback);
router.get('/users', protectRoute, getAllUsers);
router.delete('/users/:userId', protectRoute, removeTeamMember);
router.get('/users/with-gpt-counts', protectRoute, getUsersWithGptCounts);
router.get('/users/:userId/gpt-count', protectRoute, getUserGptCount);
router.patch('/user/profile', protectRoute, updateUserProfile);
router.post('/user/profile-picture', protectRoute, multer().single('profileImage'), updateUserProfilePicture);
router.post('/user/change-password', protectRoute, changePassword);
router.post('/user/update-password', protectRoute, updatePassword);
router.get('/user/api-keys', protectRoute, getApiKeys);
router.post('/user/api-keys', protectRoute, saveApiKeys);
router.put('/users/:userId/permissions', protectRoute, updateUserPermissions);
module.exports = router;
````

## File: backend/routes/chatHistory.js
````javascript
const express = require('express');
const router = express.Router();
const chatHistoryController = require('../controllers/chatHistoryController');
const { protectRoute } = require('../middleware/authMiddleware');
// All routes are protected with authentication
router.use(protectRoute);
// Save a new message
router.post('/save', chatHistoryController.saveMessage);
// Get user's chat history
router.get('/user/:userId', chatHistoryController.getUserHistory);
// Get team's chat history (for admins)
router.get('/team', chatHistoryController.getTeamHistory);
// Get specific conversation
router.get('/conversation/:userId/:gptId', chatHistoryController.getConversation);
// Delete a conversation
router.delete('/:userId/:conversationId', chatHistoryController.deleteConversation);
// --- NEW ROUTE for Admin to get specific conversation by ID ---
router.get('/admin/conversation/:conversationId', chatHistoryController.getAdminConversationById);
module.exports = router;
````

## File: backend/routes/customGptRoutes.js
````javascript
const express = require('express');
const router = express.Router();
const { 
    createCustomGpt, 
    getUserCustomGpts, 
    getCustomGptById, 
    updateCustomGpt, 
    deleteCustomGpt,
    deleteKnowledgeFile,
    uploadMiddleware,
    getAllCustomGpts,
    getUserAssignedGpts,
    assignGptToUser,
    unassignGptFromUser,
    getUserGptCount,
    getAssignedGptById,
    updateGptFolder,
    getUserFavorites,
    addToFavorites,
    removeFromFavorites,
    updateUserGptFolder
} = require('../controllers/customGptController');
const { protectRoute } = require('../middleware/authMiddleware');
// All routes need authentication
router.use(protectRoute);
// Root route - this should handle /api/custom-gpts GET requests
router.get('/', getAllCustomGpts);
// User-specific GPTs
router.get('/user', getUserCustomGpts);
// User assigned GPTs (MOVED BEFORE the /:id routes)
router.get('/user/assigned', getUserAssignedGpts);
router.get('/user/assigned/:id', getAssignedGptById);
// Favorites routes
router.get('/user/favorites', getUserFavorites);
router.post('/user/favorites/:gptId', addToFavorites);
router.delete('/user/favorites/:gptId', removeFromFavorites);
// Team routes (need to come before /:id routes)
router.get('/team/gpt-counts', getUserGptCount);
router.get('/team/members/:userId/gpts', getUserAssignedGpts);
router.post('/team/members/:userId/gpts', assignGptToUser);
router.delete('/team/members/:userId/gpts/:gptId', unassignGptFromUser);
// Create new GPT
router.post('/', uploadMiddleware, createCustomGpt);
// Parameter routes - MUST be last
router.get('/:id', getCustomGptById);
router.put('/:id', uploadMiddleware, updateCustomGpt);
router.delete('/:id', deleteCustomGpt);
router.delete('/:id/knowledge/:fileIndex', deleteKnowledgeFile);
router.patch('/:id/folder', updateGptFolder);
// Add this route with other user routes
router.patch('/user/assigned/:gptId/folder', updateUserGptFolder);
// Add this to your existing routes
router.put('/user/folder/:gptId', updateGptFolder);
module.exports = router;
````

## File: backend/routes/invitationRoutes.js
````javascript
const express = require('express');
const router = express.Router();
const { inviteTeamMember, getPendingInvitesCount, verifyInvitation } = require('../controllers/InvitationController');
const { protectRoute } = require('../middleware/authMiddleware');
router.post('/invite', protectRoute, inviteTeamMember);
router.get('/pending-invites/count', protectRoute, getPendingInvitesCount);
router.get('/verify-invitation/:token', verifyInvitation);
module.exports = router;
````

## File: backend/.gitignore
````
# Logs
logs
*.log
npm-debug.log*
yarn-debug.log*
yarn-error.log*
pnpm-debug.log*
lerna-debug.log*

node_modules
dist
dist-ssr
*.local

# Editor directories and files
.vscode/*
!.vscode/extensions.json
.idea
.DS_Store
*.suo
*.ntvs*
*.njsproj
*.sln
*.sw?
.env
.env.local
.env.development.local
.env.test.local
.env.production.local
````

## File: backend/index.js
````javascript
const dotenv = require('dotenv');
dotenv.config();
const express = require('express');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const passport = require('passport');
const compression = require('compression');
const connectDB = require('./lib/db');
const customGptRoutes = require('./routes/customGptRoutes');
const authRoutes = require('./routes/authRoutes');
const invitationRoutes = require('./routes/invitationRoutes');
const chatHistoryRoutes = require('./routes/chatHistory');
require('./config/passport');
const app = express();
app.use(compression());
app.use(express.json());
app.use(cookieParser());
app.use(cors({
  origin: process.env.FRONTEND_URL || 'http://localhost:5173',
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'Accept', 'Origin', 'X-Requested-With']
}));
app.use(passport.initialize());
app.get("/", (req, res) => {
  res.status(200).send("API is running successfully!");
});
app.get("/health", (req, res) => {
  res.status(200).json({ status: "ok" });
});
app.use('/api/auth', authRoutes);
app.use('/api/auth', invitationRoutes);
app.use('/api/custom-gpts', customGptRoutes);
app.use('/api/chat-history', chatHistoryRoutes);
connectDB()
  .then(() => console.log('MongoDB connected at server startup'))
  .catch(err => console.error('Initial MongoDB connection failed:', err));
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`); 
});
````

## File: backend/package.json
````json
{
  "name": "backend",
  "version": "1.0.0",
  "main": "index.js",
  "scripts": {
    "test": "echo \"Error: no test specified\" && exit 1",
    "start": "nodemon index.js",
    "dev": "nodemon index.js"
  },
  "keywords": [],
  "author": "",
  "license": "ISC",
  "description": "",
  "dependencies": {
    "@aws-sdk/client-s3": "^3.782.0",
    "@aws-sdk/s3-request-presigner": "^3.782.0",
    "bcryptjs": "^3.0.2",
    "cloudinary": "^2.6.0",
    "compression": "^1.8.0",
    "cookie-parser": "^1.4.7",
    "cors": "^2.8.5",
    "dotenv": "^16.4.7",
    "express": "^5.1.0",
    "express-session": "^1.18.1",
    "google-auth-library": "^9.15.1",
    "jsonwebtoken": "^9.0.2",
    "mongoose": "^8.13.1",
    "multer": "^1.4.5-lts.2",
    "nodemailer": "^6.10.0",
    "nodemon": "^3.1.9",
    "passport": "^0.7.0",
    "passport-google-oauth20": "^2.0.0",
    "uuid": "^11.1.0"
  }
}
````

## File: backend/vercel.json
````json
{
    "version": 2,
    "builds": [
      {
        "src": "index.js",
        "use": "@vercel/node"
      }
    ],
    "routes": [
      {
        "src": "/(.*)",
        "dest": "index.js",
        "methods": ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
        "headers": {
          "Access-Control-Allow-Origin": "https://www.mygpt.work",
          "Access-Control-Allow-Credentials": "true",
          "Access-Control-Allow-Methods": "GET,OPTIONS,PATCH,DELETE,POST,PUT",
          "Access-Control-Allow-Headers": "X-CSRF-Token, X-Requested-With, Accept, Accept-Version, Content-Length, Content-MD5, Content-Type, Date, X-Api-Version, Authorization, Cookie"
        }
      }
    ]
  }
````

## File: frontend/public/vite.svg
````
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" aria-hidden="true" role="img" class="iconify iconify--logos" width="31.88" height="32" preserveAspectRatio="xMidYMid meet" viewBox="0 0 256 257"><defs><linearGradient id="IconifyId1813088fe1fbc01fb466" x1="-.828%" x2="57.636%" y1="7.652%" y2="78.411%"><stop offset="0%" stop-color="#41D1FF"></stop><stop offset="100%" stop-color="#BD34FE"></stop></linearGradient><linearGradient id="IconifyId1813088fe1fbc01fb467" x1="43.376%" x2="50.316%" y1="2.242%" y2="89.03%"><stop offset="0%" stop-color="#FFEA83"></stop><stop offset="8.333%" stop-color="#FFDD35"></stop><stop offset="100%" stop-color="#FFA800"></stop></linearGradient></defs><path fill="url(#IconifyId1813088fe1fbc01fb466)" d="M255.153 37.938L134.897 252.976c-2.483 4.44-8.862 4.466-11.382.048L.875 37.958c-2.746-4.814 1.371-10.646 6.827-9.67l120.385 21.517a6.537 6.537 0 0 0 2.322-.004l117.867-21.483c5.438-.991 9.574 4.796 6.877 9.62Z"></path><path fill="url(#IconifyId1813088fe1fbc01fb467)" d="M185.432.063L96.44 17.501a3.268 3.268 0 0 0-2.634 3.014l-5.474 92.456a3.268 3.268 0 0 0 3.997 3.378l24.777-5.718c2.318-.535 4.413 1.507 3.936 3.838l-7.361 36.047c-.495 2.426 1.782 4.5 4.151 3.78l15.304-4.649c2.372-.72 4.652 1.36 4.15 3.788l-11.698 56.621c-.732 3.542 3.979 5.473 5.943 2.437l1.313-2.028l72.516-144.72c1.215-2.423-.88-5.186-3.54-4.672l-25.505 4.922c-2.396.462-4.435-1.77-3.759-4.114l16.646-57.705c.677-2.35-1.37-4.583-3.769-4.113Z"></path></svg>
````

## File: frontend/src/api/axiosInstance.js
````javascript
import axios from 'axios';
const baseURL = import.meta.env.VITE_BACKEND_URL || 'http://localhost:5000';
const axiosInstance = axios.create({
    baseURL: baseURL,
    withCredentials: true, // Include cookies by default
    timeout: 30000 // 30 seconds timeout
});
// Token management functions
const setAccessToken = (token) => {
    if (token) {
        localStorage.setItem('token', token);
        // Also update the default headers for future requests
        axiosInstance.defaults.headers.common['Authorization'] = `Bearer ${token}`;
    } else {
        // Clear token if null/undefined is passed
        removeAccessToken();
    }
};
const getAccessToken = () => {
    // Prefer localStorage, fallback to sessionStorage
    return localStorage.getItem('token') || sessionStorage.getItem('token') || null;
};
const removeAccessToken = () => {
    localStorage.removeItem('token');
    sessionStorage.removeItem('token');
    // Also remove from default headers
    delete axiosInstance.defaults.headers.common['Authorization'];
};
// Track if we're currently refreshing the token
let isRefreshing = false;
// Store pending requests that should be retried after token refresh
let failedQueue = [];
const processQueue = (error, token = null) => {
    failedQueue.forEach(prom => {
        if (error) {
            prom.reject(error);
        } else {
            prom.resolve(token);
        }
    });
    failedQueue = [];
};
// Add request interceptor to attach token to every request
axiosInstance.interceptors.request.use(
    (config) => {
        // Ensure withCredentials is set for all requests
        config.withCredentials = true;
        // Get the token from localStorage
        const token = getAccessToken();
        if (token) {
            config.headers['Authorization'] = `Bearer ${token}`;
        }
        return config;
    },
    (error) => {
        return Promise.reject(error);
    }
);
// Add response interceptor to handle auth errors
axiosInstance.interceptors.response.use(
    (response) => {
        return response;
    },
    async (error) => {
        const originalRequest = error.config;
        // Don't retry if we already tried or it's a refresh token request
        if (error.response?.status === 401 && !originalRequest._retry &&
            !originalRequest.url.includes('/api/auth/refresh')) {
            if (isRefreshing) {
                // If refresh is in progress, queue this request
                return new Promise((resolve, reject) => {
                    failedQueue.push({ resolve, reject });
                }).then(token => {
                    originalRequest.headers['Authorization'] = `Bearer ${token}`;
                    return axios(originalRequest);
                }).catch(err => {
                    return Promise.reject(err);
                });
            }
            originalRequest._retry = true;
            isRefreshing = true;
            try {
                // Use the correct refresh endpoint from AuthContext
                const response = await axios.post(`${baseURL}/api/auth/refresh`, {}, 
                    { withCredentials: true });
                if (response.data && response.data.accessToken) {
                    const newToken = response.data.accessToken;
                    setAccessToken(newToken);
                    // Process any queued requests with the new token
                    processQueue(null, newToken);
                    // Update the current request and retry
                    originalRequest.headers['Authorization'] = `Bearer ${newToken}`;
                    return axios(originalRequest);
                } else {
                    // Handle cases where refresh might succeed but not return a token
                    const refreshError = new Error('Failed to refresh token: No new token received');
                    processQueue(refreshError);
                    removeAccessToken();
                    // Don't redirect here - let the auth context handle that
                    return Promise.reject(refreshError); // Reject with specific error
                }
            } catch (refreshError) {
                // Log the actual refresh error for better debugging
                console.error("Token refresh failed:", refreshError.response?.data || refreshError.message);
                processQueue(refreshError);
                removeAccessToken();
                // Don't redirect here - let the auth context handle that
                return Promise.reject(refreshError);
            } finally {
                isRefreshing = false;
            }
        }
        // For non-401 errors or retried requests, just reject
        return Promise.reject(error);
    }
);
// Export all the necessary functions
export { 
    axiosInstance, 
    setAccessToken, 
    getAccessToken, 
    removeAccessToken 
};
````

## File: frontend/src/components/Admin/AdminChat.jsx
````javascript
import React, { useState, useEffect, useRef } from 'react';
import { motion } from 'framer-motion';
import { useParams, useNavigate, useLocation } from 'react-router-dom';
import AdminMessageInput from './AdminMessageInput';
import { useAuth } from '../../context/AuthContext';
import { useTheme } from '../../context/ThemeContext';
import { IoPersonCircleOutline, IoSettingsOutline, IoPersonOutline, IoArrowBack, IoClose, IoAddCircleOutline } from 'react-icons/io5';
import { axiosInstance } from '../../api/axiosInstance';
import axios from 'axios';
import ReactMarkdown from 'react-markdown';
import rehypeRaw from 'rehype-raw';
import remarkGfm from 'remark-gfm';
import { Prism as SyntaxHighlighter } from 'react-syntax-highlighter';
import { atomDark } from 'react-syntax-highlighter/dist/esm/styles/prism';
import { FaFilePdf, FaFileWord, FaFileAlt, FaFile } from 'react-icons/fa';
import { SiOpenai, SiGooglegemini } from 'react-icons/si';
import { FaRobot } from 'react-icons/fa6';
import { BiLogoMeta } from 'react-icons/bi';
import { RiOpenaiFill } from 'react-icons/ri';
const PYTHON_URL = import.meta.env.VITE_PYTHON_API_URL || 'http://localhost:8000';
const MarkdownStyles = () => (
    <style dangerouslySetInnerHTML={{
        __html: `
        .markdown-content {
            line-height: 1.6;
            width: 100%;
        }
        .markdown-content h1,
        .markdown-content h2,
        .markdown-content h3 {
            margin-top: 1.5em;
            margin-bottom: 0.5em;
        }
        .markdown-content h1:first-child,
        .markdown-content h2:first-child,
        .markdown-content h3:first-child {
            margin-top: 0;
        }
        .markdown-content code {
            font-family: 'SFMono-Regular', Consolas, 'Liberation Mono', Menlo, monospace;
        }
        .markdown-content pre {
            overflow-x: auto;
            border-radius: 0.375rem;
        }
        .markdown-content blockquote {
            font-style: italic;
            color: #6b7280;
        }
        .markdown-content a {
            text-decoration: none;
        }
        .markdown-content a:hover {
            text-decoration: underline;
        }
        .markdown-content table {
            border-collapse: collapse;
        }
        .markdown-content img {
            max-width: 100%;
            height: auto;
        }
        .markdown-content hr {
            border-top: 1px solid;
            margin: 1em 0;
        }
        .hide-scrollbar {
            -ms-overflow-style: none;
            scrollbar-width: none;
        }
        .hide-scrollbar::-webkit-scrollbar {
            display: none;
        }
    `}} />
);
const modelIcons = {
    'gpt-4': <RiOpenaiFill className="text-green-500" size={18} />,
    'gpt-4o-mini': <SiOpenai className="text-green-400" size={16} />,
    'claude': <FaRobot className="text-purple-400" size={16} />,
    'gemini': <SiGooglegemini className="text-blue-400" size={16} />,
    'llama': <BiLogoMeta className="text-blue-500" size={18} />
};
const AdminChat = () => {
    const { gptId } = useParams();
    const navigate = useNavigate();
    const location = useLocation();
    const { user, loading: authLoading } = useAuth();
    const { isDarkMode } = useTheme();
    const [isProfileOpen, setIsProfileOpen] = useState(false);
    const [userData, setUserData] = useState(null);
    const [isLoading, setIsLoading] = useState(false);
    const [isFetchingGpt, setIsFetchingGpt] = useState(false);
    const [gptData, setGptData] = useState(null);
    const [messages, setMessages] = useState([]);
    const [collectionName, setCollectionName] = useState(null);
    const messagesEndRef = useRef(null);
    const [userDocuments, setUserDocuments] = useState([]);
    const [isUploading, setIsUploading] = useState(false);
    const [uploadProgress, setUploadProgress] = useState(0);
    const [streamingMessage, setStreamingMessage] = useState(null);
    const [uploadedFiles, setUploadedFiles] = useState([]);
    const [backendAvailable, setBackendAvailable] = useState(null);
    const [hasInteracted, setHasInteracted] = useState(false);
    const [conversationMemory, setConversationMemory] = useState([]);
    const [hasNotifiedGptOpened, setHasNotifiedGptOpened] = useState(false);
    const [conversationId, setConversationId] = useState(null);
    const [isInitialLoading, setIsInitialLoading] = useState(false);
    const [currentConversationId, setCurrentConversationId] = useState(null);
    const [loading, setLoading] = useState({ message: false });
    const [webSearchEnabled, setWebSearchEnabled] = useState(false);
    // Use effect to handle user data changes
    useEffect(() => {
        if (user) {
            setUserData(user);
        }
    }, [user]);
    // Notify backend when GPT opens to trigger indexing
    const notifyGptOpened = async (gptData, userData) => {
        try {
            if (!gptData || !userData || !gptData._id || hasNotifiedGptOpened) {
                return;
            }
            const fileUrls = gptData.knowledgeFiles?.map(file => file.fileUrl).filter(url =>
                url && (url.startsWith('http://') || url.startsWith('https://'))
            ) || [];
            const useHybridSearch = gptData.capabilities?.hybridSearch || false;
            const response = await axios.post(
                `${PYTHON_URL}/gpt-opened`,
                {
                    user_email: userData.email,
                    gpt_name: gptData.name,
                    gpt_id: gptData._id,
                    file_urls: fileUrls,
                    use_hybrid_search: useHybridSearch,
                    gpt_schema: {
                        model: gptData.model,
                        instructions: gptData.instructions,
                        capabilities: gptData.capabilities,
                        use_hybrid_search: useHybridSearch
                    }
                },
                {
                    headers: {
                        'Content-Type': 'application/json',
                    }
                }
            );
            if (response.data.success) {
                setCollectionName(response.data.collection_name);
                setHasNotifiedGptOpened(true);
            }
        } catch (error) {
            console.error("Error notifying GPT opened:", error);
        }
    };
    // Get conversationId from URL query params
    useEffect(() => {
        const params = new URLSearchParams(location.search);
        const convId = params.get('conversationId');
        setCurrentConversationId(convId);
    }, [location.search]);
    // Main useEffect for fetching data
    useEffect(() => {
        if (!gptId) {
            setGptData(null);
            setMessages([]);
            setConversationMemory([]);
            setIsInitialLoading(false);
            return;
        }
        if (authLoading) {
            return;
        }
        if (!authLoading && !user) {
            console.warn("AdminChat: Auth finished, no user.");
            setIsInitialLoading(false);
            setGptData({ _id: gptId, name: "Admin Chat", description: "Admin user required.", model: "gpt-4o-mini" });
            setMessages([]);
            setConversationMemory([]);
            return;
        }
        if (user.role !== 'admin') {
            console.warn("AdminChat: Non-admin user trying to access.");
            setIsInitialLoading(false);
            navigate('/user/collections');
            return;
        }
        setIsInitialLoading(true);
        const fetchAdminChatData = async () => {
            let fetchedGptData = null;
            let conversationMessages = [];
            let conversationMemorySlice = [];
            try {
                const gptResponse = await axiosInstance.get(`/api/custom-gpts/${gptId}`, { withCredentials: true });
                if (gptResponse.data?.success && gptResponse.data.customGpt) {
                    fetchedGptData = gptResponse.data.customGpt;
                    setGptData(fetchedGptData);
                    const sanitizedEmail = (user.email || 'admin').replace(/[^a-zA-Z0-9]/g, '_');
                    const sanitizedGptName = (fetchedGptData.name || 'gpt').replace(/[^a-zA-Z0-9]/g, '_');
                    setCollectionName(`kb_${sanitizedEmail}_${sanitizedGptName}_${gptId}`);
                    notifyGptOpened(fetchedGptData, user).catch(err => console.warn("[AdminChat] Notify error:", err));
                } else {
                    console.warn("[AdminChat] Failed GPT fetch:", gptResponse.data);
                    fetchedGptData = { _id: gptId, name: "Assistant", description: "Details unavailable.", model: "gpt-4o-mini" };
                    setGptData(fetchedGptData);
                }
                if (currentConversationId) {
                    const historyResponse = await axiosInstance.get(`/api/chat-history/admin/conversation/${currentConversationId}`, { withCredentials: true });
                    if (historyResponse.data?.success && historyResponse.data.conversation?.messages?.length > 0) {
                        const { conversation } = historyResponse.data;
                        conversationMessages = conversation.messages.map((msg, index) => ({
                            id: `${conversation._id}-${index}-${msg.timestamp || Date.now()}`,
                            role: msg.role,
                            content: msg.content,
                            timestamp: new Date(msg.timestamp || conversation.createdAt)
                        }));
                        conversationMemorySlice = conversation.messages.slice(-10).map(msg => ({
                            role: msg.role,
                            content: msg.content,
                            timestamp: msg.timestamp || conversation.createdAt
                        }));
                    } else {
                        conversationMessages = [{
                            id: Date.now(),
                            role: 'system',
                            content: `Could not load conversation ${currentConversationId}. It might be empty or not found.`,
                            timestamp: new Date()
                        }];
                        conversationMemorySlice = [];
                    }
                } else {
                    conversationMessages = [];
                    conversationMemorySlice = [];
                }
                setMessages(conversationMessages);
                setConversationMemory(conversationMemorySlice);
            } catch (err) {
                console.error("[AdminChat] Error during fetch:", err);
                setGptData(fetchedGptData || { _id: gptId, name: "Assistant", description: "Error loading data.", model: "gpt-4o-mini" });
                setMessages([{ id: Date.now(), role: 'system', content: `Error loading chat data: ${err.message}`, timestamp: new Date() }]);
                setConversationMemory([]);
            } finally {
                setIsInitialLoading(false);
            }
        };
        fetchAdminChatData();
        return () => {
            setIsInitialLoading(false);
            setLoading(prev => ({ ...prev, message: false }));
        };
    }, [gptId, user, authLoading, currentConversationId]);
    const handlePromptClick = (item) => {
        handleChatSubmit(item.prompt);
    };
    const saveMessageToHistory = async (message, role) => {
        try {
            if (!user?._id || !gptData || !message || !message.trim()) {
                console.warn('Cannot save message - missing data:', {
                    userId: user?._id,
                    gptId: gptData?._id,
                    hasMessage: !!message,
                    role
                });
                return null;
            }
            const payload = {
                userId: user._id,
                gptId: gptData._id,
                gptName: gptData.name || 'AI Assistant',
                message: message.trim(),
                role: role,
                model: gptData.model || 'gpt-4o-mini'
            };
            if (conversationId) {
                payload.conversationId = conversationId;
            }
            const response = await axiosInstance.post('/api/chat-history/save', payload, {
                withCredentials: true
            });
            if (response.data && response.data.conversation && response.data.conversation._id) {
                setConversationId(response.data.conversation._id);
            }
            return response.data;
        } catch (error) {
            console.error(`Error saving ${role} message to history:`, error.response?.data || error.message);
            return null;
        }
    };
    const handleChatSubmit = async (message) => {
        if (!message.trim()) return;
        try {
            // Include files in the user message
            const userMessage = {
                id: Date.now(),
                role: 'user',
                content: message,
                timestamp: new Date(),
                files: uploadedFiles.length > 0 ? [...uploadedFiles] : []
            };
            await saveMessageToHistory(message, 'user');
            setMessages(prev => [...prev, userMessage]);
            // Save current files for this message then clear them for next message
            const currentFiles = [...uploadedFiles];
            if (uploadedFiles.length > 0) {
                setUploadedFiles([]); // Clear files after using them
            }
            // Important: Clear any existing streaming message first
            setStreamingMessage(null);
            // Then set loading state
            setLoading(prev => ({ ...prev, message: true }));
            setHasInteracted(true);
            const updatedMemory = [...conversationMemory];
            if (updatedMemory.length >= 10) {
                updatedMemory.splice(0, updatedMemory.length - 9);
            }
            updatedMemory.push({
                role: 'user',
                content: message,
                timestamp: new Date().toISOString()
            });
            setConversationMemory(updatedMemory);
            const useHybridSearch = gptData?.capabilities?.hybridSearch || false;
            const payload = {
                message,
                gpt_id: gptId,
                user_email: user?.email || 'unknown_admin',
                gpt_name: gptData?.name || 'unknown_gpt',
                user_documents: userDocuments,
                model: gptData?.model || 'gpt-4o-mini',
                memory: updatedMemory,
                history: messages.slice(-6).map(msg => ({
                    role: msg.role,
                    content: msg.content
                })),
                use_hybrid_search: useHybridSearch,
                system_prompt: gptData?.instructions || null,
                web_search_enabled: gptData?.capabilities?.webBrowsing || false
            };
            if (!payload.user_email) {
                payload.user_email = user?.email || 'admin@system.com';
            }
            if (!payload.gpt_name) {
                payload.gpt_name = gptData?.name || 'Admin Chat';
            }
            if (!payload.gpt_id && gptData?._id) {
                payload.gpt_id = gptData._id;
            } else if (!payload.gpt_id && gptId) {
                payload.gpt_id = gptId;
            }
            if (!payload.gpt_id) {
                throw new Error("GPT ID is missing, cannot send message.");
            }
            try {
                const controller = new AbortController();
                const timeoutId = setTimeout(() => controller.abort(), 30000);
                const response = await fetch(`${PYTHON_URL}/chat-stream`, {
                    method: "POST",
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    credentials: 'include',
                    signal: controller.signal,
                    body: JSON.stringify(payload)
                });
                clearTimeout(timeoutId);
                if (response.ok) {
                    await handleStreamingResponse(response);
                } else {
                    console.error("Stream response not OK:", response.status, response.statusText);
                    const errorText = await response.text();
                    console.error("Stream error response body:", errorText);
                    throw new Error(`HTTP error! status: ${response.status} - ${errorText || response.statusText}`);
                }
            } catch (streamingError) {
                console.warn("Streaming failed, falling back to regular chat API:", streamingError);
                const fallbackResponse = await axios.post(
                    `${PYTHON_URL}/chat`,
                    payload,
                    {
                        headers: {
                            'Content-Type': 'application/json',
                        },
                    }
                );
                if (fallbackResponse.data && fallbackResponse.data.success && fallbackResponse.data.answer) {
                    const aiResponse = {
                        id: Date.now() + 1,
                        role: 'assistant',
                        content: fallbackResponse.data.answer,
                        timestamp: new Date()
                    };
                    setMessages(prev => [...prev, aiResponse]);
                    await saveMessageToHistory(aiResponse.content, 'assistant');
                } else {
                    const errorContent = fallbackResponse.data?.answer || "Failed to get response from fallback API.";
                    const errorResponse = {
                        id: Date.now() + 1,
                        role: 'assistant',
                        content: errorContent,
                        timestamp: new Date()
                    };
                    setMessages(prev => [...prev, errorResponse]);
                    await saveMessageToHistory(errorContent, 'assistant');
                }
            }
        } catch (err) {
            console.error("Error in handleChatSubmit:", err);
            const errorContent = `I'm sorry, I couldn't process your request: ${err.message}`;
            const errorResponse = {
                id: Date.now() + 1,
                role: 'assistant',
                content: errorContent,
                timestamp: new Date()
            };
            setMessages(prev => [...prev, errorResponse]);
            await saveMessageToHistory(errorContent, 'assistant');
            setStreamingMessage(null);
        } finally {
            setLoading(prev => ({ ...prev, message: false }));
        }
    };
    const toggleProfile = () => {
        setIsProfileOpen(!isProfileOpen);
    };
    const handleGoBack = () => {
        navigate(-1);
    };
    const mockUser = {
        name: "Admin User",
        email: "admin@example.com",
        profilePic: null
    };
    useEffect(() => {
        messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
    }, [messages]);
    const handleFileUpload = async (files) => {
        if (!files.length || !gptData) return;
        try {
            setIsUploading(true);
            setUploadProgress(0);
            setUploadedFiles(Array.from(files).map(file => ({
                name: file.name,
                size: file.size,
                type: file.type
            })));
            const formData = new FormData();
            for (let i = 0; i < files.length; i++) {
                formData.append('files', files[i]);
            }
            formData.append('user_email', userData?.email || 'user@example.com');
            formData.append('gpt_id', gptData._id);
            formData.append('gpt_name', gptData.name);
            formData.append('collection_name', collectionName || gptData._id);
            formData.append('is_user_document', 'true');
            formData.append('system_prompt', gptData?.instructions || '');
            const startTime = Date.now();
            const uploadDuration = 1500;
            const progressInterval = setInterval(() => {
                const elapsed = Date.now() - startTime;
                if (elapsed < uploadDuration) {
                    const progress = Math.min(60, (elapsed / uploadDuration) * 60);
                    setUploadProgress(progress);
                } else {
                    setUploadProgress(prev => {
                        if (prev < 90) {
                            return prev + (90 - prev) * 0.08;
                        }
                        return prev;
                    });
                }
            }, 100);
            const response = await axios.post(
                `${PYTHON_URL}/upload-chat-files`,
                formData,
                {
                    headers: {
                        'Content-Type': 'multipart/form-data',
                    },
                    onUploadProgress: (progressEvent) => {
                        const percentCompleted = Math.round(
                            (progressEvent.loaded * 60) / (progressEvent.total || 100)
                        );
                        setUploadProgress(Math.min(percentCompleted, 60));
                    }
                }
            );
            clearInterval(progressInterval);
            setUploadProgress(100);
            setTimeout(() => setIsUploading(false), 500);
            if (response.data.success) {
                setUserDocuments(response.data.file_urls || []);
            } else {
                throw new Error(response.data.message || "Failed to process files");
            }
        } catch (error) {
            console.error("Error uploading files:", error);
            setIsUploading(false);
        }
    };
    const getFileIcon = (filename) => {
        if (!filename) return <FaFile size={14} />;
        const extension = filename.split('.').pop().toLowerCase();
        switch (extension) {
            case 'pdf':
                return <FaFilePdf size={14} className="text-red-400 dark:text-red-300" />;
            case 'doc':
            case 'docx':
                return <FaFileWord size={14} className="text-blue-400 dark:text-blue-300" />;
            case 'txt':
                return <FaFileAlt size={14} />;
            default:
                return <FaFile size={14} />;
        }
    };
    const handleRemoveUploadedFile = (indexToRemove) => {
        setUploadedFiles(prevFiles => prevFiles.filter((_, index) => index !== indexToRemove));
    };
    useEffect(() => {
        const checkBackendAvailability = async () => {
            try {
                await axios.get(`${PYTHON_URL}/gpt-collection-info/test/test`);
                setBackendAvailable(true);
            } catch (error) {
                if (error.code === "ERR_NETWORK") {
                    console.error("Backend server appears to be offline:", error);
                    setBackendAvailable(false);
                } else {
                    setBackendAvailable(true);
                }
            }
        };
        checkBackendAvailability();
    }, []);
    const handleStreamingResponse = async (response) => {
        const reader = response.body.getReader();
        const decoder = new TextDecoder();
        let buffer = "";
        let doneStreaming = false;
        let sourcesInfo = null;
        let streamError = null;
        const messageId = streamingMessage?.id || Date.now();
        try {
            while (!doneStreaming) {
                const { done, value } = await reader.read();
                if (done) {
                    doneStreaming = true;
                    break;
                }
                const chunk = decoder.decode(value, { stream: true });
                const lines = chunk.split('\n\n').filter(line => line.trim().startsWith('data: '));
                for (const line of lines) {
                    try {
                        const jsonStr = line.substring(6);
                        const parsed = JSON.parse(jsonStr);
                        if (parsed.type === 'error' || parsed.error) {
                            streamError = parsed.error || parsed.detail || 'Unknown streaming error';
                            console.error(`[Stream ${messageId}] Streaming Error:`, streamError);
                            buffer = `Error: ${streamError}`;
                            doneStreaming = true;
                            setStreamingMessage(prev =>
                                prev ? { ...prev, content: buffer, isStreaming: false, isError: true } :
                                    { id: messageId, role: 'assistant', content: buffer, isStreaming: false, isError: true, timestamp: new Date() }
                            );
                            break;
                        }
                        if (parsed.type === 'done') {
                            doneStreaming = true;
                            break;
                        }
                        if (parsed.type === 'content') {
                            buffer += parsed.data;
                            setStreamingMessage(prev =>
                                prev ? { ...prev, content: buffer, isStreaming: true, isError: false } :
                                    { id: messageId, role: 'assistant', content: buffer, isStreaming: true, isError: false, timestamp: new Date() }
                            );
                        }
                        if (parsed.type === 'sources_info') {
                            sourcesInfo = parsed.data;
                            buffer += `\n\n[Sources Retrieved: ${sourcesInfo.documents_retrieved_count} documents, ${sourcesInfo.retrieval_time_ms}ms]`;
                        }
                    } catch (e) {
                        console.error(`[Stream ${messageId}] Error parsing line:`, e, "Line:", line);
                    }
                }
            }
            if (!buffer && !streamError) {
                console.warn(`[Stream ${messageId}] Stream ended with no content.`);
                buffer = "No response generated. Please try rephrasing your query or check the uploaded documents.";
                streamError = true;
            }
            setStreamingMessage(prev =>
                prev ? {
                    ...prev,
                    content: buffer,
                    isStreaming: false,
                    isLoading: false,
                    isError: !!streamError
                } : {
                    id: messageId,
                    role: 'assistant',
                    content: buffer,
                    isStreaming: false,
                    isLoading: false,
                    isError: !!streamError,
                    timestamp: new Date()
                }
            );
            await saveMessageToHistory(buffer, 'assistant');
        } catch (err) {
            console.error(`[Stream ${messageId}] Error reading stream:`, err);
            buffer = `Error reading response stream: ${err.message}`;
            setStreamingMessage(prev =>
                prev ? { ...prev, content: buffer, isStreaming: false, isLoading: false, isError: true } :
                    { id: messageId, role: 'assistant', content: buffer, isStreaming: false, isLoading: false, isError: true, timestamp: new Date() }
            );
            await saveMessageToHistory(buffer, 'assistant');
        } finally {
            setLoading(prev => ({ ...prev, message: false }));
        }
    };
    useEffect(() => {
        if (streamingMessage && !streamingMessage.isStreaming) {
            setMessages(prev => {
                const exists = prev.some(m =>
                    m.content === streamingMessage.content &&
                    m.timestamp.getTime() === streamingMessage.timestamp.getTime()
                );
                if (exists) return prev;
                return [...prev, { ...streamingMessage }];
            });
            setConversationMemory(prev => [...prev, {
                role: 'assistant',
                content: streamingMessage.content,
                timestamp: new Date().toISOString()
            }]);
            setTimeout(() => {
                setStreamingMessage(null);
                setLoading(prev => ({ ...prev, message: false }));
            }, 100);
        }
    }, [streamingMessage]);
    // Determine if the web search toggle should be shown
    const showWebSearchToggle = gptData?.capabilities?.webBrowsing || false;
    const handleNewChat = () => {
        setMessages([]);
        setConversationMemory([]);
        setHasInteracted(false);
        setUserDocuments([]);
        setUploadedFiles([]);
    };
    return (
        <>
            <MarkdownStyles />
            <div className='flex flex-col h-screen bg-white dark:bg-black text-black dark:text-white overflow-hidden'>
                <div className="flex-shrink-0 bg-white dark:bg-black px-4 py-3 flex items-center justify-between">
                    <div className="flex items-center space-x-2">
                        {gptId && (
                            <button
                                onClick={handleGoBack}
                                className="text-gray-500 dark:text-gray-400 hover:text-black dark:hover:text-white p-2 rounded-full hover:bg-gray-100 dark:hover:bg-gray-800 transition-colors flex items-center justify-center w-10 h-10"
                                aria-label="Go back"
                            >
                                <IoArrowBack size={20} />
                            </button>
                        )}
                        <button
                            onClick={handleNewChat}
                            className="text-gray-500 dark:text-gray-400 hover:text-black dark:hover:text-white p-2 rounded-full hover:bg-gray-100 dark:hover:bg-gray-800 transition-colors flex items-center justify-center w-10 h-10"
                            aria-label="New Chat"
                        >
                            <IoAddCircleOutline size={24} /> 
                        </button>
                        {gptData && (
                            <div className="ml-2 text-sm md:text-base font-medium flex items-center">
                                <span className="mr-1">New Chat</span>
                                {gptData.model && (
                                    <div className="flex items-center ml-2 text-xs md:text-sm px-2 py-0.5 bg-gray-100 dark:bg-gray-800 rounded-full">
                                        {modelIcons[gptData.model] || null}
                                        <span>{gptData.model === 'gpt-4o-mini' ? 'GPT-4o Mini' : gptData.model}</span>
                                    </div>
                                )}
                            </div>
                        )}
                    </div>
                    <div className="relative">
                        <button
                            onClick={toggleProfile}
                            className="w-10 h-10 rounded-full overflow-hidden border-2 border-gray-300 dark:border-white/20 hover:border-blue-500 dark:hover:border-white/40 transition-colors"
                        >
                            {(userData || mockUser)?.profilePic ? (
                                <img
                                    src={(userData || mockUser).profilePic}
                                    alt="Profile"
                                    className="w-full h-full object-cover"
                                />
                            ) : (
                                <div className="w-full h-full bg-gray-200 dark:bg-gray-700 flex items-center justify-center">
                                    <IoPersonCircleOutline size={24} className="text-gray-500 dark:text-white" />
                                </div>
                            )}
                        </button>
                        {isProfileOpen && (
                            <div className="absolute top-12 right-0 w-64 bg-white dark:bg-[#1e1e1e] rounded-xl shadow-lg border border-gray-200 dark:border-white/10 overflow-hidden z-30">
                                <div className="p-4 border-b border-gray-200 dark:border-white/10">
                                    <p className="font-medium text-gray-900 dark:text-white">
                                        {userData?.name || mockUser.name}
                                    </p>
                                    <p className="text-sm text-gray-500 dark:text-gray-400 truncate">
                                        {userData?.email || mockUser.email}
                                    </p>
                                </div>
                                <div className="py-1">
                                    <button className="w-full px-4 py-2.5 text-left flex items-center space-x-3 hover:bg-gray-100 dark:hover:bg-white/5 text-gray-700 dark:text-gray-300">
                                        <IoPersonOutline size={18} />
                                        <span>Profile</span>
                                    </button>
                                    <button className="w-full px-4 py-2.5 text-left flex items-center space-x-3 hover:bg-gray-100 dark:hover:bg-white/5 text-gray-700 dark:text-gray-300" onClick={() => navigate('/admin/settings')}>
                                        <IoSettingsOutline size={18} />
                                        <span>Settings</span>
                                    </button>
                                </div>
                            </div>
                        )}
                    </div>
                </div>
                <div className="flex-1 overflow-y-auto p-4 flex flex-col bg-white dark:bg-black hide-scrollbar">
                    <div className="w-full max-w-3xl mx-auto flex-1 flex flex-col space-y-4 pb-4">
                        {isInitialLoading ? (
                            <div className="flex-1 flex flex-col items-center justify-center p-20">
                                <span className="mt-4 text-sm">Loading chat...</span>
                            </div>
                        ) : isFetchingGpt ? (
                            <div className="flex-1 flex items-center justify-center">
                                <div className="animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-blue-500 dark:border-blue-400"></div>
                            </div>
                        ) : messages.length === 0 ? (
                            <div className="flex-1 flex flex-col items-center justify-center text-center px-2">
                                {gptId && gptData ? (
                                    <>
                                        <div className="w-16 h-16 rounded-full bg-gradient-to-br from-blue-600 to-purple-600 flex items-center justify-center mb-4">
                                            {gptData.imageUrl ? (
                                                <img src={gptData.imageUrl} alt={gptData.name} className="w-full h-full object-cover rounded-full" />
                                            ) : (
                                                <span className="text-2xl text-white">{gptData.name?.charAt(0) || '?'}</span>
                                            )}
                                        </div>
                                        <h2 className="text-xl font-semibold mb-2 text-gray-900 dark:text-white">{gptData.name}</h2>
                                        <p className="text-gray-500 dark:text-gray-400 max-w-md">{gptData.description || 'Start a conversation...'}</p>
                                        {gptData.conversationStarter && (
                                            <div
                                                onClick={() => handleChatSubmit(gptData.conversationStarter)}
                                                className="mt-5 max-w-xs p-3 bg-gray-100 dark:bg-gray-800/70 border border-gray-300 dark:border-gray-700/70 rounded-lg text-left cursor-pointer hover:bg-gray-200 dark:hover:bg-gray-800 hover:border-gray-400 dark:hover:border-gray-600/70 transition-colors"
                                            >
                                                <p className="text-gray-800 dark:text-white text-sm">
                                                    {gptData.conversationStarter.length > 40
                                                        ? gptData.conversationStarter.substring(0, 40) + '...'
                                                        : gptData.conversationStarter
                                                    }
                                                </p>
                                            </div>
                                        )}
                                    </>
                                ) : (
                                    <>
                                        <h1 className='text-2xl sm:text-3xl md:text-4xl font-bold mb-2 text-gray-900 dark:text-white'>Welcome to AI Agent</h1>
                                        <span className='text-base sm:text-lg md:text-xl font-medium text-gray-500 dark:text-gray-400 mb-8 block'>How can I assist you today?</span>
                                    </>
                                )}
                            </div>
                        ) : (
                            <>
                                {messages.map(message => (
                                    <div
                                        key={message.id}
                                        className={`flex ${message.role === 'user' ? 'justify-end' : 'justify-start'}`}
                                    >
                                        <div
                                            className={`${message.role === 'user'
                                                    ? 'bg-black/10 dark:bg-white/80 text-black font-[16px] dark:text-black rounded-br-none max-w-max '
                                                    : 'assistant-message text-black font-[16px] dark:text-white rounded-bl-none w-full max-w-3xl'
                                                } rounded-2xl px-4 py-2`}
                                        >
                                            {message.role === 'user' ? (
                                                <>
                                                    <p className="whitespace-pre-wrap">{message.content}</p>
                                                    {/* Display files attached to this message */}
                                                    {message.files && message.files.length > 0 && (
                                                        <div className="mt-2 flex flex-wrap gap-2">
                                                            {message.files.map((file, index) => (
                                                                <div
                                                                    key={`${file.name}-${index}`}
                                                                    className="flex items-center py-1 px-2 bg-gray-50 dark:bg-gray-800/50 rounded-md border border-gray-200 dark:border-gray-700/50 max-w-fit"
                                                                >
                                                                    <div className="mr-1.5 text-gray-500 dark:text-gray-400">
                                                                        {getFileIcon(file.name)}
                                                                    </div>
                                                                    <span className="text-xs font-medium text-gray-700 dark:text-gray-300 truncate max-w-[140px]">
                                                                        {file.name}
                                                                    </span>
                                                                    {file.size && (
                                                                        <div className="text-[10px] text-gray-500 ml-1 whitespace-nowrap">
                                                                            {Math.round(file.size / 1024)} KB
                                                                        </div>
                                                                    )}
                                                                </div>
                                                            ))}
                                                        </div>
                                                    )}
                                                </>
                                            ) : (
                                                <div className="markdown-content">
                                                    <ReactMarkdown
                                                        remarkPlugins={[remarkGfm]}
                                                        rehypePlugins={[rehypeRaw]}
                                                        components={{
                                                            h1: ({ node, ...props }) => <h1 className="text-xl font-bold my-3" {...props} />,
                                                            h2: ({ node, ...props }) => <h2 className="text-lg font-bold my-2" {...props} />,
                                                            h3: ({ node, ...props }) => <h3 className="text-md font-bold my-2" {...props} />,
                                                            h4: ({ node, ...props }) => <h4 className="font-bold my-2" {...props} />,
                                                            p: ({ node, ...props }) => <p className="my-2" {...props} />,
                                                            ul: ({ node, ...props }) => <ul className="list-disc pl-5 my-2" {...props} />,
                                                            ol: ({ node, ...props }) => <ol className="list-decimal pl-5 my-2" {...props} />,
                                                            li: ({ node, index, ...props }) => <li key={index} className="my-1" {...props} />,
                                                            a: ({ node, ...props }) => <a className="text-blue-400 hover:underline" {...props} />,
                                                            blockquote: ({ node, ...props }) => <blockquote className="border-l-4 border-gray-500 dark:border-gray-400 pl-4 my-3 italic" {...props} />,
                                                            code({ node, inline, className, children, ...props }) {
                                                                const match = /language-(\w+)/.exec(className || '');
                                                                return !inline && match ? (
                                                                    <SyntaxHighlighter
                                                                        style={atomDark}
                                                                        language={match[1]}
                                                                        PreTag="div"
                                                                        className="rounded-md my-3"
                                                                        {...props}
                                                                    >
                                                                        {String(children).replace(/\n$/, '')}
                                                                    </SyntaxHighlighter>
                                                                ) : (
                                                                    <code className={`${inline ? 'bg-gray-300 dark:bg-gray-600 px-1 py-0.5 rounded text-sm' : ''} ${className}`} {...props}>
                                                                        {children}
                                                                    </code>
                                                                );
                                                            },
                                                            table: ({ node, ...props }) => (
                                                                <div className="overflow-x-auto my-3">
                                                                    <table className="min-w-full border border-gray-400 dark:border-gray-500" {...props} />
                                                                </div>
                                                            ),
                                                            thead: ({ node, ...props }) => <thead className="bg-gray-300 dark:bg-gray-600" {...props} />,
                                                            tbody: ({ node, ...props }) => <tbody className="divide-y divide-gray-400 dark:divide-gray-500" {...props} />,
                                                            tr: ({ node, ...props }) => <tr className="hover:bg-gray-300 dark:hover:bg-gray-600" {...props} />,
                                                            th: ({ node, ...props }) => <th className="px-4 py-2 text-left font-medium" {...props} />,
                                                            td: ({ node, ...props }) => <td className="px-4 py-2" {...props} />,
                                                        }}
                                                    >
                                                        {message.content}
                                                    </ReactMarkdown>
                                                </div>
                                            )}
                                            <div className={`text-xs mt-2 text-right ${message.role === 'user' ? 'text-blue-50/80' : 'text-gray-400/80'}`}>
                                            </div>
                                        </div>
                                    </div>
                                ))}
                                {streamingMessage ? (
                                    <div className="flex justify-start">
                                        <div className="w-full max-w-3xl rounded-2xl px-4 py-2 assistant-message text-black dark:text-white rounded-bl-none">
                                            <div className="markdown-content">
                                                <ReactMarkdown
                                                    remarkPlugins={[remarkGfm]}
                                                    rehypePlugins={[rehypeRaw]}
                                                    components={{
                                                        h1: ({ node, ...props }) => <h1 className="text-xl font-bold my-3" {...props} />,
                                                        h2: ({ node, ...props }) => <h2 className="text-lg font-bold my-2" {...props} />,
                                                        h3: ({ node, ...props }) => <h3 className="text-md font-bold my-2" {...props} />,
                                                        h4: ({ node, ...props }) => <h4 className="font-bold my-2" {...props} />,
                                                        p: ({ node, ...props }) => <p className="my-2" {...props} />,
                                                        ul: ({ node, ...props }) => <ul className="list-disc pl-5 my-2" {...props} />,
                                                        ol: ({ node, ...props }) => <ol className="list-decimal pl-5 my-2" {...props} />,
                                                        li: ({ node, index, ...props }) => <li key={index} className="my-1" {...props} />,
                                                        a: ({ node, ...props }) => <a className="text-blue-400 hover:underline" {...props} />,
                                                        blockquote: ({ node, ...props }) => <blockquote className="border-l-4 border-gray-500 dark:border-gray-400 pl-4 my-3 italic" {...props} />,
                                                        code({ node, inline, className, children, ...props }) {
                                                            const match = /language-(\w+)/.exec(className || '');
                                                            return !inline && match ? (
                                                                <SyntaxHighlighter
                                                                    style={atomDark}
                                                                    language={match[1]}
                                                                    PreTag="div"
                                                                    className="rounded-md my-3"
                                                                    {...props}
                                                                >
                                                                    {String(children).replace(/\n$/, '')}
                                                                </SyntaxHighlighter>
                                                            ) : (
                                                                <code className={`${inline ? 'bg-gray-300 dark:bg-gray-600 px-1 py-0.5 rounded text-sm' : ''} ${className}`} {...props}>
                                                                    {children}
                                                                </code>
                                                            );
                                                        },
                                                        table: ({ node, ...props }) => (
                                                            <div className="overflow-x-auto my-3">
                                                                <table className="min-w-full border border-gray-400 dark:border-gray-500" {...props} />
                                                            </div>
                                                        ),
                                                        thead: ({ node, ...props }) => <thead className="bg-gray-300 dark:bg-gray-600" {...props} />,
                                                        tbody: ({ node, ...props }) => <tbody className="divide-y divide-gray-400 dark:divide-gray-500" {...props} />,
                                                        tr: ({ node, ...props }) => <tr className="hover:bg-gray-300 dark:hover:bg-gray-600" {...props} />,
                                                        th: ({ node, ...props }) => <th className="px-4 py-2 text-left font-medium" {...props} />,
                                                        td: ({ node, ...props }) => <td className="px-4 py-2" {...props} />,
                                                    }}
                                                >
                                                    {streamingMessage.content}
                                                </ReactMarkdown>
                                                {streamingMessage.isStreaming && (
                                                    <div className="typing-animation mt-2 inline-flex items-center text-gray-400">
                                                        <span></span>
                                                        <span></span>
                                                        <span></span>
                                                    </div>
                                                )}
                                            </div>
                                            <div className="text-xs mt-2 text-right text-gray-400/80">
                                                {new Date(streamingMessage.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                                            </div>
                                        </div>
                                    </div>
                                ) : (
                                    !isInitialLoading && loading.message && (
                                        <div className="flex justify-start items-end space-x-2">
                                            <div className="w-full max-w-3xl rounded-2xl px-4 py-2 assistant-message text-black dark:text-white rounded-bl-none">
                                                <div className="typing-animation inline-flex items-center text-gray-400">
                                                    <span></span>
                                                    <span></span>
                                                    <span></span>
                                                </div>
                                            </div>
                                        </div>
                                    )
                                )}
                                <div ref={messagesEndRef} />
                            </>
                        )}
                    </div>
                </div>
                <div className="flex-shrink-0 w-[95%] max-w-3xl mx-auto">
                    {isUploading && (
                        <div className="mb-2 px-2">
                            <div className="flex items-center p-2 bg-blue-50 dark:bg-blue-900/20 rounded-lg border border-blue-100 dark:border-blue-800/30">
                                <div className="flex-shrink-0 mr-3">
                                    <div className="w-8 h-8 flex items-center justify-center">
                                        <svg className="animate-spin w-5 h-5 text-blue-500 dark:text-blue-400" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                                            <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                                            <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                                        </svg>
                                    </div>
                                </div>
                                <div className="flex-1 min-w-0">
                                    <div className="text-sm font-medium text-blue-700 dark:text-blue-300">
                                        {uploadedFiles.length === 1
                                            ? `Uploading ${uploadedFiles[0]?.name}`
                                            : `Uploading ${uploadedFiles.length} files`}
                                    </div>
                                    <div className="mt-1 relative h-1.5 w-full bg-blue-100 dark:bg-blue-800/40 rounded-full overflow-hidden">
                                        <div
                                            className="absolute left-0 top-0 h-full bg-blue-500 dark:bg-blue-400 transition-all duration-300"
                                            style={{ width: `${uploadProgress}%` }}
                                        ></div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    )}
                    {uploadedFiles.length > 0 && !isUploading && (
                        <div className="mb-2 flex flex-wrap gap-2">
                            {uploadedFiles.map((file, index) => (
                                <div
                                    key={`${file.name}-${index}`}
                                    className="flex items-center py-1 px-2 bg-gray-50 dark:bg-gray-800/50 rounded-md border border-gray-200 dark:border-gray-700/50 max-w-fit"
                                >
                                    <div className="mr-1.5 text-gray-500 dark:text-gray-400">
                                        {getFileIcon(file.name)}
                                    </div>
                                    <span className="text-xs font-medium text-gray-700 dark:text-gray-300 truncate max-w-[140px]">
                                        {file.name}
                                    </span>
                                    <button
                                        onClick={() => handleRemoveUploadedFile(index)}
                                        className="ml-1.5 text-gray-400 hover:text-gray-600 dark:text-gray-500 dark:hover:text-gray-300 p-0.5 rounded-full hover:bg-gray-200 dark:hover:bg-gray-700/50 transition-colors"
                                        aria-label="Remove file"
                                    >
                                        <IoClose size={14} />
                                    </button>
                                </div>
                            ))}
                        </div>
                    )}
                    <AdminMessageInput
                        onSubmit={handleChatSubmit}
                        onFileUpload={handleFileUpload}
                        isLoading={loading.message}
                        currentGptName={gptData?.name}
                        webSearchEnabled={webSearchEnabled}
                        setWebSearchEnabled={setWebSearchEnabled}
                        showWebSearchIcon={showWebSearchToggle}
                    />
                </div>
                {isProfileOpen && (
                    <div
                        className="fixed inset-0 z-20"
                        onClick={() => setIsProfileOpen(false)}
                    />
                )}
            </div>
        </>
    );
};
export default AdminChat;
````

## File: frontend/src/components/Admin/AdminDashboard.jsx
````javascript
import React, { useState, useRef, useEffect, useMemo, lazy, Suspense } from 'react';
import AdminSidebar from './AdminSidebar';
const CreateCustomGpt = lazy(() => import('./CreateCustomGpt'));
import { FiSearch, FiChevronDown, FiChevronUp, FiMenu } from 'react-icons/fi';
import AgentCard from './AgentCard';
import CategorySection from './CategorySection';
import { axiosInstance } from '../../api/axiosInstance';
import { useTheme } from '../../context/ThemeContext';
const defaultAgentImage = '/img.png';
const AdminDashboard = ({ userName = "Admin User" }) => {
    const [showCreateGpt, setShowCreateGpt] = useState(false);
    const [searchTerm, setSearchTerm] = useState('');
    const [isSortOpen, setIsSortOpen] = useState(false);
    const [sortOption, setSortOption] = useState('Default');
    const sortOptions = ['Default', 'Latest', 'Older'];
    const dropdownRef = useRef(null);
    const [showSidebar, setShowSidebar] = useState(false);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);
    const [agentsData, setAgentsData] = useState({
        featured: [],
        productivity: [],
        education: [],
        entertainment: []
    });
    const [gptCreated, setGptCreated] = useState(false);
    const { isDarkMode } = useTheme();
    const applySorting = (data, sortOpt) => {
        if (sortOpt === 'Default') return data;
        const sortedData = { ...data };
        const sortFn = sortOpt === 'Latest'
            ? (a, b) => new Date(b.createdAt) - new Date(a.createdAt)
            : (a, b) => new Date(a.createdAt) - new Date(b.createdAt);
        Object.keys(sortedData).forEach(category => {
            if (Array.isArray(sortedData[category])) {
                sortedData[category] = [...sortedData[category]].sort(sortFn);
            }
        });
        return sortedData;
    };
    useEffect(() => {
        const fetchAgents = async () => {
            try {
                setLoading(true);
                const response = await axiosInstance.get(`/api/custom-gpts`, {
                    withCredentials: true
                });
                if (response.data.success && response.data.customGpts) {
                    const sortedGpts = [...response.data.customGpts].sort((a, b) =>
                        new Date(b.createdAt) - new Date(a.createdAt)
                    );
                    const categorizedData = {
                        featured: [],
                        productivity: [],
                        education: [],
                        entertainment: []
                    };
                    categorizedData.featured = sortedGpts.slice(0, 4).map(gpt => ({
                        id: gpt._id,
                        image: gpt.imageUrl || defaultAgentImage,
                        name: gpt.name,
                        status: gpt.status || 'unknown',
                        userCount: gpt.userCount || 0,
                        messageCount: gpt.messageCount || 0,
                        modelType: gpt.model,
                        createdAt: gpt.createdAt
                    }));
                    sortedGpts.forEach(gpt => {
                        const text = (gpt.description + ' ' + gpt.name).toLowerCase();
                        const agent = {
                            id: gpt._id,
                            image: gpt.imageUrl || defaultAgentImage,
                            name: gpt.name,
                            status: gpt.status || 'unknown',
                            userCount: gpt.userCount || 0,
                            messageCount: gpt.messageCount || 0,
                            modelType: gpt.model,
                            createdAt: gpt.createdAt
                        };
                        if (categorizedData.featured.some(a => a.name === gpt.name)) {
                            return;
                        }
                        if (text.includes('work') || text.includes('task') || text.includes('productivity')) {
                            categorizedData.productivity.push(agent);
                        } else if (text.includes('learn') || text.includes('study') || text.includes('education')) {
                            categorizedData.education.push(agent);
                        } else if (text.includes('game') || text.includes('movie') || text.includes('fun')) {
                            categorizedData.entertainment.push(agent);
                        } else {
                            const categories = ['productivity', 'education', 'entertainment'];
                            const randomCategory = categories[Math.floor(Math.random() * categories.length)];
                            categorizedData[randomCategory].push(agent);
                        }
                    });
                    setAgentsData(categorizedData);
                } else {
                    setError(response.data.message || "Failed to load agents data: Invalid response format");
                }
            } catch (err) {
                console.error("Error fetching agents:", err);
                setError(`Failed to load agents data. ${err.response?.data?.message || err.message || ''}`);
            } finally {
                setLoading(false);
            }
        };
        fetchAgents();
    }, [gptCreated]);
    useEffect(() => {
        const handleResize = () => {
            if (window.innerWidth >= 640) {
                setShowSidebar(false);
            }
        };
        window.addEventListener('resize', handleResize);
        return () => window.removeEventListener('resize', handleResize);
    }, []);
    const filteredAgentsData = useMemo(() => {
        const searchTermLower = searchTerm.toLowerCase().trim();
        if (!searchTermLower) {
            return applySorting(agentsData, sortOption);
        }
        const filtered = {};
        Object.keys(agentsData).forEach(category => {
            filtered[category] = agentsData[category].filter(agent =>
                agent.name.toLowerCase().includes(searchTermLower) ||
                (agent.modelType && agent.modelType.toLowerCase().includes(searchTermLower))
            );
        });
        return applySorting(filtered, sortOption);
    }, [searchTerm, agentsData, sortOption]);
    useEffect(() => {
        function handleClickOutside(event) {
            if (dropdownRef.current && !dropdownRef.current.contains(event.target)) {
                setIsSortOpen(false);
            }
        }
        document.addEventListener("mousedown", handleClickOutside);
        return () => {
            document.removeEventListener("mousedown", handleClickOutside);
        };
    }, [dropdownRef]);
    const handleSortChange = (option) => {
        setSortOption(option);
        setIsSortOpen(false);
    };
    const hasSearchResults = Object.values(filteredAgentsData).some(
        category => category.length > 0
    );
    if (loading) {
        return (
            <div className="flex h-screen bg-black text-white items-center justify-center">
                <div className="animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-white"></div>
            </div>
        );
    }
    if (error) {
        return (
            <div className="flex h-screen bg-black text-white items-center justify-center">
                <div className="text-center p-4">
                    <p className="text-red-400 mb-4">{error}</p>
                    <button
                        onClick={() => window.location.reload()}
                        className="bg-white text-black px-6 py-2 rounded-full font-medium hover:bg-gray-200 transition-all"
                    >
                        Retry
                    </button>
                </div>
            </div>
        );
    }
    return (
        <div className="flex h-screen bg-black text-white font-sans">
            {/* Mobile Sidebar Overlay */}
            {showSidebar && (
                <div
                    className="fixed inset-0 bg-black/80 z-40 sm:hidden"
                    onClick={() => setShowSidebar(false)}
                />
            )}
            {/* Main Content */}
            <div className="flex-1 flex flex-col h-full overflow-hidden">
                {!showCreateGpt ? (
                    <>
                        {/* Header Section */}
                        <div className="bg-black px-4 sm:px-8 py-6 border-b border-gray-800 flex-shrink-0">
                            {/* Desktop Header */}
                            <div className="hidden sm:flex items-center justify-between">
                                <h1 className="text-2xl font-bold">Admin Dashboard</h1>
                                <div className="flex items-center gap-4">
                                    <div className="relative">
                                        <FiSearch className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400" />
                                        <input
                                            type="text"
                                            placeholder="Search GPTs..."
                                            value={searchTerm}
                                            onChange={(e) => setSearchTerm(e.target.value)}
                                            className="w-64 pl-10 pr-4 py-2 rounded-full bg-gray-900 border border-gray-700 focus:ring-2 focus:ring-white focus:border-white transition-all text-white placeholder-gray-400"
                                        />
                                    </div>
                                    <button
                                        onClick={() => setShowCreateGpt(true)}
                                        className="bg-white text-black px-6 py-2 rounded-full font-medium hover:bg-gray-200 transition-all"
                                    >
                                        Create GPT
                                    </button>
                                </div>
                            </div>
                            {/* Mobile Header */}
                            <div className="block sm:hidden">
                                <div className="flex items-center mb-4">
                                    <button
                                        onClick={() => setShowSidebar(!showSidebar)}
                                        className="p-2 rounded-full hover:bg-gray-800"
                                    >
                                        <FiMenu size={24} />
                                    </button>
                                    <h1 className="flex-1 text-center text-xl font-bold">Admin Dashboard</h1>
                                    <div className="w-10"></div>
                                </div>
                                <div className="flex items-center gap-3">
                                    <div className="flex-1 relative">
                                        <FiSearch className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400" />
                                        <input
                                            type="text"
                                            placeholder="Search GPTs..."
                                            value={searchTerm}
                                            onChange={(e) => setSearchTerm(e.target.value)}
                                            className="w-full pl-10 pr-4 py-2 rounded-full bg-gray-900 border border-gray-700 focus:ring-2 focus:ring-white text-white placeholder-gray-400"
                                        />
                                    </div>
                                    <button
                                        onClick={() => setShowCreateGpt(true)}
                                        className="bg-white text-black px-4 py-2 rounded-full font-medium hover:bg-gray-200"
                                    >
                                        Create
                                    </button>
                                </div>
                            </div>
                        </div>
                        {/* Main Content Area */}
                        <div className="flex-1 flex flex-col p-4 sm:p-8 overflow-hidden bg-black">
                            {searchTerm && !hasSearchResults ? (
                                <div className="text-center py-12 text-gray-400">
                                    No agents found for "{searchTerm}"
                                </div>
                            ) : (
                                <>
                                    {/* Featured Agents Section */}
                                    {filteredAgentsData.featured && filteredAgentsData.featured.length > 0 && (
                                        <div className="mb-8 flex-shrink-0">
                                            <h2 className="text-xl font-semibold mb-4">Featured Agents</h2>
                                            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4">
                                                {filteredAgentsData.featured.map((agent) => (
                                                    <AgentCard
                                                        key={agent.id || agent.name}
                                                        agentId={agent.id}
                                                        agentImage={agent.image}
                                                        agentName={agent.name}
                                                        status={agent.status}
                                                        userCount={agent.userCount}
                                                        messageCount={agent.messageCount}
                                                        modelType={agent.modelType}
                                                        hideActionIcons={true}
                                                    />
                                                ))}
                                            </div>
                                        </div>
                                    )}
                                    {/* Categories Header and Sort */}
                                    <div className="flex items-center justify-between mb-6 flex-shrink-0">
                                        <h2 className="text-xl font-semibold">Categories</h2>
                                        <div className="relative" ref={dropdownRef}>
                                            <button
                                                onClick={() => setIsSortOpen(!isSortOpen)}
                                                className="flex items-center text-sm text-gray-400 hover:text-white py-2 px-4 bg-gray-900 rounded-full border border-gray-700"
                                            >
                                                Sort: {sortOption}
                                                {isSortOpen ? <FiChevronUp className="ml-2" /> : <FiChevronDown className="ml-2" />}
                                            </button>
                                            {isSortOpen && (
                                                <div className="absolute top-full right-0 mt-2 w-36 bg-gray-900 rounded-lg shadow-lg z-10 border border-gray-700">
                                                    <ul>
                                                        {sortOptions.map((option) => (
                                                            <li key={option}>
                                                                <button
                                                                    onClick={() => handleSortChange(option)}
                                                                    className={`block w-full text-left px-4 py-2 text-sm ${sortOption === option ? 'bg-white text-black' : 'text-gray-300 hover:bg-gray-800'} transition-all`}
                                                                >
                                                                    {option}
                                                                </button>
                                                            </li>
                                                        ))}
                                                    </ul>
                                                </div>
                                            )}
                                        </div>
                                    </div>
                                    {/* Scrollable Categories */}
                                    <div className="flex-1 overflow-y-auto [scrollbar-width:none] [-ms-overflow-style:none] [&::-webkit-scrollbar]:hidden">
                                        {Object.entries(filteredAgentsData).map(([category, agents]) => {
                                            if (category === 'featured' || agents.length === 0) return null;
                                            const categoryTitle = category
                                                .replace(/([A-Z])/g, ' $1')
                                                .replace(/^./, (str) => str.toUpperCase());
                                            return (
                                                <CategorySection
                                                    key={category}
                                                    title={categoryTitle}
                                                    agentCount={agents.length}
                                                    agents={agents}
                                                    hideActionIcons={true}
                                                />
                                            );
                                        })}
                                    </div>
                                </>
                            )}
                        </div>
                    </>
                ) : (
                    <div className="h-full">
                        <Suspense fallback={<div className="flex h-full items-center justify-center text-gray-400">Loading Editor...</div>}>
                            <CreateCustomGpt
                                onGoBack={() => setShowCreateGpt(false)}
                                onGptCreated={() => {
                                    setGptCreated(prev => !prev);
                                    setShowCreateGpt(false);
                                }}
                            />
                        </Suspense>
                    </div>
                )}
            </div>
        </div>
    );
};
export default AdminDashboard;
````

## File: frontend/src/components/Admin/AdminMessageInput.jsx
````javascript
import React, { useState, useRef, useEffect } from 'react';
import { IoSendSharp } from 'react-icons/io5';
import { HiMiniPaperClip } from 'react-icons/hi2';
import { BsGlobe2 } from 'react-icons/bs';
import { useTheme } from '../../context/ThemeContext';
const AdminMessageInput = ({ onSubmit, onFileUpload, isLoading, currentGptName, webSearchEnabled, setWebSearchEnabled, showWebSearchIcon }) => {
    const [inputMessage, setInputMessage] = useState('');
    const textareaRef = useRef(null);
    const fileInputRef = useRef(null);
    const { isDarkMode } = useTheme();
    // More robust auto-resize textarea
    const resizeTextarea = () => {
        if (textareaRef.current) {
            // Temporarily reset height to get accurate scrollHeight
            textareaRef.current.style.height = 'auto'; // Reset first
            const scrollHeight = textareaRef.current.scrollHeight;
            // Define min and max heights (adjust as needed)
            const minHeight = 40; // Example min height
            const maxHeight = 160; // Example max height (approx 6 lines)
            // Calculate new height, clamped between min and max
            const newHeight = Math.max(minHeight, Math.min(scrollHeight, maxHeight));
            textareaRef.current.style.height = newHeight + 'px';
            // Add overflow-y: auto if maxHeight is reached
            textareaRef.current.style.overflowY = scrollHeight > maxHeight ? 'auto' : 'hidden';
        }
    };
    // Auto-resize when input changes
    useEffect(() => {
        resizeTextarea();
    }, [inputMessage]);
    // Also resize on window resize
    useEffect(() => {
        window.addEventListener('resize', resizeTextarea);
        return () => window.removeEventListener('resize', resizeTextarea);
    }, []);
    const handleSubmit = (e) => {
        e.preventDefault();
        // Prevent submission if loading or input is empty
        if (isLoading || !inputMessage.trim()) return;
        onSubmit(inputMessage);
        setInputMessage('');
        // Reset height after submitting
        setTimeout(() => {
            if (textareaRef.current) {
                textareaRef.current.style.height = '40px'; // Reset to min-height
                textareaRef.current.style.overflowY = 'hidden'; // Reset overflow
            }
        }, 0);
    };
    // Function to handle click on the paperclip icon
    const handleUploadClick = () => {
        fileInputRef.current.click(); // Trigger click on the hidden file input
    };
    // Function to handle file selection
    const handleFileChange = (e) => {
        const files = e.target.files;
        if (files && files.length > 0) {
            if (onFileUpload) {
                onFileUpload(files);
            }
            e.target.value = null;
        }
    };
    // Function to toggle web search
    const toggleWebSearch = () => {
        setWebSearchEnabled(!webSearchEnabled);
    };
    return (
        <div className="w-full p-2 sm:p-4 bg-white dark:bg-black">
            <form onSubmit={handleSubmit}>
                <div className="bg-gray-100 dark:bg-[#1e1e1e] rounded-xl sm:rounded-2xl shadow-sm border border-gray-200 dark:border-gray-700/50 relative group ">
                    <div className="flex flex-col px-3 sm:px-4 py-2 sm:py-3">
                        <textarea
                            ref={textareaRef}
                            className="w-full bg-transparent border-0 outline-none text-black dark:text-white resize-none overflow-hidden min-h-[40px] text-sm sm:text-base placeholder-gray-500 dark:placeholder-gray-400 custom-scrollbar-dark dark:custom-scrollbar"
                            placeholder="Ask anything..."
                            value={inputMessage}
                            onChange={(e) => setInputMessage(e.target.value)}
                            rows={1}
                            disabled={isLoading}
                            onKeyDown={(e) => {
                                if (e.key === 'Enter' && !e.shiftKey) {
                                    e.preventDefault();
                                    handleSubmit(e);
                                }
                            }}
                            style={{ height: '40px' }}
                        />
                        <div className="flex justify-between items-center mt-1.5 sm:mt-2">
                            <div className="flex items-center">
                                <input
                                    type="file"
                                    ref={fileInputRef}
                                    onChange={handleFileChange}
                                    style={{ display: 'none' }}
                                    multiple
                                    disabled={isLoading}
                                />
                                <button
                                    type="button"
                                    onClick={handleUploadClick}
                                    className={`text-gray-400 dark:text-gray-500 rounded-full w-7 h-7 sm:w-8 sm:h-8 flex items-center justify-center hover:bg-gray-200 dark:hover:bg-gray-700/50 transition-colors ${isLoading ? 'cursor-not-allowed opacity-50' : ''}`}
                                    aria-label="Attach file"
                                    disabled={isLoading}
                                >
                                    <HiMiniPaperClip size={18} className="sm:text-[20px]" />
                                </button>
                                {/* Conditionally render Web Search Toggle Button */}
                                {showWebSearchIcon && (
                                    <button
                                        type="button"
                                        onClick={toggleWebSearch}
                                        className={`ml-1 rounded-full w-7 h-7 sm:w-8 sm:h-8 flex items-center justify-center transition-colors ${
                                            webSearchEnabled 
                                                ? 'text-blue-500 dark:text-blue-400 bg-blue-100 dark:bg-blue-900/30' 
                                                : 'text-gray-400 dark:text-gray-500 hover:bg-gray-200 dark:hover:bg-gray-700/50'
                                        } ${isLoading ? 'cursor-not-allowed opacity-50' : ''}`}
                                        aria-label={webSearchEnabled ? "Disable web search" : "Enable web search"}
                                        disabled={isLoading}
                                    >
                                        <BsGlobe2 size={16} className="sm:text-[18px]" />
                                    </button>
                                )}
                            </div>
                            <button
                                type="submit"
                                className={`rounded-full w-7 h-7 sm:w-8 sm:h-8 flex items-center justify-center transition-all duration-200 ${!inputMessage.trim() || isLoading
                                        ? 'bg-white dark:bg-black text-black dark:text-white cursor-not-allowed'
                                        : 'bg-white hover:bg-white/70 text-black'
                                    }`}
                                disabled={!inputMessage.trim() || isLoading}
                                aria-label="Send message"
                            >
                                {isLoading ? (
                                    <div className="animate-spin rounded-full h-4 w-4 border-t-2 border-b-2 border-white"></div>
                                ) : (
                                    <IoSendSharp size={16} className="sm:text-[18px] translate-x-[1px]" />
                                )}
                            </button>
                        </div>
                    </div>
                </div>
            </form>
        </div>
    );
};
export default AdminMessageInput;
````

## File: frontend/src/components/Admin/AdminSidebar.jsx
````javascript
import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../../context/AuthContext';
import { useTheme } from '../../context/ThemeContext';
import {
    IoGridOutline,
    IoFolderOpenOutline,
    IoPeopleOutline,
    IoSettingsOutline,
    IoTimeOutline,
    IoExitOutline,
    IoChevronBackOutline,
    IoChevronForwardOutline,
    IoMenuOutline
} from 'react-icons/io5';
const AdminSidebar = ({ activePage = 'dashboard', onNavigate }) => {
    const [isCollapsed, setIsCollapsed] = useState(false);
    const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false);
    const [activeItem, setActiveItem] = useState(activePage);
    const navigate = useNavigate();
    const { logout } = useAuth();
    const { isDarkMode } = useTheme();
    useEffect(() => {
        setActiveItem(activePage);
    }, [activePage]);
    const handleLogout = async () => {
        if (window.confirm("Are you sure you want to logout?")) {
            await logout();
        }
    };
    useEffect(() => {
        const handleResize = () => {
            if (window.innerWidth < 768) {
                setIsCollapsed(true);
            }
        };
        window.addEventListener('resize', handleResize);
        handleResize();
        return () => window.removeEventListener('resize', handleResize);
    }, []);
    const toggleSidebar = () => {
        setIsCollapsed(!isCollapsed);
    };
    const toggleMobileMenu = () => {
        setIsMobileMenuOpen(!isMobileMenuOpen);
    };
    const handleNavigation = (itemId) => {
        if (onNavigate) {
            onNavigate(itemId);
        }
        if (window.innerWidth < 768 && isMobileMenuOpen) {
            toggleMobileMenu();
        }
    };
    const navItems = [
        { id: 'dashboard', label: 'Dashboard', icon: <IoGridOutline size={20} /> },
        { id: 'collections', label: 'Collections', icon: <IoFolderOpenOutline size={20} /> },
        { id: 'team', label: 'Team', icon: <IoPeopleOutline size={20} /> },
        { id: 'settings', label: 'Settings', icon: <IoSettingsOutline size={20} /> },
        { id: 'history', label: 'History', icon: <IoTimeOutline size={20} /> },
    ];
    return (
        <>
            <div className="md:hidden fixed top-4 left-4 z-50">
                <button
                    onClick={toggleMobileMenu}
                    className="rounded-full p-2 bg-gray-100 dark:bg-gray-800 text-gray-800 dark:text-white shadow-lg hover:bg-gray-200 dark:hover:bg-gray-700"
                >
                    <IoMenuOutline size={24} />
                </button>
            </div>
            {isMobileMenuOpen && (
                <div
                    className="md:hidden fixed inset-0 bg-black/60 dark:bg-black/80 z-40"
                    onClick={() => setIsMobileMenuOpen(false)}
                />
            )}
            <div
                className={`fixed md:relative h-screen bg-white dark:bg-[#121212] text-black dark:text-white flex flex-col justify-between transition-all duration-300 ease-in-out z-50 border-r border-gray-200 dark:border-gray-800
                    ${isCollapsed ? 'w-[70px]' : 'w-[240px]'}
                    ${isMobileMenuOpen ? 'translate-x-0' : '-translate-x-full md:translate-x-0'}
                `}
            >
                <div>
                    <div className={`px-4 py-6 mb-4 flex ${isCollapsed ? 'justify-center' : 'justify-between'} items-center`}>
                        {!isCollapsed && <h1 className="text-xl font-bold text-gray-900 dark:text-white">Admin Panel</h1>}
                        <button
                            onClick={toggleSidebar}
                            className="rounded-full p-1.5 bg-gray-100 dark:bg-white/10 text-gray-700 dark:text-white hover:bg-gray-200 dark:hover:bg-white/20 transition-colors hidden md:flex items-center justify-center"
                        >
                            {isCollapsed ? <IoChevronForwardOutline size={16} /> : <IoChevronBackOutline size={16} />}
                        </button>
                    </div>
                    <div className="flex flex-col space-y-1 px-2">
                        {navItems.map((item) => (
                            <button
                                key={item.id}
                                onClick={() => handleNavigation(item.id)}
                                className={`flex items-center ${isCollapsed ? 'justify-center' : 'justify-start'} w-full px-4 py-3 rounded-lg text-left transition-colors ${activePage === item.id || (activePage === 'collections' && (item.id === 'create-gpt' || item.id.startsWith('edit-gpt')))
                                        ? 'bg-white dark:bg-white/10 text-black dark:text-white'
                                        : 'text-gray-600 dark:text-gray-400 hover:bg-gray-100 dark:hover:bg-black hover:text-gray-900 dark:hover:text-white'
                                    }`}
                                title={isCollapsed ? item.label : ''}
                            >
                                <span className="flex items-center justify-center">{item.icon}</span>
                                {!isCollapsed && <span className="ml-3">{item.label}</span>}
                            </button>
                        ))}
                    </div>
                </div>
                <div className="px-2 pb-6 mt-auto">
                    <button
                        onClick={handleLogout}
                        className={`flex items-center ${isCollapsed ? 'justify-center' : 'justify-start'} w-full px-4 py-3 text-gray-600 dark:text-gray-400 hover:bg-red-100 dark:hover:bg-red-900/20 hover:text-red-600 dark:hover:text-red-300 rounded-lg text-left transition-colors`}
                        title={isCollapsed ? 'Logout' : ''}
                    >
                        <span className="flex items-center justify-center"><IoExitOutline size={20} /></span>
                        {!isCollapsed && <span className="ml-3">Logout</span>}
                    </button>
                </div>
            </div>
        </>
    );
};
export default AdminSidebar;
````

## File: frontend/src/components/Admin/AgentCard.jsx
````javascript
import React from 'react';
import { FaCircle, FaUsers, FaCommentDots } from 'react-icons/fa';
import { FiCode, FiEdit, FiTrash2, FiFolderPlus, FiFolder } from 'react-icons/fi';
import { SiOpenai, SiGooglegemini } from 'react-icons/si';
import { FaRobot } from 'react-icons/fa6';
import { BiLogoMeta } from 'react-icons/bi';
import { RiOpenaiFill } from 'react-icons/ri';
import { useNavigate } from 'react-router-dom';
import { useTheme } from '../../context/ThemeContext';
// Model icons mapping
const modelIcons = {
    'gpt-4': <RiOpenaiFill className="text-green-500" size={18} />,
    'gpt-3.5': <SiOpenai className="text-green-400" size={16} />,
    'claude': <FaRobot className="text-purple-400" size={16} />,
    'gemini': <SiGooglegemini className="text-blue-400" size={16} />,
    'llama': <BiLogoMeta className="text-blue-500" size={18} />
};
const AgentCard = ({ agentId, agentImage, agentName, status, userCount, messageCount, modelType, createdAt, hideActionIcons = false }) => {
    const navigate = useNavigate();
    const { isDarkMode } = useTheme();
    const statusDotColor = status === 'online'
        ? (isDarkMode ? 'bg-green-400' : 'bg-green-500')
        : (isDarkMode ? 'bg-red-500' : 'bg-red-600');
    const statusTextColor = status === 'online'
        ? (isDarkMode ? 'text-green-300' : 'text-green-600')
        : (isDarkMode ? 'text-red-300' : 'text-red-600');
    const formatDate = (dateString) => {
        if (!dateString) return '';
        return new Date(dateString).toLocaleDateString('en-US', {
            year: 'numeric',
            month: 'short',
            day: 'numeric'
        });
    };
    return (
        <div
            key={agentId}
            className="bg-white dark:bg-gray-800 rounded-lg overflow-hidden border border-gray-200 dark:border-gray-700 hover:border-blue-400/50 dark:hover:border-gray-600 transition-all shadow-md hover:shadow-lg flex flex-col cursor-pointer group"
            onClick={() => navigate(`/admin/chat/${agentId}`)}
        >
            <div className="h-24 sm:h-32 bg-gradient-to-br from-gray-100 to-gray-300 dark:from-gray-700 dark:to-gray-900 relative flex-shrink-0 overflow-hidden">
                {agentImage ? (
                    <img
                        src={agentImage}
                        alt={agentName}
                        className="w-full h-full object-cover opacity-80 dark:opacity-70 group-hover:scale-105 transition-transform duration-300"
                        loading="lazy"
                    />
                ) : (
                    <div className="w-full h-full flex items-center justify-center bg-gradient-to-br from-blue-50/50 to-purple-100/50 dark:from-blue-900/30 dark:to-purple-900/30">
                        <span className={`text-3xl sm:text-4xl ${isDarkMode ? 'text-white/30' : 'text-gray-500/40'}`}>{agentName.charAt(0)}</span>
                    </div>
                )}
                <div className="absolute top-2 right-2 flex gap-1.5 opacity-0 group-hover:opacity-100 transition-opacity duration-200">
                    {!hideActionIcons && (
                        <>
                            <button
                                onClick={(e) => { e.stopPropagation(); }}
                                className="p-1.5 sm:p-2 bg-white/80 dark:bg-gray-900/70 text-gray-700 dark:text-gray-200 rounded-full hover:bg-green-500 hover:text-white dark:hover:bg-green-700/80 transition-colors shadow"
                                title="Move to Folder"
                            >
                                <FiFolderPlus size={14} />
                            </button>
                            <button
                                onClick={(e) => { e.stopPropagation(); }}
                                className="p-1.5 sm:p-2 bg-white/80 dark:bg-gray-900/70 text-gray-700 dark:text-gray-200 rounded-full hover:bg-blue-500 hover:text-white dark:hover:bg-blue-700/80 transition-colors shadow"
                                title="Edit GPT"
                            >
                                <FiEdit size={14} />
                            </button>
                            <button
                                onClick={(e) => { e.stopPropagation(); }}
                                className="p-1.5 sm:p-2 bg-white/80 dark:bg-gray-900/70 text-gray-700 dark:text-gray-200 rounded-full hover:bg-red-500 hover:text-white dark:hover:bg-red-700/80 transition-colors shadow"
                                title="Delete GPT"
                            >
                                <FiTrash2 size={14} />
                            </button>
                        </>
                    )}
                </div>
            </div>
            <div className="p-3 sm:p-4 flex flex-col flex-grow">
                <div className="flex items-start justify-between mb-1.5 sm:mb-2">
                    <h3 className="font-semibold text-base sm:text-lg line-clamp-1 text-gray-900 dark:text-white">{agentName}</h3>
                    <div className="flex items-center flex-shrink-0 gap-1 bg-gray-100 dark:bg-gray-700 px-1.5 sm:px-2 py-0.5 rounded text-[10px] sm:text-xs text-gray-600 dark:text-gray-300">
                        {React.cloneElement(modelIcons[modelType] || <FaRobot className="text-gray-500" />, { size: 12 })}
                        <span className="hidden sm:inline">{modelType}</span>
                    </div>
                </div>
                <div className="mt-auto pt-2 border-t border-gray-100 dark:border-gray-700 text-[10px] sm:text-xs text-gray-500 dark:text-gray-400 flex justify-between items-center">
                    <span>Created: {formatDate(createdAt)}</span>
                    <div className="flex items-center gap-2">
                        <span className="whitespace-nowrap">{userCount} users</span>
                        <span className="whitespace-nowrap">{messageCount} msgs</span>
                    </div>
                </div>
            </div>
        </div>
    );
};
export default React.memo(AgentCard);
````

## File: frontend/src/components/Admin/AssignGptsModal.jsx
````javascript
import React, { useState, useEffect } from 'react';
import { IoClose } from 'react-icons/io5';
import { FiSearch, FiCheck } from 'react-icons/fi';
import { axiosInstance } from '../../api/axiosInstance';
import { toast } from 'react-toastify';
import { useTheme } from '../../context/ThemeContext'; // Import useTheme
const AssignGptsModal = ({ isOpen, onClose, teamMember, onAssignmentChange }) => { // Added onAssignmentChange
    const [allGpts, setAllGpts] = useState([]);
    // selectedGpts state removed, using assignedGptIds and temporary selection
    const [searchTerm, setSearchTerm] = useState('');
    const [loading, setLoading] = useState(true);
    const [assignedGptIds, setAssignedGptIds] = useState(new Set());
    const [saving, setSaving] = useState(false); // State for save operation
    const [locallySelectedIds, setLocallySelectedIds] = useState(new Set()); // Track selections made in this modal session
    const { isDarkMode } = useTheme(); // Use theme context
    // Fetch all GPTs and user's assigned GPTs
    useEffect(() => {
        if (!isOpen || !teamMember) return;
        const fetchData = async () => {
            setLoading(true);
            setLocallySelectedIds(new Set()); // Reset local selections on open
            try {
                const [allGptsResponse, userGptsResponse] = await Promise.all([
                    axiosInstance.get('/api/custom-gpts', { withCredentials: true }),
                    axiosInstance.get(`/api/custom-gpts/team/members/${teamMember.id}/gpts`, { withCredentials: true })
                ]);
                if (allGptsResponse.data?.customGpts) {
                    setAllGpts(allGptsResponse.data.customGpts);
                }
                if (userGptsResponse.data?.gpts) {
                    const assignedIds = new Set(userGptsResponse.data.gpts.map(gpt => gpt._id));
                    setAssignedGptIds(assignedIds);
                    setLocallySelectedIds(assignedIds); // Initialize local selection with current assignments
                } else {
                    setAssignedGptIds(new Set()); // Ensure it's a set even if fetch fails
                    setLocallySelectedIds(new Set());
                }
            } catch (error) {
                console.error("Error fetching GPTs:", error);
                toast.error(`Failed to load GPT data: ${error.response?.data?.message || error.message}`);
                setAssignedGptIds(new Set()); // Reset on error
                setLocallySelectedIds(new Set());
            } finally {
                setLoading(false);
            }
        };
        fetchData();
    }, [isOpen, teamMember]);
    // Toggle local selection of a GPT ID
    const toggleGptSelection = (gptId) => {
        setLocallySelectedIds(prev => {
            const newSet = new Set(prev);
            if (newSet.has(gptId)) {
                newSet.delete(gptId); // Unselect
            } else {
                newSet.add(gptId); // Select
            }
            return newSet;
        });
    };
    // Assign/Unassign GPTs based on the difference between initial and final selections
    const handleSaveChanges = async () => {
        setSaving(true);
        let errors = [];
        try {
            const initialAssignedIds = assignedGptIds;
            const finalSelectedIds = locallySelectedIds;
            const idsToAssign = [...finalSelectedIds].filter(id => !initialAssignedIds.has(id));
            const idsToUnassign = [...initialAssignedIds].filter(id => !finalSelectedIds.has(id));
            // Process assignments one by one instead of using Promise.all
            for (const gptId of idsToAssign) {
                try {
                    // Ensure we're using the correct content type and body format
                    await axiosInstance.post(
                        `/api/custom-gpts/team/members/${teamMember.id}/gpts`,
                        { gptId }, // Make sure this matches exactly what the backend expects
                        {
                            withCredentials: true,
                            headers: {
                                'Content-Type': 'application/json'
                            }
                        }
                    );
                } catch (err) {
                    console.error(`Failed to assign GPT ${gptId}:`, err.response?.data || err.message);
                    errors.push({ type: 'assign', gptId, error: err.response?.data?.message || err.message });
                }
            }
            // Process unassignments one by one
            for (const gptId of idsToUnassign) {
                try {
                    await axiosInstance.delete(
                        `/api/custom-gpts/team/members/${teamMember.id}/gpts/${gptId}`,
                        { withCredentials: true }
                    );
                } catch (err) {
                    console.error(`Failed to unassign GPT ${gptId}:`, err.response?.data || err.message);
                    errors.push({ type: 'unassign', gptId, error: err.response?.data?.message || err.message });
                }
            }
            // Determine message based on results
            if (errors.length === 0) {
                let successMessage = "Assignments updated successfully.";
                if (idsToAssign.length > 0 && idsToUnassign.length === 0) {
                    successMessage = `Assigned ${idsToAssign.length} GPT(s).`;
                } else if (idsToUnassign.length > 0 && idsToAssign.length === 0) {
                    successMessage = `Unassigned ${idsToUnassign.length} GPT(s).`;
                } else if (idsToAssign.length > 0 && idsToUnassign.length > 0) {
                    successMessage = `Assigned ${idsToAssign.length}, Unassigned ${idsToUnassign.length} GPT(s).`;
                }
                toast.success(successMessage);
            } else {
                // Some operations failed
                if (errors.length < (idsToAssign.length + idsToUnassign.length)) {
                    // Partial success
                    toast.warning(`Some operations failed. ${errors.length} error(s) occurred.`);
                } else {
                    // All operations failed
                    toast.error("Failed to update assignments. Please try again.");
                }
            }
            // Always call the callback, even if there were some errors
            if (onAssignmentChange) {
                onAssignmentChange(teamMember.id);
            }
            onClose();
        } catch (error) {
            console.error("Error in handleSaveChanges:", error);
            toast.error(`Failed to update assignments: ${error.message}`);
        } finally {
            setSaving(false);
        }
    };
    // Filter GPTs based on search term
    const filteredGpts = allGpts.filter(gpt =>
        gpt.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
        (gpt.description && gpt.description.toLowerCase().includes(searchTerm.toLowerCase()))
    );
    if (!isOpen) return null;
    const changesMade = (() => {
        if (assignedGptIds.size !== locallySelectedIds.size) return true;
        for (const id of assignedGptIds) {
            if (!locallySelectedIds.has(id)) return true;
        }
        return false;
    })();
    return (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
            {/* Apply theme overlay */}
            <div className="absolute inset-0 bg-black/60 dark:bg-black/80" onClick={onClose}></div>
            <div className="relative bg-white dark:bg-gray-800 w-full max-w-2xl max-h-[90vh] rounded-xl shadow-xl border border-gray-200 dark:border-gray-700 overflow-hidden flex flex-col">
                <div className="px-6 py-4 border-b border-gray-200 dark:border-gray-700 flex justify-between items-center bg-gray-50 dark:bg-gray-900 flex-shrink-0">
                    <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
                        Assign GPTs to {teamMember?.name}
                    </h3>
                    <button
                        onClick={onClose}
                        className="text-gray-400 hover:text-gray-600 dark:text-gray-500 dark:hover:text-white transition-colors rounded-full p-1 hover:bg-gray-200 dark:hover:bg-gray-700"
                    >
                        <IoClose size={22} />
                    </button>
                </div>
                <div className="p-4 border-b border-gray-200 dark:border-gray-700 flex-shrink-0">
                    <div className="relative">
                        <FiSearch className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400 dark:text-gray-500" />
                        <input
                            type="text"
                            placeholder="Search GPTs..."
                            value={searchTerm}
                            onChange={(e) => setSearchTerm(e.target.value)}
                            className="w-full pl-10 pr-4 py-2 rounded-lg bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-600 focus:ring-2 focus:ring-blue-500 focus:border-transparent outline-none text-sm text-black dark:text-white placeholder-gray-500 dark:placeholder-gray-400"
                        />
                    </div>
                </div>
                <div className="flex-1 overflow-y-auto custom-scrollbar-dark dark:custom-scrollbar">
                    {loading ? (
                        <div className="flex justify-center items-center h-40 text-gray-500 dark:text-gray-400">
                            <div className="animate-spin rounded-full h-8 w-8 border-t-2 border-b-2 border-blue-500"></div>
                        </div>
                    ) : filteredGpts.length === 0 ? (
                        <div className="p-6 text-center text-gray-500 dark:text-gray-400">
                            No GPTs found{searchTerm && ` matching "${searchTerm}"`}.
                        </div>
                    ) : (
                        <div className="space-y-2 p-4">
                            {filteredGpts.map(gpt => {
                                const isSelected = locallySelectedIds.has(gpt._id);
                                return (
                                    <div
                                        key={gpt._id}
                                        className={`
                                            p-3 rounded-lg border transition-colors duration-150 flex items-center cursor-pointer
                                            ${isSelected
                                                ? 'bg-blue-50 dark:bg-blue-900/30 border-blue-300 dark:border-blue-700 ring-1 ring-blue-400 dark:ring-blue-600'
                                                : 'bg-white dark:bg-gray-700/50 border-gray-200 dark:border-gray-600 hover:bg-gray-50 dark:hover:bg-gray-700'
                                            }
                                        `}
                                        onClick={() => toggleGptSelection(gpt._id)}
                                    >
                                        <div className="flex-shrink-0 w-10 h-10 rounded-full overflow-hidden bg-gradient-to-br from-gray-200 to-gray-300 dark:from-blue-600 dark:to-purple-600 flex items-center justify-center mr-3">
                                            {gpt.imageUrl ? (
                                                <img src={gpt.imageUrl} alt={gpt.name} className="w-full h-full object-cover" />
                                            ) : (
                                                <span className={`text-lg ${isDarkMode ? 'text-white' : 'text-gray-600'}`}>{gpt.name.charAt(0)}</span>
                                            )}
                                        </div>
                                        <div className="flex-1 mr-3 overflow-hidden">
                                            <h3 className="font-medium truncate text-gray-900 dark:text-white" title={gpt.name}>{gpt.name}</h3>
                                            <p className="text-xs text-gray-500 dark:text-gray-400 line-clamp-1" title={gpt.description}>{gpt.description}</p>
                                        </div>
                                        <div className="flex-shrink-0">
                                            <div className={`w-5 h-5 rounded border-2 flex items-center justify-center transition-all duration-150 ${isSelected
                                                    ? 'bg-blue-600 border-blue-600'
                                                    : 'bg-white dark:bg-gray-600 border-gray-300 dark:border-gray-500 group-hover:border-gray-400 dark:group-hover:border-gray-400'
                                                }`}>
                                                {isSelected && <FiCheck className="text-white" size={14} strokeWidth={3} />}
                                            </div>
                                        </div>
                                    </div>
                                );
                            })}
                        </div>
                    )}
                </div>
                <div className="px-6 py-4 border-t border-gray-200 dark:border-gray-700 flex justify-between items-center bg-gray-50 dark:bg-gray-900 flex-shrink-0">
                    <div className="text-sm text-gray-600 dark:text-gray-400">
                        {locallySelectedIds.size} GPT(s) selected
                    </div>
                    <div className="flex space-x-3">
                        <button
                            onClick={onClose}
                            className="px-4 py-2 bg-white dark:bg-gray-700 border border-gray-300 dark:border-gray-600 text-gray-800 dark:text-white rounded-lg font-medium hover:bg-gray-50 dark:hover:bg-gray-600 transition-colors text-sm"
                        >
                            Cancel
                        </button>
                        <button
                            onClick={handleSaveChanges}
                            disabled={!changesMade || saving}
                            className="px-4 py-2 bg-black dark:bg-white text-white dark:text-black rounded-lg font-medium hover:bg-black/70 dark:hover:bg-white/70 transition-colors disabled:opacity-60 disabled:cursor-not-allowed text-sm flex items-center"
                        >
                            {saving && <div className="animate-spin rounded-full h-4 w-4 border-t-2 border-b-2 border-white mr-2"></div>}
                            {saving ? 'Saving...' : 'Save Changes'}
                        </button>
                    </div>
                </div>
            </div>
        </div>
    );
};
export default AssignGptsModal;
````

## File: frontend/src/components/Admin/CategorySection.jsx
````javascript
import React, { useState, useEffect } from 'react';
import AgentCard from './AgentCard';
import { useNavigate } from 'react-router-dom';
import { useTheme } from '../../context/ThemeContext';
import { FiUser, FiMessageSquare, FiCode, FiMoreHorizontal, FiExternalLink } from 'react-icons/fi';
import { FixedSizeGrid } from 'react-window';
const CategorySection = ({ title, agentCount, agents, virtualized = false, hideActionIcons = false }) => {
    // Detect mobile view
    const [isMobileView, setIsMobileView] = useState(false);
    const navigate = useNavigate();
    const { isDarkMode } = useTheme();
    useEffect(() => {
        const handleResize = () => {
            setIsMobileView(window.innerWidth < 640);
        };
        window.addEventListener('resize', handleResize);
        handleResize();
        return () => window.removeEventListener('resize', handleResize);
    }, []);
    // Mobile agent item component with theme styles
    const MobileAgentItem = ({ agent, onClick }) => {
        const statusColor = agent.status === 'online' || agent.status === 'Active'
            ? (isDarkMode ? 'bg-green-400' : 'bg-green-500')
            : (isDarkMode ? 'bg-red-500' : 'bg-red-600');
        return (
            <div
                className="p-3 border-b border-gray-200 dark:border-gray-700/50 w-full flex items-center cursor-pointer hover:bg-gray-50 dark:hover:bg-gray-700/30 transition-colors group"
                onClick={onClick}
            >
                <div className="flex-shrink-0 mr-3 relative">
                    <img src={agent.image} alt={agent.name} className="w-10 h-10 rounded-full object-cover border border-gray-300 dark:border-gray-600" />
                    <div className={`absolute bottom-0 right-0 w-2.5 h-2.5 rounded-full border-2 ${isDarkMode ? 'border-gray-800/50' : 'border-white'} ${statusColor}`}></div>
                </div>
                <div className="flex-grow overflow-hidden">
                    <div className="flex items-center justify-between">
                        <h3 className="font-medium text-gray-900 dark:text-white truncate pr-2 group-hover:text-blue-600 dark:group-hover:text-blue-400 transition-colors" title={agent.name}>{agent.name}</h3>
                    </div>
                    <div className="flex items-center text-gray-500 dark:text-gray-400 text-xs mt-1 gap-3 flex-wrap">
                        <span className="flex items-center gap-1" title={`${agent.userCount} Users`}><FiUser size={12} /> {agent.userCount}</span>
                        <span className="flex items-center gap-1" title={`${agent.messageCount} Messages`}><FiMessageSquare size={12} /> {agent.messageCount}</span>
                        <span className="flex items-center gap-1 text-xs px-1.5 py-0.5 bg-gray-100 dark:bg-gray-700 rounded text-gray-600 dark:text-gray-300" title={`Model: ${agent.modelType}`}><FiCode size={12} /> {agent.modelType}</span>
                    </div>
                </div>
                <div className="ml-2 flex-shrink-0 opacity-0 group-hover:opacity-100 transition-opacity">
                    <FiExternalLink className="text-gray-400 dark:text-gray-500" size={14} />
                </div>
            </div>
        );
    };
    // Calculate rows and columns based on viewport width
    const columnCount = window.innerWidth < 640 ? 1 :
        window.innerWidth < 1024 ? 2 :
            window.innerWidth < 1280 ? 3 : 4;
    const rowCount = Math.ceil(agents.length / columnCount);
    return (
        <div className="mb-8">
            <div className="flex items-center justify-between mb-4">
                <h3 className="text-base sm:text-lg font-semibold text-gray-900 dark:text-white">{title}</h3>
                <span className="text-xs md:text-sm text-gray-500 dark:text-gray-400">{agentCount} agents</span>
            </div>
            {virtualized ? (
                <FixedSizeGrid
                    columnCount={columnCount}
                    columnWidth={300}
                    height={400}
                    rowCount={rowCount}
                    rowHeight={220}
                    width={columnCount * 300}
                    className="mx-auto"
                >
                    {({ columnIndex, rowIndex, style }) => {
                        const index = rowIndex * columnCount + columnIndex;
                        if (index >= agents.length) return null;
                        const agent = agents[index];
                        return (
                            <div style={style}>
                                <AgentCard
                                    key={agent.id || agent.name}
                                    agentId={agent.id}
                                    agentImage={agent.image}
                                    agentName={agent.name}
                                    status={agent.status}
                                    userCount={agent.userCount}
                                    messageCount={agent.messageCount}
                                    modelType={agent.modelType}
                                    hideActionIcons={hideActionIcons}
                                />
                            </div>
                        );
                    }}
                </FixedSizeGrid>
            ) : (
                <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-3 md:gap-4">
                    {agents.map((agent) => (
                        <AgentCard
                            key={agent.id || agent.name}
                            agentId={agent.id}
                            agentImage={agent.image}
                            agentName={agent.name}
                            status={agent.status}
                            userCount={agent.userCount}
                            messageCount={agent.messageCount}
                            modelType={agent.modelType}
                            hideActionIcons={hideActionIcons}
                        />
                    ))}
                </div>
            )}
        </div>
    );
};
export default React.memo(CategorySection);
````

## File: frontend/src/components/Admin/CollectionsPage.jsx
````javascript
import React, { useState, useEffect, useRef, useCallback, useMemo, memo } from 'react';
import axios from 'axios';
import { FiEdit, FiTrash2, FiSearch, FiChevronDown, FiChevronUp, FiPlus, FiInfo, FiFolder, FiFolderPlus } from 'react-icons/fi';
import { SiOpenai, SiGooglegemini } from 'react-icons/si';
import { FaRobot } from 'react-icons/fa6';
import { BiLogoMeta } from 'react-icons/bi';
import { RiOpenaiFill } from 'react-icons/ri';
import { useNavigate } from 'react-router-dom';
import { axiosInstance } from '../../api/axiosInstance';
import { useTheme } from '../../context/ThemeContext';
import { toast } from 'react-toastify';
import MoveToFolderModal from './MoveToFolderModal';
// Model icons mapping
const modelIcons = {
    'gpt-4': <RiOpenaiFill className="text-green-500" size={18} />,
    'gpt-3.5': <SiOpenai className="text-green-400" size={16} />,
    'claude': <FaRobot className="text-purple-400" size={16} />,
    'gemini': <SiGooglegemini className="text-blue-400" size={16} />,
    'llama': <BiLogoMeta className="text-blue-500" size={18} />
};
// Memoized GPT card component
const GptCard = memo(({ gpt, onDelete, onEdit, formatDate, onNavigate, isDarkMode, onMoveToFolder }) => (
    <div
        key={gpt._id}
        className="bg-white dark:bg-gray-800 rounded-lg overflow-hidden border border-gray-200 dark:border-gray-700 hover:border-blue-400/50 dark:hover:border-gray-600 transition-all shadow-md hover:shadow-lg flex flex-col cursor-pointer group"
        onClick={() => onNavigate(`/admin/chat/${gpt._id}`)}
    >
        <div className="h-24 sm:h-32 bg-gradient-to-br from-gray-100 to-gray-300 dark:from-gray-700 dark:to-gray-900 relative flex-shrink-0 overflow-hidden">
            {gpt.imageUrl ? (
                <img
                    src={gpt.imageUrl}
                    alt={gpt.name}
                    className="w-full h-full object-cover opacity-80 dark:opacity-70 group-hover:scale-105 transition-transform duration-300"
                    loading="lazy"
                />
            ) : (
                <div className="w-full h-full flex items-center justify-center bg-gradient-to-br from-blue-50/50 to-purple-100/50 dark:from-blue-900/30 dark:to-purple-900/30">
                    <span className={`text-3xl sm:text-4xl ${isDarkMode ? 'text-white/30' : 'text-gray-500/40'}`}>{gpt.name.charAt(0)}</span>
                </div>
            )}
            <div className="absolute top-2 right-2 flex gap-1.5 opacity-0 group-hover:opacity-100 transition-opacity duration-200">
                <button
                    onClick={(e) => { e.stopPropagation(); onMoveToFolder(gpt); }}
                    className="p-1.5 sm:p-2 bg-white/80 dark:bg-gray-900/70 text-gray-700 dark:text-gray-200 rounded-full hover:bg-green-500 hover:text-white dark:hover:bg-green-700/80 transition-colors shadow"
                    title="Move to Folder"
                >
                    <FiFolderPlus size={14} />
                </button>
                <button
                    onClick={(e) => { e.stopPropagation(); onEdit(gpt._id); }}
                    className="p-1.5 sm:p-2 bg-white/80 dark:bg-gray-900/70 text-gray-700 dark:text-gray-200 rounded-full hover:bg-blue-500 hover:text-white dark:hover:bg-blue-700/80 transition-colors shadow"
                    title="Edit GPT"
                >
                    <FiEdit size={14} />
                </button>
                <button
                    onClick={(e) => { e.stopPropagation(); onDelete(gpt._id); }}
                    className="p-1.5 sm:p-2 bg-white/80 dark:bg-gray-900/70 text-gray-700 dark:text-gray-200 rounded-full hover:bg-red-500 hover:text-white dark:hover:bg-red-700/80 transition-colors shadow"
                    title="Delete GPT"
                >
                    <FiTrash2 size={14} />
                </button>
            </div>
        </div>
        <div className="p-3 sm:p-4 flex flex-col flex-grow">
            <div className="flex items-start justify-between mb-1.5 sm:mb-2">
                <h3 className="font-semibold text-base sm:text-lg line-clamp-1 text-gray-900 dark:text-white">{gpt.name}</h3>
                <div className="flex items-center flex-shrink-0 gap-1 bg-gray-100 dark:bg-gray-700 px-1.5 sm:px-2 py-0.5 rounded text-[10px] sm:text-xs text-gray-600 dark:text-gray-300">
                    {React.cloneElement(modelIcons[gpt.model] || <FaRobot className="text-gray-500" />, { size: 12 })}
                    <span className="hidden sm:inline">{gpt.model}</span>
                </div>
            </div>
            <p className="text-gray-600 dark:text-gray-300 text-xs sm:text-sm h-10 sm:h-12 line-clamp-2 sm:line-clamp-3 mb-3">{gpt.description}</p>
            <div className="mt-auto pt-2 border-t border-gray-100 dark:border-gray-700 text-[10px] sm:text-xs text-gray-500 dark:text-gray-400 flex justify-between items-center">
                <span>Created: {formatDate(gpt.createdAt)}</span>
                {gpt.knowledgeFiles?.length > 0 && (
                    <span className="whitespace-nowrap">{gpt.knowledgeFiles.length} {gpt.knowledgeFiles.length === 1 ? 'file' : 'files'}</span>
                )}
            </div>
            {gpt.folder && (
                <div className="flex items-center gap-1 text-xs text-gray-500 dark:text-gray-400 mb-1.5">
                    <FiFolder size={12} />
                    <span>{gpt.folder}</span>
                </div>
            )}
        </div>
    </div>
));
const CollectionsPage = () => {
    const [customGpts, setCustomGpts] = useState([]);
    const [folders, setFolders] = useState(['All', 'Uncategorized']); // Default folders
    const [selectedFolder, setSelectedFolder] = useState('All');
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);
    const [searchTerm, setSearchTerm] = useState('');
    const [sortOption, setSortOption] = useState('newest');
    const [showSortOptions, setShowSortOptions] = useState(false);
    const sortDropdownRef = useRef(null);
    const { isDarkMode } = useTheme();
    const navigate = useNavigate();
    const [showMoveModal, setShowMoveModal] = useState(false);
    const [gptToMove, setGptToMove] = useState(null);
    const fetchCustomGpts = useCallback(async () => {
        try {
            setLoading(true);
            setError(null);
            const response = await axiosInstance.get(`/api/custom-gpts`, { withCredentials: true });
            if (response.data.success && response.data.customGpts) {
                setCustomGpts(response.data.customGpts);
                // Extract unique folders from GPTs
                const uniqueFolders = [...new Set(response.data.customGpts
                    .filter(gpt => gpt.folder)
                    .map(gpt => gpt.folder))];
                setFolders(prev => [...new Set(['All', 'Uncategorized', ...uniqueFolders])]);
            } else {
                const message = response.data.message || "Failed to fetch custom GPTs";
                setError(message);
                toast.error(message);
            }
        } catch (err) {
            console.error("Error fetching custom GPTs:", err);
            const message = err.response?.data?.message || "Error connecting to server";
            setError(message);
            toast.error(message);
        } finally {
            setLoading(false);
        }
    }, []);
    useEffect(() => {
        fetchCustomGpts();
    }, [fetchCustomGpts]);
    const handleClickOutside = useCallback((event) => {
        if (sortDropdownRef.current && !sortDropdownRef.current.contains(event.target)) {
            setShowSortOptions(false);
        }
    }, []);
    useEffect(() => {
        document.addEventListener("mousedown", handleClickOutside);
        return () => document.removeEventListener("mousedown", handleClickOutside);
    }, [handleClickOutside]);
    const handleDelete = useCallback(async (id) => {
        if (window.confirm("Are you sure you want to delete this GPT?")) {
            setLoading(true);
            try {
                const response = await axiosInstance.delete(`/api/custom-gpts/${id}`, { withCredentials: true });
                if (response.data.success) {
                    toast.success(`GPT deleted successfully.`);
                    fetchCustomGpts();
                } else {
                    toast.error(response.data.message || "Failed to delete GPT");
                }
            } catch (err) {
                console.error("Error deleting custom GPT:", err);
                toast.error(err.response?.data?.message || "Error deleting GPT");
            } finally {
                setLoading(false);
            }
        }
    }, [fetchCustomGpts]);
    const handleEdit = useCallback((id) => {
        navigate(`/admin/edit-gpt/${id}`);
    }, [navigate]);
    const handleCreateNew = useCallback(() => {
        navigate('/admin/create-gpt');
    }, [navigate]);
    const handleNavigate = useCallback((path) => {
        navigate(path);
    }, [navigate]);
    const formatDate = useCallback((dateString) => {
        return new Date(dateString).toLocaleDateString('en-US', {
            year: 'numeric',
            month: 'short',
            day: 'numeric'
        });
    }, []);
    const handleSearchChange = useCallback((e) => {
        setSearchTerm(e.target.value);
    }, []);
    const toggleSortOptions = useCallback(() => {
        setShowSortOptions(prev => !prev);
    }, []);
    const handleSortOptionSelect = useCallback((option) => {
        setSortOption(option);
        setShowSortOptions(false);
    }, []);
    // Function to open the move modal
    const handleMoveToFolder = useCallback((gpt) => {
        setGptToMove(gpt);
        setShowMoveModal(true);
    }, []);
    // Function called when a GPT is successfully moved
    const handleGptMoved = useCallback((movedGpt, newFolderName) => {
        // Update the local state
        setCustomGpts(prevGpts =>
            prevGpts.map(gpt =>
                gpt._id === movedGpt._id ? { ...gpt, folder: newFolderName || null } : gpt
            )
        );
        // Add the new folder to the list if it's not already there
        if (newFolderName && !folders.includes(newFolderName)) {
            setFolders(prevFolders => [...prevFolders, newFolderName]);
        }
        setShowMoveModal(false);
        setGptToMove(null);
        toast.success(`GPT "${movedGpt.name}" moved successfully.`);
    }, [folders]); // Include folders in dependency array
    const filteredGpts = useMemo(() => {
        return customGpts
            .filter(gpt => {
                if (!gpt || !gpt.name || !gpt.description || !gpt.model) return false;
                // Folder filtering
                if (selectedFolder === 'All') return true;
                if (selectedFolder === 'Uncategorized') return !gpt.folder;
                return gpt.folder === selectedFolder;
            })
            .filter(gpt => {
                if (!searchTerm) return true;
                const searchLower = searchTerm.toLowerCase();
                return (
                    gpt.name.toLowerCase().includes(searchLower) ||
                    gpt.description.toLowerCase().includes(searchLower) ||
                    gpt.model.toLowerCase().includes(searchLower)
                );
            })
            .sort((a, b) => {
                const dateA = a.createdAt ? new Date(a.createdAt) : 0;
                const dateB = b.createdAt ? new Date(b.createdAt) : 0;
                const nameA = a.name || '';
                const nameB = b.name || '';
                switch (sortOption) {
                    case 'newest': return dateB - dateA;
                    case 'oldest': return dateA - dateB;
                    case 'alphabetical': return nameA.localeCompare(nameB);
                    default: return dateB - dateA;
                }
            });
    }, [customGpts, searchTerm, sortOption, selectedFolder]);
    if (loading && customGpts.length === 0) {
        return (
            <div className="flex items-center justify-center h-full bg-white dark:bg-black text-gray-600 dark:text-gray-400">
                <div className="animate-spin rounded-full h-10 w-10 border-t-2 border-b-2 border-blue-500"></div>
            </div>
        );
    }
    if (error && customGpts.length === 0) {
        return (
            <div className="flex flex-col items-center justify-center h-full bg-white dark:bg-black text-gray-600 dark:text-gray-400 p-6">
                <FiInfo size={40} className="mb-4 text-red-500" />
                <h2 className="text-xl font-semibold mb-2 text-gray-800 dark:text-gray-200">Loading Failed</h2>
                <p className="text-center mb-4">{error}</p>
                <button
                    onClick={fetchCustomGpts}
                    className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors"
                >
                    Retry
                </button>
            </div>
        );
    }
    return (
        <div className="flex flex-col h-full bg-gray-50 dark:bg-black text-black dark:text-white p-4 sm:p-6 overflow-hidden">
            {/* Header */}
            <div className="mb-4 md:mb-6 flex-shrink-0 text-center sm:text-left ">
                <h1 className="text-xl sm:text-2xl font-bold text-gray-900 dark:text-white">Collections</h1>
                <p className="text-sm text-gray-500 dark:text-gray-400 mt-1">Manage your custom GPTs</p>
            </div>
            {/* Controls: Folder, Search, Sort, Create */}
            <div className="flex flex-col md:flex-row md:items-center justify-between mb-4 md:mb-6 gap-3 md:gap-4 flex-shrink-0">
                <div className="flex flex-col sm:flex-row sm:items-center gap-3 w-full md:w-auto">
                    {/* Folder Dropdown */}
                    <div className="relative">
                        <select
                            value={selectedFolder}
                            onChange={(e) => setSelectedFolder(e.target.value)}
                            className="w-full sm:w-36 px-3 py-2 rounded-lg bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-700 text-gray-700 dark:text-gray-300 text-sm hover:bg-gray-50 dark:hover:bg-gray-700 appearance-none cursor-pointer"
                            aria-label="Select Folder"
                        >
                            {folders.map(folder => (
                                <option key={folder} value={folder}>
                                    {folder}
                                </option>
                            ))}
                        </select>
                        <FiFolder className="absolute right-3 top-1/2 transform -translate-y-1/2 text-gray-400 dark:text-gray-500 pointer-events-none" />
                    </div>
                    {/* Search Input */}
                    <div className="relative flex-grow sm:flex-grow-0">
                        <FiSearch className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400 dark:text-gray-500" />
                        <input
                            type="text"
                            placeholder="Search GPTs..."
                            value={searchTerm}
                            onChange={handleSearchChange}
                            className="w-full sm:w-52 md:w-64 pl-10 pr-4 py-2 rounded-lg bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-700 focus:ring-2 focus:ring-blue-500 focus:border-transparent outline-none transition-all text-sm text-black dark:text-white placeholder-gray-500 dark:placeholder-gray-400"
                            aria-label="Search GPTs"
                        />
                    </div>
                    {/* Sort Dropdown */}
                    <div className="relative" ref={sortDropdownRef}>
                        <button
                            onClick={toggleSortOptions}
                            className="flex items-center justify-between w-full sm:w-36 px-3 py-2 rounded-lg bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-700 text-gray-700 dark:text-gray-300 text-sm hover:bg-gray-50 dark:hover:bg-gray-700"
                            aria-haspopup="true"
                            aria-expanded={showSortOptions}
                        >
                            <span className="truncate">Sort: {sortOption.charAt(0).toUpperCase() + sortOption.slice(1)}</span>
                            {showSortOptions ? <FiChevronUp size={16} /> : <FiChevronDown size={16} />}
                        </button>
                        {showSortOptions && (
                            <div className="absolute left-0 mt-2 w-36 bg-white dark:bg-gray-800 rounded-md shadow-lg ring-1 ring-black ring-opacity-5 dark:ring-gray-700 z-10 overflow-hidden">
                                {['newest', 'oldest', 'alphabetical'].map((option) => (
                                    <button
                                        key={option}
                                        onClick={() => handleSortOptionSelect(option)}
                                        className={`w-full text-left px-4 py-2 text-sm ${sortOption === option ? 'font-semibold text-white dark:text-blue-400 bg-blue-50 dark:bg-blue-900/30' : 'text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700'}`}
                                    >
                                        {option.charAt(0).toUpperCase() + option.slice(1)}
                                    </button>
                                ))}
                            </div>
                        )}
                    </div>
                </div>
                {/* Create Button */}
                <button
                    onClick={handleCreateNew}
                    className="flex items-center gap-2 px-4 py-2 bg-black dark:bg-white hover:bg-gray-100 dark:hover:bg-gray-700 text-black dark:text- rounded-lg font-medium text-sm transition-colors flex-shrink-0 whitespace-nowrap"
                >
                    <FiPlus size={18} /> Create New GPT
                </button>
            </div>
            {/* GPT Grid */}
            <div className="flex-1 overflow-y-auto pb-4 scrollbar-hide">
                {filteredGpts.length > 0 ? (
                    <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-3 xl:grid-cols-4 gap-4">
                        {filteredGpts.map((gpt) => (
                            <GptCard
                                key={gpt._id}
                                gpt={gpt}
                                onDelete={handleDelete}
                                onEdit={handleEdit}
                                formatDate={formatDate}
                                onNavigate={handleNavigate}
                                isDarkMode={isDarkMode}
                                onMoveToFolder={handleMoveToFolder}
                            />
                        ))}
                    </div>
                ) : (
                    <div className="flex flex-col items-center justify-center h-full text-center text-gray-500 dark:text-gray-400 pt-10">
                        <FaRobot size={48} className="mb-4 text-gray-400 dark:text-gray-500" />
                        <h3 className="text-lg font-semibold text-gray-700 dark:text-gray-300">No GPTs Found</h3>
                        <p className="max-w-xs mt-1">
                            {searchTerm
                                ? `No GPTs match your search "${searchTerm}" in ${selectedFolder === 'All' ? 'any folder' : `the '${selectedFolder}' folder`}.`
                                : `No GPTs found in ${selectedFolder === 'All' ? 'your collections' : `the '${selectedFolder}' folder`}.`}
                        </p>
                        {!searchTerm && selectedFolder === 'All' && (
                            <button
                                onClick={handleCreateNew}
                                className="mt-4 flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg font-medium text-sm transition-colors"
                            >
                                <FiPlus size={18} /> Create Your First GPT
                            </button>
                        )}
                    </div>
                )}
            </div>
            {/* Move to Folder Modal */}
            {showMoveModal && gptToMove && (
                <MoveToFolderModal
                    isOpen={showMoveModal}
                    onClose={() => { setShowMoveModal(false); setGptToMove(null); }}
                    gpt={gptToMove}
                    existingFolders={folders.filter(f => f !== 'All' && f !== 'Uncategorized')}
                    onSuccess={handleGptMoved}
                />
            )}
        </div>
    );
};
export default CollectionsPage;
````

## File: frontend/src/components/Admin/CreateCustomGpt.jsx
````javascript
import React, { useState, useEffect } from 'react';
import { IoAddOutline, IoCloseOutline, IoPersonCircleOutline, IoInformationCircleOutline, IoSearchOutline, IoSparklesOutline, IoArrowBackOutline } from 'react-icons/io5';
import { FaBox, FaUpload, FaGlobe, FaChevronDown } from 'react-icons/fa';
import { LuBrain } from 'react-icons/lu';
import { SiOpenai, SiGooglegemini } from 'react-icons/si';
import { BiLogoMeta } from 'react-icons/bi';
import { FaRobot } from 'react-icons/fa6';
import { RiOpenaiFill } from 'react-icons/ri';
import { toast } from 'react-toastify';
import { useNavigate } from 'react-router-dom';
import { axiosInstance } from '../../api/axiosInstance';
import { useTheme } from '../../context/ThemeContext'; // Import useTheme
import axios from 'axios';
// Import Markdown components
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
const PYTHON_URL = import.meta.env.VITE_PYTHON_API_URL;
const CreateCustomGpt = ({ onGoBack, editGptId = null, onGptCreated }) => {
    const navigate = useNavigate();
    const { isDarkMode } = useTheme(); // Get theme state
    // System prompt example with markdown hints
    const defaultInstructions = `You are a helpful, creative, clever, and very friendly AI assistant.
When providing code examples:
- Focus on readability and maintainability
- Include helpful comments
- Consider edge cases
- Explain the reasoning behind your implementation
- Avoid implementing solutions with known security vulnerabilities or performance issues.
**Key guidelines**: 
* Be concise and direct in your responses
* If you don't know something, admit it rather than making up information
* Provide step-by-step explanations when appropriate`;
    // State for GPT Configuration
    const [formData, setFormData] = useState({
        name: 'My Custom GPT',
        description: 'A helpful assistant that can answer questions about various topics.',
        instructions: defaultInstructions,
        conversationStarter: '',
    });
    // Simplified capabilities state
    const [capabilities, setCapabilities] = useState({
        webBrowsing: true,
        hybridSearch: false
    });
    const [imagePreview, setImagePreview] = useState(null);
    const [imageFile, setImageFile] = useState(null); // Store the actual file
    const [promptMode, setPromptMode] = useState('edit'); // 'edit' or 'preview'
    const [selectedModel, setSelectedModel] = useState('gpt-4');
    const [isTemplateDropdownOpen, setIsTemplateDropdownOpen] = useState(false); // State for dropdown
    const [knowledgeFiles, setKnowledgeFiles] = useState([]); // State for knowledge files
    const [isMobileView, setIsMobileView] = useState(false);
    const [isLoading, setIsLoading] = useState(false); // Keep for initial fetch in edit mode
    const [isSaving, setIsSaving] = useState(false); // New state for save button
    const [isEditMode, setIsEditMode] = useState(false);
    // Check if we're in edit mode
    useEffect(() => {
        if (editGptId) {
            setIsEditMode(true);
            setIsLoading(true); // Set loading true only for initial fetch
            fetchGptDetails(editGptId);
        }
    }, [editGptId]);
    // Fetch GPT details if in edit mode
    const fetchGptDetails = async (id) => {
        try {
            const response = await axiosInstance.get(
                `${axiosInstance.defaults.baseURL.endsWith('/api') ? axiosInstance.defaults.baseURL : `${axiosInstance.defaults.baseURL}/api`}/custom-gpts/${id}`,
                { withCredentials: true }
            );
            const gpt = response.data.customGpt;
            // Set form data
            setFormData({
                name: gpt.name,
                description: gpt.description,
                instructions: gpt.instructions,
                conversationStarter: gpt.conversationStarter || '',
            });
            // Set other states
            setSelectedModel(gpt.model);
            setCapabilities({
                ...capabilities, // Keep default values
                ...gpt.capabilities, // Override with existing values
                // Ensure hybridSearch is defined even if not in original data
                hybridSearch: gpt.capabilities?.hybridSearch ?? false
            });
            // Set image preview if exists
            if (gpt.imageUrl) {
                setImagePreview(gpt.imageUrl);
            }
            // Set knowledge files
            if (gpt.knowledgeFiles && gpt.knowledgeFiles.length > 0) {
                setKnowledgeFiles(gpt.knowledgeFiles.map(file => ({
                    name: file.name,
                    url: file.fileUrl,
                    // Mark as already uploaded to distinguish from new files
                    isUploaded: true,
                    index: gpt.knowledgeFiles.indexOf(file) // Maintain original index if needed
                })));
            }
        } catch (error) {
            console.error("Error fetching GPT details:", error);
            toast.error("Failed to load GPT details");
        } finally {
            setIsLoading(false); // Stop loading after fetch completes/fails
        }
    };
    // Check screen size on mount and resize
    useEffect(() => {
        const handleResize = () => {
            setIsMobileView(window.innerWidth < 768);
        };
        window.addEventListener('resize', handleResize);
        handleResize(); // Initial check
        return () => window.removeEventListener('resize', handleResize);
    }, []);
    // Model icons mapping
    const modelIcons = {
        'gpt-4': <RiOpenaiFill className="text-green-500 mr-2" size={18} />,
        'gpt-4o-mini': <SiOpenai className="text-green-400 mr-2" size={16} />,
        'claude': <FaRobot className="text-purple-400 mr-2" size={16} />,
        'gemini': <SiGooglegemini className="text-blue-400 mr-2" size={16} />,
        'llama': <BiLogoMeta className="text-blue-500 mr-2" size={18} />
    };
    const handleInputChange = (e) => {
        const { name, value } = e.target;
        setFormData({
            ...formData,
            [name]: value
        });
    };
    const handleImageUpload = (e) => {
        const file = e.target.files[0];
        if (file) {
            setImageFile(file); // Store the file for later upload
            const reader = new FileReader();
            reader.onloadend = () => {
                setImagePreview(reader.result);
            };
            reader.readAsDataURL(file);
        }
    };
    // Updated handler for simplified capabilities
    const handleCapabilityChange = (capability) => {
        setCapabilities(prevCapabilities => ({
            ...prevCapabilities,
            [capability]: !prevCapabilities[capability]
        }));
    };
    const handleGeneratePrompt = () => {
        setFormData({ ...formData, instructions: 'Generated prompt: Be concise and helpful.' });
        setPromptMode('edit'); // Switch back to edit mode after generating
    };
    const handleSelectTemplate = (templateInstructions) => {
        setFormData({ ...formData, instructions: templateInstructions });
        setIsTemplateDropdownOpen(false);
        setPromptMode('edit');
    };
    // Handler for knowledge file upload
    const handleKnowledgeUpload = (e) => {
        const files = Array.from(e.target.files);
        // Create file objects with preview capabilities
        const newFiles = files.map(file => ({
            file, // Keep the file object for upload
            name: file.name,
            type: file.type,
            size: file.size,
            isUploaded: false // Mark as not yet uploaded to server
        }));
        setKnowledgeFiles([...knowledgeFiles, ...newFiles]);
    };
    // Handler to remove a knowledge file
    const removeKnowledgeFile = async (index) => {
        const fileToRemove = knowledgeFiles[index];
        // If the file is already uploaded to the server and we're in edit mode
        if (fileToRemove.isUploaded && isEditMode && editGptId) {
            try {
                await axiosInstance.delete(
                    `${axiosInstance.defaults.baseURL.endsWith('/api') ? axiosInstance.defaults.baseURL : `${axiosInstance.defaults.baseURL}/api`}/custom-gpts/${editGptId}/knowledge/${fileToRemove.index}`, // Using original index
                    { withCredentials: true }
                );
                toast.success("File deleted successfully");
                setKnowledgeFiles(prevFiles => prevFiles.filter((_, i) => i !== index));
            } catch (error) {
                console.error("Error deleting file:", error);
                toast.error("Failed to delete file");
                return; // Don't remove from UI if server deletion failed
            }
        } else {
            setKnowledgeFiles(prevFiles => prevFiles.filter((_, i) => i !== index));
        }
    };
    // Example prompt templates
    const promptTemplates = {
        "Coding Expert": "You are an expert programmer with deep knowledge of software development best practices. Help users with coding problems, architecture decisions, and debugging issues.\n\nWhen providing code examples:\n- Focus on readability and maintainability\n- Include helpful comments\n- Consider edge cases\n- Explain the reasoning behind your implementation\n- Avoid implementing solutions with known security vulnerabilities or performance issues.",
        "Creative Writer": "You are a creative writing assistant. Help users brainstorm ideas, develop characters, write dialogue, and overcome writer's block. Use vivid language and imaginative suggestions.",
        "Marketing Assistant": "You are a helpful marketing assistant. Generate ad copy, social media posts, email campaigns, and suggest marketing strategies based on user goals and target audience.",
    };
    // System Prompt Section - Updated with Markdown support
    const renderSystemPromptSection = () => (
        <div className="border border-gray-400 dark:border-gray-700 rounded-lg overflow-hidden">
            <div className="p-3 md:p-4 border-b border-gray-400 dark:border-gray-700">
                <div className="flex items-center mb-1 md:mb-2">
                    <LuBrain className="text-purple-500 dark:text-purple-400 mr-2" size={16} />
                    <h3 className="text-sm md:text-base font-medium text-gray-800 dark:text-gray-100">Model Instructions</h3>
                </div>
                <p className="text-xs text-gray-500 dark:text-gray-400">
                    Set instructions for how your GPT should behave and respond.
                    <span className="ml-1 italic">Supports Markdown formatting.</span>
                </p>
            </div>
            <div className="p-3 md:p-4">
                <div className="flex justify-between items-center mb-2 md:mb-3">
                    <label className="text-xs md:text-sm font-medium text-gray-600 dark:text-gray-300">System Prompt</label>
                    <div className="flex space-x-2">
                        <button
                            onClick={handleGeneratePrompt}
                            className="flex items-center text-xs text-white px-2 py-1 rounded-md bg-purple-600 hover:bg-purple-700"
                        >
                            <IoSparklesOutline className="mr-1" size={14} />
                            Generate
                        </button>
                        <button
                            onClick={() => setIsTemplateDropdownOpen(!isTemplateDropdownOpen)}
                            className="flex items-center text-xs text-gray-700 dark:text-gray-300 px-2 py-1 rounded-md bg-gray-200 dark:bg-gray-700 hover:bg-gray-300 dark:hover:bg-gray-600"
                        >
                            <IoSearchOutline className="mr-1" size={14} />
                            Templates
                        </button>
                    </div>
                </div>
                {/* Template Selector Dropdown */}
                {isTemplateDropdownOpen && (
                    <div className="relative mb-2 md:mb-3">
                        <div className="absolute z-10 mt-1 w-full bg-white dark:bg-[#262626] border border-gray-400 dark:border-gray-700 rounded-md shadow-lg max-h-48 overflow-y-auto no-scrollbar">
                            <ul>
                                {Object.entries(promptTemplates).map(([name, instructions]) => (
                                    <li key={name}>
                                        <button
                                            onClick={() => handleSelectTemplate(instructions)}
                                            className="w-full text-left px-3 py-2 text-xs md:text-sm text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700"
                                        >
                                            {name}
                                        </button>
                                    </li>
                                ))}
                            </ul>
                        </div>
                    </div>
                )}
                {/* Edit/Preview Toggle */}
                <div className="flex rounded-t-md overflow-hidden mb-0 bg-gray-300 dark:bg-gray-800">
                    <button
                        onClick={() => setPromptMode('edit')}
                        className={`flex-1 py-1.5 text-xs md:text-sm font-medium ${promptMode === 'edit' ? 'bg-gray-400 dark:bg-gray-600 text-gray-900 dark:text-white' : 'bg-gray-300 dark:bg-gray-800 text-gray-600 dark:text-gray-400'}`}
                    >
                        Edit
                    </button>
                    <button
                        onClick={() => setPromptMode('preview')}
                        className={`flex-1 py-1.5 text-xs md:text-sm font-medium ${promptMode === 'preview' ? 'bg-purple-600 text-white' : 'bg-gray-300 dark:bg-gray-800 text-gray-600 dark:text-gray-400'}`}
                    >
                        Preview
                    </button>
                </div>
                {/* Conditional Rendering: Edit Textarea or Preview with Markdown */}
                {promptMode === 'edit' ? (
                    <div className="relative">
                        <textarea
                            name="instructions"
                            value={formData.instructions}
                            onChange={handleInputChange}
                            className="w-full bg-white dark:bg-[#262626] border border-gray-400 dark:border-gray-700 border-t-0 rounded-b-md px-3 py-2 text-xs md:text-sm text-gray-900 dark:text-white focus:outline-none focus:ring-1 focus:ring-blue-500 min-h-[120px] md:min-h-[200px] no-scrollbar placeholder-gray-500 dark:placeholder-gray-400 font-mono"
                            placeholder="Instructions for how the GPT should behave..."
                            style={{ lineHeight: '1.5' }}
                        />
                        <div className="absolute bottom-2 right-2 text-xs text-gray-500 dark:text-gray-400 italic">
                            Supports Markdown
                        </div>
                    </div>
                ) : (
                    <div className="w-full bg-white dark:bg-[#262626] border border-gray-400 dark:border-gray-700 border-t-0 rounded-b-md px-3 py-2 text-xs md:text-sm text-gray-900 dark:text-white min-h-[120px] md:min-h-[200px] overflow-y-auto no-scrollbar">
                        <ReactMarkdown
                            remarkPlugins={[remarkGfm]}
                            components={{
                                // Apply styling to specific elements
                                p: ({ node, ...props }) => <p className="mb-3 text-gray-900 dark:text-white" {...props} />,
                                h1: ({ node, ...props }) => <h1 className="text-xl font-bold mb-2 mt-3 text-gray-900 dark:text-white" {...props} />,
                                h2: ({ node, ...props }) => <h2 className="text-lg font-semibold mb-2 mt-3 text-gray-900 dark:text-white" {...props} />,
                                h3: ({ node, ...props }) => <h3 className="text-base font-medium mb-2 mt-2 text-gray-900 dark:text-white" {...props} />,
                                ul: ({ node, ...props }) => <ul className="list-disc pl-5 mb-3 text-gray-900 dark:text-white" {...props} />,
                                ol: ({ node, ...props }) => <ol className="list-decimal pl-5 mb-3 text-gray-900 dark:text-white" {...props} />,
                                li: ({ node, ...props }) => <li className="mb-1 text-gray-900 dark:text-white" {...props} />,
                                code: ({ node, inline, ...props }) =>
                                    inline
                                        ? <code className="bg-gray-100 dark:bg-gray-800 px-1 py-0.5 rounded text-gray-900 dark:text-white font-mono text-sm" {...props} />
                                        : <code className="block bg-gray-100 dark:bg-gray-800 p-2 rounded text-gray-900 dark:text-white font-mono text-sm overflow-x-auto" {...props} />,
                                pre: ({ node, ...props }) => <pre className="bg-gray-100 dark:bg-gray-800 p-3 rounded-md mb-3 overflow-x-auto" {...props} />,
                                blockquote: ({ node, ...props }) => <blockquote className="border-l-4 border-gray-300 dark:border-gray-700 pl-3 italic my-2" {...props} />,
                                a: ({ node, ...props }) => <a className="text-blue-600 dark:text-blue-400 hover:underline" {...props} />
                            }}
                        >
                            {formData.instructions}
                        </ReactMarkdown>
                    </div>
                )}
                {/* Markdown helper */}
                {promptMode === 'edit' && (
                    <div className="mt-2 flex flex-wrap gap-1">
                        <button
                            onClick={() => insertMarkdown('**bold**')}
                            className="px-2 py-1 text-xs bg-gray-200 dark:bg-gray-700 text-gray-700 dark:text-gray-300 rounded hover:bg-gray-300 dark:hover:bg-gray-600"
                            title="Bold"
                        >
                            <strong>B</strong>
                        </button>
                        <button
                            onClick={() => insertMarkdown('*italic*')}
                            className="px-2 py-1 text-xs bg-gray-200 dark:bg-gray-700 text-gray-700 dark:text-gray-300 rounded hover:bg-gray-300 dark:hover:bg-gray-600"
                            title="Italic"
                        >
                            <em>I</em>
                        </button>
                        <button
                            onClick={() => insertMarkdown('## Heading')}
                            className="px-2 py-1 text-xs bg-gray-200 dark:bg-gray-700 text-gray-700 dark:text-gray-300 rounded hover:bg-gray-300 dark:hover:bg-gray-600"
                            title="Heading"
                        >
                            H
                        </button>
                        <button
                            onClick={() => insertMarkdown('- List item')}
                            className="px-2 py-1 text-xs bg-gray-200 dark:bg-gray-700 text-gray-700 dark:text-gray-300 rounded hover:bg-gray-300 dark:hover:bg-gray-600"
                            title="List"
                        >
                            • List
                        </button>
                        <button
                            onClick={() => insertMarkdown('```\ncode block\n```')}
                            className="px-2 py-1 text-xs bg-gray-200 dark:bg-gray-700 text-gray-700 dark:text-gray-300 rounded hover:bg-gray-300 dark:hover:bg-gray-600"
                            title="Code Block"
                        >
                            {'</>'}
                        </button>
                    </div>
                )}
            </div>
        </div>
    );
    // Function to insert markdown at cursor position
    const insertMarkdown = (markdown) => {
        const textarea = document.querySelector('textarea[name="instructions"]');
        if (textarea) {
            const start = textarea.selectionStart;
            const end = textarea.selectionEnd;
            const newText = formData.instructions.substring(0, start) + markdown + formData.instructions.substring(end);
            setFormData({
                ...formData,
                instructions: newText
            });
            // Focus back on textarea and set cursor position after the inserted markdown
            setTimeout(() => {
                textarea.focus();
                textarea.setSelectionRange(start + markdown.length, start + markdown.length);
            }, 0);
        }
    };
    // Modify triggerKnowledgeIndexing to include system prompt
    const triggerKnowledgeIndexing = async (gptId, fileUrls, email) => {
        try {
            // Always trigger indexing even if there are no files to save system prompt
            const response = await axios.post(
                `${PYTHON_URL}/index-knowledge`,
                {
                    file_urls: fileUrls,
                    user_email: email || "user@example.com",
                    gpt_name: formData.name,
                    gpt_id: gptId,
                    force_recreate: false,
                    system_prompt: formData.instructions,
                    use_hybrid_search: capabilities.hybridSearch,
                    schema: {
                        model: selectedModel,
                        capabilities: capabilities,
                        name: formData.name,
                        description: formData.description,
                        instructions: formData.instructions,
                        conversationStarter: formData.conversationStarter,
                        use_hybrid_search: capabilities.hybridSearch
                    }
                }
            );
            if (response.data.success) {
                toast.success("Knowledge files indexed successfully");
            } else {
                console.error("KB indexing failed");
                toast.warning("Knowledge file upload succeeded but indexing failed. Search functionality may be limited.");
            }
        } catch (error) {
            console.error("Error triggering KB indexing:", error);
            toast.warning("Knowledge files uploaded but indexing failed. Search functionality may be limited.");
        }
    };
    // Modify handleSaveGpt to call the indexing function
    const handleSaveGpt = async () => {
        setIsSaving(true);
        try {
            // Prepare form data for API
            const apiFormData = new FormData();
            apiFormData.append('name', formData.name);
            apiFormData.append('description', formData.description);
            apiFormData.append('instructions', formData.instructions);
            apiFormData.append('conversationStarter', formData.conversationStarter);
            apiFormData.append('model', selectedModel);
            apiFormData.append('capabilities', JSON.stringify(capabilities));
            // Add image if selected
            if (imageFile) {
                apiFormData.append('image', imageFile);
            }
            const newKnowledgeFiles = knowledgeFiles.filter(file => !file.isUploaded);
            newKnowledgeFiles.forEach(fileObj => {
                apiFormData.append('knowledgeFiles', fileObj.file);
            });
            let response;
            let successMessage = '';
            if (isEditMode) {
                response = await axiosInstance.put(
                    `${axiosInstance.defaults.baseURL.endsWith('/api') ? axiosInstance.defaults.baseURL : `${axiosInstance.defaults.baseURL}/api`}/custom-gpts/${editGptId}`,
                    apiFormData,
                    {
                        withCredentials: true,
                        headers: { 'Content-Type': 'multipart/form-data' }
                    }
                );
                successMessage = "Custom GPT updated successfully!";
            } else {
                response = await axiosInstance.post(
                    `${axiosInstance.defaults.baseURL.endsWith('/api') ? axiosInstance.defaults.baseURL : `${axiosInstance.defaults.baseURL}/api`}/custom-gpts`,
                    apiFormData,
                    {
                        withCredentials: true,
                        headers: { 'Content-Type': 'multipart/form-data' }
                    }
                );
                successMessage = "Custom GPT created successfully!";
            }
            // Get gptId and extract file URLs from response
            const gptId = response.data.customGpt._id;
            const fileUrls = response.data.customGpt.knowledgeFiles.map(file => file.fileUrl);
            const userEmail = response.data.customGpt.createdBy.email || "user@example.com";
            // Always trigger indexing to pass system prompt, even if no files
            triggerKnowledgeIndexing(gptId, fileUrls, userEmail);
            if (response.status === 200 || response.status === 201) {
                toast.success(successMessage);
                // Call the callback to notify parent *before* navigating
                if (onGptCreated) {
                    onGptCreated();
                }
                // Navigate back after success and notification
                if (onGoBack) {
                    onGoBack();
                } else {
                    navigate('/admin'); // Fallback navigation
                }
            } else {
                toast.error(response.data?.message || "Failed to save Custom GPT");
            }
        } catch (error) {
            console.error("Error saving GPT:", error);
            toast.error(error.response?.data?.message || "An error occurred while saving.");
        } finally {
            setIsSaving(false);
        }
    };
    if (isLoading && isEditMode) {
        return (
            <div className="w-full h-full flex items-center justify-center bg-gray-100 dark:bg-[#1A1A1A]">
                <div className="animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-purple-500"></div>
            </div>
        );
    }
    return (
        <div className={`w-full h-full flex flex-col ${isDarkMode ? 'dark' : ''} bg-gray-100 dark:bg-[#1A1A1A] text-gray-900 dark:text-white`}>
            <div className={`flex ${isMobileView ? 'flex-col' : 'flex-row'} flex-1 overflow-hidden`}>
                {/* Right Side - Preview (Now appears first in JSX for flex-col ordering) */}
                <div className={`${isMobileView ? 'w-full h-1/2 border-b border-gray-300 dark:border-gray-800' : 'w-1/2 h-full'} bg-gray-200 dark:bg-[#2A2A2A] flex flex-col`}>
                    <div className="p-4 md:p-6 flex flex-col flex-1">
                        <div className="mb-3 md:mb-4 flex justify-between items-center">
                            <h2 className="text-base md:text-xl font-bold text-gray-900 dark:text-white">Preview</h2>
                            <button className="flex items-center text-xs md:text-sm text-gray-600 dark:text-gray-300 px-2 md:px-3 py-1 rounded-md bg-gray-300 dark:bg-gray-800 hover:bg-gray-400 dark:hover:bg-gray-700">
                                <IoInformationCircleOutline className="mr-1" size={14} />
                                View Details
                            </button>
                        </div>
                        {/* UserDashboard Preview */}
                        <div className="flex-1 flex flex-col bg-white dark:bg-black rounded-lg overflow-hidden relative">
                            {/* Mock Header with Profile Icon */}
                            <div className="absolute top-2 md:top-4 right-2 md:right-4">
                                <div className="w-8 h-8 md:w-10 md:h-10 rounded-full overflow-hidden border-2 border-white/20 dark:border-white/20">
                                    <div className="w-full h-full bg-gray-300 dark:bg-gray-700 flex items-center justify-center">
                                        <IoPersonCircleOutline size={20} className="text-gray-800 dark:text-white" />
                                    </div>
                                </div>
                            </div>
                            {/* Preview Content - Updated to center content */}
                            <div className="flex-1 flex flex-col p-4 md:p-6 items-center justify-center">
                                {/* Header */}
                                <div className="text-center mb-2 md:mb-4">
                                    <div className="flex justify-center mb-2 md:mb-4">
                                        {imagePreview ? (
                                            <div className="w-12 h-12 md:w-16 md:h-16 rounded-full overflow-hidden">
                                                <img src={imagePreview} alt="GPT" className="w-full h-full object-cover" />
                                            </div>
                                        ) : (
                                            <div className="w-12 h-12 md:w-16 md:h-16 rounded-full bg-gray-200 dark:bg-gray-800 flex items-center justify-center">
                                                <FaBox size={20} className="text-gray-500 dark:text-gray-600" />
                                            </div>
                                        )}
                                    </div>
                                    <h1 className="text-lg md:text-2xl font-bold text-gray-900 dark:text-white">
                                        {formData.name || "Welcome to AI Agent"}
                                    </h1>
                                    <span className="text-sm md:text-base font-medium mt-1 md:mt-2 block text-gray-600 dark:text-gray-300">
                                        {formData.description || "How can I assist you today?"}
                                    </span>
                                </div>
                                {/* Conversation Starter as Preset Card (if provided) */}
                                {formData.conversationStarter && (
                                    <div className="w-full max-w-xs md:max-w-md mx-auto mt-2 md:mt-4">
                                        <div className="bg-white/80 dark:bg-white/[0.05] backdrop-blur-xl border border-gray-300 dark:border-white/20 shadow-[0_0_15px_rgba(204,43,94,0.2)] rounded-xl p-2 md:p-3 text-left">
                                            <p className="text-xs md:text-sm text-gray-700 dark:text-gray-300">{formData.conversationStarter}</p>
                                        </div>
                                    </div>
                                )}
                            </div>
                            {/* Chat Input at Bottom */}
                            <div className="p-3 md:p-4 border-t border-gray-300 dark:border-gray-800">
                                <div className="relative">
                                    <input
                                        type="text"
                                        className="w-full bg-gray-100 dark:bg-[#1A1A1A] border border-gray-400 dark:border-gray-700 rounded-lg px-3 md:px-4 py-2 md:py-3 pr-8 md:pr-10 text-gray-900 dark:text-white focus:outline-none text-sm placeholder-gray-500 dark:placeholder-gray-500"
                                        placeholder="Ask anything"
                                        disabled
                                    />
                                    <button className="absolute right-3 top-1/2 transform -translate-y-1/2 text-gray-500 dark:text-gray-500">
                                        <IoAddOutline size={18} />
                                    </button>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                {/* Left Side - Configuration Panel (Now appears second in JSX for flex-col ordering) */}
                <div className={`${isMobileView ? 'w-full h-1/2' : 'w-1/2 h-full border-r border-gray-300 dark:border-gray-800'} overflow-y-auto p-4 md:p-6 no-scrollbar`}>
                    <div className="mb-4 md:mb-6 flex items-center">
                        {/* Back Button */}
                        <button
                            onClick={onGoBack}
                            className="mr-3 md:mr-4 p-1 rounded-full hover:bg-gray-200 dark:hover:bg-gray-700 transition-colors"
                            title="Back to Dashboard"
                        >
                            <IoArrowBackOutline size={20} className="text-gray-700 dark:text-gray-300" />
                        </button>
                        <div>
                            <h1 className="text-lg md:text-2xl font-bold text-gray-900 dark:text-white">Custom GPT Builder</h1>
                            <p className="text-xs md:text-sm text-gray-500 dark:text-gray-400">Configure your GPT on the left, test it on the right</p>
                        </div>
                    </div>
                    {/* Image Upload at top center */}
                    <div className="flex justify-center mb-5 md:mb-8">
                        <div
                            onClick={() => document.getElementById('gptImage').click()}
                            className="w-16 h-16 md:w-24 md:h-24 rounded-full border-2 border-dashed border-gray-400 dark:border-gray-600 flex items-center justify-center cursor-pointer hover:border-blue-500"
                        >
                            {imagePreview ? (
                                <img src={imagePreview} alt="GPT Preview" className="w-full h-full object-cover rounded-full" />
                            ) : (
                                <IoAddOutline size={24} className="text-gray-500 dark:text-gray-500" />
                            )}
                            <input
                                type="file"
                                id="gptImage"
                                className="hidden"
                                accept="image/*"
                                onChange={handleImageUpload}
                            />
                        </div>
                    </div>
                    {/* Basic Configuration Section */}
                    <div className="space-y-4">
                        {/* Name Field */}
                        <div>
                            <label className="block text-xs md:text-sm font-medium text-gray-600 dark:text-gray-300 mb-1">Name</label>
                            <input
                                type="text"
                                name="name"
                                value={formData.name}
                                onChange={handleInputChange}
                                className="w-full bg-white dark:bg-[#262626] border border-gray-400 dark:border-gray-700 rounded-md px-3 py-2 text-sm text-gray-900 dark:text-white focus:outline-none focus:ring-1 focus:ring-blue-500 placeholder-gray-500 dark:placeholder-gray-400"
                                placeholder="My Custom GPT"
                            />
                        </div>
                        {/* Description Field */}
                        <div>
                            <label className="block text-xs md:text-sm font-medium text-gray-600 dark:text-gray-300 mb-1">Description</label>
                            <input
                                type="text"
                                name="description"
                                value={formData.description}
                                onChange={handleInputChange}
                                className="w-full bg-white dark:bg-[#262626] border border-gray-400 dark:border-gray-700 rounded-md px-3 py-2 text-sm text-gray-900 dark:text-white focus:outline-none focus:ring-1 focus:ring-blue-500 placeholder-gray-500 dark:placeholder-gray-400"
                                placeholder="A helpful assistant that can answer questions about various topics."
                            />
                        </div>
                        {/* Model Selection with Icons */}
                        <div>
                            <label className="block text-xs md:text-sm font-medium text-gray-600 dark:text-gray-300 mb-1">Model</label>
                            <div className="relative">
                                <select
                                    value={selectedModel}
                                    onChange={(e) => setSelectedModel(e.target.value)}
                                    className="w-full bg-white dark:bg-[#262626] border border-gray-400 dark:border-gray-700 rounded-md pl-10 pr-4 py-2 text-sm text-gray-900 dark:text-white focus:outline-none focus:ring-1 focus:ring-blue-500 appearance-none"
                                >
                                    <option value="gpt-4">GPT-4</option>
                                    <option value="gpt-4o-mini">GPT-4o Mini</option>
                                    <option value="claude">Claude</option>
                                    <option value="gemini">Gemini</option>
                                    <option value="llama">Llama</option>
                                </select>
                                <div className="absolute inset-y-0 left-0 flex items-center pl-3 pointer-events-none">
                                    {modelIcons[selectedModel]}
                                </div>
                                <div className="absolute inset-y-0 right-0 flex items-center pr-3 pointer-events-none">
                                    <FaChevronDown className="text-gray-400 dark:text-gray-400" size={12} />
                                </div>
                            </div>
                        </div>
                        {/* System Prompt Section */}
                        {renderSystemPromptSection()}
                        {/* Web Browsing Capability */}
                        <div className="flex items-center justify-between pt-2">
                            <div>
                                <div className="flex items-center">
                                    <FaGlobe className="text-gray-500 dark:text-gray-400 mr-2" size={14} />
                                    <label htmlFor="webBrowsingToggle" className="text-xs md:text-sm font-medium text-gray-600 dark:text-gray-300 cursor-pointer">Web Browsing</label>
                                </div>
                                <p className="text-xs text-gray-500 dark:text-gray-500 mt-1">Allow your GPT to search and browse the web</p>
                            </div>
                            <label htmlFor="webBrowsingToggle" className="relative inline-flex items-center cursor-pointer">
                                <input
                                    id="webBrowsingToggle"
                                    type="checkbox"
                                    className="sr-only peer"
                                    checked={capabilities.webBrowsing}
                                    onChange={() => handleCapabilityChange('webBrowsing')}
                                />
                                <div className="w-9 h-5 md:w-11 md:h-6 bg-gray-300 dark:bg-gray-700 rounded-full peer peer-checked:after:translate-x-full peer-checked:bg-purple-600 after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white dark:after:bg-white after:border-gray-300 dark:after:border-gray-600 after:border after:rounded-full after:h-4 after:w-4 md:after:h-5 md:after:w-5 after:transition-all"></div>
                            </label>
                        </div>
                        {/* Hybrid Search Capability */}
                        <div className="flex items-center justify-between pt-2">
                            <div>
                                <div className="flex items-center">
                                    <LuBrain className="text-gray-500 dark:text-gray-400 mr-2" size={14} />
                                    <label htmlFor="hybridSearchToggle" className="text-xs md:text-sm font-medium text-gray-600 dark:text-gray-300 cursor-pointer">Hybrid Search</label>
                                </div>
                                <p className="text-xs text-gray-500 dark:text-gray-500 mt-1">Enable more accurate knowledge retrieval with hybrid search</p>
                            </div>
                            <label htmlFor="hybridSearchToggle" className="relative inline-flex items-center cursor-pointer">
                                <input
                                    id="hybridSearchToggle"
                                    type="checkbox"
                                    className="sr-only peer"
                                    checked={capabilities.hybridSearch}
                                    onChange={() => handleCapabilityChange('hybridSearch')}
                                />
                                <div className="w-9 h-5 md:w-11 md:h-6 bg-gray-300 dark:bg-gray-700 rounded-full peer peer-checked:after:translate-x-full peer-checked:bg-purple-600 after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white dark:after:bg-white after:border-gray-300 dark:after:border-gray-600 after:border after:rounded-full after:h-4 after:w-4 md:after:h-5 md:after:w-5 after:transition-all"></div>
                            </label>
                        </div>
                        {/* Conversation Starter */}
                        <div>
                            <label className="block text-xs md:text-sm font-medium text-gray-600 dark:text-gray-300 mb-1">Conversation Starter</label>
                            <input
                                type="text"
                                name="conversationStarter"
                                value={formData.conversationStarter}
                                onChange={handleInputChange}
                                className="w-full bg-white dark:bg-[#262626] border border-gray-400 dark:border-gray-700 rounded-md px-3 py-2 text-xs md:text-sm text-gray-900 dark:text-white focus:outline-none focus:ring-1 focus:ring-blue-500 placeholder-gray-500 dark:placeholder-gray-400"
                                placeholder="Add a conversation starter..."
                            />
                        </div>
                        {/* Knowledge Section */}
                        <div className="space-y-2 md:space-y-3">
                            <label className="block text-xs md:text-sm font-medium text-gray-600 dark:text-gray-300">Knowledge</label>
                            <div className="border-2 border-dashed border-gray-400 dark:border-gray-700 rounded-lg p-3 md:p-4 text-center">
                                <FaUpload className="h-4 w-4 md:h-6 md:w-6 mx-auto mb-1 md:mb-2 text-gray-500 dark:text-gray-500" />
                                <h3 className="font-medium text-xs md:text-sm text-gray-800 dark:text-white mb-1">Upload Files</h3>
                                <p className="text-xs text-gray-500 dark:text-gray-400 mb-2 md:mb-3">Upload PDFs, docs, or text files to give your GPT specific knowledge</p>
                                <button
                                    type="button"
                                    onClick={() => document.getElementById('knowledgeFiles').click()}
                                    className="px-3 md:px-4 py-1 md:py-1.5 text-xs md:text-sm bg-gray-200 dark:bg-[#262626] text-gray-700 dark:text-gray-300 rounded-md hover:bg-gray-300 dark:hover:bg-gray-700 transition-colors"
                                >
                                    Select Files
                                </button>
                                <input
                                    type="file"
                                    id="knowledgeFiles"
                                    className="hidden"
                                    multiple
                                    onChange={handleKnowledgeUpload}
                                />
                            </div>
                            {/* Display uploaded files */}
                            {knowledgeFiles.length > 0 && (
                                <div className="mt-2">
                                    <ul className="space-y-1">
                                        {knowledgeFiles.map((file, index) => (
                                            <li key={index} className="flex justify-between items-center bg-white dark:bg-[#262626] px-3 py-1.5 rounded text-xs md:text-sm border border-gray-400 dark:border-gray-700">
                                                <span className="text-gray-700 dark:text-gray-300 truncate mr-2">{file.name}</span>
                                                <button
                                                    type="button"
                                                    onClick={() => removeKnowledgeFile(index)}
                                                    className="text-gray-500 dark:text-gray-500 hover:text-red-500 dark:hover:text-red-400"
                                                >
                                                    <IoCloseOutline size={16} />
                                                </button>
                                            </li>
                                        ))}
                                    </ul>
                                </div>
                            )}
                            {knowledgeFiles.length === 0 && (
                                <div className="text-xs md:text-sm text-gray-500 dark:text-gray-500 mt-2">No files uploaded yet</div>
                            )}
                        </div>
                    </div>
                    {/* Save Button - Updated */}
                    <div className="mt-4 md:mt-6 pt-3 md:pt-4 border-t border-gray-400 dark:border-gray-700">
                        <button
                            onClick={handleSaveGpt}
                            disabled={isSaving} // Disable button when saving
                            className={`w-full px-4 py-2 md:py-3 rounded-md text-white text-sm md:text-base font-medium transition-colors shadow-lg ${isSaving
                                    ? 'bg-gray-400 dark:bg-gray-500 cursor-not-allowed'
                                    : 'bg-gradient-to-r from-purple-600 to-blue-600 hover:from-purple-700 hover:to-blue-700'
                                }`}
                        >
                            {isSaving
                                ? 'Saving...'
                                : isEditMode
                                    ? "Update Configuration"
                                    : "Save Configuration"}
                        </button>
                    </div>
                </div>
            </div>
        </div>
    );
};
export default CreateCustomGpt;
````

## File: frontend/src/components/Admin/EditPermissionsModal.jsx
````javascript
import React, { useState, useEffect } from 'react';
import { IoClose, IoBriefcaseOutline, IoRibbonOutline, IoPersonOutline } from 'react-icons/io5';
import { axiosInstance } from '../../api/axiosInstance';
import { toast } from 'react-toastify';
import { useTheme } from '../../context/ThemeContext';
const EditPermissionsModal = ({ isOpen, onClose, member, onPermissionsUpdated }) => {
  const [role, setRole] = useState('Employee');
  const [department, setDepartment] = useState('Not Assigned');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const { isDarkMode } = useTheme();
  useEffect(() => {
    if (member) {
      setRole(member.role || 'Employee');
      setDepartment(member.department || 'Not Assigned');
    }
  }, [member]);
  if (!isOpen || !member) return null;
  const handleSubmit = async (e) => {
    e.preventDefault();
    setIsSubmitting(true);
    try {
      const response = await axiosInstance.put(`/api/auth/users/${member.id}/permissions`, {
        role,
        department,
      }, { withCredentials: true });
      if (response.data.success) {
        toast.success('Permissions updated successfully');
        const updatedRole = response.data.user.role.charAt(0).toUpperCase() + response.data.user.role.slice(1);
        onPermissionsUpdated({
          ...member,
          role: updatedRole,
          department: response.data.user.department,
        });
        onClose();
      } else {
        const errorMessage = response.data.message || 'Failed to update permissions';
        toast.error(errorMessage);
      }
    } catch (error) {
      const errorMessage = error.response?.data?.message || 'Failed to update permissions';
      toast.error(errorMessage);
      console.error("Permission update error:", error);
    } finally {
      setIsSubmitting(false);
    }
  };
  const SelectInput = ({ id, label, value, onChange, children, icon: Icon }) => (
    <div>
      <label htmlFor={id} className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
        {label}
      </label>
      <div className="relative">
        {Icon && <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
          <Icon className="text-gray-400 dark:text-gray-500" size={16} />
        </div>}
        <select
          id={id}
          value={value}
          onChange={onChange}
          className={`appearance-none w-full ${Icon ? 'pl-10' : 'pl-3'} pr-8 py-2 rounded-lg bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-600 focus:ring-2 focus:ring-blue-500 focus:border-transparent outline-none text-sm text-black dark:text-white`}
        >
          {children}
        </select>
        <div className="absolute inset-y-0 right-0 pr-3 flex items-center pointer-events-none">
          <svg className="h-5 w-5 text-gray-400" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
            <path fillRule="evenodd" d="M5.293 7.293a1 1 0 011.414 0L10 10.586l3.293-3.293a1 1 0 111.414 1.414l-4 4a1 1 0 01-1.414 0l-4-4a1 1 0 010-1.414z" clipRule="evenodd" />
          </svg>
        </div>
      </div>
    </div>
  );
  const TextInput = ({ id, label, value, onChange, placeholder, icon: Icon }) => (
    <div>
      <label htmlFor={id} className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
        {label}
      </label>
      <div className="relative">
        {Icon && <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
          <Icon className="text-gray-400 dark:text-gray-500" size={16} />
        </div>}
        <input
          id={id}
          type="text"
          value={value}
          onChange={onChange}
          placeholder={placeholder}
          className={`w-full ${Icon ? 'pl-10' : 'pl-3'} pr-3 py-2 rounded-lg bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-600 focus:ring-2 focus:ring-blue-500 focus:border-transparent outline-none text-sm text-black dark:text-white placeholder-gray-500 dark:placeholder-gray-400`}
        />
      </div>
    </div>
  );
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 dark:bg-black/80 transition-opacity duration-300">
      <div className="relative bg-white dark:bg-gray-800 w-full max-w-md rounded-xl shadow-xl border border-gray-200 dark:border-gray-700 overflow-hidden transform transition-transform duration-300 scale-100">
        <div className="px-6 py-4 border-b border-gray-200 dark:border-gray-700 flex justify-between items-center bg-gray-50 dark:bg-gray-900">
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white">Edit Member Permissions</h3>
          <button
            onClick={onClose}
            className="text-gray-400 hover:text-gray-600 dark:text-gray-500 dark:hover:text-white transition-colors rounded-full p-1 hover:bg-gray-200 dark:hover:bg-gray-700"
          >
            <IoClose size={22} />
          </button>
        </div>
        <form onSubmit={handleSubmit} className="px-6 py-6 space-y-5">
          <div className="mb-2">
            <label className="block text-xs font-medium text-gray-500 dark:text-gray-400 mb-1">
              Member
            </label>
            <div className="flex items-center p-3 bg-gray-100 dark:bg-gray-700/60 rounded-lg border border-gray-200 dark:border-gray-600/50">
              <div className="h-10 w-10 rounded-full bg-gradient-to-br from-blue-500 to-purple-600 flex items-center justify-center text-white text-lg font-medium mr-3 flex-shrink-0">
                {member.name.charAt(0)}
              </div>
              <div>
                <div className="text-gray-900 dark:text-white font-medium">{member.name}</div>
                <div className="text-gray-500 dark:text-gray-400 text-sm">{member.email}</div>
              </div>
            </div>
          </div>
          <SelectInput
            id="edit-role"
            label="Role"
            value={role}
            onChange={(e) => setRole(e.target.value)}
            icon={IoRibbonOutline}
          >
            <option value="Admin">Admin</option>
            <option value="Employee">Employee</option>
          </SelectInput>
          <SelectInput
            id="edit-department"
            label="Department"
            value={department}
            onChange={(e) => setDepartment(e.target.value)}
            icon={IoBriefcaseOutline}
          >
            <option value="Not Assigned">Not Assigned</option>
            <option value="Product">Product</option>
            <option value="Engineering">Engineering</option>
            <option value="Design">Design</option>
            <option value="Marketing">Marketing</option>
            <option value="Sales">Sales</option>
            <option value="Customer Support">Customer Support</option>
          </SelectInput>
          <div className="pt-5 border-t border-gray-200 dark:border-gray-700 flex justify-end gap-3">
            <button
              type="button"
              onClick={onClose}
              className="px-4 py-2 bg-white dark:bg-gray-700 border border-gray-300 dark:border-gray-600 text-gray-800 dark:text-white rounded-lg font-medium hover:bg-gray-50 dark:hover:bg-gray-600 transition-colors text-sm"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={isSubmitting}
              className="px-4 py-2 bg-black dark:bg-white text-white dark:text-black rounded-lg font-medium hover:bg-blue-700 transition-colors disabled:opacity-60 disabled:cursor-not-allowed text-sm min-w-[150px] flex justify-center items-center"
            >
              {isSubmitting ? (
                <>
                  <svg className="animate-spin -ml-1 mr-2 h-4 w-4 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                  </svg>
                  Updating...
                </>
              ) : 'Update Permissions'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};
export default EditPermissionsModal;
````

## File: frontend/src/components/Admin/HistoryPage.jsx
````javascript
import React, { useState, useEffect, useRef } from 'react';
import {
  IoPersonOutline,
  IoPeopleOutline,
  IoTimeOutline,
  IoSearchOutline,
  IoFilterOutline,
  IoChevronDown,
  IoEllipse,
  IoArrowBack,
  IoChatbubblesOutline
} from 'react-icons/io5';
import { useNavigate, useLocation } from 'react-router-dom';
import { useTheme } from '../../context/ThemeContext'; // Import useTheme
import { useAuth } from '../../context/AuthContext';
import { axiosInstance } from '../../api/axiosInstance';
// Import team member data
import { teamMembers } from './teamData';
const HistoryPage = () => {
  const navigate = useNavigate();
  const location = useLocation();
  const { isDarkMode } = useTheme(); // Get theme state
  const { user } = useAuth();
  // Initialize view type from URL parameter or default to 'personal'
  const queryParams = new URLSearchParams(location.search);
  const initialView = queryParams.get('view') || 'personal';
  const [viewType, setViewType] = useState(initialView);
  const [isLoading, setIsLoading] = useState(false);
  const [activities, setActivities] = useState([]);
  const [filteredActivities, setFilteredActivities] = useState([]);
  const [searchQuery, setSearchQuery] = useState('');
  const [filterOpen, setFilterOpen] = useState(false);
  const [filterOptions, setFilterOptions] = useState({
    actionTypes: {
      create: true,
      edit: true,
      delete: true,
      settings: true,
      chat: true,
    },
    dateRange: 'all',
  });
  const filterDropdownRef = useRef(null);
  // Fetch real chat history data
  useEffect(() => {
    const fetchActivityData = async () => {
      if (!user?._id) return;
      setIsLoading(true);
      try {
        // For personal view - fetch user's own chat history
        if (viewType === 'personal') {
          const response = await axiosInstance.get(
            `/api/chat-history/user/${user._id}`,
            { withCredentials: true }
          );
          if (response.data.success && response.data.conversations) {
            const conversations = response.data.conversations;
            // Format conversations for display
            const formattedHistory = conversations.map(convo => ({
              id: convo._id,
              user: { id: user._id, name: user.name || 'You', email: user.email || '' },
              action: 'Chat conversation',
              details: `with ${convo.gptName || 'AI Assistant'}`,
              timestamp: convo.updatedAt || convo.createdAt,
              conversation: convo,
              type: 'chat'
            }));
            setActivities(formattedHistory);
            setFilteredActivities(formattedHistory);
          } else {
            setActivities([]);
            setFilteredActivities([]);
          }
        }
        // For team view - fetch all team chat history except current user's
        else if (viewType === 'team') {
          try {
            // Check if user is an admin
            if (user.role !== 'admin') {
              setViewType('personal');
              return;
            }
            const response = await axiosInstance.get(
              `/api/chat-history/team`,
              { withCredentials: true }
            );
            if (response.data.success && response.data.conversations) {
              const conversations = response.data.conversations;
              // Filter out the current admin's own conversations if desired
              const teamConversations = conversations.filter(
                convo => convo.userId !== user._id
              );
              // Group conversations by user ID
              const userActivityMap = new Map();
              teamConversations.forEach(convo => {
                const userId = convo.userId;
                if (!userId) return; // Skip conversations without a user ID
                if (!userActivityMap.has(userId)) {
                  userActivityMap.set(userId, {
                    userId: userId,
                    userName: convo.userName || 'Team Member',
                    userEmail: convo.userEmail || '',
                    conversationCount: 0,
                    lastActivityTimestamp: new Date(0), // Initialize for comparison
                    lastGptName: '',
                  });
                }
                const userData = userActivityMap.get(userId);
                userData.conversationCount += 1;
                const currentTimestamp = new Date(convo.updatedAt || convo.createdAt);
                if (currentTimestamp > userData.lastActivityTimestamp) {
                  userData.lastActivityTimestamp = currentTimestamp;
                  userData.lastGptName = convo.gptName || 'AI Assistant';
                }
              });
              // Convert map to an array of user summaries
              const userSummaries = Array.from(userActivityMap.values());
              // Sort users by last activity (most recent first)
              userSummaries.sort((a, b) =>
                b.lastActivityTimestamp - a.lastActivityTimestamp
              );
              // Format for display
              const formattedHistory = userSummaries.map(summary => ({
                id: summary.userId, // Use userId as the key/id for the summary item
                user: {
                  id: summary.userId,
                  name: summary.userName,
                  email: summary.userEmail
                },
                action: `Had ${summary.conversationCount} conversation(s)`,
                details: `Last interaction with ${summary.lastGptName}`,
                timestamp: summary.lastActivityTimestamp,
                type: 'user_summary' // New type to differentiate rendering
              }));
              setActivities(formattedHistory);
              setFilteredActivities(formattedHistory);
            } else {
              setActivities([]);
              setFilteredActivities([]);
            }
          } catch (error) {
            console.warn("Team history view error:", error);
            // Handle errors appropriately
            if (error.response?.status === 403) {
              setViewType('personal');
            } else {
              setViewType('personal');
            }
          }
        }
      } catch (error) {
        console.error("Error fetching activity data:", error);
        setActivities([]);
        setFilteredActivities([]);
      } finally {
        setIsLoading(false);
      }
    };
    fetchActivityData();
  }, [user, viewType]);
  // Filter activities based on search query and filter options
  useEffect(() => {
    let filtered = [...activities];
    // Apply search filter
    if (searchQuery) {
      filtered = filtered.filter(activity =>
        activity.action.toLowerCase().includes(searchQuery.toLowerCase()) ||
        activity.details.toLowerCase().includes(searchQuery.toLowerCase()) ||
        (activity.user && activity.user.name.toLowerCase().includes(searchQuery.toLowerCase()))
      );
    }
    // Apply action type filters
    filtered = filtered.filter(activity => {
      const actionType = getActionType(activity.action);
      return filterOptions.actionTypes[actionType];
    });
    // Apply date range filter
    if (filterOptions.dateRange !== 'all') {
      const now = new Date();
      let cutoffDate;
      if (filterOptions.dateRange === 'today') {
        cutoffDate = new Date(now.setHours(0, 0, 0, 0));
      } else if (filterOptions.dateRange === 'week') {
        cutoffDate = new Date(now.setDate(now.getDate() - 7));
      } else if (filterOptions.dateRange === 'month') {
        cutoffDate = new Date(now.setMonth(now.getMonth() - 1));
      }
      filtered = filtered.filter(activity => new Date(activity.timestamp) >= cutoffDate);
    }
    setFilteredActivities(filtered);
  }, [searchQuery, filterOptions, activities]);
  // Helper function to determine action type
  const getActionType = (action) => {
    if (action.includes('Chat conversation')) return 'chat';
    if (action.includes('Created') || action.includes('Added')) return 'create';
    if (action.includes('Edited') || action.includes('Updated') || action.includes('Modified')) return 'edit';
    if (action.includes('Deleted') || action.includes('Removed')) return 'delete';
    if (action.includes('Changed settings') || action.includes('Updated settings')) return 'settings';
    return 'chat'; // Default to chat as most activities will be chats now
  };
  // Handle chat history item click
  const handleChatHistoryClick = (conversation) => {
    if (conversation && conversation.gptId) {
      navigate(`/admin/chat/${conversation.gptId}?loadHistory=true&conversationId=${conversation._id}`);
    }
  };
  // Format the timestamp
  const formatTimestamp = (timestamp) => {
    const date = new Date(timestamp);
    const now = new Date();
    const diffTime = Math.abs(now - date);
    const diffDays = Math.floor(diffTime / (1000 * 60 * 60 * 24));
    const diffHours = Math.floor(diffTime / (1000 * 60 * 60));
    // Simplified timestamp format
    if (diffDays === 0) {
      if (diffHours < 1) {
        return 'Just now';
      } else if (diffHours < 2) {
        return '1 hour ago';
      } else if (diffHours < 24) {
        return `${diffHours} hours ago`;
      }
      return 'Today';
    } else if (diffDays === 1) {
      return 'Yesterday';
    } else if (diffDays < 7) {
      return `${diffDays} days ago`;
    } else {
      return date.toLocaleDateString(undefined, {
        month: 'short',
        day: 'numeric',
        year: 'numeric'
      });
    }
  };
  // Toggle filter options
  const toggleFilterOption = (type, value) => {
    setFilterOptions(prev => ({
      ...prev,
      actionTypes: {
        ...prev.actionTypes,
        [type]: value
      }
    }));
  };
  // Set date range filter
  const setDateRangeFilter = (range) => {
    setFilterOptions(prev => ({
      ...prev,
      dateRange: range
    }));
    setFilterOpen(false); // Close on selection
  };
  // Click outside hook for filter dropdown
  useEffect(() => {
    function handleClickOutside(event) {
      if (filterDropdownRef.current && !filterDropdownRef.current.contains(event.target)) {
        setFilterOpen(false);
      }
    }
    document.addEventListener("mousedown", handleClickOutside);
    return () => document.removeEventListener("mousedown", handleClickOutside);
  }, [filterDropdownRef]);
  // When view type changes, update URL
  useEffect(() => {
    // Update URL when view type changes without navigating
    const newUrl = `/admin/history?view=${viewType}`;
    window.history.replaceState(null, '', newUrl);
  }, [viewType]);
  // Determine if team view is available
  const isTeamViewAvailable = user?.role === 'admin';
  // CSS for hiding scrollbars
  const scrollbarHideStyles = `
    .hide-scrollbar::-webkit-scrollbar {
      display: none;
    }
    .hide-scrollbar {
      -ms-overflow-style: none;  /* IE and Edge */
      scrollbar-width: none;  /* Firefox */
    }
  `;
  return (
    <div className={`flex flex-col h-full ${isDarkMode ? 'dark' : ''} bg-white dark:bg-black text-gray-900 dark:text-gray-100 overflow-hidden`}>
      {/* Add hidden scrollbar styles */}
      <style>{scrollbarHideStyles}</style>
      {/* Header section */}
      <div className="px-6 pt-6 pb-5 flex-shrink-0 border-b border-gray-300 dark:border-gray-800">
        <h1 className="text-2xl font-semibold text-gray-900 dark:text-white">Activity History</h1>
        <p className="text-sm text-gray-500 dark:text-gray-400 mt-1">Track actions and changes across your workspace</p>
      </div>
      {/* Controls section */}
      <div className="px-6 py-4 flex-shrink-0 border-b border-gray-300 dark:border-gray-800">
        <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-4">
          {/* View switcher */}
          <div className="inline-flex items-center p-1 rounded-lg bg-gray-100 dark:bg-gray-900 border border-gray-300 dark:border-gray-700 self-center sm:self-start">
            <button
              onClick={() => setViewType('personal')}
              className={`flex items-center px-3 py-1.5 rounded text-sm transition-all ${viewType === 'personal'
                  ? 'bg-gray-300 dark:bg-gray-700 text-gray-900 dark:text-white font-medium'
                  : 'text-gray-500 dark:text-gray-400 hover:text-gray-800 dark:hover:text-white hover:bg-gray-200 dark:hover:bg-gray-800'
                }`}
            >
              <IoPersonOutline size={16} className="mr-1.5" />
              <span>Personal</span>
            </button>
            <button
              onClick={() => isTeamViewAvailable ? setViewType('team') : null}
              className={`flex items-center px-3 py-1.5 rounded text-sm transition-all ${viewType === 'team'
                  ? 'bg-gray-300 dark:bg-gray-700 text-gray-900 dark:text-white font-medium'
                  : isTeamViewAvailable
                    ? 'text-gray-500 dark:text-gray-400 hover:text-gray-800 dark:hover:text-white hover:bg-gray-200 dark:hover:bg-gray-800'
                    : 'text-gray-400 dark:text-gray-600 cursor-not-allowed'
                }`}
              title={isTeamViewAvailable ? 'View team history' : 'Requires admin privileges'}
            >
              <IoPeopleOutline size={16} className="mr-1.5" />
              <span>Team</span>
            </button>
          </div>
          {/* Search and filter */}
          <div className="flex flex-1 sm:justify-end max-w-lg gap-2 self-center w-full sm:w-auto">
            <div className="relative flex-1 sm:max-w-xs">
              <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                <IoSearchOutline className="text-gray-400 dark:text-gray-500" size={18} />
              </div>
              <input
                type="text"
                className="w-full pl-10 pr-3 py-2 bg-gray-100 dark:bg-gray-900 border border-gray-300 dark:border-gray-700 rounded-lg text-gray-900 dark:text-gray-100 text-sm placeholder-gray-500 dark:placeholder-gray-500 focus:outline-none focus:ring-1 focus:ring-gray-500 focus:border-gray-500"
                placeholder="Search activities..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
              />
            </div>
            <div className="relative" ref={filterDropdownRef}>
              <button
                onClick={() => setFilterOpen(!filterOpen)}
                className="flex items-center px-3 py-2 bg-gray-100 dark:bg-gray-900 border border-gray-300 dark:border-gray-700 rounded-lg text-sm text-gray-600 dark:text-gray-300 hover:bg-gray-200 dark:hover:bg-gray-800 hover:border-gray-400 dark:hover:border-gray-600 transition-colors"
              >
                <IoFilterOutline size={16} className="mr-1.5" />
                <span>Filter</span>
                <IoChevronDown size={14} className={`ml-1 transition-transform ${filterOpen ? 'rotate-180' : ''}`} />
              </button>
              {/* Filter Dropdown */}
              {filterOpen && (
                <div className="absolute right-0 mt-2 w-60 rounded-lg bg-gray-100 dark:bg-gray-900 border border-gray-300 dark:border-gray-700 shadow-2xl z-20 p-4">
                  <div className="mb-4">
                    <h3 className="text-gray-700 dark:text-gray-300 font-medium text-sm mb-2">Action Types</h3>
                    <div className="space-y-1.5">
                      {Object.keys(filterOptions.actionTypes).map((type) => (
                        <label key={type} className="flex items-center text-sm">
                          <input
                            type="checkbox"
                            className="form-checkbox h-4 w-4 rounded bg-gray-200 dark:bg-gray-700 border-gray-400 dark:border-gray-600 text-blue-500 focus:ring-blue-500 focus:ring-offset-gray-100 dark:focus:ring-offset-gray-900"
                            checked={filterOptions.actionTypes[type]}
                            onChange={(e) => toggleFilterOption(type, e.target.checked)}
                          />
                          <span className="ml-2 text-gray-700 dark:text-gray-300 capitalize">{type}</span>
                        </label>
                      ))}
                    </div>
                  </div>
                  <div>
                    <h3 className="text-gray-700 dark:text-gray-300 font-medium text-sm mb-2">Time Period</h3>
                    <div className="grid grid-cols-2 gap-2">
                      {['today', 'week', 'month', 'all'].map((range) => (
                        <button
                          key={range}
                          className={`px-2 py-1 rounded text-xs font-medium transition-colors ${filterOptions.dateRange === range
                              ? 'bg-blue-600 text-white'
                              : 'bg-gray-200 dark:bg-gray-800 text-gray-600 dark:text-gray-400 hover:bg-gray-300 dark:hover:bg-gray-700 hover:text-gray-800 dark:hover:text-gray-200'
                            }`}
                          onClick={() => setDateRangeFilter(range)}
                        >
                          {range === 'all' ? 'All Time' : `Last ${range}`}
                        </button>
                      ))}
                    </div>
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
      {/* Timeline content - add hide-scrollbar class */}
      <div className="flex-1 overflow-y-auto py-6 px-4 flex justify-center hide-scrollbar">
        {isLoading ? (
          <div className="flex items-center justify-center h-full">
            <div className="rounded-full h-10 w-10 border-t-2 border-b-2 border-blue-500 animate-spin"></div>
          </div>
        ) : filteredActivities.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-full text-center text-gray-500 dark:text-gray-500 px-4">
            <div className="border-2 border-gray-300 dark:border-gray-800 rounded-full p-4 mb-4">
              <IoTimeOutline size={32} className="text-gray-400 dark:text-gray-600" />
            </div>
            <h3 className="text-lg font-medium text-gray-700 dark:text-gray-300 mb-1">No Activities Found</h3>
            <p className="text-sm max-w-sm">
              {searchQuery || filterOptions.dateRange !== 'all' || !Object.values(filterOptions.actionTypes).every(v => v)
                ? "No activities match your current filters. Try adjusting your search or filter criteria."
                : viewType === 'team'
                  ? "No team activities found. Team member activity will appear here."
                  : "No personal activities recorded yet. Your chat history will appear here."
              }
            </p>
          </div>
        ) : (
          <div className="w-full max-w-4xl">
            <div className="space-y-3 relative border-l border-gray-300 dark:border-gray-800 ml-4">
              {filteredActivities.map((activity) => (
                <div
                  key={activity.id}
                  className={`relative bg-gray-100 dark:bg-gray-800 hover:bg-gray-200 dark:hover:bg-gray-750 border border-gray-300 dark:border-gray-700 rounded-lg p-4 ml-4 transition-colors ${(activity.type === 'user_summary' || activity.type === 'chat') ? 'cursor-pointer group' : ''
                    } ${activity.type === 'user_summary' ? '' : activity.isSecondaryUserConvo ? 'ml-8 border-l-4 border-l-blue-500/30' : ''}`}
                  onClick={() => {
                    if (activity.type === 'user_summary') {
                      navigate(`/admin/history/user/${activity.user.id}?view=${viewType}`);
                    } else if (activity.type === 'chat' && activity.conversation) {
                      navigate(`/admin/chat/${activity.conversation.gptId}?conversationId=${activity.conversation._id}`);
                    }
                  }}
                >
                  <div className="absolute -left-[10px] top-[50%] transform -translate-y-1/2 flex items-center justify-center w-5 h-5 rounded-full bg-gray-200 dark:bg-gray-700 border-2 border-gray-300 dark:border-gray-600">
                    {activity.type === 'user_summary' ? (
                      <IoPersonOutline size={10} className="text-purple-500" />
                    ) : activity.type === 'chat' && activity.isSecondaryUserConvo ? (
                      <IoChatbubblesOutline size={10} className={'text-blue-400'} />
                    ) : activity.type === 'chat' ? (
                      <IoChatbubblesOutline size={10} className={'text-blue-500'} />
                    ) : (
                      <IoEllipse size={6} className="text-gray-500 dark:text-gray-400" />
                    )}
                  </div>
                  <div className="flex justify-between items-start gap-4">
                    <div>
                      {(activity.type === 'user_summary' || (viewType === 'personal' && activity.type === 'chat') || (viewType === 'team' && !activity.isSecondaryUserConvo)) && activity.user && (
                        <div className="mb-1.5 flex items-center">
                          <span
                            className={`font-semibold text-gray-900 dark:text-white ${activity.type === 'user_summary' ? 'cursor-pointer group-hover:underline' : ''}`}
                            onClick={(e) => {
                              if (activity.type === 'user_summary') {
                                e.stopPropagation();
                                navigate(`/admin/history/user/${activity.user.id}?view=${viewType}`);
                              }
                            }}
                          >
                            {viewType === 'personal' ? 'You' : activity.user?.name || 'Team Member'}
                            {activity.type === 'user_summary' && activity.totalUserConversations > 1 && (
                              <span className="ml-2 text-xs font-normal text-gray-500 dark:text-gray-400">
                                ({activity.totalUserConversations} conversations)
                              </span>
                            )}
                          </span>
                        </div>
                      )}
                      {viewType === 'team' && activity.isSecondaryUserConvo && (
                        <div className="text-xs text-gray-500 dark:text-gray-400 mb-1">
                          Same user, different conversation
                        </div>
                      )}
                      <p className="text-sm">
                        <span className="text-gray-700 dark:text-gray-300">{activity.action}</span>
                        {activity.details && (
                          <> - <span className="font-medium text-gray-900 dark:text-white">{activity.details}</span></>
                        )}
                      </p>
                      {activity.type === 'chat' && activity.conversation?.messages && activity.conversation.messages.length > 0 && (
                        <div className="mt-2 bg-gray-200 dark:bg-gray-700 rounded p-2 text-xs text-gray-600 dark:text-gray-300">
                          <div className="line-clamp-1">
                            <span className="font-semibold">Last message: </span>
                            {activity.conversation.lastMessage || activity.conversation.messages[activity.conversation.messages.length - 1].content.substring(0, 50)}
                          </div>
                          <div className="mt-1 text-gray-500 dark:text-gray-400 text-[10px] group-hover:text-blue-600 dark:group-hover:text-blue-400 transition-colors">
                            Click to view conversation
                          </div>
                        </div>
                      )}
                    </div>
                    <div className="text-xs text-gray-500 dark:text-gray-500 whitespace-nowrap flex-shrink-0">
                      {formatTimestamp(activity.timestamp)}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
export default HistoryPage;
````

## File: frontend/src/components/Admin/InviteTeamMemberModal.jsx
````javascript
import React, { useState, useEffect } from 'react';
import { FiMail, FiX, FiUser, FiSend, FiCheckCircle } from 'react-icons/fi';
import { axiosInstance } from '../../api/axiosInstance';
import { useTheme } from '../../context/ThemeContext';
import { toast } from 'react-toastify';
const InviteTeamMemberModal = ({ isOpen, onClose, onInviteSent }) => {
  const [email, setEmail] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState(false);
  const { isDarkMode } = useTheme();
  useEffect(() => {
    if (isOpen) {
      setEmail('');
      setError('');
      setSuccess(false);
      setLoading(false);
    }
  }, [isOpen]);
  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');
    try {
      const response = await axiosInstance.post(
        `/api/auth/invite`,
        { email },
        { withCredentials: true }
      );
      if (response.data.success) {
        setSuccess(true);
        toast.success(`Invitation sent successfully to ${email}!`);
        if (onInviteSent) {
          onInviteSent({ email });
        }
      } else {
        const message = response.data.message || 'Failed to send invitation';
        setError(message);
        toast.error(message);
      }
    } catch (err) {
      const message = err.response?.data?.message || 'An error occurred sending the invitation';
      setError(message);
      toast.error(message);
      console.error('Invitation error:', err);
    } finally {
      setLoading(false);
    }
  };
  const handleClose = () => {
    setSuccess(false);
    onClose();
  };
  const handleSendAnother = () => {
    setSuccess(false);
    setEmail('');
    setError('');
  };
  if (!isOpen) return null;
  return (
    <div className="fixed inset-0 bg-black/60 dark:bg-black/80 flex items-center justify-center z-50 p-4 transition-opacity duration-300">
      <div className="bg-white dark:bg-gray-800 rounded-lg w-full max-w-md border border-gray-200 dark:border-gray-700 shadow-xl transform transition-transform duration-300 scale-100">
        <div className="flex justify-between items-center border-b border-gray-200 dark:border-gray-700 p-4">
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white flex items-center">
            <FiMail className="mr-2" /> Invite Team Member
          </h3>
          <button
            onClick={handleClose}
            className="text-gray-400 hover:text-gray-600 dark:text-gray-500 dark:hover:text-white focus:outline-none p-1 rounded-full hover:bg-gray-100 dark:hover:bg-gray-700"
          >
            <FiX size={20} />
          </button>
        </div>
        {success ? (
          <div className="p-6 text-center">
            <FiCheckCircle className="mx-auto h-16 w-16 text-green-500 mb-4" />
            <h4 className="text-xl font-semibold mb-2 text-gray-900 dark:text-white">Invitation Sent!</h4>
            <p className="text-gray-600 dark:text-gray-300 mb-6">
              An invitation has been sent to <strong className="text-gray-800 dark:text-gray-100">{email}</strong>.
            </p>
            <div className="flex justify-center gap-3">
              <button
                onClick={handleClose}
                className="px-4 py-2 bg-white dark:bg-gray-700 border border-gray-300 dark:border-gray-600 text-gray-800 dark:text-white rounded-lg font-medium hover:bg-gray-50 dark:hover:bg-gray-600 transition-colors text-sm"
              >
                Close
              </button>
              <button
                onClick={handleSendAnother}
                className="px-4 py-2 bg-blue-600 text-white rounded-lg font-medium hover:bg-blue-700 transition-colors text-sm flex items-center"
              >
                <FiSend className="mr-1.5" size={14} /> Send Another
              </button>
            </div>
          </div>
        ) : (
          <form onSubmit={handleSubmit} className="p-6">
            <div className="space-y-5">
              <div>
                <label htmlFor="invite-email" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                  Email Address
                </label>
                <div className="relative">
                  <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                    <FiMail className="text-gray-400 dark:text-gray-500" />
                  </div>
                  <input
                    id="invite-email"
                    type="email"
                    required
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    className="w-full pl-10 pr-4 py-2 rounded-lg bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-600 focus:ring-2 focus:ring-blue-500 focus:border-transparent outline-none text-sm text-black dark:text-white placeholder-gray-500 dark:placeholder-gray-400"
                    placeholder="colleague@company.com"
                  />
                </div>
              </div>
              <div className="flex justify-end gap-3 pt-2">
                <button
                  type="button"
                  onClick={handleClose}
                  className="px-4 py-2 bg-white dark:bg-gray-700 border border-gray-300 dark:border-gray-600 text-gray-800 dark:text-white rounded-lg font-medium hover:bg-gray-50 dark:hover:bg-gray-600 transition-colors text-sm"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={loading || !email}
                  className="px-4 py-2 bg-blue-600 text-white rounded-lg font-medium hover:bg-blue-700 transition-colors disabled:opacity-60 disabled:cursor-not-allowed text-sm flex items-center justify-center min-w-[130px]"
                >
                  {loading ? (
                    <>
                      <svg className="animate-spin -ml-1 mr-2 h-4 w-4 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                        <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                        <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                      </svg>
                      Sending...
                    </>
                  ) : (
                    <>
                      <FiSend className="mr-1.5" size={14} /> Send Invitation
                    </>
                  )}
                </button>
              </div>
            </div>
          </form>
        )}
      </div>
    </div>
  );
};
export default InviteTeamMemberModal;
````

## File: frontend/src/components/Admin/MoveToFolderModal.jsx
````javascript
import React, { useState, useEffect } from 'react';
import { FiX, FiFolder, FiPlus } from 'react-icons/fi';
import { axiosInstance } from '../../api/axiosInstance';
import { toast } from 'react-toastify';
const MoveToFolderModal = ({ isOpen, onClose, gpt, existingFolders = [], onSuccess }) => {
    const [targetFolder, setTargetFolder] = useState('');
    const [newFolderName, setNewFolderName] = useState('');
    const [isCreatingNew, setIsCreatingNew] = useState(false);
    const [isLoading, setIsLoading] = useState(false);
    // Reset state when modal opens or gpt changes
    useEffect(() => {
        if (isOpen) {
            setTargetFolder(gpt?.folder || ''); // Pre-select current folder or empty
            setNewFolderName('');
            setIsCreatingNew(false);
            setIsLoading(false);
        }
    }, [isOpen, gpt]);
    const handleFolderChange = (e) => {
        const value = e.target.value;
        setTargetFolder(value);
        if (value === '__CREATE_NEW__') {
            setIsCreatingNew(true);
            setNewFolderName(''); // Clear any previous input
        } else {
            setIsCreatingNew(false);
        }
    };
    const handleMove = async () => {
        let finalFolderName = isCreatingNew ? newFolderName.trim() : targetFolder;
        // Basic validation for new folder name
        if (isCreatingNew && !finalFolderName) {
            toast.error("Please enter a name for the new folder.");
            return;
        }
        // Prevent moving to 'All' or 'Uncategorized' pseudo-folders
        if (finalFolderName === 'All' || finalFolderName === 'Uncategorized') {
             toast.error("Cannot move to 'All' or 'Uncategorized'. Choose or create a specific folder.");
             return;
        }
        // If selecting 'Uncategorized' from dropdown, set folder to null/empty
        if (!isCreatingNew && finalFolderName === '') {
            finalFolderName = null; // Represent unassigning folder
        }
        setIsLoading(true);
        try {
            // **BACKEND CALL** (We'll create this endpoint next)
            await axiosInstance.patch(`/api/custom-gpts/${gpt._id}/folder`, 
                { folder: finalFolderName }, // Send null if unassigning
                { withCredentials: true }
            );
            onSuccess(gpt, finalFolderName); // Notify parent component
        } catch (err) {
            console.error("Error moving GPT:", err);
            toast.error(err.response?.data?.message || "Failed to move GPT.");
        } finally {
            setIsLoading(false);
        }
    };
    if (!isOpen || !gpt) return null;
    return (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 dark:bg-black/80 backdrop-blur-sm">
            <div className="relative bg-white dark:bg-gray-800 w-full max-w-md rounded-lg shadow-xl border border-gray-200 dark:border-gray-700">
                {/* Header */}
                <div className="flex justify-between items-center p-4 border-b border-gray-200 dark:border-gray-700">
                    <h3 className="text-lg font-semibold text-gray-900 dark:text-white">Move GPT to Folder</h3>
                    <button 
                        onClick={onClose}
                        className="text-gray-400 hover:text-gray-600 dark:text-gray-500 dark:hover:text-white transition-colors rounded-full p-1 hover:bg-gray-200 dark:hover:bg-gray-700"
                        disabled={isLoading}
                    >
                        <FiX size={20} />
                    </button>
                </div>
                {/* Body */}
                <div className="p-6 space-y-4">
                    <p className="text-sm text-gray-600 dark:text-gray-300">
                        Move <span className="font-medium text-gray-900 dark:text-white">{gpt.name}</span> to:
                    </p>
                    {/* Folder Selection Dropdown */}
                    <div className="relative">
                        <FiFolder className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400 dark:text-gray-500" />
                        <select
                            value={isCreatingNew ? '__CREATE_NEW__' : targetFolder}
                            onChange={handleFolderChange}
                            className="w-full pl-10 pr-4 py-2 rounded-lg bg-white dark:bg-gray-700 border border-gray-300 dark:border-gray-600 text-gray-900 dark:text-white text-sm appearance-none cursor-pointer focus:ring-2 focus:ring-blue-500 focus:border-transparent outline-none"
                            disabled={isLoading}
                        >
                            <option value="">Uncategorized</option> 
                            {existingFolders.sort().map(folder => (
                                <option key={folder} value={folder}>
                                    {folder}
                                </option>
                            ))}
                            <option value="__CREATE_NEW__">-- Create New Folder --</option>
                        </select>
                    </div>
                    {/* New Folder Name Input (conditional) */}
                    {isCreatingNew && (
                        <div className="relative">
                             <FiPlus className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400 dark:text-gray-500" />
                            <input
                                type="text"
                                placeholder="Enter new folder name..."
                                value={newFolderName}
                                onChange={(e) => setNewFolderName(e.target.value)}
                                className="w-full pl-10 pr-4 py-2 rounded-lg bg-white dark:bg-gray-700 border border-gray-300 dark:border-gray-600 text-gray-900 dark:text-white text-sm focus:ring-2 focus:ring-blue-500 focus:border-transparent outline-none"
                                disabled={isLoading}
                                autoFocus
                            />
                        </div>
                    )}
                </div>
                {/* Footer */}
                <div className="flex justify-end gap-3 p-4 border-t border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-800/50 rounded-b-lg">
                    <button
                        onClick={onClose}
                        disabled={isLoading}
                        className="px-4 py-2 rounded-md text-sm font-medium text-gray-700 dark:text-gray-300 bg-white dark:bg-gray-700 border border-gray-300 dark:border-gray-600 hover:bg-gray-50 dark:hover:bg-gray-600 disabled:opacity-50"
                    >
                        Cancel
                    </button>
                    <button
                        onClick={handleMove}
                        disabled={isLoading || (isCreatingNew && !newFolderName.trim())}
                        className="px-4 py-2 rounded-md text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center"
                    >
                        {isLoading ? (
                            <div className="animate-spin rounded-full h-4 w-4 border-t-2 border-b-2 border-white"></div>
                        ) : (
                            'Move GPT'
                        )}
                    </button>
                </div>
            </div>
        </div>
    );
};
export default MoveToFolderModal;
````

## File: frontend/src/components/Admin/SettingsPage.jsx
````javascript
import React, { useState, useEffect, useRef } from 'react';
import { IoSave, IoMoon, IoSunny, IoPersonOutline, IoKey, IoEyeOutline, IoEyeOffOutline, IoCheckmarkCircle } from 'react-icons/io5';
import { toast } from 'react-toastify';
import { useAuth } from '../../context/AuthContext';
import { useTheme } from '../../context/ThemeContext';
import { useNavigate } from 'react-router-dom';
import { axiosInstance } from '../../api/axiosInstance';
const SettingsPage = () => {
    const { user, loading: authLoading } = useAuth();
    const { isDarkMode, toggleTheme } = useTheme();
    const navigate = useNavigate();
    const [activeTab, setActiveTab] = useState('general');
    const [isLoading, setIsLoading] = useState(false);
    const [apiKeysLoading, setApiKeysLoading] = useState(false);
    const [passwordLoading, setPasswordLoading] = useState(false);
    // State to manage visibility of API keys
    const [showKeys, setShowKeys] = useState({
        openai: false,
        claude: false,
        gemini: false,
        llama: false,
    });
    // API keys state
    const [apiKeys, setApiKeys] = useState({
        openai: '',
        claude: '',
        gemini: '',
        llama: '',
    });
    // Password change state
    const [passwordData, setPasswordData] = useState({
        currentPassword: '',
        newPassword: '',
        confirmPassword: ''
    });
    // Load API keys from the backend on mount
    useEffect(() => {
        const fetchApiKeys = async () => {
            if (!user) return;
            try {
                setApiKeysLoading(true);
                const response = await axiosInstance.get('/api/auth/user/api-keys', {
                    withCredentials: true
                });
                if (response.data && response.data.success) {
                    // Convert the server response to our format
                    const keys = response.data.apiKeys || {};
                    setApiKeys({
                        openai: keys.openai || '',
                        claude: keys.claude || '',
                        gemini: keys.gemini || '',
                        llama: keys.llama || ''
                    });
                } else {
                    // If the server doesn't have API keys stored yet, try to load from localStorage for backward compatibility
                    const savedKeys = JSON.parse(localStorage.getItem('apiKeys') || '{}');
                    setApiKeys(prev => ({ ...prev, ...savedKeys }));
                }
            } catch (error) {
                // Fallback to localStorage if server fetch fails
                const savedKeys = JSON.parse(localStorage.getItem('apiKeys') || '{}');
                setApiKeys(prev => ({ ...prev, ...savedKeys }));
            } finally {
                setApiKeysLoading(false);
            }
        };
        fetchApiKeys();
    }, [user]);
    const toggleKeyVisibility = (keyName) => {
        setShowKeys(prev => ({ ...prev, [keyName]: !prev[keyName] }));
    };
    const handleApiKeyChange = (e) => {
        const { name, value } = e.target;
        setApiKeys({ ...apiKeys, [name]: value });
    };
    const saveApiKeys = async () => {
        try {
            setApiKeysLoading(true);
            // First, try to refresh the token before making the API call
            try {
                await axiosInstance.post('/api/auth/refresh');
            } catch (refreshError) {
                // Token refresh failed, continuing anyway
            }
            // Now make the API call with the refreshed token
            const response = await axiosInstance.post('/api/auth/user/api-keys', { apiKeys }, { withCredentials: true });
            if (response.data && response.data.success) {
                localStorage.setItem('apiKeys', JSON.stringify(apiKeys));
                toast.success("API keys updated successfully");
            } else {
                throw new Error(response.data?.message || "Failed to save API keys");
            }
        } catch (error) {
            toast.error(error.response?.data?.message || "Failed to save API keys");
            // Still try to save to localStorage as fallback
            try {
                localStorage.setItem('apiKeys', JSON.stringify(apiKeys));
                toast.info("API keys saved locally (offline mode)");
            } catch (localError) {
                // Error saving to localStorage
            }
        } finally {
            setApiKeysLoading(false);
        }
    };
    const handlePasswordChange = (e) => {
        const { name, value } = e.target;
        setPasswordData(prev => ({
            ...prev,
            [name]: value
        }));
    };
    const updatePassword = async () => {
        // Password validation
        if (!passwordData.currentPassword) {
            toast.error("Current password is required");
            return;
        }
        if (!passwordData.newPassword) {
            toast.error("New password is required");
            return;
        }
        if (passwordData.newPassword !== passwordData.confirmPassword) {
            toast.error("New passwords don't match");
            return;
        }
        try {
            setPasswordLoading(true);
            // Make API call to update the password
            const response = await axiosInstance.post('/api/auth/update-password', {
                currentPassword: passwordData.currentPassword,
                newPassword: passwordData.newPassword
            }, { withCredentials: true });
            if (response.data && response.data.success) {
                toast.success("Password updated successfully");
                setPasswordData({
                    currentPassword: '',
                    newPassword: '',
                    confirmPassword: ''
                });
            } else {
                throw new Error(response.data?.message || "Failed to update password");
            }
        } catch (error) {
            toast.error(error.response?.data?.message || "Failed to update password");
        } finally {
            setPasswordLoading(false);
        }
    };
    // CSS for hiding scrollbars
    const scrollbarHideStyles = `
        .hide-scrollbar::-webkit-scrollbar {
            display: none;
        }
        .hide-scrollbar {
            -ms-overflow-style: none;  /* IE and Edge */
            scrollbar-width: none;  /* Firefox */
        }
    `;
    // Helper function to render API key input field
    const renderApiKeyInput = (modelName, placeholder) => (
        <div className="relative overflow-hidden transition-all duration-300 rounded-lg bg-gray-100 dark:bg-gray-800 border border-gray-300 dark:border-gray-700 p-4 hover:border-blue-500/30">
            <div className="flex items-center justify-between mb-2">
                <label className="block text-sm font-medium capitalize text-gray-800 dark:text-white">{modelName} API Key</label>
            </div>
            <div className="relative">
                <input
                    type={showKeys[modelName] ? 'text' : 'password'}
                    name={modelName}
                    value={apiKeys[modelName]}
                    onChange={handleApiKeyChange}
                    className="w-full bg-white dark:bg-gray-700 border border-gray-300 dark:border-gray-600 rounded-lg px-3 py-2.5 pr-10 text-sm focus:outline-none focus:border-blue-500/50 focus:ring-1 focus:ring-blue-500/50 text-black dark:text-white placeholder-gray-400 dark:placeholder-gray-500"
                    placeholder={placeholder}
                />
                <button
                    type="button"
                    onClick={() => toggleKeyVisibility(modelName)}
                    className="absolute inset-y-0 right-0 px-3 flex items-center text-gray-500 dark:text-gray-400 hover:text-black dark:hover:text-white"
                    aria-label={showKeys[modelName] ? `Hide ${modelName} key` : `Show ${modelName} key`}
                >
                    {showKeys[modelName] ? <IoEyeOffOutline size={18} /> : <IoEyeOutline size={18} />}
                </button>
            </div>
            <p className="text-xs text-gray-500 dark:text-gray-400 mt-1.5">Used for {modelName.charAt(0).toUpperCase() + modelName.slice(1)} models</p>
        </div>
    );
    return (
        <div className="flex flex-col h-full bg-white dark:bg-black text-black dark:text-white overflow-hidden">
            {/* Add the scrollbar-hiding styles */}
            <style>{scrollbarHideStyles}</style>
            {/* Top panel */}
            <div className="px-6 pt-6 pb-4 border-b border-gray-200 dark:border-gray-800 flex-shrink-0 text-center sm:text-left">
                <h1 className="text-xl font-bold text-gray-900 dark:text-white">Settings</h1>
                <p className="text-sm text-gray-500 dark:text-gray-400 mt-1">Customize your experience and manage your account</p>
            </div>
            {/* Tab Navigation */}
            <div className="px-6 pt-4 flex-shrink-0">
                <div className="flex gap-1 overflow-x-auto border-b border-gray-200 dark:border-gray-800 pb-px hide-scrollbar">
                    {[
                        { id: 'general', label: 'General', icon: IoPersonOutline },
                        { id: 'api-keys', label: 'API Keys', icon: IoKey },
                    ].map(tab => (
                        <button
                            key={tab.id}
                            onClick={() => setActiveTab(tab.id)}
                            className={`px-4 py-2.5 rounded-t-lg text-sm font-medium transition-all duration-200 flex items-center gap-2 whitespace-nowrap border-b-2
                                ${activeTab === tab.id
                                    ? 'text-blue-600 dark:text-blue-400 border-blue-500 dark:border-blue-500 bg-blue-50 dark:bg-gray-800/50'
                                    : 'text-gray-500 dark:text-gray-400 border-transparent hover:text-gray-800 dark:hover:text-white hover:bg-gray-100 dark:hover:bg-gray-800/30'
                                }`}
                        >
                            <tab.icon size={16} />
                            <span>{tab.label}</span>
                        </button>
                    ))}
                </div>
            </div>
            {/* Content Area - Added hide-scrollbar class */}
            <div className="flex-1 overflow-y-auto p-6 hide-scrollbar bg-white dark:bg-black">
                {activeTab === 'general' && (
                    <div className="space-y-8 max-w-3xl mx-auto">
                        {/* Account Details Card */}
                        <div className="bg-white dark:bg-gray-800 rounded-lg overflow-hidden border border-gray-200 dark:border-gray-700 shadow-sm">
                            <div className="p-6">
                                <h3 className="text-xl font-semibold text-gray-900 dark:text-white mb-6">Account Details</h3>
                                {authLoading ? (
                                    <div className="animate-pulse flex items-center space-x-4">
                                        <div className="w-16 h-16 rounded-full bg-gray-200 dark:bg-gray-700"></div>
                                        <div className="space-y-3 flex-1">
                                            <div className="h-4 bg-gray-200 dark:bg-gray-700 rounded w-3/4"></div>
                                            <div className="h-3 bg-gray-200 dark:bg-gray-700 rounded w-1/2"></div>
                                        </div>
                                    </div>
                                ) : user ? (
                                    <div className="flex items-center space-x-6">
                                        <div className="w-20 h-20 rounded-full bg-gradient-to-br from-blue-500 to-purple-600 flex items-center justify-center text-white text-2xl font-bold shadow-lg">
                                            {user.name ? user.name.charAt(0).toUpperCase() : '?'}
                                        </div>
                                        <div>
                                            <p className="text-xl font-medium text-gray-900 dark:text-white">{user.name || 'N/A'}</p>
                                            <p className="text-gray-500 dark:text-gray-400 mt-1">{user.email || 'N/A'}</p>
                                            <div className="flex items-center gap-1.5 mt-2 text-green-500 dark:text-green-400 text-sm">
                                                <IoCheckmarkCircle size={16} />
                                                <span>Verified account</span>
                                            </div>
                                        </div>
                                    </div>
                                ) : (
                                    <p className="text-gray-500 dark:text-gray-400">Could not load user information.</p>
                                )}
                            </div>
                        </div>
                        {/* Appearance Card */}
                        <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6 shadow-sm">
                            <div className="flex items-center justify-between mb-6">
                                <div>
                                    <h3 className="text-xl font-semibold text-gray-900 dark:text-white">Appearance</h3>
                                    <p className="text-gray-500 dark:text-gray-400 mt-1">Choose your preferred theme</p>
                                </div>
                            </div>
                            <div className="grid grid-cols-2 gap-4">
                                <button
                                    onClick={() => toggleTheme(true)}
                                    className={`relative overflow-hidden p-4 rounded-lg transition-all duration-300 ${isDarkMode
                                        ? 'border-2 border-blue-500 bg-gray-100 dark:bg-gray-900'
                                        : 'border border-gray-300 dark:border-gray-700 bg-gray-50 dark:bg-gray-700 hover:bg-gray-100 dark:hover:bg-gray-600'
                                        }`}
                                >
                                    <div className="relative">
                                        <div className="flex items-center justify-center">
                                            <div className={`p-2 rounded-lg mb-3 ${isDarkMode ? 'bg-blue-100 dark:bg-gray-800' : 'bg-gray-200 dark:bg-gray-600'}`}>
                                                <IoMoon size={20} className="text-blue-500 dark:text-blue-400" />
                                            </div>
                                        </div>
                                        <p className="text-center font-medium text-gray-900 dark:text-white">Dark Mode</p>
                                        <p className="text-xs text-center text-gray-500 dark:text-gray-400 mt-1">Reduced light emission</p>
                                    </div>
                                </button>
                                <button
                                    onClick={() => toggleTheme(false)}
                                    className={`relative overflow-hidden p-4 rounded-lg transition-all duration-300 ${!isDarkMode
                                        ? 'border-2 border-blue-500 bg-gray-100 dark:bg-gray-900'
                                        : 'border border-gray-300 dark:border-gray-700 bg-gray-50 dark:bg-gray-700 hover:bg-gray-100 dark:hover:bg-gray-600'
                                        }`}
                                >
                                    <div className="relative">
                                        <div className="flex items-center justify-center">
                                            <div className={`p-2 rounded-lg mb-3 ${!isDarkMode ? 'bg-amber-100 dark:bg-gray-800' : 'bg-gray-200 dark:bg-gray-600'}`}>
                                                <IoSunny size={20} className="text-amber-500 dark:text-amber-300" />
                                            </div>
                                        </div>
                                        <p className="text-center font-medium text-gray-900 dark:text-white">Light Mode</p>
                                        <p className="text-xs text-center text-gray-500 dark:text-gray-400 mt-1">Enhanced visibility</p>
                                    </div>
                                </button>
                            </div>
                        </div>
                        {/* Password Change Section */}
                        <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6 shadow-sm">
                            <h3 className="text-xl font-semibold text-gray-900 dark:text-white mb-6">Change Password</h3>
                            <div className="space-y-4">
                                <input
                                    type="password"
                                    name="currentPassword"
                                    value={passwordData.currentPassword}
                                    onChange={handlePasswordChange}
                                    className="w-full bg-gray-100 dark:bg-gray-700 border border-gray-300 dark:border-gray-600 rounded-lg px-4 py-3 text-black dark:text-white focus:outline-none focus:border-blue-500/50 focus:ring-1 focus:ring-blue-500/50 placeholder-gray-400 dark:placeholder-gray-500"
                                    placeholder="Current password"
                                    autoComplete="current-password"
                                />
                                <input
                                    type="password"
                                    name="newPassword"
                                    value={passwordData.newPassword}
                                    onChange={handlePasswordChange}
                                    className="w-full bg-gray-100 dark:bg-gray-700 border border-gray-300 dark:border-gray-600 rounded-lg px-4 py-3 text-black dark:text-white focus:outline-none focus:border-blue-500/50 focus:ring-1 focus:ring-blue-500/50 placeholder-gray-400 dark:placeholder-gray-500"
                                    placeholder="New password"
                                    autoComplete="new-password"
                                />
                                <input
                                    type="password"
                                    name="confirmPassword"
                                    value={passwordData.confirmPassword}
                                    onChange={handlePasswordChange}
                                    className="w-full bg-gray-100 dark:bg-gray-700 border border-gray-300 dark:border-gray-600 rounded-lg px-4 py-3 text-black dark:text-white focus:outline-none focus:border-blue-500/50 focus:ring-1 focus:ring-blue-500/50 placeholder-gray-400 dark:placeholder-gray-500"
                                    placeholder="Confirm new password"
                                    autoComplete="new-password"
                                />
                                <div className="pt-2 flex justify-end">
                                    <button
                                        onClick={updatePassword}
                                        disabled={passwordLoading}
                                        className="flex items-center gap-2 px-5 py-2.5 bg-black dark:bg-white hover:bg-black/80 dark:hover:bg-white/80 rounded-lg text-white dark:text-black font-medium transition-all disabled:opacity-70 disabled:cursor-not-allowed"
                                    >
                                        {passwordLoading ? (
                                            <div className="w-5 h-5 border-2 border-white border-t-transparent rounded-full animate-spin"></div>
                                        ) : (
                                            <IoSave size={18} />
                                        )}
                                        <span>{passwordLoading ? 'Updating...' : 'Update Password'}</span>
                                    </button>
                                </div>
                            </div>
                        </div>
                    </div>
                )}
                {activeTab === 'api-keys' && (
                    <div className="space-y-8 max-w-3xl mx-auto">
                        <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6 shadow-sm">
                            <div className="mb-6">
                                <h3 className="text-xl font-semibold text-gray-900 dark:text-white">Model API Keys</h3>
                                <p className="text-gray-500 dark:text-gray-400 mt-1">Connect your AI models with API keys</p>
                            </div>
                            {apiKeysLoading && apiKeys.openai === '' && apiKeys.claude === '' && apiKeys.gemini === '' && apiKeys.llama === '' ? (
                                <div className="py-8 flex justify-center">
                                    <div className="w-8 h-8 border-2 border-blue-500 border-t-transparent rounded-full animate-spin"></div>
                                </div>
                            ) : (
                                <div className="grid gap-4 md:grid-cols-2">
                                    {renderApiKeyInput('openai', 'sk-...')}
                                    {renderApiKeyInput('claude', 'sk-ant-...')}
                                    {renderApiKeyInput('gemini', 'AIza...')}
                                    {renderApiKeyInput('llama', 'meta-llama-...')}
                                </div>
                            )}
                            <div className="bg-blue-50 dark:bg-blue-900/20 border border-blue-300 dark:border-blue-500/30 rounded-lg p-4 flex items-start gap-3 mt-6">
                                <IoCheckmarkCircle className="text-blue-500 dark:text-blue-400 flex-shrink-0 mt-0.5" size={20} />
                                <p className="text-sm text-blue-700 dark:text-blue-200/80">
                                    Your API keys are securely stored and encrypted in the database. They are never shared with third parties.
                                </p>
                            </div>
                            <div className="mt-6 flex justify-end">
                                <button
                                    onClick={saveApiKeys}
                                    disabled={apiKeysLoading}
                                    className={`flex items-center gap-2 px-5 py-2.5 bg-black dark:bg-white hover:bg-black/80 dark:hover:bg-white/80 rounded-lg text-white dark:text-black font-medium transition-all disabled:opacity-70 disabled:cursor-not-allowed`}
                                >
                                    {apiKeysLoading ? (
                                        <div className="w-5 h-5 border-2 border-white border-t-transparent rounded-full animate-spin"></div>
                                    ) : (
                                        <IoSave size={18} />
                                    )}
                                    <span>{apiKeysLoading ? 'Saving...' : 'Save API Keys'}</span>
                                </button>
                            </div>
                        </div>
                    </div>
                )}
            </div>
        </div>
    );
};
export default SettingsPage;
````

## File: frontend/src/components/Admin/teamData.js
````javascript
// Team members data shared between components
export const teamMembers = [
    {
        id: 1,
        name: 'Emily Johnson',
        email: 'emily@gptnexus.com',
        role: 'Admin',
        department: 'Product',
        joined: 'Mar 15, 2022',
        lastActive: 'Apr 2, 2023',
        status: 'Active',
        assignedGPTs: 8
    },
    {
        id: 2,
        name: 'Michael Chen',
        email: 'michael@gptnexus.com',
        role: 'Employee',
        department: 'Engineering',
        joined: 'Jan 10, 2022',
        lastActive: 'Apr 3, 2023',
        status: 'Active',
        assignedGPTs: 12
    },
    {
        id: 3,
        name: 'Sophia Martinez',
        email: 'sophia@gptnexus.com',
        role: 'Employee',
        department: 'Design',
        joined: 'May 22, 2022',
        lastActive: 'Apr 1, 2023',
        status: 'Active',
        assignedGPTs: 6
    },
    {
        id: 4,
        name: 'David Wilson',
        email: 'david@gptnexus.com',
        role: 'Employee',
        department: 'Marketing',
        joined: 'Jul 8, 2022',
        lastActive: 'Mar 28, 2023',
        status: 'Inactive',
        assignedGPTs: 4
    },
    {
        id: 5,
        name: 'Sarah Rodriguez',
        email: 'sarah@gptnexus.com',
        role: 'Employee',
        department: 'Sales',
        joined: 'Feb 15, 2022',
        lastActive: 'Apr 5, 2023',
        status: 'Active',
        assignedGPTs: 7
    },
    {
        id: 6,
        name: 'James Kim',
        email: 'james@gptnexus.com',
        role: 'Admin',
        department: 'Engineering',
        joined: 'Jan 5, 2022',
        lastActive: 'Apr 3, 2023',
        status: 'Active',
        assignedGPTs: 15
    },
    {
        id: 7,
        name: 'Olivia Wang',
        email: 'olivia@gptnexus.com',
        role: 'Employee',
        department: 'Design',
        joined: 'Mar 20, 2022',
        lastActive: 'Apr 4, 2023',
        status: 'Active',
        assignedGPTs: 9
    },
    {
        id: 8,
        name: 'Robert Brown',
        email: 'robert@gptnexus.com',
        role: 'Employee',
        department: 'Product',
        joined: 'Feb 12, 2022',
        lastActive: 'Mar 30, 2023',
        status: 'Inactive',
        assignedGPTs: 5
    },
    {
        id: 9,
        name: 'Emma Davis',
        email: 'emma@gptnexus.com',
        role: 'Employee',
        department: 'Marketing',
        joined: 'Apr 5, 2022',
        lastActive: 'Apr 2, 2023',
        status: 'Active',
        assignedGPTs: 3
    },
    {
        id: 10,
        name: 'Daniel Lee',
        email: 'daniel@gptnexus.com',
        role: 'Employee',
        department: 'Engineering',
        joined: 'Jan 18, 2022',
        lastActive: 'Apr 1, 2023',
        status: 'Active',
        assignedGPTs: 8
    },
    {
        id: 11,
        name: 'Isabella Garcia',
        email: 'isabella@gptnexus.com',
        role: 'Employee',
        department: 'Customer Support',
        joined: 'Mar 1, 2022',
        lastActive: 'Mar 29, 2023',
        status: 'Inactive',
        assignedGPTs: 6
    },
    {
        id: 12,
        name: 'Alexander Smith',
        email: 'alex@gptnexus.com',
        role: 'Employee',
        department: 'Sales',
        joined: 'Feb 8, 2022',
        lastActive: 'Apr 3, 2023',
        status: 'Active',
        assignedGPTs: 11
    }
];
````

## File: frontend/src/components/Admin/TeamManagement.jsx
````javascript
import React, { useState, useEffect, useCallback, useRef } from 'react';
import {
    FiSearch,
    FiFilter,
    FiMoreVertical,
    FiUser,
    FiUsers,
    FiBell,
    FiBox,
    FiCalendar,
    FiMail,
    FiEdit,
    FiTrash2,
    FiChevronRight,
    FiChevronDown,
    FiCheck
} from 'react-icons/fi';
import AssignGptsModal from './AssignGptsModal';
import TeamMemberDetailsModal from './TeamMemberDetailsModal';
import InviteTeamMemberModal from './InviteTeamMemberModal';
import EditPermissionsModal from './EditPermissionsModal';
import { axiosInstance } from '../../api/axiosInstance';
import { toast } from 'react-toastify';
import { useTheme } from '../../context/ThemeContext';
import { useAuth } from '../../context/AuthContext'; // Import useAuth
// API URL from environment variables
// List of departments for filter dropdown (static data since backend doesn't have this info)
const departments = [
    'All Departments',
    'Product',
    'Engineering',
    'Design',
    'Marketing',
    'Sales',
    'Customer Support'
];
const TeamManagement = () => {
    const [teamMembers, setTeamMembers] = useState([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);
    const [searchTerm, setSearchTerm] = useState('');
    const [selectedMember, setSelectedMember] = useState(null);
    const [showActionsMenu, setShowActionsMenu] = useState(null);
    const [showDepartmentsDropdown, setShowDepartmentsDropdown] = useState(false);
    const [showStatusDropdown, setShowStatusDropdown] = useState(false);
    const [selectedDepartment, setSelectedDepartment] = useState('All Departments');
    const [selectedStatus, setSelectedStatus] = useState('All Status');
    const [isMobileView, setIsMobileView] = useState(window.innerWidth < 768);
    const [showAssignGptsModal, setShowAssignGptsModal] = useState(false);
    const [selectedMemberForGpts, setSelectedMemberForGpts] = useState(null);
    const [showDetailsModal, setShowDetailsModal] = useState(false);
    const [selectedMemberForDetails, setSelectedMemberForDetails] = useState(null);
    const [showInviteModal, setShowInviteModal] = useState(false);
    const [pendingInvitesCount, setPendingInvitesCount] = useState(0);
    const [assignmentChanged, setAssignmentChanged] = useState(false);
    const [refreshInterval, setRefreshInterval] = useState(null);
    const [showEditPermissionsModal, setShowEditPermissionsModal] = useState(false);
    const [selectedMemberForPermissions, setSelectedMemberForPermissions] = useState(null);
    const { isDarkMode } = useTheme();
    const { user } = useAuth(); // Get current user from auth context
    const actionsMenuRef = useRef(null);
    const departmentFilterRef = useRef(null);
    const statusFilterRef = useRef(null);
    const [page, setPage] = useState(1);
    const [pageSize, setPageSize] = useState(10);
    const [cachedMembers, setCachedMembers] = useState({});
    const [totalMembers, setTotalMembers] = useState(0);
    // Add responsive detection
    useEffect(() => {
        const handleResize = () => {
            setIsMobileView(window.innerWidth < 768);
        };
        window.addEventListener('resize', handleResize);
        return () => window.removeEventListener('resize', handleResize);
    }, []);
    // Improved error handling for API calls
    const handleApiError = (error, defaultMessage) => {
        console.error(defaultMessage, error);
        const errorMessage = error.response?.data?.message || defaultMessage;
        toast?.error(errorMessage);
        return errorMessage;
    };
    // Function to format date (should be defined before use or moved outside component)
    const formatDate = (dateString) => {
        if (!dateString) return 'N/A';
        const date = new Date(dateString);
        return date.toLocaleDateString('en-US', {
            year: 'numeric',
            month: 'short',
            day: 'numeric'
        });
    };
    // Fetch team data with GPT counts
    const fetchTeamData = useCallback(async (refresh = false) => {
        if (!refresh && teamMembers.length > 0) return; // Don't reload if data exists
        try {
            setLoading(true);
            // Make a single API call to get users with their GPT counts
            const response = await axiosInstance.get(`/api/auth/users/with-gpt-counts?page=${page}&limit=${pageSize}`, {
                withCredentials: true
            });
            if (response.data && response.data.users) {
                const formattedUsers = response.data.users.map(user => {
                    const isActive = user.lastActive
                        ? (new Date() - new Date(user.lastActive)) < 24 * 60 * 60 * 1000
                        : false;
                    return {
                        id: user._id,
                        name: user.name,
                        email: user.email,
                        role: user.role || 'Employee',
                        department: user.department || 'Not Assigned',
                        joined: formatDate(user.createdAt),
                        lastActive: user.lastActive ? formatDate(user.lastActive) : 'Never',
                        status: isActive ? 'Active' : 'Inactive',
                        assignedGPTs: user.gptCount || 0 // Use count from combined response
                    };
                });
                setTeamMembers(formattedUsers);
                setTotalMembers(response.data.total || formattedUsers.length);
                setError(null);
                // Cache the data
                setCachedMembers(prev => ({
                    ...prev,
                    [page]: formattedUsers
                }));
            }
        } catch (err) {
            console.error("Error fetching team members:", err);
            setError("Failed to load team data. Please check your connection.");
        } finally {
            setLoading(false);
        }
    }, [page, pageSize, teamMembers.length]);
    // Initial mount effect
    useEffect(() => {
        // Check if we have cached data for this page
        if (cachedMembers[page]) {
            setTeamMembers(cachedMembers[page]);
        } else {
            fetchTeamData();
        }
    }, [fetchTeamData, page, cachedMembers]);
    // Reduced polling frequency
    useEffect(() => {
        // Only set up interval if component is mounted and visible
        const interval = setInterval(() => {
            if (document.visibilityState === 'visible') {
                fetchTeamData(true); // Force refresh
            }
        }, 30000); // Reduced from 10s to 30s
        return () => clearInterval(interval);
    }, [fetchTeamData]);
    // IMPROVEMENT 3: Handle GPT assignment changes more efficiently
    const handleGptAssignmentChange = useCallback((memberId) => {
        // Convert to standard pattern if it's a MongoDB ObjectId string
        if (typeof memberId === 'string' && /^[0-9a-fA-F]{24}$/.test(memberId)) {
        } else if (typeof memberId !== 'string') {
            console.error("Invalid member ID type:", typeof memberId);
            return;
        }
        const fetchUpdatedCount = async () => {
            try {
                // Get the updated count for this user
                const response = await axiosInstance.get(`/api/auth/users/${memberId}/gpt-count`, {
                    withCredentials: true
                });
                if (response.data && typeof response.data.count !== 'undefined') {
                    // Update this member's GPT count in the state
                    setTeamMembers(prev => prev.map(member =>
                        member.id === memberId
                            ? { ...member, assignedGPTs: response.data.count }
                            : member
                    ));
                    // Also update the count in cache
                    setCachedMembers(prev => {
                        const newCache = { ...prev };
                        Object.keys(newCache).forEach(pageKey => {
                            if (Array.isArray(newCache[pageKey])) {
                                newCache[pageKey] = newCache[pageKey].map(member =>
                                    member.id === memberId
                                        ? { ...member, assignedGPTs: response.data.count }
                                        : member
                                );
                            }
                        });
                        return newCache;
                    });
                } else {
                    console.warn("Invalid response format for GPT count:", response.data);
                }
            } catch (err) {
                console.error("Error updating GPT count:", err);
                // Don't show a toast here - the user has already closed the modal
            }
        };
        // Call the async function
        fetchUpdatedCount();
    }, []);
    // Fetch pending invites count
    useEffect(() => {
        const fetchPendingInvites = async () => {
            try {
                const response = await axiosInstance.get(`/api/auth/pending-invites/count`, {
                    withCredentials: true
                });
                if (response.data && response.data.count !== undefined) {
                    setPendingInvitesCount(response.data.count);
                }
            } catch (err) {
                console.error("Error fetching pending invites count:", err);
                // Keep current count or set to 0
            }
        };
        fetchPendingInvites();
    }, []);
    const filteredMembers = teamMembers.filter(member => {
        const matchesSearch =
            member.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
            member.email.toLowerCase().includes(searchTerm.toLowerCase()) ||
            (member.department && member.department.toLowerCase().includes(searchTerm.toLowerCase())) ||
            (member.position && member.position.toLowerCase().includes(searchTerm.toLowerCase()));
        const matchesDepartment = selectedDepartment === 'All Departments' ||
            member.department === selectedDepartment;
        const matchesStatus = selectedStatus === 'All Status' ||
            member.status === selectedStatus;
        return matchesSearch && matchesDepartment && matchesStatus;
    });
    const toggleActionsMenu = (memberId) => {
        setShowActionsMenu(showActionsMenu === memberId ? null : memberId);
    };
    const handleInviteMember = () => {
        setShowInviteModal(true);
    };
    const handleAssignGpts = (member) => {
        setSelectedMemberForGpts(member);
        setShowAssignGptsModal(true);
        setShowActionsMenu(null); // Close the actions menu
    };
    const handleViewMemberDetails = (member) => {
        // Don't allow viewing details of the current user
        if (user?._id === member.id) {
            return;
        }
        setSelectedMemberForDetails(member);
        setShowDetailsModal(true);
    };
    // CSS for hiding scrollbars
    const scrollbarHideStyles = `
        .hide-scrollbar::-webkit-scrollbar {
            display: none;
        }
        .hide-scrollbar {
            -ms-overflow-style: none;  /* IE and Edge */
            scrollbar-width: none;  /* Firefox */
        }
    `;
    // Email team member function
    const handleEmailTeamMember = async (email) => {
        // Open default email client with recipient's address
        window.location.href = `mailto:${email}`;
        setShowActionsMenu(null);
    };
    // Edit permissions function
    const handleEditPermissions = (member) => {
        setSelectedMemberForPermissions(member);
        setShowEditPermissionsModal(true);
        setShowActionsMenu(null); // Close the actions menu
    };
    // Handle remove team member
    const handleRemoveTeamMember = async (memberId) => {
        if (window.confirm("Are you sure you want to remove this team member? All their data including chat histories and assignments will be permanently deleted.")) {
            try {
                setLoading(true);
                const response = await axiosInstance.delete(`/api/auth/users/${memberId}`, {
                    withCredentials: true
                });
                if (response.data.success) {
                    // Remove user from local state
                    setTeamMembers(prev => prev.filter(member => member.id !== memberId));
                    // Also update the cache
                    setCachedMembers(prev => {
                        const newCache = { ...prev };
                        for (const pageKey in newCache) {
                            if (newCache[pageKey]) {
                                newCache[pageKey] = newCache[pageKey].filter(member => member.id !== memberId);
                            }
                        }
                        return newCache;
                    });
                    // Update the total count
                    setTotalMembers(prev => Math.max(0, prev - 1));
                    toast.success("Team member and all associated data removed successfully");
                }
            } catch (err) {
                handleApiError(err, "Failed to remove team member");
            } finally {
                setLoading(false);
                setShowActionsMenu(null);
            }
        } else {
            setShowActionsMenu(null);
        }
    };
    // Add function to handle permission updates
    const handlePermissionsUpdated = (updatedMember) => {
        setTeamMembers(prev =>
            prev.map(member =>
                member.id === updatedMember.id ? updatedMember : member
            )
        );
    };
    // Mobile card view for team members
    const MobileTeamMemberCard = ({ member }) => (
        <div
            className={`bg-white dark:bg-gray-800 p-4 rounded-lg shadow border border-gray-200 dark:border-gray-700 mb-3 ${user?._id === member.id ? 'opacity-80' : 'cursor-pointer'
                }`}
            onClick={() => user?._id !== member.id && handleViewMemberDetails(member)}
        >
            <div className="flex items-center justify-between mb-3">
                <div className="flex items-center">
                    <div className="w-10 h-10 rounded-full bg-gray-200 dark:bg-gray-600 flex items-center justify-center mr-3">
                        <FiUser className="text-gray-600 dark:text-gray-300" />
                    </div>
                    <div>
                        <p className="font-semibold text-gray-900 dark:text-white">{member.name}</p>
                        <p className="text-sm text-gray-500 dark:text-gray-400">{member.email}</p>
                        {user?._id === member.id && (
                            <span className="text-xs bg-blue-100 dark:bg-blue-900/30 text-blue-700 dark:text-blue-400 px-2 py-0.5 rounded-full mt-1 inline-block">
                                You
                            </span>
                        )}
                    </div>
                </div>
                {user?._id !== member.id ? (
                    <FiChevronRight className="text-gray-400 dark:text-gray-500" />
                ) : (
                    <span className="text-xs text-gray-400 italic">Current user</span>
                )}
            </div>
            <div className="text-sm space-y-1">
                <p><strong className="text-gray-600 dark:text-gray-300">Role:</strong> {member.role}</p>
                <p><strong className="text-gray-600 dark:text-gray-300">Department:</strong> {member.department}</p>
                <p><strong className="text-gray-600 dark:text-gray-300">Status:</strong>
                    <span className={`ml-1 px-2 py-0.5 rounded-full text-xs font-medium ${member.status === 'Active'
                            ? 'bg-green-100 dark:bg-green-900/50 text-green-700 dark:text-green-300'
                            : 'bg-red-100 dark:bg-red-900/50 text-red-700 dark:text-red-300'
                        }`}>
                        {member.status}
                    </span>
                </p>
                <p><strong className="text-gray-600 dark:text-gray-300">GPTs:</strong> {member.assignedGPTs}</p>
            </div>
        </div>
    );
    // Add pagination controls
    const renderPagination = () => {
        const totalPages = Math.ceil(totalMembers / pageSize);
        return (
            <div className="flex items-center justify-between border-t border-gray-200 dark:border-gray-700 px-4 py-3 sm:px-6 mt-4">
                <div className="flex-1 flex justify-between sm:hidden">
                    <button
                        onClick={() => setPage(Math.max(1, page - 1))}
                        disabled={page === 1}
                        className="relative inline-flex items-center px-4 py-2 border border-gray-300 dark:border-gray-600 text-sm font-medium rounded-md text-gray-700 dark:text-gray-300 bg-white dark:bg-gray-800 hover:bg-gray-50 dark:hover:bg-gray-700 disabled:opacity-50"
                    >
                        Previous
                    </button>
                    <button
                        onClick={() => setPage(Math.min(totalPages, page + 1))}
                        disabled={page === totalPages}
                        className="ml-3 relative inline-flex items-center px-4 py-2 border border-gray-300 dark:border-gray-600 text-sm font-medium rounded-md text-gray-700 dark:text-gray-300 bg-white dark:bg-gray-800 hover:bg-gray-50 dark:hover:bg-gray-700 disabled:opacity-50"
                    >
                        Next
                    </button>
                </div>
            </div>
        );
    };
    if (loading) {
        return <div className="flex justify-center items-center h-screen bg-white dark:bg-black"><div className="animate-spin rounded-full h-16 w-16 border-t-4 border-b-4 border-blue-500"></div></div>;
    }
    if (error) {
        return <div className="flex justify-center items-center h-screen bg-white dark:bg-black text-red-500 p-4">{error}</div>;
    }
    return (
        <div className="flex flex-col h-full bg-gray-50 dark:bg-gray-900 text-black dark:text-white p-4 sm:p-6 overflow-hidden">
            <style>{scrollbarHideStyles}</style>
            <div className="mb-6 flex-shrink-0">
                <h1 className="text-2xl font-bold text-gray-900 dark:text-white mb-1">Team Management</h1>
                <p className="text-gray-600 dark:text-gray-400">Manage your team members, permissions, and GPT assignments.</p>
            </div>
            <div className="mb-4 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 flex-shrink-0">
                <div className="relative flex-grow sm:flex-grow-0 sm:w-64 md:w-72">
                    <FiSearch className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400 dark:text-gray-500" />
                    <input
                        type="text"
                        placeholder="Search members..."
                        value={searchTerm}
                        onChange={(e) => setSearchTerm(e.target.value)}
                        className="w-full pl-10 pr-4 py-2 rounded-lg border border-gray-300 dark:border-gray-700 bg-white dark:bg-gray-800 focus:ring-2 focus:ring-blue-500 focus:border-transparent outline-none text-black dark:text-white placeholder-gray-500 dark:placeholder-gray-400"
                    />
                </div>
                <div className="flex items-center gap-3">
                    <div className="relative" ref={departmentFilterRef}>
                        <button
                            onClick={() => setShowDepartmentsDropdown(!showDepartmentsDropdown)}
                            className="flex items-center gap-1 px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-700 bg-white dark:bg-gray-800 text-sm text-gray-700 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-700"
                        >
                            <FiFilter size={14} />
                            <span>{selectedDepartment === 'All Departments' ? 'Department' : selectedDepartment}</span>
                            <FiChevronDown size={16} className={`transition-transform ${showDepartmentsDropdown ? 'rotate-180' : ''}`} />
                        </button>
                        {showDepartmentsDropdown && (
                            <div className="absolute left-0 mt-2 w-48 bg-white dark:bg-gray-800 rounded-md shadow-lg ring-1 ring-black ring-opacity-5 dark:ring-gray-700 z-10 overflow-hidden">
                                {departments.map(dept => (
                                    <button
                                        key={dept}
                                        onClick={() => { setSelectedDepartment(dept); setShowDepartmentsDropdown(false); }}
                                        className={`w-full text-left px-4 py-2 text-sm flex items-center justify-between ${selectedDepartment === dept ? 'font-semibold text-blue-600 dark:text-blue-400 bg-blue-50 dark:bg-blue-900/30' : 'text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700'}`}
                                    >
                                        {dept}
                                        {selectedDepartment === dept && <FiCheck size={14} />}
                                    </button>
                                ))}
                            </div>
                        )}
                    </div>
                    <div className="relative" ref={statusFilterRef}>
                        <button
                            onClick={() => setShowStatusDropdown(!showStatusDropdown)}
                            className="flex items-center gap-1 px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-700 bg-white dark:bg-gray-800 text-sm text-gray-700 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-700"
                        >
                            <FiUsers size={14} />
                            <span>{selectedStatus}</span>
                            <FiChevronDown size={16} className={`transition-transform ${showStatusDropdown ? 'rotate-180' : ''}`} />
                        </button>
                        {showStatusDropdown && (
                            <div className="absolute left-0 mt-2 w-40 bg-white dark:bg-gray-800 rounded-md shadow-lg ring-1 ring-black ring-opacity-5 dark:ring-gray-700 z-10 overflow-hidden">
                                {['All Status', 'Active', 'Inactive'].map(status => (
                                    <button
                                        key={status}
                                        onClick={() => { setSelectedStatus(status); setShowStatusDropdown(false); }}
                                        className={`w-full text-left px-4 py-2 text-sm flex items-center justify-between ${selectedStatus === status ? 'font-semibold text-blue-600 dark:text-blue-400 bg-blue-50 dark:bg-blue-900/30' : 'text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700'}`}
                                    >
                                        {status}
                                        {selectedStatus === status && <FiCheck size={14} />}
                                    </button>
                                ))}
                            </div>
                        )}
                    </div>
                    <button
                        onClick={handleInviteMember}
                        className="flex items-center gap-2 px-4 py-2 bg-black/80 dark:bg-white hover:bg-black/80 dark:hover:bg-white/70 text-white dark:text-black rounded-lg font-medium text-sm transition-colors relative"
                    >
                        Invite Member
                        {pendingInvitesCount > 0 && (
                            <span className="absolute -top-1 -right-1 flex h-4 w-4 items-center justify-center rounded-full bg-red-500 text-xs font-bold text-white">
                                {pendingInvitesCount}
                            </span>
                        )}
                    </button>
                </div>
            </div>
            <div className="flex-1 overflow-y-auto hide-scrollbar -mx-4 sm:-mx-6 px-4 sm:px-6">
                {isMobileView ? (
                    <div className="space-y-3">
                        {filteredMembers.length > 0 ? (
                            filteredMembers.map(member => (
                                <MobileTeamMemberCard key={member.id} member={member} />
                            ))
                        ) : (
                            <p className="text-center text-gray-500 dark:text-gray-400 py-8">No team members found matching your criteria.</p>
                        )}
                    </div>
                ) : (
                    <div className="overflow-x-auto bg-white dark:bg-gray-800 rounded-lg shadow border border-gray-200 dark:border-gray-700">
                        <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
                            <thead className="bg-gray-50 dark:bg-gray-700/50">
                                <tr>
                                    {['Member', 'Role', 'Department', 'GPTs Assigned', 'Status', 'Joined', 'Last Active', ''].map((header) => (
                                        <th key={header} scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider whitespace-nowrap">
                                            {header}
                                        </th>
                                    ))}
                                </tr>
                            </thead>
                            <tbody className="bg-white dark:bg-gray-800 divide-y divide-gray-200 dark:divide-gray-700">
                                {filteredMembers.length > 0 ? filteredMembers.map((member) => (
                                    <tr
                                        key={member.id}
                                        className="hover:bg-gray-50 dark:hover:bg-gray-700/50 transition-colors"
                                        onClick={() => user?._id !== member.id && handleViewMemberDetails(member)}
                                    >
                                        <td className="px-6 py-4 whitespace-nowrap cursor-pointer" onClick={() => user?._id !== member.id && handleViewMemberDetails(member)}>
                                            <div className="flex items-center">
                                                <div className="flex-shrink-0 h-10 w-10 rounded-full bg-gray-200 dark:bg-gray-600 flex items-center justify-center">
                                                    <FiUser className="text-gray-600 dark:text-gray-300" />
                                                </div>
                                                <div className="ml-4">
                                                    <div className="text-sm font-medium text-gray-900 dark:text-white">{member.name}</div>
                                                    <div className="text-sm text-gray-500 dark:text-gray-400">{member.email}</div>
                                                </div>
                                            </div>
                                        </td>
                                        <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-700 dark:text-gray-300">{member.role}</td>
                                        <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-700 dark:text-gray-300">{member.department}</td>
                                        <td className="px-6 py-4 whitespace-nowrap text-sm text-center text-gray-700 dark:text-gray-300">{member.assignedGPTs}</td>
                                        <td className="px-6 py-4 whitespace-nowrap">
                                            <span className={`px-2.5 py-0.5 inline-flex text-xs leading-5 font-semibold rounded-full ${member.status === 'Active'
                                                    ? 'bg-green-100 dark:bg-green-900/50 text-green-800 dark:text-green-300'
                                                    : 'bg-red-100 dark:bg-red-900/50 text-red-800 dark:text-red-300'
                                                }`}>
                                                {member.status}
                                            </span>
                                        </td>
                                        <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400">{member.joined}</td>
                                        <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400">{member.lastActive}</td>
                                        <td className="px-6 py-4 whitespace-nowrap text-right text-sm font-medium relative">
                                            <button
                                                onClick={(e) => { e.stopPropagation(); toggleActionsMenu(member.id); }}
                                                className={`text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-white p-1.5 rounded-full hover:bg-gray-100 dark:hover:bg-gray-700 ${user?._id === member.id ? 'opacity-50 cursor-not-allowed' : ''}`}
                                                data-member-id={member.id}
                                                disabled={user?._id === member.id}
                                                title={user?._id === member.id ? "You cannot modify your own account" : ""}
                                            >
                                                <FiMoreVertical size={18} />
                                            </button>
                                        </td>
                                    </tr>
                                )) : (
                                    <tr>
                                        <td colSpan="8" className="px-6 py-12 text-center text-sm text-gray-500 dark:text-gray-400">
                                            No team members found matching your criteria.
                                        </td>
                                    </tr>
                                )}
                            </tbody>
                        </table>
                    </div>
                )}
            </div>
            {/* Add pagination at the bottom */}
            {!loading && !error && filteredMembers.length > 0 && renderPagination()}
            {/* Render action menus with fixed position - FIX FOR THREEDDOTS DROPDOWN MENU ALIGNMENT */}
            {showActionsMenu && filteredMembers.map((member) => (
                member.id === showActionsMenu && user?._id !== member.id && (
                    <div
                        key={`menu-${member.id}`}
                        className="fixed z-50"
                        ref={node => {
                            if (node) {
                                const buttonRect = document.querySelector(`[data-member-id="${member.id}"]`)?.getBoundingClientRect();
                                if (buttonRect) {
                                    // Improved positioning for the dropdown with better alignment
                                    const isNearRightEdge = window.innerWidth - buttonRect.right < 200;
                                    node.style.top = `${buttonRect.bottom + window.scrollY + 5}px`;
                                    // If near the right edge of the screen, align right edge of dropdown with button
                                    if (isNearRightEdge) {
                                        node.style.right = `${window.innerWidth - buttonRect.right - window.scrollX}px`;
                                        node.style.left = 'auto';
                                    } else {
                                        // Otherwise center the dropdown below the button
                                        node.style.left = `${buttonRect.left + window.scrollX - 60}px`;
                                    }
                                }
                            }
                        }}
                    >
                        <div
                            ref={actionsMenuRef}
                            className="w-48 bg-white dark:bg-gray-800 rounded-md shadow-lg ring-1 ring-black ring-opacity-5 dark:ring-gray-700 overflow-hidden"
                        >
                            <div className="py-1" role="menu" aria-orientation="vertical" aria-labelledby="options-menu">
                                <button onClick={() => handleAssignGpts(member)} className="w-full text-left px-4 py-2 text-sm text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700 flex items-center gap-2">
                                    <FiBox size={14} /> Assign GPTs
                                </button>
                                <button onClick={() => handleEditPermissions(member)} className="w-full text-left px-4 py-2 text-sm text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700 flex items-center gap-2">
                                    <FiEdit size={14} /> Edit Permissions
                                </button>
                                <button onClick={() => handleEmailTeamMember(member.email)} className="w-full text-left px-4 py-2 text-sm text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700 flex items-center gap-2">
                                    <FiMail size={14} /> Send Email
                                </button>
                                <div className="border-t border-gray-100 dark:border-gray-700 my-1"></div>
                                <button onClick={() => handleRemoveTeamMember(member.id)} className="w-full text-left px-4 py-2 text-sm text-red-600 dark:text-red-400 hover:bg-red-50 dark:hover:bg-red-900/20 flex items-center gap-2">
                                    <FiTrash2 size={14} /> Remove Member
                                </button>
                            </div>
                        </div>
                    </div>
                )
            ))}
            {/* Modals */}
            {showAssignGptsModal && selectedMemberForGpts && (
                <AssignGptsModal
                    isOpen={showAssignGptsModal}
                    onClose={() => setShowAssignGptsModal(false)}
                    teamMember={selectedMemberForGpts}
                    onAssignmentChange={handleGptAssignmentChange}
                />
            )}
            {showDetailsModal && selectedMemberForDetails && (
                <TeamMemberDetailsModal
                    isOpen={showDetailsModal}
                    onClose={() => setShowDetailsModal(false)}
                    member={selectedMemberForDetails}
                />
            )}
            {showInviteModal && (
                <InviteTeamMemberModal
                    isOpen={showInviteModal}
                    onClose={() => setShowInviteModal(false)}
                    onInviteSent={() => {
                        setPendingInvitesCount(prev => prev + 1);
                        toast.success("Invitation sent successfully");
                    }}
                />
            )}
            {showEditPermissionsModal && selectedMemberForPermissions && (
                <EditPermissionsModal
                    isOpen={showEditPermissionsModal}
                    onClose={() => setShowEditPermissionsModal(false)}
                    member={selectedMemberForPermissions}
                    onPermissionsUpdated={handlePermissionsUpdated}
                />
            )}
        </div>
    );
};
export default TeamManagement;
````

## File: frontend/src/components/Admin/TeamMemberDetailsModal.jsx
````javascript
import React, { useState, useCallback, useMemo, useEffect, lazy, Suspense, memo } from 'react';
import { IoClose, IoPersonCircleOutline, IoAppsOutline } from 'react-icons/io5';
import { FiBox, FiPlus, FiTrash2 } from 'react-icons/fi';
import { axiosInstance } from '../../api/axiosInstance';
import { toast } from 'react-toastify';
import { useTheme } from '../../context/ThemeContext';
import { useAuth } from '../../context/AuthContext';
const AssignGptsModal = lazy(() => import('./AssignGptsModal'));
const TeamMemberDetailsModal = memo(({ isOpen, onClose, member }) => {
  const { user } = useAuth();
  const { isDarkMode } = useTheme();
  const [tabState, setTabState] = useState({
    activeTab: 'profile',
    data: { gpts: null },
    loading: { gpts: false },
  });
  const [showAssignGptsModal, setShowAssignGptsModal] = useState(false);
  const formatDate = useCallback((dateString) => {
    if (!dateString) return 'N/A';
    return new Date(dateString).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' });
  }, []);
  const formatRelativeTime = useCallback(
    (dateString) => {
      if (!dateString) return 'N/A';
      const date = new Date(dateString);
      const diffInSeconds = Math.floor((Date.now() - date) / 1000);
      if (diffInSeconds < 60) return 'Just now';
      if (diffInSeconds < 3600) return `${Math.floor(diffInSeconds / 60)} minutes ago`;
      if (diffInSeconds < 86400) return `${Math.floor(diffInSeconds / 3600)} hours ago`;
      if (diffInSeconds < 172800) return 'Yesterday';
      return formatDate(dateString);
    },
    [formatDate]
  );
  const handleApiError = (error, message) => {
    console.error(message, error);
    toast.error(message);
  };
  const fetchTabData = async (tabName) => {
    if (tabState.data[tabName]) return;
    setTabState((prev) => ({ ...prev, loading: { ...prev.loading, [tabName]: true } }));
    try {
      const response = await axiosInstance.get(`/api/custom-gpts/team/members/${member.id}/gpts`, {
        withCredentials: true,
      });
      setTabState((prev) => ({
        ...prev,
        data: { ...prev.data, gpts: response.data.gpts },
        loading: { ...prev.loading, gpts: false },
      }));
    } catch (error) {
      handleApiError(error, `Failed to fetch ${tabName}`);
    }
  };
  const refreshGpts = async () => {
    setTabState((prev) => ({ ...prev, loading: { ...prev.loading, gpts: true } }));
    try {
      const response = await axiosInstance.get(`/api/custom-gpts/team/members/${member.id}/gpts`, {
        withCredentials: true,
      });
      setTabState((prev) => ({
        ...prev,
        data: { ...prev.data, gpts: response.data.gpts },
        loading: { ...prev.loading, gpts: false },
      }));
    } catch (error) {
      handleApiError(error, 'Failed to refresh GPTs');
    }
  };
  const handleRemoveGpt = async (gptId) => {
    try {
      await axiosInstance.delete(`/api/custom-gpts/team/members/${member.id}/gpts/${gptId}`, {
        withCredentials: true,
      });
      setTabState((prev) => ({
        ...prev,
        data: { ...prev.data, gpts: prev.data.gpts.filter((gpt) => gpt._id !== gptId) },
      }));
      toast.success('GPT unassigned successfully');
    } catch (error) {
      handleApiError(error, 'Failed to unassign GPT');
    }
  };
  useEffect(() => {
    if (!isOpen || !member) return;
    fetchTabData(tabState.activeTab);
  }, [isOpen, member, tabState.activeTab]);
  useEffect(() => {
    if (!isOpen) {
      setTabState((prev) => ({ ...prev, data: { gpts: null } }));
    }
  }, [isOpen]);
  if (!isOpen || !member || user?._id === member.id) return null;
  const GptCard = ({ gpt, onRemove }) => (
    <div className="flex items-center justify-between p-3 rounded-lg bg-gray-700/50 border border-gray-600">
      <div className="flex items-center">
        <div className="w-10 h-10 rounded-full overflow-hidden bg-gradient-to-br from-blue-600 to-purple-600 flex items-center justify-center mr-3">
          {gpt.imageUrl ? (
            <img src={gpt.imageUrl} alt={gpt.name} className="w-full h-full object-cover" />
          ) : (
            <span className={`text-lg ${isDarkMode ? 'text-white' : 'text-gray-600'}`}>{gpt.name.charAt(0)}</span>
          )}
        </div>
        <div>
          <h4 className="font-medium text-white">{gpt.name}</h4>
          <p className="text-xs text-gray-400">{gpt.description}</p>
        </div>
      </div>
      <div className="flex items-center">
        <div className="text-xs text-gray-400 mr-4">Assigned: {formatRelativeTime(gpt.assignedAt)}</div>
        <button
          onClick={() => onRemove(gpt._id)}
          className="text-red-400 hover:text-red-300 p-1.5 hover:bg-gray-600 rounded-full transition-colors"
          title="Remove GPT"
        >
          <FiTrash2 size={18} />
        </button>
      </div>
    </div>
  );
  const renderProfileTab = () => (
    <div className="space-y-6 py-6 px-1">
      <div className="flex items-center space-x-4">
        <div className="h-16 w-16 rounded-full bg-gradient-to-br from-blue-500 to-purple-600 flex items-center justify-center text-white text-2xl font-medium flex-shrink-0">
          {member.name.charAt(0)}
        </div>
      </div>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div className="bg-gray-50 dark:bg-gray-700/50 rounded-lg p-4 border border-gray-200 dark:border-gray-600/50">
          <h3 className="text-sm font-medium text-gray-600 dark:text-gray-300 mb-3">Personal Information</h3>
          <div className="space-y-3">
            <div>
              <p className="text-xs text-gray-500 dark:text-gray-400">Email</p>
              <p className="text-sm text-gray-800 dark:text-white truncate" title={member.email}>
                {member.email}
              </p>
            </div>
            <div>
              <p className="text-xs text-gray-500 dark:text-gray-400">Department</p>
              <p className="text-sm text-gray-800 dark:text-white">{member.department}</p>
            </div>
          </div>
        </div>
        <div className="bg-gray-50 dark:bg-gray-700/50 rounded-lg p-4 border border-gray-200 dark:border-gray-600/50">
          <h3 className="text-sm font-medium text-gray-600 dark:text-gray-300 mb-3">Account Status</h3>
          <div className="space-y-3">
            <div>
              <p className="text-xs text-gray-500 dark:text-gray-400">Role</p>
              <p className="text-sm text-gray-800 dark:text-white">{member.role}</p>
            </div>
            <div>
              <p className="text-xs text-gray-500 dark:text-gray-400 mb-1">Status</p>
              <span
                className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${member.status === 'Active'
                    ? 'bg-green-100 dark:bg-green-900/50 text-green-800 dark:text-green-300'
                    : 'bg-red-100 dark:bg-red-900/50 text-red-800 dark:text-red-300'
                  }`}
              >
                {member.status}
              </span>
            </div>
            <div>
              <p className="text-xs text-gray-500 dark:text-gray-400">Joined Date</p>
              <p className="text-sm text-gray-800 dark:text-white">{formatDate(member.joined)}</p>
            </div>
            <div>
              <p className="text-xs text-gray-500 dark:text-gray-400">Last Active</p>
              <p className="text-sm text-gray-800 dark:text-white">{formatRelativeTime(member.lastActive)}</p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
  const renderAssignedGptsTab = () => (
    <div className="py-4">
      <div className="flex justify-between items-center mb-4">
        <h3 className="text-lg font-medium text-white">Assigned GPTs ({tabState.data.gpts?.length || 0})</h3>
        <button
          className="bg-black dark:bg-white hover:bg-black/70 dark:hover:bg-white/70 text-white dark:text-black text-sm rounded-md px-3 py-1.5 flex items-center"
          onClick={() => setShowAssignGptsModal(true)}
        >
          <FiPlus className="mr-1.5" size={14} />
          Assign GPTs
        </button>
      </div>
      {tabState.loading.gpts ? (
        <div className="flex justify-center py-10">
          <div className="animate-spin rounded-full h-8 w-8 border-t-2 border-b-2 border-blue-500"></div>
        </div>
      ) : tabState.data.gpts?.length > 0 ? (
        <div className="space-y-3">
          {tabState.data.gpts.map((gpt) => (
            <GptCard key={gpt._id} gpt={gpt} onRemove={handleRemoveGpt} />
          ))}
        </div>
      ) : (
        <div className="text-center py-10 bg-gray-800 rounded-lg border border-gray-700">
          <FiBox className="mx-auto text-gray-500" size={32} />
          <p className="mt-2 text-gray-400">No GPTs assigned yet</p>
          <button
            className="mt-4 bg-blue-600 hover:bg-blue-700 text-white text-sm rounded-md px-4 py-2"
            onClick={() => setShowAssignGptsModal(true)}
          >
            Assign First GPT
          </button>
        </div>
      )}
    </div>
  );
  const tabs = [
    { id: 'profile', label: 'Profile', icon: IoPersonCircleOutline, render: renderProfileTab },
    { id: 'gpts', label: 'Assigned GPTs', icon: IoAppsOutline, render: renderAssignedGptsTab },
  ];
  const TabContent = useMemo(() => tabs.find((tab) => tab.id === tabState.activeTab)?.render() || null, [
    tabState.activeTab,
    member,
    tabState.data.gpts,
    tabState.loading.gpts,
    isDarkMode,
  ]);
  return (
    <>
      <div
        className={`fixed inset-0 z-50 flex items-center justify-center p-4 ${isOpen ? 'opacity-100' : 'opacity-0 pointer-events-none'
          } transition-opacity duration-300`}
      >
        <div className="absolute inset-0 bg-black/60 dark:bg-black/80" onClick={onClose}></div>
        <div
          className={`relative bg-white dark:bg-gray-800 w-full max-w-3xl max-h-[90vh] rounded-xl shadow-xl border border-gray-200 dark:border-gray-700 overflow-hidden flex flex-col transform ${isOpen ? 'scale-100' : 'scale-95'
            } transition-transform duration-300`}
        >
          <div className="px-6 py-4 border-b border-gray-200 dark:border-gray-700 flex justify-between items-center bg-gray-50 dark:bg-gray-900 flex-shrink-0">
            <h3 className="text-lg font-semibold text-gray-900 dark:text-white truncate pr-4">
              Member Details: {member?.name}
            </h3>
            <button
              onClick={onClose}
              className="text-gray-400 hover:text-gray-600 dark:text-gray-500 dark:hover:text-white transition-colors rounded-full p-1 hover:bg-gray-200 dark:hover:bg-gray-700 flex-shrink-0"
            >
              <IoClose size={22} />
            </button>
          </div>
          <div className="px-6 pt-4 border-b border-gray-200 dark:border-gray-700 flex-shrink-0 bg-white dark:bg-gray-800">
            <div className="flex gap-1 -mb-px">
              {tabs.map((tab) => (
                <button
                  key={tab.id}
                  onClick={() => setTabState((prev) => ({ ...prev, activeTab: tab.id }))}
                  className={`px-4 py-2.5 border-b-2 text-sm font-medium transition-colors duration-200 flex items-center gap-2 whitespace-nowrap ${tabState.activeTab === tab.id
                      ? 'border-blue-500 text-blue-600 dark:text-blue-400'
                      : 'border-transparent text-gray-500 dark:text-gray-400 hover:text-gray-800 dark:hover:text-white hover:border-gray-300 dark:hover:border-gray-600'
                    }`}
                >
                  <tab.icon size={16} /> {tab.label}
                </button>
              ))}
            </div>
          </div>
          <div className="flex-1 overflow-y-auto p-6 bg-gray-50 dark:bg-gray-800/50 custom-scrollbar-dark dark:custom-scrollbar">
            {TabContent}
          </div>
        </div>
      </div>
      {showAssignGptsModal && member && (
        <Suspense fallback={<div>Loading...</div>}>
          <AssignGptsModal
            isOpen={showAssignGptsModal}
            onClose={() => {
              setShowAssignGptsModal(false);
              refreshGpts();
            }}
            teamMember={member}
            onAssignmentChange={refreshGpts}
          />
        </Suspense>
      )}
    </>
  );
});
export default TeamMemberDetailsModal;
````

## File: frontend/src/components/Admin/UserHistoryPage.jsx
````javascript
import React, { useState, useEffect, useRef } from 'react';
import { useParams, useNavigate, useLocation } from 'react-router-dom';
import {
    IoArrowBack,
    IoTimeOutline,
    IoSearchOutline,
    IoFilterOutline,
    IoChevronDown,
    IoEllipse,
    IoChatbubbleEllipsesOutline,
    IoCheckmark
} from 'react-icons/io5';
import { FiUser, FiUsers, FiBox, FiCalendar, FiMail, FiActivity } from 'react-icons/fi';
import { useTheme } from '../../context/ThemeContext';
import { useAuth } from '../../context/AuthContext';
import { axiosInstance } from '../../api/axiosInstance';
const UserHistoryPage = () => {
    const { userId } = useParams();
    const navigate = useNavigate();
    const location = useLocation();
    const { isDarkMode } = useTheme();
    const { user: currentUser } = useAuth();
    const [isLoading, setIsLoading] = useState(true);
    const [user, setUser] = useState(null);
    const [conversations, setConversations] = useState([]);
    const [filteredConversations, setFilteredConversations] = useState([]);
    const [searchQuery, setSearchQuery] = useState('');
    const [filterOpen, setFilterOpen] = useState(false);
    const [filterOptions, setFilterOptions] = useState({
        dateRange: 'all',
    });
    const filterDropdownRef = useRef(null);
    const queryParams = new URLSearchParams(location.search);
    const previousView = queryParams.get('view') || 'team';
    // Fetch user data and conversations
    useEffect(() => {
        const fetchUserData = async () => {
            setIsLoading(true);
            try {
                // Fetch the conversation history first
                const historyResponse = await axiosInstance.get(`/api/chat-history/user/${userId}`, {
                    withCredentials: true
                });
                if (historyResponse.data && historyResponse.data.success) {
                    const conversationData = historyResponse.data.conversations || [];
                    // Extract user data from team history (which includes user details)
                    let userData = null;
                    // First try to get team history to extract user data
                    try {
                        const teamHistoryResponse = await axiosInstance.get('/api/chat-history/team', {
                            withCredentials: true
                        });
                        if (teamHistoryResponse.data && teamHistoryResponse.data.success) {
                            // Find conversations for this specific user
                            const userConvos = teamHistoryResponse.data.conversations.filter(
                                c => c.userId === userId
                            );
                            if (userConvos.length > 0) {
                                // Extract user data from the first conversation
                                userData = {
                                    _id: userId,
                                    name: userConvos[0].userName,
                                    email: userConvos[0].userEmail,
                                    profilePicture: userConvos[0].userProfilePic,
                                    role: userConvos[0].userRole || 'User',
                                    createdAt: userConvos[0].createdAt,
                                    lastActive: userConvos[0].updatedAt
                                };
                            }
                        }
                    } catch (error) {
                    }
                    // Process and enrich the conversation data
                    const processedConversations = conversationData.map(convo => ({
                        ...convo,
                        messageCount: convo.messages?.length || 0,
                        previewContent: convo.lastMessage ||
                            (convo.messages?.length > 0 ? convo.messages[convo.messages.length - 1].content : 'No messages'),
                        lastActivity: convo.updatedAt || convo.createdAt
                    }));
                    setConversations(processedConversations);
                    setFilteredConversations(processedConversations);
                    // If we couldn't get user data from team history, use the best available information
                    if (!userData) {
                        // If this is not the current user, we need a different approach to get user data
                        // Just use the user ID and extract name from history if possible
                        userData = {
                            _id: userId,
                            name: processedConversations.length > 0 && processedConversations[0].userName
                                ? processedConversations[0].userName
                                : `User ${userId.substring(0, 6)}...`,
                            email: processedConversations.length > 0 && processedConversations[0].userEmail
                                ? processedConversations[0].userEmail
                                : `user-${userId.substring(0, 4)}@example.com`,
                            role: 'User',
                            createdAt: processedConversations.length > 0 ? processedConversations[0].createdAt : new Date(),
                            lastActive: processedConversations.length > 0 ? processedConversations[0].updatedAt : new Date()
                        };
                    }
                    // Set the complete user data
                    setUser({
                        ...userData,
                        totalConversations: processedConversations.length,
                        totalMessages: processedConversations.reduce((sum, convo) => sum + (convo.messageCount || 0), 0),
                        uniqueGpts: [...new Set(processedConversations.map(c => c.gptName))].length,
                        favoriteGpt: processedConversations.length > 0 ? processedConversations[0].gptName : 'None'
                    });
                } else {
                    console.warn("Failed to fetch conversation history");
                    navigate(`/admin/history?view=${previousView}`);
                }
            } catch (error) {
                console.error("Error fetching user data:", error);
                navigate(`/admin/history?view=${previousView}`);
            } finally {
                setIsLoading(false);
            }
        };
        if (userId) {
            fetchUserData();
        }
    }, [userId, navigate, previousView, currentUser]);
    // Filter conversations based on search and date range
    useEffect(() => {
        let filtered = [...conversations];
        if (searchQuery) {
            const lowerQuery = searchQuery.toLowerCase();
            filtered = filtered.filter(convo =>
                (convo.gptName && convo.gptName.toLowerCase().includes(lowerQuery)) ||
                (convo.lastMessage && convo.lastMessage.toLowerCase().includes(lowerQuery))
            );
        }
        if (filterOptions.dateRange !== 'all') {
            const now = new Date();
            let cutoffDate;
            if (filterOptions.dateRange === 'today') {
                cutoffDate = new Date(now.getFullYear(), now.getMonth(), now.getDate());
            } else if (filterOptions.dateRange === 'week') {
                const startOfToday = new Date(now.getFullYear(), now.getMonth(), now.getDate());
                cutoffDate = new Date(startOfToday.setDate(startOfToday.getDate() - 7));
            } else if (filterOptions.dateRange === 'month') {
                const startOfToday = new Date(now.getFullYear(), now.getMonth(), now.getDate());
                cutoffDate = new Date(startOfToday.setMonth(startOfToday.getMonth() - 1));
            }
            if (cutoffDate) {
                filtered = filtered.filter(convo => new Date(convo.updatedAt || convo.createdAt) >= cutoffDate);
            }
        }
        setFilteredConversations(filtered);
    }, [searchQuery, filterOptions, conversations]);
    // Format timestamp
    const formatTimestamp = (timestamp) => {
        if (!timestamp) return 'N/A';
        const date = new Date(timestamp);
        const now = new Date();
        // Check if the date is today
        const isToday = date.toDateString() === now.toDateString();
        // Check if the date was yesterday
        const yesterday = new Date(now);
        yesterday.setDate(now.getDate() - 1);
        const isYesterday = date.toDateString() === yesterday.toDateString();
        const timeString = date.toLocaleTimeString([], {
            hour: 'numeric',
            minute: '2-digit',
            hour12: true
        }).toLowerCase(); // Ensure lowercase am/pm
        if (isToday) {
            return `Today, ${timeString}`;
        } else if (isYesterday) {
            return `Yesterday, ${timeString}`;
        } else {
            // Format for older dates
            return date.toLocaleDateString(undefined, {
                month: 'short',
                day: 'numeric',
                year: date.getFullYear() !== now.getFullYear() ? 'numeric' : undefined, // Show year if not current year
            }) + `, ${timeString}`; // Add time back
        }
    };
    // Format date only
    const formatDateOnly = (dateString) => {
        if (!dateString) return 'N/A';
        const date = new Date(dateString);
        return date.toLocaleDateString('en-US', {
            year: 'numeric',
            month: 'short',
            day: 'numeric'
        });
    };
    // Format relative time for Last Active
    const formatRelativeTime = (dateString) => {
        if (!dateString) return 'Never';
        const date = new Date(dateString);
        const now = new Date();
        const diffTime = now - date; // Difference in milliseconds
        const diffSeconds = Math.floor(diffTime / 1000);
        const diffMinutes = Math.floor(diffSeconds / 60);
        const diffHours = Math.floor(diffMinutes / 60);
        const diffDays = Math.floor(diffHours / 24);
        if (diffDays > 30) return formatDateOnly(dateString); // Older than a month, show date
        if (diffDays >= 1) return `${diffDays} day${diffDays > 1 ? 's' : ''} ago`;
        if (diffHours >= 1) return `${diffHours} hour${diffHours > 1 ? 's' : ''} ago`;
        if (diffMinutes >= 1) return `${diffMinutes} min${diffMinutes > 1 ? 's' : ''} ago`;
        return 'Just now';
    };
    // Set date range filter
    const setDateRangeFilter = (range) => {
        setFilterOptions(prev => ({ ...prev, dateRange: range }));
        setFilterOpen(false);
    };
    // Handle chat history item click to navigate to conversation
    const handleConversationClick = (conversation) => {
        if (conversation && conversation.gptId && conversation._id) {
            navigate(`/admin/chat/${conversation.gptId}?conversationId=${conversation._id}`);
        } else {
            console.error("Missing gptId or conversation._id, cannot navigate", conversation);
        }
    };
    // Click outside handling for filter dropdown
    useEffect(() => {
        function handleClickOutside(event) {
            if (filterDropdownRef.current && !filterDropdownRef.current.contains(event.target)) {
                setFilterOpen(false);
            }
        }
        document.addEventListener("mousedown", handleClickOutside);
        return () => document.removeEventListener("mousedown", handleClickOutside);
    }, [filterDropdownRef]);
    // CSS for hiding scrollbars
    const scrollbarHideStyles = `
      .hide-scrollbar::-webkit-scrollbar { display: none; }
      .hide-scrollbar { -ms-overflow-style: none; scrollbar-width: none; }
    `;
    // Render loading state for user profile
    const renderProfileLoading = () => (
        <div className="animate-pulse">
            <div className="flex items-center mb-6">
                <div className="h-14 w-14 rounded-full bg-gray-200 dark:bg-gray-700 mr-4 flex-shrink-0"></div>
                <div className="flex-1">
                    <div className="h-6 bg-gray-200 dark:bg-gray-700 rounded w-3/4 mb-2"></div>
                    <div className="h-4 bg-gray-200 dark:bg-gray-700 rounded w-1/2"></div>
                </div>
            </div>
            <div className="mb-6 space-y-3">
                <div className="flex gap-3">
                    <div className="h-5 bg-gray-200 dark:bg-gray-700 rounded-full w-16"></div>
                    <div className="h-5 bg-gray-200 dark:bg-gray-700 rounded w-24"></div>
                </div>
                <div className="h-4 bg-gray-200 dark:bg-gray-700 rounded w-full"></div>
                <div className="h-4 bg-gray-200 dark:bg-gray-700 rounded w-5/6"></div>
            </div>
            <div className="space-y-3">
                <div className="h-16 bg-gray-200 dark:bg-gray-700 rounded-lg"></div>
                <div className="h-16 bg-gray-200 dark:bg-gray-700 rounded-lg"></div>
                <div className="h-16 bg-gray-200 dark:bg-gray-700 rounded-lg"></div>
            </div>
        </div>
    );
    // Render loading state for conversation list
    const renderConversationLoading = () => (
        <div className="space-y-3">
            {[...Array(5)].map((_, i) => (
                <div key={i} className="flex items-center p-4 bg-white dark:bg-gray-800/60 rounded-lg shadow-sm animate-pulse border border-gray-200 dark:border-gray-700/50">
                    <div className="w-8 h-8 rounded-full bg-gray-200 dark:bg-gray-700 mr-4 flex-shrink-0"></div>
                    <div className="flex-1 space-y-2">
                        <div className="h-3 bg-gray-200 dark:bg-gray-700 rounded w-3/4"></div>
                        <div className="h-3 bg-gray-200 dark:bg-gray-700 rounded w-1/2"></div>
                    </div>
                    <div className="h-3 bg-gray-200 dark:bg-gray-700 rounded w-1/4 ml-4"></div>
                </div>
            ))}
        </div>
    );
    return (
        <div className={`flex flex-col h-full bg-white dark:bg-black text-black dark:text-white overflow-hidden`}>
            <style>{scrollbarHideStyles}</style>
            {/* Back button */}
            <div className="px-6 pt-6 pb-3 flex-shrink-0 border-b border-gray-200 dark:border-gray-800">
                <button
                    onClick={() => navigate(`/admin/history?view=${previousView}`)}
                    className="flex items-center text-gray-500 dark:text-gray-400 hover:text-blue-600 dark:hover:text-blue-400 transition-colors text-sm"
                >
                    <IoArrowBack size={16} className="mr-1" />
                    <span>Back to History</span>
                </button>
            </div>
            {/* Main content area */}
            <div className="flex-1 overflow-hidden flex flex-col lg:flex-row">
                {/* Left side - User profile */}
                <div className="lg:w-[320px] xl:w-[360px] p-6 border-b lg:border-b-0 lg:border-r border-gray-200 dark:border-gray-700 overflow-y-auto hide-scrollbar bg-gray-50 dark:bg-gray-900/40 flex-shrink-0">
                    {isLoading ? renderProfileLoading() : user ? (
                        <>
                            <div className="flex items-center mb-6">
                                {user.profilePicture ? (
                                    <img
                                        src={user.profilePicture}
                                        alt={`${user.name}'s profile`}
                                        className="h-14 w-14 rounded-full object-cover mr-4 flex-shrink-0 border-2 border-white dark:border-gray-800"
                                    />
                                ) : (
                                    <div className="h-14 w-14 rounded-full bg-gradient-to-br from-blue-500 to-purple-600 flex items-center justify-center text-white text-xl font-medium mr-4 flex-shrink-0">
                                        {user.name?.charAt(0) || 'U'}
                                    </div>
                                )}
                                <div className="overflow-hidden">
                                    <h1 className="text-xl lg:text-2xl font-semibold text-gray-900 dark:text-white truncate" title={user.name}>{user.name}</h1>
                                    <p className="text-sm text-gray-500 dark:text-gray-400 truncate" title={user.email}>{user.email}</p>
                                </div>
                            </div>
                            <div className="mb-6">
                                <div className="flex items-center gap-2 mb-3 flex-wrap">
                                    <span className={`px-2.5 py-0.5 inline-flex items-center text-xs leading-5 font-semibold rounded-full ${user.lastActive && (new Date().getTime() - new Date(user.lastActive).getTime() < 7 * 24 * 60 * 60 * 1000)
                                            ? 'bg-green-100 dark:bg-green-900/50 text-green-800 dark:text-green-300'
                                            : 'bg-yellow-100 dark:bg-yellow-900/50 text-yellow-800 dark:text-yellow-300'
                                        }`}>
                                        <IoEllipse className={`mr-1.5 ${user.lastActive && (new Date().getTime() - new Date(user.lastActive).getTime() < 7 * 24 * 60 * 60 * 1000)
                                                ? 'text-green-500'
                                                : 'text-yellow-500'
                                            }`} size={8} />
                                        {user.lastActive && (new Date().getTime() - new Date(user.lastActive).getTime() < 7 * 24 * 60 * 60 * 1000)
                                            ? 'Recently Active'
                                            : 'Inactive'
                                        }
                                    </span>
                                    <span className="text-gray-500 dark:text-gray-400 text-xs flex items-center bg-gray-100 dark:bg-gray-700 px-2 py-0.5 rounded-full">
                                        <FiUser className="mr-1" size={12} />
                                        {user.role || 'User'}
                                    </span>
                                </div>
                                <div className="space-y-2 text-sm">
                                    <div className="flex items-start">
                                        <FiBox className="mr-2 mt-0.5 text-gray-400 dark:text-gray-500 flex-shrink-0" size={14} />
                                        <span className="text-gray-600 dark:text-gray-400 mr-1">User ID:</span>
                                        <span className="font-medium text-gray-800 dark:text-gray-200 truncate" title={user._id}>
                                            {user._id ? `${user._id.substring(0, 6)}...${user._id.substring(user._id.length - 4)}` : 'Not available'}
                                        </span>
                                    </div>
                                    <div className="flex items-start">
                                        <FiUsers className="mr-2 mt-0.5 text-gray-400 dark:text-gray-500 flex-shrink-0" size={14} />
                                        <span className="text-gray-600 dark:text-gray-400 mr-1">Favorite GPT:</span>
                                        <span className="font-medium text-gray-800 dark:text-gray-200">
                                            {user.favoriteGpt || (user.gptList && user.gptList.length > 0 ? user.gptList[0] : 'None')}
                                        </span>
                                    </div>
                                    <div className="flex items-start">
                                        <FiCalendar className="mr-2 mt-0.5 text-gray-400 dark:text-gray-500 flex-shrink-0" size={14} />
                                        <span className="text-gray-600 dark:text-gray-400 mr-1">First Chat:</span>
                                        <span className="font-medium text-gray-800 dark:text-gray-200">{formatDateOnly(user.createdAt)}</span>
                                    </div>
                                    <div className="flex items-start">
                                        <FiActivity className="mr-2 mt-0.5 text-gray-400 dark:text-gray-500 flex-shrink-0" size={14} />
                                        <span className="text-gray-600 dark:text-gray-400 mr-1">Last Active:</span>
                                        <span className="font-medium text-gray-800 dark:text-gray-200">{formatRelativeTime(user.lastActive)}</span>
                                    </div>
                                </div>
                            </div>
                            {/* Usage Statistics */}
                            <div className="space-y-3">
                                <div className="bg-white dark:bg-gray-800/50 rounded-lg p-4 border border-gray-200 dark:border-gray-700/60">
                                    <h3 className="text-sm font-medium text-gray-600 dark:text-gray-300 mb-3">Usage Overview</h3>
                                    <div className="flex justify-between items-center text-sm">
                                        <span className="text-gray-500 dark:text-gray-400">Total Conversations:</span>
                                        <span className="font-medium text-gray-800 dark:text-gray-200">{user.totalConversations || conversations.length}</span>
                                    </div>
                                    <div className="flex justify-between items-center text-sm mt-1">
                                        <span className="text-gray-500 dark:text-gray-400">Total Messages:</span>
                                        <span className="font-medium text-gray-800 dark:text-gray-200">{user.totalMessages || '—'}</span>
                                    </div>
                                    <div className="flex justify-between items-center text-sm mt-1">
                                        <span className="text-gray-500 dark:text-gray-400">Unique GPTs Used:</span>
                                        <span className="font-medium text-gray-800 dark:text-gray-200">{user.uniqueGpts || '—'}</span>
                                    </div>
                                </div>
                                {/* Last Conversation */}
                                {conversations.length > 0 && (
                                    <div className="bg-white dark:bg-gray-800/50 rounded-lg p-4 border border-gray-200 dark:border-gray-700/60">
                                        <h3 className="text-sm font-medium text-gray-600 dark:text-gray-300 mb-2">Latest Activity</h3>
                                        <p className="text-xs text-gray-500 dark:text-gray-400">
                                            Last conversation with <span className="font-medium text-gray-700 dark:text-gray-300">{conversations[0].gptName}</span>
                                        </p>
                                        <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">
                                            {formatTimestamp(conversations[0].updatedAt || conversations[0].createdAt)}
                                        </p>
                                    </div>
                                )}
                            </div>
                        </>
                    ) : (
                        <p className="text-center text-gray-500 dark:text-gray-400 py-10">User not found.</p>
                    )}
                </div>
                {/* Right side - Conversation history */}
                <div className="flex-1 flex flex-col overflow-hidden bg-white dark:bg-black">
                    {/* Search and Filter */}
                    <div className="px-6 py-3 border-b border-gray-200 dark:border-gray-700 flex flex-col sm:flex-row items-center gap-3 sm:gap-4 flex-shrink-0">
                        <div className="text-sm font-medium text-gray-800 dark:text-gray-200 flex-shrink-0">
                            Conversation History ({filteredConversations.length})
                        </div>
                        <div className="flex-grow flex items-center gap-3 w-full sm:w-auto justify-end">
                            <div className="relative flex-grow max-w-xs w-full">
                                <IoSearchOutline className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400 dark:text-gray-500" size={16} />
                                <input
                                    type="text"
                                    placeholder="Search conversations..."
                                    value={searchQuery}
                                    onChange={(e) => setSearchQuery(e.target.value)}
                                    className="w-full pl-9 pr-4 py-1.5 rounded-lg border border-gray-300 dark:border-gray-700 bg-white dark:bg-gray-800 focus:ring-1 focus:ring-blue-500 focus:border-blue-500 outline-none text-sm text-black dark:text-white placeholder-gray-500 dark:placeholder-gray-400"
                                />
                            </div>
                            <div className="relative" ref={filterDropdownRef}>
                                <button
                                    onClick={() => setFilterOpen(!filterOpen)}
                                    className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-gray-300 dark:border-gray-700 bg-white dark:bg-gray-800 text-sm text-gray-700 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-700 flex-shrink-0"
                                >
                                    <IoFilterOutline size={14} /> Date
                                    <IoChevronDown size={14} className={`transition-transform ${filterOpen ? 'rotate-180' : ''}`} />
                                </button>
                                {filterOpen && (
                                    <div className="absolute right-0 mt-2 w-40 bg-white dark:bg-gray-800 rounded-lg shadow-xl border border-gray-200 dark:border-gray-700 z-20 overflow-hidden">
                                        {[{ label: 'All Time', value: 'all' }, { label: 'Today', value: 'today' }, { label: 'Last 7 Days', value: 'week' }, { label: 'Last 30 Days', value: 'month' }].map(range => (
                                            <button
                                                key={range.value}
                                                onClick={() => setDateRangeFilter(range.value)}
                                                className={`w-full text-left px-3 py-1.5 text-sm flex justify-between items-center transition-colors ${filterOptions.dateRange === range.value
                                                        ? 'bg-blue-50 dark:bg-blue-900/30 text-blue-700 dark:text-blue-300 font-medium'
                                                        : 'text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700'
                                                    }`}
                                            >
                                                {range.label}
                                                {filterOptions.dateRange === range.value && <IoCheckmark size={16} />}
                                            </button>
                                        ))}
                                    </div>
                                )}
                            </div>
                        </div>
                    </div>
                    {/* Conversation List */}
                    <div className="flex-1 overflow-y-auto p-4 md:p-6 bg-gray-50 dark:bg-gray-900/50 custom-scrollbar-dark dark:custom-scrollbar">
                        {isLoading ? renderConversationLoading() : filteredConversations.length > 0 ? (
                            <ul className="space-y-3">
                                {filteredConversations.map((convo) => (
                                    <li
                                        key={convo._id}
                                        className="flex items-center p-4 bg-white dark:bg-gray-800 rounded-lg shadow-sm border border-gray-200 dark:border-gray-700/50 transition-colors hover:bg-gray-50 dark:hover:bg-gray-700/60 cursor-pointer group"
                                        onClick={() => handleConversationClick(convo)}
                                    >
                                        <div className="w-8 h-8 rounded-full flex items-center justify-center mr-4 bg-blue-100 dark:bg-blue-900/50 text-blue-600 dark:text-blue-300 flex-shrink-0">
                                            <IoChatbubbleEllipsesOutline size={16} />
                                        </div>
                                        <div className="flex-1 overflow-hidden">
                                            <p className="text-sm font-medium text-gray-900 dark:text-gray-100 truncate group-hover:text-blue-600 dark:group-hover:text-blue-400 transition-colors" title={convo.gptName}>
                                                {convo.gptName || 'Unknown GPT'}
                                            </p>
                                            <p className="text-xs text-gray-500 dark:text-gray-400 truncate" title={convo.previewContent || convo.lastMessage}>
                                                {convo.previewContent || convo.lastMessage || (convo.messages?.length > 0 ? convo.messages[convo.messages.length - 1].content : 'No messages')}
                                            </p>
                                        </div>
                                        <div className="ml-4 text-right flex-shrink-0">
                                            <p className="text-xs text-gray-500 dark:text-gray-400 whitespace-nowrap">
                                                {formatTimestamp(convo.lastActivity || convo.updatedAt || convo.createdAt)}
                                            </p>
                                            <p className="text-xs text-gray-400 dark:text-gray-500">{convo.messageCount || convo.messages?.length || 0} messages</p>
                                        </div>
                                    </li>
                                ))}
                            </ul>
                        ) : (
                            <div className="text-center py-12 px-4">
                                <IoTimeOutline className="mx-auto h-12 w-12 text-gray-400 dark:text-gray-500" />
                                <h3 className="mt-2 text-lg font-medium text-gray-900 dark:text-white">No Conversations Found</h3>
                                <p className="mt-1 text-sm text-gray-500 dark:text-gray-400 max-w-md mx-auto">
                                    {searchQuery || filterOptions.dateRange !== 'all' ? 'Try adjusting your search or filters.' : `No conversation history available for ${user?.name || 'this user'}.`}
                                </p>
                            </div>
                        )}
                    </div>
                </div>
            </div>
        </div>
    );
};
export default UserHistoryPage;
````

## File: frontend/src/components/UI/Skeleton.jsx
````javascript
import React from 'react';
export const Skeleton = ({ className, ...props }) => {
  return (
    <div 
      className={`animate-pulse bg-gray-300 dark:bg-gray-700 rounded ${className}`}
      {...props}
    />
  );
};
````

## File: frontend/src/components/User/ChatInput.jsx
````javascript
import React, { useState, useRef, useEffect } from 'react';
import { IoSendSharp } from 'react-icons/io5';
import { HiMiniPaperClip } from 'react-icons/hi2';
import { FiGlobe } from 'react-icons/fi';
const ChatInput = ({ onSubmit, onFileUpload, isLoading, isDarkMode, showWebSearch, webSearchEnabled, setWebSearchEnabled }) => {
    const [inputMessage, setInputMessage] = useState('');
    const textareaRef = useRef(null);
    const fileInputRef = useRef(null);
    // More robust auto-resize textarea
    const resizeTextarea = () => {
        if (textareaRef.current) {
            // Reset height to get accurate scrollHeight
            textareaRef.current.style.height = '0px';
            const scrollHeight = textareaRef.current.scrollHeight;
            // Apply minimum height (40px) and max height (e.g., 120px or 200px)
            const minHeight = 40;
            const maxHeight = window.innerWidth < 640 ? 120 : 200; // Example responsive max-height
            textareaRef.current.style.height = Math.min(maxHeight, Math.max(minHeight, scrollHeight)) + 'px';
        }
    };
    // Auto-resize when input changes
    useEffect(() => {
        resizeTextarea();
    }, [inputMessage]);
    // Also resize on window resize
    useEffect(() => {
        window.addEventListener('resize', resizeTextarea);
        // Initial resize
        resizeTextarea();
        return () => window.removeEventListener('resize', resizeTextarea);
    }, []);
    const handleSubmit = (e) => {
        e.preventDefault();
        if (inputMessage.trim() && !isLoading) { // Don't submit if loading
            onSubmit(inputMessage);
            setInputMessage('');
            // Reset height after clearing input
            setTimeout(() => {
                if (textareaRef.current) {
                    textareaRef.current.style.height = '40px'; // Reset to min-height
                }
            }, 0);
        }
    };
    // Function to handle click on the paperclip icon
    const handleUploadClick = () => {
        fileInputRef.current.click(); // Trigger click on the hidden file input
    };
    // Function to handle file selection
    const handleFileChange = (e) => {
        const files = e.target.files;
        if (files && files.length > 0) {
            if (onFileUpload) {
                onFileUpload(files);
            }
            e.target.value = null;
        }
    };
    // Add this function to toggle web search
    const toggleWebSearch = () => {
        if (setWebSearchEnabled) {
            setWebSearchEnabled(!webSearchEnabled);
        }
    };
    return (
        <div className="w-full">
            <form onSubmit={handleSubmit}>
                <div className={`rounded-2xl sm:rounded-3xl shadow-md ${isDarkMode ? 'bg-[#1e1e1e]' : 'bg-white'
                    }`}>
                    <div className={`flex flex-col px-3 sm:px-4 py-2 sm:py-3 rounded-2xl sm:rounded-3xl border ${isDarkMode ? 'border-gray-700/50' : 'border-gray-200'
                        }`}>
                        <textarea
                            ref={textareaRef}
                            className={`w-full bg-transparent border-0 outline-none resize-none overflow-y-auto min-h-[40px] text-sm sm:text-base no-scrollbar ${isDarkMode ? 'text-white placeholder-gray-500' : 'text-gray-900 placeholder-gray-400'
                                }`}
                            placeholder="Ask anything..."
                            value={inputMessage}
                            onChange={(e) => setInputMessage(e.target.value)}
                            rows={1}
                            onKeyDown={(e) => {
                                if (e.key === 'Enter' && !e.shiftKey) {
                                    e.preventDefault();
                                    handleSubmit(e);
                                }
                            }}
                            disabled={isLoading}
                            style={{ maxHeight: window.innerWidth < 640 ? '120px' : '200px' }}
                        />
                        <div className="flex justify-between items-center mt-1 sm:mt-2">
                            <div className="flex items-center gap-1">
                                <input
                                    type="file"
                                    ref={fileInputRef}
                                    onChange={handleFileChange}
                                    style={{ display: 'none' }}
                                    multiple
                                    disabled={isLoading}
                                />
                                {showWebSearch && (
                                    <button
                                        type="button"
                                        onClick={toggleWebSearch}
                                        className={`rounded-full w-7 h-7 sm:w-8 sm:h-8 flex items-center justify-center transition-colors ${
                                            webSearchEnabled 
                                                ? `${isDarkMode ? 'text-blue-400 bg-blue-900/30' : 'text-blue-500 bg-blue-100'}`
                                                : `${isDarkMode ? 'text-gray-400 hover:bg-gray-700/50' : 'text-gray-500 hover:bg-gray-200'}`
                                        }`}
                                        title={webSearchEnabled ? "Web search enabled" : "Enable web search"}
                                        disabled={isLoading}
                                    >
                                        <FiGlobe size={16} className="sm:text-[18px]" />
                                    </button>
                                )}
                                <button
                                    type="button"
                                    onClick={handleUploadClick}
                                    className={`rounded-full w-7 h-7 sm:w-8 sm:h-8 flex items-center justify-center transition-colors ${isDarkMode
                                            ? 'text-gray-400 hover:bg-gray-700/50'
                                            : 'text-gray-500 hover:bg-gray-200'
                                        }`}
                                    disabled={isLoading}
                                >
                                    <HiMiniPaperClip size={18} className="sm:text-[20px]" />
                                </button>
                            </div>
                            <button
                                type="submit"
                                className={`rounded-full w-7 h-7 sm:w-8 sm:h-8 flex items-center justify-center transition-colors ${isDarkMode
                                        ? 'bg-gray-700 hover:bg-gray-600 text-white'
                                        : 'bg-blue-500 hover:bg-blue-600 text-white'
                                    } disabled:opacity-50 disabled:cursor-not-allowed`}
                                disabled={!inputMessage.trim() || isLoading}
                            >
                                {isLoading ? (
                                    <div className="animate-spin rounded-full h-4 w-4 border-t-2 border-b-2 border-white"></div>
                                ) : (
                                    <IoSendSharp size={16} className="sm:text-[18px]" />
                                )}
                            </button>
                        </div>
                    </div>
                </div>
            </form>
        </div>
    );
};
export default ChatInput;
````

## File: frontend/src/components/User/FavoritesPage.jsx
````javascript
import React, { useState, useEffect, useRef, useMemo, useCallback, memo } from 'react';
import { FiSearch, FiMessageSquare, FiHeart, FiChevronDown, FiChevronUp, FiXCircle, FiFolder, FiPlus } from 'react-icons/fi';
import { useNavigate } from 'react-router-dom';
import { axiosInstance } from '../../api/axiosInstance';
import { useTheme } from '../../context/ThemeContext';
import MoveToFolderModal from './MoveToFolderModal';
import { toast } from 'react-toastify';
// Memoized Favorite Card Component
const FavoriteCard = memo(({ gpt, formatDate, onChatClick, onRemoveFavorite, onMoveToFolder, isDarkMode }) => (
    <div
        key={gpt._id}
        className={`rounded-lg overflow-hidden border transition-all flex flex-col group ${isDarkMode
            ? 'bg-gray-800 border-gray-700 hover:border-gray-600 shadow-lg hover:shadow-xl'
            : 'bg-white border-gray-200 hover:border-gray-300 shadow-md hover:shadow-lg'
            }`}
    >
        <div className={`h-24 sm:h-32 relative flex-shrink-0 ${!gpt.imageUrl && (isDarkMode ? 'bg-gradient-to-br from-gray-700 to-gray-900' : 'bg-gradient-to-br from-gray-100 to-gray-300')
            }`}>
            {gpt.imageUrl ? (
                <img
                    src={gpt.imageUrl}
                    alt={gpt.name}
                    className={`w-full h-full object-cover ${isDarkMode ? 'opacity-70' : 'opacity-90'}`}
                    loading="lazy"
                />
            ) : (
                <div className={`w-full h-full flex items-center justify-center ${isDarkMode ? 'bg-gradient-to-br from-purple-900/50 to-blue-900/50' : 'bg-gradient-to-br from-purple-100/50 to-blue-100/50'}`}>
                    <span className={`text-3xl sm:text-4xl ${isDarkMode ? 'text-white/30' : 'text-gray-500/50'}`}>{gpt.name.charAt(0)}</span>
                </div>
            )}
            <button
                onClick={(e) => { e.stopPropagation(); onRemoveFavorite(gpt._id); }}
                className={`absolute top-2 right-2 p-1.5 rounded-full transition-all ${isDarkMode ? 'bg-black/40 hover:bg-black/60 text-red-500 hover:text-red-400' : 'bg-white/60 hover:bg-white/80 text-red-500 hover:text-red-600'
                    }`}
                title="Remove from favorites"
            >
                <FiHeart size={16} fill="currentColor" />
            </button>
            <button
                onClick={(e) => { e.stopPropagation(); onMoveToFolder(gpt); }}
                className={`absolute top-2 right-10 p-1.5 rounded-full transition-all ${isDarkMode ? 'bg-black/40 hover:bg-black/60 text-gray-400 hover:text-blue-400' : 'bg-white/60 hover:bg-white/80 text-gray-500 hover:text-blue-500'
                    }`}
                title="Move to folder"
            >
                <FiFolder size={16} />
            </button>
        </div>
        <div className="p-3 sm:p-4 flex-grow flex flex-col">
            <div className="flex items-start justify-between mb-1.5 sm:mb-2">
                <h3 className={`font-semibold text-base sm:text-lg line-clamp-1 ${isDarkMode ? 'text-white' : 'text-gray-900'}`}>{gpt.name}</h3>
                <div className={`flex items-center flex-shrink-0 gap-1 px-1.5 sm:px-2 py-0.5 rounded text-[10px] sm:text-xs ${isDarkMode ? 'bg-gray-700 text-gray-200' : 'bg-gray-200 text-gray-600'
                    }`}>
                    <span>{gpt.model || 'N/A'}</span>
                </div>
            </div>
            {gpt.folder && (
                <div className={`flex items-center gap-1 text-xs mb-1.5 ${isDarkMode ? 'text-gray-400' : 'text-gray-500'}`}>
                    <FiFolder size={12} />
                    <span>{gpt.folder}</span>
                </div>
            )}
            <p className={`text-xs sm:text-sm line-clamp-2 flex-grow ${isDarkMode ? 'text-gray-300' : 'text-gray-600'}`}>
                {gpt.description || 'No description available.'}
            </p>
            <div className={`mt-auto pt-2 border-t text-[10px] sm:text-xs flex justify-between items-center ${isDarkMode ? 'border-gray-700 text-gray-400' : 'border-gray-200 text-gray-500'
                }`}>
                <span>Favorited: {formatDate(gpt.createdAt || new Date())}</span>
                {gpt.capabilities?.webBrowsing && (
                    <span className={`whitespace-nowrap px-1.5 py-0.5 rounded-full ${isDarkMode ? 'bg-green-900/40 text-green-200' : 'bg-green-100 text-green-700'
                        }`}>Web</span>
                )}
            </div>
            <button
                className={`mt-3 w-full py-2 rounded-lg transition-colors text-white text-sm font-medium flex items-center justify-center gap-2 ${isDarkMode ? 'bg-blue-600 hover:bg-blue-700' : 'bg-blue-500 hover:bg-blue-600'
                    }`}
                onClick={(e) => { e.stopPropagation(); onChatClick(gpt._id); }}
            >
                <FiMessageSquare size={16} />
                Chat with GPT
            </button>
        </div>
    </div>
));
const FavoritesPage = () => {
    const [favoriteGpts, setFavoriteGpts] = useState([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);
    const [searchTerm, setSearchTerm] = useState('');
    const [sortOption, setSortOption] = useState('newest');
    const [showSortOptions, setShowSortOptions] = useState(false);
    const sortDropdownRef = useRef(null);
    const navigate = useNavigate();
    const { isDarkMode } = useTheme();
    const [showMoveModal, setShowMoveModal] = useState(false);
    const [gptToMove, setGptToMove] = useState(null);
    const [folders, setFolders] = useState(['All']);
    const [selectedFolder, setSelectedFolder] = useState('All');
    const [showFolderOptions, setShowFolderOptions] = useState(false);
    const folderDropdownRef = useRef(null);
    const fetchFavoriteGpts = useCallback(async () => {
        try {
            setLoading(true);
            setError(null);
            const response = await axiosInstance.get('/api/custom-gpts/user/favorites', {
                withCredentials: true
            });
            if (response.data.success && Array.isArray(response.data.gpts)) {
                const fetchedGpts = response.data.gpts;
                setFavoriteGpts(fetchedGpts);
                const uniqueFolders = [...new Set(fetchedGpts
                    .map(gpt => gpt.folder)
                    .filter(folder => folder)
                )];
                setFolders(prev => [...new Set(['All', ...uniqueFolders])]);
            } else {
                console.warn("API response successful but 'gpts' field is not an array or missing:", response.data);
                setFavoriteGpts([]);
                setFolders(['All']);
                setError("No favorites found or received unexpected data format.");
            }
        } catch (error) {
            console.error("Error fetching favorite GPTs:", error);
            const errorMsg = error.response?.data?.message || "Failed to load your favorite GPTs";
            setError(errorMsg);
            setFavoriteGpts([]);
            setFolders(['All']);
        } finally {
            setLoading(false);
        }
    }, []);
    useEffect(() => {
        fetchFavoriteGpts();
    }, [fetchFavoriteGpts]);
    useEffect(() => {
        const handleClickOutside = (event) => {
            if (sortDropdownRef.current && !sortDropdownRef.current.contains(event.target)) {
                setShowSortOptions(false);
            }
            if (folderDropdownRef.current && !folderDropdownRef.current.contains(event.target)) {
                setShowFolderOptions(false);
            }
        };
        document.addEventListener("mousedown", handleClickOutside);
        return () => document.removeEventListener("mousedown", handleClickOutside);
    }, []);
    const filteredGpts = useMemo(() => {
        return favoriteGpts
            .filter(gpt =>
                gpt.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
                (gpt.description && gpt.description.toLowerCase().includes(searchTerm.toLowerCase()))
            )
            .filter(gpt => {
                if (selectedFolder === 'All') return true;
                return gpt.folder === selectedFolder;
            })
            .sort((a, b) => {
                const dateA = a.createdAt ? new Date(a.createdAt) : new Date(0);
                const dateB = b.createdAt ? new Date(b.createdAt) : new Date(0);
                const nameA = a.name || '';
                const nameB = b.name || '';
                switch (sortOption) {
                    case 'newest': return dateB - dateA;
                    case 'oldest': return dateA - dateB;
                    case 'alphabetical': return nameA.localeCompare(nameB);
                    default: return dateB - dateA;
                }
            });
    }, [favoriteGpts, searchTerm, sortOption, selectedFolder]);
    const formatDate = useCallback((dateString) => {
        try {
            const date = new Date(dateString);
            if (isNaN(date.getTime())) return 'Invalid Date';
            return date.toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' });
        } catch (e) {
            console.error("Error formatting date:", dateString, e);
            return 'Unknown Date';
        }
    }, []);
    const handleChatClick = useCallback((gptId) => {
        navigate(`/user/chat?gptId=${gptId}`);
    }, [navigate]);
    const handleRemoveFavorite = useCallback(async (gptId) => {
        const originalFavorites = [...favoriteGpts];
        setFavoriteGpts(prev => prev.filter(gpt => gpt._id !== gptId));
        try {
            await axiosInstance.delete(`/api/custom-gpts/user/favorites/${gptId}`, {
                withCredentials: true
            });
            toast.info("Removed from favorites");
        } catch (error) {
            console.error("Error removing favorite:", error);
            toast.error("Failed to remove favorite");
            setFavoriteGpts(originalFavorites);
        }
    }, [favoriteGpts]);
    const handleSearchChange = useCallback((e) => {
        setSearchTerm(e.target.value);
    }, []);
    const toggleSortOptions = useCallback(() => {
        setShowSortOptions(prev => !prev);
    }, []);
    const selectSortOption = useCallback((option) => {
        setSortOption(option);
        setShowSortOptions(false);
    }, []);
    const handleRetry = useCallback(() => {
        fetchFavoriteGpts();
    }, [fetchFavoriteGpts]);
    const handleMoveToFolder = useCallback((gpt) => {
        setGptToMove(gpt);
        setShowMoveModal(true);
    }, []);
    const handleGptMoved = useCallback((updatedGpt, newFolderName) => {
        setFavoriteGpts(prev => prev.map(gpt =>
            gpt._id === updatedGpt._id
                ? updatedGpt
                : gpt
        ));
        if (newFolderName && !folders.includes(newFolderName)) {
            setFolders(prevFolders => [...new Set([...prevFolders, newFolderName])]);
            setSelectedFolder(newFolderName);
        } else if (updatedGpt.folder && updatedGpt.folder !== selectedFolder) {
            setSelectedFolder(updatedGpt.folder);
        } else if (!updatedGpt.folder && selectedFolder !== 'All') {
            setSelectedFolder('All');
        }
        toast.success(`Moved "${updatedGpt.name}" to ${updatedGpt.folder || 'No Folder'}`);
    }, [folders]);
    if (loading && favoriteGpts.length === 0) {
        return (
            <div className={`flex items-center justify-center h-full ${isDarkMode ? 'bg-black text-white' : 'bg-gray-50 text-gray-700'}`}>
                <div className={`animate-spin rounded-full h-10 w-10 border-t-2 border-b-2 ${isDarkMode ? 'border-blue-500' : 'border-blue-600'}`}></div>
            </div>
        );
    }
    return (
        <div className={`flex flex-col h-full p-4 sm:p-6 overflow-hidden transition-colors duration-300 ${isDarkMode ? 'bg-black text-white' : 'bg-gray-50 text-gray-900'
            }`}>
            <div className="mb-4 md:mb-6 flex-shrink-0 text-center md:text-left">
                <h1 className="text-xl sm:text-2xl font-bold">Your Favorites</h1>
                <p className={`text-sm mt-1 ${isDarkMode ? 'text-gray-400' : 'text-gray-600'}`}>
                    GPTs you've marked as favorites for quick access
                </p>
            </div>
            <div className="flex flex-col sm:flex-row sm:items-center justify-between mb-4 md:mb-6 gap-4 flex-shrink-0">
                <div className="flex flex-col sm:flex-row gap-2 sm:gap-4 flex-grow">
                    <div className="relative flex-grow sm:flex-grow-0">
                        <FiSearch className={`absolute left-3 top-1/2 transform -translate-y-1/2 ${isDarkMode ? 'text-gray-400' : 'text-gray-500'}`} />
                        <input
                            type="text"
                            placeholder="Search favorites..."
                            value={searchTerm}
                            onChange={handleSearchChange}
                            className={`w-full sm:w-52 md:w-64 pl-10 pr-4 py-2 rounded-lg border focus:ring-2 focus:ring-blue-500 focus:border-blue-500 transition-all text-sm ${isDarkMode
                                ? 'bg-gray-700 border-gray-600 text-white placeholder-gray-400'
                                : 'bg-white border-gray-300 text-gray-900 placeholder-gray-500'
                                }`}
                        />
                    </div>
                    <div className="relative" ref={folderDropdownRef}>
                        <button
                            onClick={() => setShowFolderOptions(prev => !prev)}
                            className={`flex items-center justify-between w-full sm:w-40 px-3 py-2 rounded-lg border text-sm transition-colors ${isDarkMode
                                ? 'bg-gray-700 border-gray-600 text-white hover:bg-gray-600'
                                : 'bg-white border-gray-300 text-gray-700 hover:bg-gray-50'
                                }`}
                        >
                            <span className="truncate flex items-center gap-2">
                                <FiFolder size={16} />
                                {selectedFolder}
                            </span>
                            {showFolderOptions ? <FiChevronUp size={16} /> : <FiChevronDown size={16} />}
                        </button>
                        {showFolderOptions && (
                            <div className={`absolute z-10 w-full mt-1 rounded-lg shadow-lg border overflow-hidden text-sm max-h-60 overflow-y-auto ${isDarkMode
                                ? 'bg-gray-800 border-gray-700 text-white'
                                : 'bg-white border-gray-200 text-gray-700'
                                }`}>
                                {folders.map((folder) => (
                                    <button
                                        key={folder}
                                        className={`block w-full text-left px-3 py-2 transition-colors flex items-center gap-2 ${selectedFolder === folder
                                            ? (isDarkMode ? 'bg-blue-600' : 'bg-blue-100 text-blue-700 font-medium')
                                            : (isDarkMode ? 'hover:bg-gray-700' : 'hover:bg-gray-100')
                                            }`}
                                        onClick={() => {
                                            setSelectedFolder(folder);
                                            setShowFolderOptions(false);
                                        }}
                                    >
                                        <FiFolder size={14} />
                                        {folder}
                                    </button>
                                ))}
                            </div>
                        )}
                    </div>
                </div>
                <div className="relative" ref={sortDropdownRef}>
                    <button
                        onClick={toggleSortOptions}
                        className={`flex items-center justify-between w-full sm:w-36 px-3 py-2 rounded-lg border text-sm transition-colors ${isDarkMode
                            ? 'bg-gray-700 border-gray-600 text-white hover:bg-gray-600'
                            : 'bg-white border-gray-300 text-gray-700 hover:bg-gray-50'
                            }`}
                    >
                        <span className="truncate">Sort: {sortOption.charAt(0).toUpperCase() + sortOption.slice(1)}</span>
                        {showSortOptions ? <FiChevronUp size={16} /> : <FiChevronDown size={16} />}
                    </button>
                    {showSortOptions && (
                        <div className={`absolute z-10 w-full sm:w-36 mt-1 rounded-lg shadow-lg border overflow-hidden text-sm ${isDarkMode
                            ? 'bg-gray-800 border-gray-700 text-white'
                            : 'bg-white border-gray-200 text-gray-700'
                            }`}>
                            {['newest', 'oldest', 'alphabetical'].map((optionValue) => (
                                <button
                                    key={optionValue}
                                    className={`block w-full text-left px-3 py-2 transition-colors ${sortOption === optionValue
                                        ? (isDarkMode ? 'bg-blue-600' : 'bg-blue-100 text-blue-700 font-medium')
                                        : (isDarkMode ? 'hover:bg-gray-700' : 'hover:bg-gray-100')
                                        }`}
                                    onClick={() => selectSortOption(optionValue)}
                                >
                                    {optionValue.charAt(0).toUpperCase() + optionValue.slice(1)}
                                </button>
                            ))}
                        </div>
                    )}
                </div>
            </div>
            <div className="flex-1 overflow-y-auto pb-6 custom-scrollbar-dark dark:custom-scrollbar">
                {error ? (
                    <div className={`flex flex-col items-center justify-center h-full text-center ${isDarkMode ? 'text-red-400' : 'text-red-600'}`}>
                        <FiXCircle size={40} className="mb-4 opacity-70" />
                        <p className="text-lg mb-4">{error}</p>
                        <button
                            onClick={handleRetry}
                            className={`px-4 py-2 rounded-lg transition-colors text-white ${isDarkMode ? 'bg-blue-600 hover:bg-blue-700' : 'bg-blue-500 hover:bg-blue-600'
                                }`}
                        >
                            Try Again
                        </button>
                    </div>
                ) : filteredGpts.length === 0 ? (
                    <div className={`flex flex-col items-center justify-center h-full text-center ${isDarkMode ? 'text-gray-400' : 'text-gray-500'}`}>
                        <FiHeart size={40} className={`mb-4 opacity-50 ${isDarkMode ? 'text-gray-600' : 'text-gray-400'}`} />
                        <p className="text-lg mb-2">
                            {searchTerm ? `No favorites matching "${searchTerm}"` : "You don't have any favorite GPTs yet"}
                        </p>
                        <p className="text-sm">
                            {searchTerm ? "Try a different search term." : "Add GPTs to your favorites for quick access."}
                        </p>
                        {!searchTerm && (
                            <button
                                onClick={() => navigate('/user/collections')}
                                className={`mt-6 px-4 py-2 rounded-lg transition-colors text-white ${isDarkMode ? 'bg-blue-600 hover:bg-blue-700' : 'bg-blue-500 hover:bg-blue-600'
                                    }`}
                            >
                                Browse Collections
                            </button>
                        )}
                    </div>
                ) : (
                    <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4 sm:gap-6">
                        {filteredGpts.map((gpt) => (
                            <FavoriteCard
                                key={gpt._id}
                                gpt={gpt}
                                formatDate={formatDate}
                                onChatClick={handleChatClick}
                                onRemoveFavorite={handleRemoveFavorite}
                                onMoveToFolder={handleMoveToFolder}
                                isDarkMode={isDarkMode}
                            />
                        ))}
                    </div>
                )}
            </div>
            {showMoveModal && gptToMove && (
                <MoveToFolderModal
                    isOpen={showMoveModal}
                    onClose={() => { setShowMoveModal(false); setGptToMove(null); }}
                    gpt={gptToMove}
                    existingFolders={folders.filter(f => f !== 'All')}
                    onSuccess={handleGptMoved}
                />
            )}
        </div>
    );
};
export default FavoritesPage;
````

## File: frontend/src/components/User/HistoryPage.jsx
````javascript
import React, { useState, useEffect, useMemo, useCallback, memo, useRef } from 'react';
import { FiSearch, FiMessageSquare, FiClock, FiCalendar, FiTrash2, FiXCircle, FiExternalLink, FiArrowRight } from 'react-icons/fi';
import { IoEllipse, IoPersonCircleOutline, IoSparkles, IoClose } from 'react-icons/io5';
import { useNavigate } from 'react-router-dom';
import { useTheme } from '../../context/ThemeContext';
import { axiosInstance } from '../../api/axiosInstance';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
// Memoized Conversation Item Component
const ConversationItem = memo(({ conv, formatTimestamp, onDelete, isDarkMode, navigate }) => (
    <div
        className={`p-4 rounded-lg border mb-3 cursor-pointer transition-all group ${isDarkMode
                ? 'bg-gray-800/50 border-gray-700 hover:bg-gray-700/70 hover:border-gray-600'
                : 'bg-white border-gray-200 hover:bg-gray-50 hover:border-gray-300'
            }`}
        onClick={() => navigate(`/user/chat?gptId=${conv.gptId}&loadHistory=true`, {
            state: { fromHistory: true }
        })}
    >
        <div className="flex items-center justify-between mb-2">
            <h3 className={`font-semibold truncate mr-4 group-hover:text-blue-600 dark:group-hover:text-blue-400 transition-colors ${isDarkMode ? 'text-white' : 'text-gray-800'}`}>{conv.gptName}</h3>
            <span className={`text-xs flex-shrink-0 ${isDarkMode ? 'text-gray-400' : 'text-gray-500'}`}>
                {formatTimestamp(conv.timestamp)}
            </span>
        </div>
        <p className={`text-sm line-clamp-2 mb-3 ${isDarkMode ? 'text-gray-300' : 'text-gray-600'}`}>
            <span className={isDarkMode ? 'text-gray-500' : 'text-gray-400'}>Last:</span> {conv.lastMessage}
        </p>
        <div className="flex items-center justify-between text-xs">
            <div className="flex items-center gap-3">
                <span className={`flex items-center gap-1 ${isDarkMode ? 'text-gray-400' : 'text-gray-500'}`}>
                    <FiMessageSquare size={13} /> {conv.messageCount} msgs
                </span>
                <span className={`px-1.5 py-0.5 rounded flex items-center gap-1 ${isDarkMode ? 'bg-gray-700 text-gray-200' : 'bg-gray-100 text-gray-600'}`}>
                    {conv.model}
                </span>
            </div>
            <button
                onClick={(e) => onDelete(conv, e)}
                className={`p-1 rounded-full opacity-0 group-hover:opacity-100 focus:opacity-100 transition-opacity ${isDarkMode
                        ? 'text-red-400 hover:bg-red-900/30'
                        : 'text-red-500 hover:bg-red-100'
                    }`}
                title="Delete conversation"
            >
                <FiTrash2 size={16} />
            </button>
        </div>
        <FiExternalLink className={`absolute top-3 right-3 opacity-0 group-hover:opacity-50 transition-opacity ${isDarkMode ? 'text-gray-500' : 'text-gray-400'}`} size={14} />
    </div>
));
// New component to display a single message
const MessageItem = memo(({ message, isDarkMode, userProfilePic, gptImageUrl }) => (
    <div className={`flex items-start mb-4 ${message.role === 'user' ? 'justify-end' : 'justify-start'}`}>
        {message.role === 'assistant' && (
            <div className={`flex-shrink-0 w-8 h-8 rounded-full flex items-center justify-center mr-2 ${isDarkMode ? 'bg-gray-700' : 'bg-gray-300'}`}>
                {gptImageUrl ? (
                    <img src={gptImageUrl} alt="GPT" className="w-full h-full rounded-full object-cover" />
                ) : (
                    <IoSparkles size={16} className={isDarkMode ? 'text-blue-400' : 'text-blue-600'} />
                )}
            </div>
        )}
        <div
            className={`max-w-[80%] p-3 rounded-lg ${message.role === 'user'
                    ? (isDarkMode ? 'bg-blue-600 text-white ml-2' : 'bg-blue-500 text-white ml-2')
                    : (isDarkMode ? 'bg-gray-700 text-gray-100' : 'bg-gray-200 text-gray-800')
                }`}
        >
            <ReactMarkdown
                remarkPlugins={[remarkGfm]}
                components={{
                    p: ({ node, children }) => <p className="mb-2 last:mb-0">{children}</p>,
                    a: ({ node, ...props }) => <a className="text-blue-400 hover:underline" {...props} />,
                    code({ node, inline, className, children, ...props }) {
                        return inline ? (
                            <code className={`px-1 rounded ${isDarkMode ? 'bg-gray-600' : 'bg-gray-300'} ${className}`} {...props}>
                                {children}
                            </code>
                        ) : (
                            <pre className={`p-2 rounded overflow-x-auto my-2 text-sm ${isDarkMode ? 'bg-black/30' : 'bg-gray-100'} ${className}`} {...props}>
                                <code>{children}</code>
                            </pre>
                        );
                    }
                }}
            >
                {message.content}
            </ReactMarkdown>
        </div>
        {message.role === 'user' && (
            <div className={`flex-shrink-0 w-8 h-8 rounded-full overflow-hidden border ml-2 ${isDarkMode ? 'border-white/20 bg-gray-700' : 'border-gray-300 bg-gray-300'}`}>
                {userProfilePic ? (
                    <img src={userProfilePic} alt="You" className="w-full h-full object-cover" />
                ) : (
                    <div className={`w-full h-full flex items-center justify-center`}>
                        <IoPersonCircleOutline size={16} className={isDarkMode ? 'text-gray-300' : 'text-gray-600'} />
                    </div>
                )}
            </div>
        )}
    </div>
));
const HistoryPage = () => {
    const [conversations, setConversations] = useState([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);
    const [searchTerm, setSearchTerm] = useState('');
    const [filterPeriod, setFilterPeriod] = useState('all');
    const [showDeleteConfirm, setShowDeleteConfirm] = useState(false);
    const [selectedConversation, setSelectedConversation] = useState(null);
    const [conversationMessages, setConversationMessages] = useState([]);
    const [loadingMessages, setLoadingMessages] = useState(false);
    const messagesEndRef = useRef(null);
    const navigate = useNavigate();
    const { isDarkMode } = useTheme();
    const user = JSON.parse(localStorage.getItem('user'));
    // Scroll to bottom when viewing conversation
    useEffect(() => {
        if (messagesEndRef.current) {
            messagesEndRef.current.scrollIntoView({ behavior: "smooth" });
        }
    }, [conversationMessages]);
    // Memoize the fetch function to prevent unnecessary recreations
    const fetchConversationHistory = useCallback(async () => {
        try {
            setError(null);
            const response = await axiosInstance.get(`/api/chat-history/user/${user._id}`, {
                withCredentials: true
            });
            if (response.data && response.data.success) {
                const formattedConversations = response.data.conversations.map(conv => ({
                    id: conv._id,
                    gptId: conv.gptId,
                    gptName: conv.gptName,
                    lastMessage: conv.lastMessage,
                    timestamp: new Date(conv.updatedAt),
                    messageCount: conv.messages?.length || 0,
                    model: conv.model,
                    summary: conv.summary,
                    messages: conv.messages || []
                }));
                setConversations(formattedConversations);
            } else {
                throw new Error('Failed to fetch conversations');
            }
        } catch (error) {
            console.error("Error fetching conversation history:", error);
            setError("Failed to load your conversation history");
        } finally {
            setLoading(false);
        }
    }, [user?._id]);
    // Function to fetch full conversation details
    const fetchConversationDetails = useCallback(async (conversationId) => {
        if (!user?._id || !conversationId) return;
        try {
            setLoadingMessages(true);
            const response = await axiosInstance.get(`/api/chat-history/conversation/${user._id}/${conversationId}`, {
                withCredentials: true
            });
            if (response.data && response.data.success) {
                setConversationMessages(response.data.conversation.messages || []);
            } else {
                throw new Error('Failed to fetch conversation details');
            }
        } catch (error) {
            console.error("Error fetching conversation details:", error);
            setConversationMessages([]);
        } finally {
            setLoadingMessages(false);
        }
    }, [user]);
    // Use the memoized fetch function in useEffect
    useEffect(() => {
        if (user?._id) {
            fetchConversationHistory();
        } else {
            setLoading(false); // Set loading to false if no user
        }
    }, [user, fetchConversationHistory]);
    const filteredConversations = useMemo(() => {
        let filtered = [...conversations];
        if (searchTerm) {
            const lowerSearchTerm = searchTerm.toLowerCase();
            filtered = filtered.filter(conv =>
                conv.gptName.toLowerCase().includes(lowerSearchTerm) ||
                conv.lastMessage.toLowerCase().includes(lowerSearchTerm) ||
                (conv.summary && conv.summary.toLowerCase().includes(lowerSearchTerm))
            );
        }
        if (filterPeriod !== 'all') {
            const now = new Date();
            let cutoffDate;
            switch (filterPeriod) {
                case 'today': cutoffDate = new Date(now.getFullYear(), now.getMonth(), now.getDate()); break;
                case 'week': {
                    const startOfToday = new Date(now.getFullYear(), now.getMonth(), now.getDate());
                    cutoffDate = new Date(startOfToday.setDate(startOfToday.getDate() - 7));
                    break;
                }
                case 'month': {
                    const startOfToday = new Date(now.getFullYear(), now.getMonth(), now.getDate());
                    cutoffDate = new Date(startOfToday.setMonth(startOfToday.getMonth() - 1));
                    break;
                }
                default: cutoffDate = null;
            }
            if (cutoffDate) {
                filtered = filtered.filter(conv => new Date(conv.timestamp) >= cutoffDate);
            }
        }
        return filtered.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
    }, [conversations, searchTerm, filterPeriod]);
    const formatTimestamp = useCallback((timestamp) => {
        try {
            const date = new Date(timestamp);
            if (isNaN(date)) return 'Invalid Date';
            const now = new Date();
            const diffMs = now - date;
            const diffDays = Math.floor(diffMs / (1000 * 60 * 60 * 24));
            if (diffDays === 0) return date.toLocaleTimeString([], { hour: 'numeric', minute: '2-digit', hour12: true }).toLowerCase();
            if (diffDays === 1) return 'Yesterday';
            if (diffDays < 7) return `${diffDays} days ago`;
            return date.toLocaleDateString([], { month: 'short', day: 'numeric' });
        } catch (e) {
            console.error("Error formatting timestamp:", timestamp, e);
            return 'Unknown Date';
        }
    }, []);
    const confirmDeleteConversation = useCallback((conv, e) => {
        e.stopPropagation();
        setSelectedConversation(conv);
        setShowDeleteConfirm(true);
    }, []);
    const handleDeleteConversation = useCallback(async () => {
        if (!selectedConversation || !user?._id) return;
        try {
            const response = await axiosInstance.delete(
                `/api/chat-history/${user._id}/${selectedConversation.id}`,
                { withCredentials: true }
            );
            if (response.data && response.data.success) {
                setConversations(prev => prev.filter(c => c.id !== selectedConversation.id));
                setShowDeleteConfirm(false);
                setSelectedConversation(null);
            } else {
                throw new Error('Failed to delete conversation');
            }
        } catch (error) {
            console.error('Error deleting conversation:', error);
        }
    }, [selectedConversation, user]);
    const cancelDelete = useCallback(() => {
        setShowDeleteConfirm(false);
        setSelectedConversation(null);
    }, []);
    const handleSearchChange = useCallback((e) => setSearchTerm(e.target.value), []);
    const handleFilterChange = useCallback((e) => setFilterPeriod(e.target.value), []);
    const handleRetry = useCallback(() => {
        setLoading(true);
        fetchConversationHistory();
    }, [fetchConversationHistory]);
    const handleContinueConversation = useCallback((conv) => {
        navigate(`/user/chat?gptId=${conv.gptId}&loadHistory=true`, {
            state: { fromHistory: true }
        });
    }, [navigate]);
    if (!user?._id) {
        return (
            <div className={`flex flex-col items-center justify-center h-full ${isDarkMode ? 'bg-black text-white' : 'bg-gray-50 text-gray-900'
                }`}>
                <p className="text-lg mb-4">Please log in to view your conversation history</p>
                <button
                    onClick={() => navigate('/login')}
                    className={`px-4 py-2 rounded-lg transition-colors text-white ${isDarkMode ? 'bg-blue-600 hover:bg-blue-700' : 'bg-blue-500 hover:bg-blue-600'
                        }`}
                >
                    Log In
                </button>
            </div>
        );
    }
    if (loading && conversations.length === 0) {
        return (
            <div className={`flex items-center justify-center h-full ${isDarkMode ? 'bg-black text-white' : 'bg-gray-50 text-gray-700'
                }`}>
                <div className={`animate-spin rounded-full h-10 w-10 border-t-2 border-b-2 ${isDarkMode ? 'border-blue-500' : 'border-blue-600'
                    }`}></div>
            </div>
        );
    }
    return (
        <div className={`flex flex-col h-full p-4 sm:p-6 overflow-hidden transition-colors duration-300 ${isDarkMode ? 'bg-black text-white' : 'bg-gray-50 text-gray-900'
            }`}>
            <div className="mb-5 flex-shrink-0 text-center md:text-left">
                <h1 className="text-xl sm:text-2xl font-bold">Conversation History</h1>
                <p className={`text-sm mt-1 ${isDarkMode ? 'text-gray-400' : 'text-gray-600'}`}>
                    View and continue your previous conversations
                </p>
            </div>
            <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between mb-6 gap-4 flex-shrink-0">
                <div className="relative w-full sm:w-auto sm:flex-1 max-w-lg">
                    <FiSearch className={`absolute left-3 top-1/2 transform -translate-y-1/2 ${isDarkMode ? 'text-gray-400' : 'text-gray-500'}`} size={18} />
                    <input
                        type="text"
                        placeholder="Search conversations (name, message, summary)..."
                        value={searchTerm}
                        onChange={handleSearchChange}
                        className={`w-full pl-10 pr-4 py-2.5 rounded-lg border focus:ring-2 focus:ring-blue-500 focus:border-blue-500 transition-all text-sm sm:text-base ${isDarkMode
                                ? 'bg-gray-700 border-gray-600 text-white placeholder-gray-400'
                                : 'bg-white border-gray-300 text-gray-900 placeholder-gray-500'
                            }`}
                    />
                </div>
                <div className="flex items-center gap-2 self-end sm:self-center">
                    <FiCalendar className={isDarkMode ? 'text-gray-400' : 'text-gray-500'} size={16} />
                    <select
                        value={filterPeriod}
                        onChange={handleFilterChange}
                        className={`border rounded-lg py-1.5 px-3 focus:ring-1 focus:ring-blue-500 focus:border-blue-500 outline-none transition-colors text-sm appearance-none pr-8 ${isDarkMode
                                ? 'bg-gray-700 border-gray-600 text-white'
                                : 'bg-white border-gray-300 text-gray-900'
                            }`}
                        style={{ backgroundImage: `url('data:image/svg+xml;utf8,<svg fill="${isDarkMode ? 'white' : 'black'}" height="20" viewBox="0 0 20 20" width="20" xmlns="http://www.w3.org/2000/svg"><path d="M7 10l5 5 5-5z"/><path d="M0 0h24v24H0z" fill="none"/></svg>')`, backgroundRepeat: 'no-repeat', backgroundPosition: 'right 0.5rem center', backgroundSize: '1em 1em' }}
                    >
                        <option value="all">All Time</option>
                        <option value="today">Today</option>
                        <option value="week">This Week</option>
                        <option value="month">This Month</option>
                    </select>
                </div>
            </div>
            <div className="flex-1 overflow-y-auto no-scrollbar pb-4">
                {loading ? (
                    <div className="space-y-3 animate-pulse">
                        {[...Array(4)].map((_, i) => (
                            <div key={i} className={`p-4 rounded-lg border ${isDarkMode ? 'bg-gray-800/50 border-gray-700' : 'bg-white border-gray-200'}`}>
                                <div className="flex items-center justify-between mb-2">
                                    <div className={`h-4 rounded w-1/3 ${isDarkMode ? 'bg-gray-700' : 'bg-gray-300'}`}></div>
                                    <div className={`h-3 rounded w-1/4 ${isDarkMode ? 'bg-gray-700' : 'bg-gray-300'}`}></div>
                                </div>
                                <div className={`h-3 rounded w-full mb-3 ${isDarkMode ? 'bg-gray-700' : 'bg-gray-300'}`}></div>
                                <div className="flex items-center justify-between text-xs">
                                    <div className="flex items-center gap-3">
                                        <div className={`h-3 rounded w-16 ${isDarkMode ? 'bg-gray-700' : 'bg-gray-300'}`}></div>
                                        <div className={`h-4 px-4 py-0.5 rounded ${isDarkMode ? 'bg-gray-700' : 'bg-gray-200'}`}></div>
                                    </div>
                                    <div className={`h-6 w-6 rounded-full ${isDarkMode ? 'bg-gray-700' : 'bg-gray-200'}`}></div>
                                </div>
                            </div>
                        ))}
                    </div>
                ) : error ? (
                    <div className={`flex flex-col items-center justify-center h-full text-center ${isDarkMode ? 'text-red-400' : 'text-red-600'}`}>
                        <FiXCircle size={40} className="mb-4 opacity-70" />
                        <p className="text-lg mb-4">{error}</p>
                        <button
                            onClick={handleRetry}
                            className={`px-4 py-2 rounded-lg transition-colors text-white ${isDarkMode ? 'bg-blue-600 hover:bg-blue-700' : 'bg-blue-500 hover:bg-blue-600'
                                }`}
                        >
                            Try Again
                        </button>
                    </div>
                ) : filteredConversations.length === 0 ? (
                    <div className={`flex flex-col items-center justify-center h-full text-center py-12 ${isDarkMode ? 'text-gray-400' : 'text-gray-500'}`}>
                        <FiClock size={40} className={`mb-4 opacity-50 ${isDarkMode ? 'text-gray-600' : 'text-gray-400'}`} />
                        <p className="text-lg mb-2">
                            {searchTerm || filterPeriod !== 'all' ? `No conversations matching criteria` : "No conversation history yet"}
                        </p>
                        <p className="text-sm max-w-md">
                            {searchTerm || filterPeriod !== 'all'
                                ? "Try adjusting your search or time filter."
                                : "Start chatting with GPTs to build your history."}
                        </p>
                        {!searchTerm && filterPeriod === 'all' && (
                            <button
                                onClick={() => navigate('/user/collections')}
                                className={`mt-6 px-4 py-2 rounded-lg transition-colors text-white ${isDarkMode ? 'bg-blue-600 hover:bg-blue-700' : 'bg-blue-500 hover:bg-blue-600'
                                    }`}
                            >
                                Browse Collections
                            </button>
                        )}
                    </div>
                ) : (
                    <div className="space-y-3">
                        {filteredConversations.map((conv) => (
                            <ConversationItem
                                key={conv.id}
                                conv={conv}
                                formatTimestamp={formatTimestamp}
                                onDelete={confirmDeleteConversation}
                                isDarkMode={isDarkMode}
                                navigate={navigate}
                            />
                        ))}
                    </div>
                )}
            </div>
            {/* Delete Confirmation Modal */}
            {showDeleteConfirm && selectedConversation && (
                <div className="fixed inset-0 bg-black/60 dark:bg-black/80 flex items-center justify-center z-50 p-4">
                    <div className={`p-6 rounded-lg shadow-xl w-full max-w-sm border ${isDarkMode ? 'bg-gray-800 border-gray-700' : 'bg-white border-gray-200'
                        }`}>
                        <h3 className={`text-lg font-semibold mb-2 ${isDarkMode ? 'text-white' : 'text-gray-900'}`}>Delete Conversation?</h3>
                        <p className={`text-sm mb-5 ${isDarkMode ? 'text-gray-300' : 'text-gray-600'}`}>
                            Are you sure you want to delete the conversation with "{selectedConversation.gptName}"? This action cannot be undone.
                        </p>
                        <div className="flex justify-end gap-3">
                            <button
                                onClick={cancelDelete}
                                className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors ${isDarkMode
                                        ? 'bg-gray-600 hover:bg-gray-500 text-white'
                                        : 'bg-gray-100 hover:bg-gray-200 text-gray-700 border border-gray-300'
                                    }`}
                            >
                                Cancel
                            </button>
                            <button
                                onClick={handleDeleteConversation}
                                className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors bg-red-600 hover:bg-red-700 text-white`}
                            >
                                Delete
                            </button>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
};
export default HistoryPage;
````

## File: frontend/src/components/User/MoveToFolderModal.jsx
````javascript
import React, { useState, useEffect, useRef, useCallback } from 'react';
import { FiFolder, FiFolderPlus, FiX, FiCheck, FiPlus } from 'react-icons/fi';
import { axiosInstance } from '../../api/axiosInstance';
import { useTheme } from '../../context/ThemeContext';
const MoveToFolderModal = ({ isOpen, onClose, gpt, existingFolders, onSuccess }) => {
    const [selectedFolder, setSelectedFolder] = useState(gpt.folder || 'Uncategorized');
    const [newFolder, setNewFolder] = useState('');
    const [isCreatingNew, setIsCreatingNew] = useState(false);
    const [isLoading, setIsLoading] = useState(false);
    const [error, setError] = useState(null);
    const modalRef = useRef(null);
    const { isDarkMode } = useTheme();
    useEffect(() => {
        // Reset state when modal opens
        if (isOpen) {
            setSelectedFolder(gpt.folder || 'Uncategorized');
            setNewFolder('');
            setIsCreatingNew(false);
            setError(null);
        }
    }, [isOpen, gpt]);
    // Handle click outside to close
    useEffect(() => {
        const handleClickOutside = (e) => {
            if (modalRef.current && !modalRef.current.contains(e.target)) {
                onClose();
            }
        };
        if (isOpen) {
            document.addEventListener('mousedown', handleClickOutside);
        }
        return () => {
            document.removeEventListener('mousedown', handleClickOutside);
        };
    }, [isOpen, onClose]);
    // Handle escape key to close
    useEffect(() => {
        const handleEscKey = (e) => {
            if (e.key === 'Escape') {
                onClose();
            }
        };
        if (isOpen) {
            document.addEventListener('keydown', handleEscKey);
        }
        return () => {
            document.removeEventListener('keydown', handleEscKey);
        };
    }, [isOpen, onClose]);
    const handleSubmit = useCallback(async (e) => {
        e.preventDefault();
        setIsLoading(true);
        setError(null);
        try {
            // Ensure folderName is null if 'Uncategorized' or empty string is chosen/created
            let finalFolderName = isCreatingNew ? newFolder.trim() : selectedFolder;
            if (finalFolderName === 'Uncategorized' || finalFolderName === '') {
                finalFolderName = null;
            }
            // Call backend API to update the folder on the UserGptAssignment record
            const response = await axiosInstance.patch(`/api/custom-gpts/user/assigned/${gpt._id}/folder`,
                { folder: finalFolderName }, // Send finalFolderName (can be null)
                { withCredentials: true }
            );
            if (response.data.success) {
                // Pass the updated GPT info (including the new folder) back to parent
                // Also pass the potentially new folder name if one was created
                onSuccess({ ...gpt, folder: response.data.assignment.folder }, isCreatingNew ? finalFolderName : null);
                onClose();
            } else {
                setError(response.data.message || 'Failed to move GPT to folder');
            }
        } catch (error) {
            console.error('Error moving GPT to folder:', error);
            setError(error.response?.data?.message || 'An error occurred while moving GPT to folder');
        } finally {
            setIsLoading(false);
        }
    }, [gpt, selectedFolder, newFolder, isCreatingNew, onSuccess, onClose]);
    if (!isOpen) return null;
    return (
        <div className={`fixed inset-0 z-50 flex items-center justify-center bg-black/50 backdrop-blur-sm transition-opacity ${isOpen ? 'opacity-100' : 'opacity-0 pointer-events-none'}`}>
            <div
                ref={modalRef}
                className={`w-full max-w-md rounded-lg shadow-xl p-6 transition-transform ${isDarkMode ? 'bg-gray-800 text-white' : 'bg-white text-gray-800'
                    } ${isOpen ? 'scale-100' : 'scale-95'}`}
            >
                <div className="flex justify-between items-center mb-5">
                    <h3 className="text-lg font-semibold flex items-center gap-2">
                        <FiFolder />
                        Move to Folder
                    </h3>
                    <button
                        onClick={onClose}
                        className={`p-1.5 rounded-full transition-colors ${isDarkMode
                                ? 'hover:bg-gray-700 text-gray-400 hover:text-white'
                                : 'hover:bg-gray-100 text-gray-500 hover:text-gray-700'
                            }`}
                    >
                        <FiX size={18} />
                    </button>
                </div>
                <p className={`text-sm mb-5 ${isDarkMode ? 'text-gray-300' : 'text-gray-600'}`}>
                    Moving: <span className="font-medium">{gpt.name}</span>
                </p>
                {error && (
                    <div className={`mb-4 p-2 rounded-md text-sm ${isDarkMode ? 'bg-red-900/40 text-red-300 border border-red-800/50' : 'bg-red-50 text-red-600 border border-red-100'
                        }`}>
                        {error}
                    </div>
                )}
                <form onSubmit={handleSubmit}>
                    <div className="mb-4">
                        <label className={`block mb-2 text-sm font-medium ${isDarkMode ? 'text-gray-300' : 'text-gray-700'}`}>
                            Select Folder
                        </label>
                        <div className="grid grid-cols-2 gap-2 mb-3">
                            {['Uncategorized', ...existingFolders].map(folder => (
                                <button
                                    key={folder}
                                    type="button"
                                    onClick={() => {
                                        setSelectedFolder(folder);
                                        setIsCreatingNew(false);
                                    }}
                                    className={`flex items-center p-2 rounded-md transition-colors ${selectedFolder === folder && !isCreatingNew
                                            ? (isDarkMode ? 'bg-blue-600 text-white' : 'bg-blue-100 text-blue-700')
                                            : (isDarkMode ? 'bg-gray-700 hover:bg-gray-600' : 'bg-gray-100 hover:bg-gray-200')
                                        }`}
                                >
                                    <FiFolder className="mr-2" size={16} />
                                    <span className="truncate">{folder}</span>
                                </button>
                            ))}
                            <button
                                type="button"
                                onClick={() => setIsCreatingNew(true)}
                                className={`flex items-center p-2 rounded-md transition-colors ${isCreatingNew
                                        ? (isDarkMode ? 'bg-blue-600 text-white' : 'bg-blue-100 text-blue-700')
                                        : (isDarkMode ? 'bg-gray-700 hover:bg-gray-600' : 'bg-gray-100 hover:bg-gray-200')
                                    }`}
                            >
                                <FiPlus className="mr-2" size={16} />
                                <span>New Folder</span>
                            </button>
                        </div>
                        {isCreatingNew && (
                            <div className="mt-3">
                                <label className={`block mb-2 text-sm font-medium ${isDarkMode ? 'text-gray-300' : 'text-gray-700'}`}>
                                    New Folder Name
                                </label>
                                <input
                                    type="text"
                                    value={newFolder}
                                    onChange={(e) => setNewFolder(e.target.value)}
                                    className={`w-full p-2 rounded-md border ${isDarkMode
                                            ? 'bg-gray-700 border-gray-600 text-white'
                                            : 'bg-white border-gray-300 text-gray-900'
                                        }`}
                                    placeholder="Enter folder name"
                                    required
                                />
                            </div>
                        )}
                    </div>
                    <div className="flex justify-end space-x-3">
                        <button
                            type="button"
                            onClick={onClose}
                            className={`px-4 py-2 rounded-md transition-colors ${isDarkMode
                                    ? 'bg-gray-700 hover:bg-gray-600 text-white'
                                    : 'bg-gray-200 hover:bg-gray-300 text-gray-700'
                                }`}
                            disabled={isLoading}
                        >
                            Cancel
                        </button>
                        <button
                            type="submit"
                            className={`px-4 py-2 rounded-md transition-colors text-white ${isDarkMode
                                    ? 'bg-blue-600 hover:bg-blue-700'
                                    : 'bg-blue-500 hover:bg-blue-600'
                                } ${isLoading ? 'opacity-70 cursor-not-allowed' : ''}`}
                            disabled={isLoading || (isCreatingNew && !newFolder.trim())}
                        >
                            {isLoading ? 'Moving...' : 'Move'}
                        </button>
                    </div>
                </form>
            </div>
        </div>
    );
};
export default MoveToFolderModal;
````

## File: frontend/src/components/User/SettingsPage.jsx
````javascript
import React, { useState, useEffect, useCallback, memo, useRef } from 'react';
import { useAuth } from '../../context/AuthContext';
import { useTheme } from '../../context/ThemeContext';
import {
  FiUser, FiBell, FiMonitor, FiChevronRight,
  FiEdit2, FiCamera, FiCheck, FiInfo, FiXCircle, FiCheckCircle, FiLoader
} from 'react-icons/fi';
import { axiosInstance } from '../../api/axiosInstance';
// Account settings section component
const AccountSettings = memo(({
  formData,
  handleInputChange,
  handleAccountUpdate,
  handlePasswordChange,
  handleImageUpload,
  isDarkMode,
  toggleTheme,
  message,
  setMessage,
  isUpdatingAccount,
  isUpdatingPassword
}) => {
  const profileImageInputRef = useRef(null);
  const triggerImageUpload = () => {
    profileImageInputRef.current?.click();
  };
  return (
    <div className="animate-fadeIn">
      <div className="mb-8">
        <h2 className={`text-xl font-semibold mb-1 ${isDarkMode ? 'text-white' : 'text-gray-900'}`}>Account Information</h2>
        <p className={`text-sm ${isDarkMode ? 'text-gray-400' : 'text-gray-600'}`}>Manage your personal information and profile picture</p>
      </div>
      <div className="mb-8">
        <div className="flex items-center justify-center md:justify-start mb-6">
          <div className="relative">
            <div className={`w-24 h-24 rounded-full overflow-hidden border-2 ${isDarkMode
                ? 'bg-gradient-to-br from-blue-800 to-purple-800 border-white/10'
                : 'bg-gradient-to-br from-blue-100 to-purple-100 border-gray-300'
              }`}>
              {formData.profileImage ? (
                <img
                  src={formData.profileImage instanceof File ? URL.createObjectURL(formData.profileImage) : formData.profileImage}
                  alt="Profile"
                  className="w-full h-full object-cover"
                />
              ) : (
                <div className="w-full h-full flex items-center justify-center">
                  <span className={`text-3xl font-semibold ${isDarkMode ? 'text-white/70' : 'text-gray-500'}`}>
                    {formData.name ? formData.name.charAt(0).toUpperCase() : 'U'}
                  </span>
                </div>
              )}
            </div>
            <button
              type="button"
              onClick={triggerImageUpload}
              className={`absolute bottom-0 right-0 p-1.5 rounded-full cursor-pointer border-2 hover:bg-blue-700 transition-colors ${isDarkMode
                  ? 'bg-blue-600 border-gray-800 text-white'
                  : 'bg-blue-500 border-white text-white'
                }`}
              title="Change profile picture"
            >
              <FiCamera size={16} />
            </button>
            <input
              ref={profileImageInputRef}
              type="file"
              accept="image/*"
              onChange={handleImageUpload}
              className="hidden"
              name="profileImageInput"
            />
          </div>
        </div>
        <form onSubmit={handleAccountUpdate} className="space-y-5">
          <div>
            <label className={`block text-sm font-medium mb-1.5 ${isDarkMode ? 'text-gray-300' : 'text-gray-700'}`}>Full Name</label>
            <input
              type="text"
              name="name"
              value={formData.name}
              onChange={handleInputChange}
              className={`w-full border rounded-lg py-2.5 px-3 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition duration-200 ${isDarkMode
                  ? 'bg-gray-800 border-gray-700 text-white placeholder-gray-500'
                  : 'bg-white border-gray-300 text-gray-900 placeholder-gray-400'
                }`}
              placeholder="Your full name"
              disabled={isUpdatingAccount}
            />
          </div>
          <div>
            <label className={`block text-sm font-medium mb-1.5 ${isDarkMode ? 'text-gray-300' : 'text-gray-700'}`}>Email Address</label>
            <input
              type="email"
              name="email"
              value={formData.email}
              onChange={handleInputChange}
              className={`w-full border rounded-lg py-2.5 px-3 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition duration-200 ${isDarkMode
                  ? 'bg-gray-800 border-gray-700 text-white placeholder-gray-500'
                  : 'bg-white border-gray-300 text-gray-900 placeholder-gray-400'
                }`}
              placeholder="your.email@example.com"
              disabled={isUpdatingAccount}
            />
            <p className={`mt-1 text-xs ${isDarkMode ? 'text-gray-500' : 'text-gray-500'}`}>Your email address is used for notifications and account recovery</p>
          </div>
          <div className="pt-2">
            <button
              type="submit"
              disabled={isUpdatingAccount || isUpdatingPassword}
              className={`text-white py-2.5 px-5 rounded-lg transition duration-200 font-medium flex items-center justify-center min-w-[130px] ${isDarkMode
                  ? 'bg-blue-600 hover:bg-blue-700'
                  : 'bg-blue-500 hover:bg-blue-600'
                } ${isUpdatingAccount ? 'opacity-70 cursor-not-allowed' : ''}`}
            >
              {isUpdatingAccount ? (
                <>
                  <FiLoader className="animate-spin mr-2" size={18} /> Saving...
                </>
              ) : (
                'Save Changes'
              )}
            </button>
          </div>
        </form>
      </div>
      <div className={`border-t pt-8 mb-8 ${isDarkMode ? 'border-gray-700' : 'border-gray-200'}`}>
        <h2 className={`text-xl font-semibold mb-1 ${isDarkMode ? 'text-white' : 'text-gray-900'}`}>Appearance</h2>
        <p className={`text-sm mb-5 ${isDarkMode ? 'text-gray-400' : 'text-gray-600'}`}>Customize how the application looks</p>
        <div className="space-y-5">
          <div className="flex justify-between items-center">
            <div>
              <h3 className={`text-base font-medium ${isDarkMode ? 'text-gray-100' : 'text-gray-800'}`}>Dark Mode</h3>
              <p className={`text-sm ${isDarkMode ? 'text-gray-400' : 'text-gray-600'}`}>Use dark theme throughout the application</p>
            </div>
            <label className="relative inline-flex items-center cursor-pointer">
              <input
                type="checkbox"
                name="darkMode"
                checked={isDarkMode}
                onChange={() => toggleTheme()}
                className="sr-only peer"
              />
              <div className={`w-11 h-6 rounded-full peer peer-focus:outline-none peer-focus:ring-2 peer-focus:ring-blue-500 after:content-[''] after:absolute after:top-[2px] after:start-[2px] after:border after:rounded-full after:h-5 after:w-5 after:transition-all ${isDarkMode
                  ? 'bg-blue-600 after:translate-x-full after:border-white after:bg-white'
                  : 'bg-gray-300 after:border-gray-400 after:bg-white'
                }`}></div>
            </label>
          </div>
        </div>
      </div>
      <div className={`border-t pt-8 ${isDarkMode ? 'border-gray-700' : 'border-gray-200'}`}>
        <h2 className={`text-xl font-semibold mb-1 ${isDarkMode ? 'text-white' : 'text-gray-900'}`}>Change Password</h2>
        <p className={`text-sm mb-5 ${isDarkMode ? 'text-gray-400' : 'text-gray-600'}`}>Update your password to maintain account security</p>
        <form onSubmit={handlePasswordChange} className="space-y-5">
          <div>
            <label className={`block text-sm font-medium mb-1.5 ${isDarkMode ? 'text-gray-300' : 'text-gray-700'}`}>Current Password</label>
            <input
              type="password"
              name="currentPassword"
              value={formData.currentPassword}
              onChange={handleInputChange}
              className={`w-full border rounded-lg py-2.5 px-3 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition duration-200 ${isDarkMode
                  ? 'bg-gray-800 border-gray-700 text-white placeholder-gray-500'
                  : 'bg-white border-gray-300 text-gray-900 placeholder-gray-400'
                }`}
              placeholder="••••••••••••"
              disabled={isUpdatingPassword}
            />
          </div>
          <div>
            <label className={`block text-sm font-medium mb-1.5 ${isDarkMode ? 'text-gray-300' : 'text-gray-700'}`}>New Password</label>
            <input
              type="password"
              name="newPassword"
              value={formData.newPassword}
              onChange={handleInputChange}
              className={`w-full border rounded-lg py-2.5 px-3 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition duration-200 ${isDarkMode
                  ? 'bg-gray-800 border-gray-700 text-white placeholder-gray-500'
                  : 'bg-white border-gray-300 text-gray-900 placeholder-gray-400'
                }`}
              placeholder="Minimum 6 characters"
              disabled={isUpdatingPassword}
            />
          </div>
          <div>
            <label className={`block text-sm font-medium mb-1.5 ${isDarkMode ? 'text-gray-300' : 'text-gray-700'}`}>Confirm New Password</label>
            <input
              type="password"
              name="confirmPassword"
              value={formData.confirmPassword}
              onChange={handleInputChange}
              className={`w-full border rounded-lg py-2.5 px-3 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition duration-200 ${isDarkMode
                  ? 'bg-gray-800 border-gray-700 text-white placeholder-gray-500'
                  : 'bg-white border-gray-300 text-gray-900 placeholder-gray-400'
                }`}
              placeholder="••••••••••••"
              disabled={isUpdatingPassword}
            />
          </div>
          <div className="pt-2">
            <button
              type="submit"
              disabled={isUpdatingPassword || isUpdatingAccount}
              className={`text-white py-2.5 px-5 rounded-lg transition duration-200 font-medium flex items-center justify-center min-w-[170px] ${isDarkMode
                  ? 'bg-blue-600 hover:bg-blue-700'
                  : 'bg-blue-500 hover:bg-blue-600'
                } ${isUpdatingPassword ? 'opacity-70 cursor-not-allowed' : ''}`}
            >
              {isUpdatingPassword ? (
                <>
                  <FiLoader className="animate-spin mr-2" size={18} /> Updating...
                </>
              ) : (
                'Update Password'
              )}
            </button>
          </div>
        </form>
      </div>
      {message.text && (
        <div className={`mt-6 p-3 rounded-lg flex items-center gap-3 text-sm ${message.type === 'success'
            ? (isDarkMode ? 'bg-green-900/40 text-green-200 border border-green-700/50' : 'bg-green-100 text-green-700 border border-green-200')
            : (isDarkMode ? 'bg-red-900/40 text-red-200 border border-red-700/50' : 'bg-red-100 text-red-700 border border-red-200')
          }`}>
          {message.type === 'success' ? <FiCheckCircle size={18} /> : <FiXCircle size={18} />}
          <span>{message.text}</span>
          <button onClick={() => setMessage({ text: '', type: '' })} className="ml-auto p-1 rounded-full hover:bg-white/10">
            <FiXCircle size={16} />
          </button>
        </div>
      )}
    </div>
  );
});
const SettingsPage = () => {
  const { user, loading: authLoading, fetchUser } = useAuth();
  const { isDarkMode, toggleTheme } = useTheme();
  const [isLoading, setIsLoading] = useState(true);
  const [isUpdatingAccount, setIsUpdatingAccount] = useState(false);
  const [isUpdatingPassword, setIsUpdatingPassword] = useState(false);
  const [message, setMessage] = useState({ text: '', type: '' });
  const [formData, setFormData] = useState({
    name: '',
    email: '',
    profileImage: null,
    currentPassword: '',
    newPassword: '',
    confirmPassword: '',
  });
  useEffect(() => {
    if (message.text) {
      const timer = setTimeout(() => {
        setMessage({ text: '', type: '' });
      }, 5000);
      return () => clearTimeout(timer);
    }
  }, [message]);
  useEffect(() => {
    if (user) {
      setFormData(prev => ({
        ...prev,
        name: user.name || '',
        email: user.email || '',
        profileImage: user.profilePic || null,
      }));
      setIsLoading(false);
    } else if (!authLoading) {
      setIsLoading(false);
    }
  }, [user, authLoading]);
  const handleInputChange = useCallback((e) => {
    const { name, value, type, checked } = e.target;
    setFormData(prev => ({
      ...prev,
      [name]: type === 'checkbox' ? checked : value
    }));
  }, []);
  const handleImageUpload = useCallback((e) => {
    if (e.target.files && e.target.files[0]) {
      const file = e.target.files[0];
      if (!file.type.startsWith('image/')) {
        setMessage({ text: 'Please select a valid image file.', type: 'error' });
        return;
      }
      if (file.size > 5 * 1024 * 1024) {
        setMessage({ text: 'Image file size should not exceed 5MB.', type: 'error' });
        return;
      }
      setFormData(prev => ({
        ...prev,
        profileImage: file
      }));
      setMessage({ text: '', type: '' });
    }
  }, []);
  const handleAccountUpdate = useCallback(async (e) => {
    e.preventDefault();
    setMessage({ text: '', type: '' });
    setIsUpdatingAccount(true);
    try {
      let profilePicUrl = formData.profileImage instanceof File ? null : formData.profileImage;
      if (formData.profileImage instanceof File) {
        const imageFormData = new FormData();
        imageFormData.append('profileImage', formData.profileImage);
        const uploadResponse = await axiosInstance.post('/api/auth/user/profile-picture', imageFormData, {
          headers: { 'Content-Type': 'multipart/form-data' }
        });
        if (uploadResponse.data.success) {
          profilePicUrl = uploadResponse.data.user.profilePic;
          setFormData(prev => ({ ...prev, profileImage: profilePicUrl }));
        } else {
          throw new Error(uploadResponse.data.message || 'Failed to upload profile picture.');
        }
      }
      const nameChanged = user ? formData.name !== user.name : true;
      const emailChanged = user ? formData.email !== user.email : true;
      if (nameChanged || emailChanged) {
        const profileData = {
          name: formData.name,
          email: formData.email,
        };
        const updateResponse = await axiosInstance.patch('/api/auth/user/profile', profileData);
        if (!updateResponse.data.success) {
          throw new Error(updateResponse.data.message || 'Failed to update profile information.');
        }
      }
      setMessage({ text: 'Account updated successfully!', type: 'success' });
      await fetchUser();
    } catch (error) {
      console.error("Account update failed:", error);
      const errorMsg = error.response?.data?.message || error.message || 'Failed to update account.';
      setMessage({ text: errorMsg, type: 'error' });
    } finally {
      setIsUpdatingAccount(false);
    }
  }, [formData.name, formData.email, formData.profileImage, fetchUser, user]);
  const handlePasswordChange = useCallback(async (e) => {
    e.preventDefault();
    setMessage({ text: '', type: '' });
    if (formData.newPassword !== formData.confirmPassword) {
      setMessage({ text: 'New passwords do not match.', type: 'error' });
      return;
    }
    if (!formData.currentPassword || formData.newPassword.length < 6) {
      setMessage({ text: 'Please fill current password and ensure new password is at least 6 characters.', type: 'error' });
      return;
    }
    setIsUpdatingPassword(true);
    try {
      const response = await axiosInstance.post('/api/auth/user/change-password', {
        currentPassword: formData.currentPassword,
        newPassword: formData.newPassword,
      });
      if (response.data.success) {
        setMessage({ text: 'Password updated successfully!', type: 'success' });
        setFormData(prev => ({
          ...prev,
          currentPassword: '',
          newPassword: '',
          confirmPassword: '',
        }));
      } else {
        throw new Error(response.data.message || 'Failed to update password.');
      }
    } catch (error) {
      console.error("Password change failed:", error);
      const errorMsg = error.response?.data?.message || 'Failed to update password.';
      setMessage({ text: errorMsg, type: 'error' });
    } finally {
      setIsUpdatingPassword(false);
    }
  }, [formData.currentPassword, formData.newPassword, formData.confirmPassword]);
  if (isLoading || authLoading) {
    return (
      <div className={`flex items-center justify-center h-screen ${isDarkMode ? 'bg-black text-white' : 'bg-gray-50 text-gray-700'}`}>
        <div className={`animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 ${isDarkMode ? 'border-blue-500' : 'border-blue-600'}`}></div>
      </div>
    );
  }
  return (
    <div className={`flex flex-col h-full min-h-screen transition-colors duration-300 ${isDarkMode ? 'bg-black text-white' : 'bg-gray-50 text-gray-900'
      }`}>
      <div className="p-4 sm:p-6 md:p-8 lg:p-10 border-b border-gray-200 dark:border-gray-700">
        <h1 className="text-xl sm:text-2xl font-bold">Settings</h1>
      </div>
      <div className="flex-1 p-4 sm:p-6 md:p-8 lg:p-10 overflow-y-auto scrollbar-hide">
        <AccountSettings
          formData={formData}
          handleInputChange={handleInputChange}
          handleAccountUpdate={handleAccountUpdate}
          handlePasswordChange={handlePasswordChange}
          handleImageUpload={handleImageUpload}
          isDarkMode={isDarkMode}
          toggleTheme={toggleTheme}
          message={message}
          setMessage={setMessage}
          isUpdatingAccount={isUpdatingAccount}
          isUpdatingPassword={isUpdatingPassword}
        />
      </div>
    </div>
  );
};
export default SettingsPage;
````

## File: frontend/src/components/User/Sidebar.jsx
````javascript
import React, { useState, useEffect } from 'react';
import {
  IoGridOutline,
  IoFolderOpenOutline,
  IoHeartOutline,
  IoTimeOutline,
  IoExitOutline,
  IoChevronBackOutline,
  IoChevronForwardOutline,
  IoMenuOutline,
  IoSettingsOutline
} from 'react-icons/io5';
import { useAuth } from '../../context/AuthContext';
import { useTheme } from '../../context/ThemeContext';
import { axiosInstance } from '../../api/axiosInstance';
const Sidebar = ({ activePage = 'dashboard', onNavigate }) => {
  const [isCollapsed, setIsCollapsed] = useState(false);
  const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false);
  const [activeItem, setActiveItem] = useState(activePage);
  const [assignedGptsCount, setAssignedGptsCount] = useState(0);
  const { logout } = useAuth();
  const { isDarkMode } = useTheme();
  // Fetch assigned GPTs count
  useEffect(() => {
    const fetchAssignedGpts = async () => {
      try {
        const response = await axiosInstance.get(`/api/custom-gpts/user/assigned`, {
          withCredentials: true
        });
        if (response.data.success && response.data.assignedGpts) {
          setAssignedGptsCount(response.data.assignedGpts.length);
        }
      } catch (error) {
        console.error("Error fetching assigned GPTs:", error);
      }
    };
    fetchAssignedGpts();
  }, []);
  // Auto-collapse on small screens
  useEffect(() => {
    const handleResize = () => {
      if (window.innerWidth < 768) {
        setIsCollapsed(true);
      }
    };
    window.addEventListener('resize', handleResize);
    handleResize(); // Check on initial render
    return () => window.removeEventListener('resize', handleResize);
  }, []);
  const toggleSidebar = () => {
    setIsCollapsed(!isCollapsed);
  };
  const toggleMobileMenu = () => {
    setIsMobileMenuOpen(!isMobileMenuOpen);
  };
  const handleNavigation = (itemId) => {
    setActiveItem(itemId);
    if (onNavigate) {
      onNavigate(itemId);
    }
    // Close mobile menu after navigation on small screens
    if (window.innerWidth < 768) {
      setIsMobileMenuOpen(false);
    }
  };
  const handleLogout = async () => {
    try {
      await logout();
    } catch (error) {
      console.error("Logout failed:", error);
    }
  };
  const navItems = [
    { id: 'dashboard', label: 'Dashboard', icon: <IoGridOutline size={20} /> },
    // { 
    //   id: 'collections', 
    //   label: 'Collections', 
    //   icon: <IoFolderOpenOutline size={20} />
    // },
    { id: 'favourites', label: 'Favourites', icon: <IoHeartOutline size={20} /> },
    { id: 'history', label: 'History', icon: <IoTimeOutline size={20} /> },
    { id: 'settings', label: 'Settings', icon: <IoSettingsOutline size={20} /> },
  ];
  return (
    <>
      {/* Mobile Menu Button - Only visible on small screens */}
      <div className="md:hidden fixed top-4 left-4 z-50">
        <button
          onClick={toggleMobileMenu}
          className={`rounded-full p-2 shadow-lg transition-colors ${isDarkMode
              ? 'bg-gray-800 text-white hover:bg-gray-700'
              : 'bg-white text-gray-700 hover:bg-gray-100'
            }`}
        >
          <IoMenuOutline size={24} />
        </button>
      </div>
      {/* Mobile Menu Overlay */}
      {isMobileMenuOpen && (
        <div
          className="md:hidden fixed inset-0 bg-black/80 z-40"
          onClick={() => setIsMobileMenuOpen(false)}
        />
      )}
      {/* Sidebar */}
      <div
        className={`fixed md:relative h-screen flex flex-col justify-between transition-all duration-300 ease-in-out z-40
          ${isDarkMode ? 'bg-[#121212] text-white' : 'bg-gray-50 text-gray-800 border-r border-gray-200'}
          ${isCollapsed ? 'w-[70px]' : 'w-[240px]'}
          ${isMobileMenuOpen ? 'translate-x-0' : '-translate-x-full md:translate-x-0'}
        `}
      >
        {/* Top content */}
        <div>
          {/* Logo and Toggle Button */}
          <div className={`px-4 py-6 mb-4 flex ${isCollapsed ? 'justify-center' : 'justify-between'} items-center`}>
            {!isCollapsed && <h1 className="text-xl font-bold">AI Agent</h1>}
            <button
              onClick={toggleSidebar}
              className={`rounded-full p-1.5 transition-colors hidden md:flex items-center justify-center ${isDarkMode
                  ? 'bg-white/10 hover:bg-white/20 text-white'
                  : 'bg-gray-200 hover:bg-gray-300 text-gray-600'
                }`}
            >
              {isCollapsed ? <IoChevronForwardOutline size={16} /> : <IoChevronBackOutline size={16} />}
            </button>
          </div>
          {/* Navigation */}
          <div className="flex flex-col space-y-1 px-2">
            {navItems.map((item) => (
              <button
                key={item.id}
                onClick={() => handleNavigation(item.id)}
                className={`flex items-center ${isCollapsed ? 'justify-center' : 'justify-start'} px-4 py-3 rounded-lg text-left transition-colors ${activeItem === item.id
                    ? (isDarkMode ? 'bg-white/10 text-white' : 'bg-blue-100 text-blue-700 font-medium')
                    : (isDarkMode
                      ? 'text-gray-400 hover:bg-white/5 hover:text-white'
                      : 'text-gray-600 hover:bg-gray-100 hover:text-gray-900')
                  }`}
                title={isCollapsed ? item.label : ''}
              >
                <span className="flex items-center justify-center">{item.icon}</span>
                {!isCollapsed && (
                  <div className="flex items-center justify-between w-full">
                    <span className="ml-3">{item.label}</span>
                  </div>
                )}
              </button>
            ))}
          </div>
        </div>
        {/* Bottom logout button */}
        <div className="px-2 pb-6">
          <button
            onClick={handleLogout}
            className={`flex items-center ${isCollapsed ? 'justify-center' : 'justify-start'} w-full px-4 py-3 rounded-lg text-left transition-colors ${isDarkMode
                ? 'text-gray-400 hover:bg-white/5 hover:text-white'
                : 'text-gray-600 hover:bg-gray-100 hover:text-gray-900'
              }`}
            title={isCollapsed ? 'Logout' : ''}
          >
            <span className="flex items-center justify-center"><IoExitOutline size={20} /></span>
            {!isCollapsed && <span className="ml-3">Logout</span>}
          </button>
        </div>
      </div>
    </>
  );
};
export default Sidebar;
````

## File: frontend/src/components/User/UserChat.jsx
````javascript
import React, { useState, useEffect, useRef } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import ChatInput from './ChatInput';
import { useAuth } from '../../context/AuthContext';
import { useTheme } from '../../context/ThemeContext';
import { IoPersonCircleOutline, IoSettingsOutline, IoPersonOutline, IoArrowBack, IoSparkles, IoAddCircleOutline } from 'react-icons/io5';
import { axiosInstance } from '../../api/axiosInstance';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import axios from 'axios';
import { IoClose } from 'react-icons/io5';
import { FaFilePdf, FaFileWord, FaFileAlt, FaFile } from 'react-icons/fa';
import rehypeRaw from 'rehype-raw';
import { Prism as SyntaxHighlighter } from 'react-syntax-highlighter';
import { atomDark } from 'react-syntax-highlighter/dist/esm/styles/prism';
import { SiOpenai, SiGooglegemini } from 'react-icons/si';
import { FaRobot } from 'react-icons/fa6';
import { BiLogoMeta } from 'react-icons/bi';
import { RiOpenaiFill } from 'react-icons/ri';
const pythonApiUrl = import.meta.env.VITE_PYTHON_API_URL || 'http://localhost:8000';
const modelIcons = {
    'gpt-4': <RiOpenaiFill className="text-green-500" size={18} />,
    'gpt-4o-mini': <SiOpenai className="text-green-400" size={16} />,
    'claude': <FaRobot className="text-purple-400" size={16} />,
    'gemini': <SiGooglegemini className="text-blue-400" size={16} />,
    'llama': <BiLogoMeta className="text-blue-500" size={18} />
};
const MarkdownStyles = () => (
    <style dangerouslySetInnerHTML={{
        __html: `
        .markdown-content {
            line-height: 1.8;
            width: 100%;
        }
        .markdown-content h1,
        .markdown-content h2,
        .markdown-content h3 {
            margin-top: 2em;
            margin-bottom: 0.8em;
            line-height: 1.4;
        }
        .markdown-content h1:first-child,
        .markdown-content h2:first-child,
        .markdown-content h3:first-child {
            margin-top: 0.5em;
        }
        .markdown-content h1 {
            font-size: 1.75rem;
            margin-bottom: 1em;
        }
        .markdown-content h2 {
            font-size: 1.5rem;
            margin-bottom: 0.9em;
        }
        .markdown-content h3 {
            font-size: 1.25rem;
            margin-bottom: 0.8em;
        }
        .markdown-content p {
            margin-bottom: 1.2em;
            margin-top: 1.2em;
        }
        .markdown-content ul,
        .markdown-content ol {
            margin-top: 1.2em;
            margin-bottom: 1.2em;
            padding-left: 1.5em;
        }
        .markdown-content li {
            margin-bottom: 0.6em;
        }
        .markdown-content li:last-child {
            margin-bottom: 0;
        }
        .markdown-content code {
            font-family: 'SFMono-Regular', Consolas, 'Liberation Mono', Menlo, monospace;
            padding: 0.2em 0.4em;
        }
        .markdown-content pre {
            overflow-x: auto;
            border-radius: 0.375rem;
            margin: 1.5em 0;
            padding: 1em;
        }
        .markdown-content blockquote {
            font-style: italic;
            color: #6b7280;
            border-left: 4px solid;
            padding-left: 1em;
            margin: 1.5em 0;
        }
        .markdown-content a {
            text-decoration: none;
        }
        .markdown-content a:hover {
            text-decoration: underline;
        }
        .markdown-content table {
            border-collapse: collapse;
            margin: 1.5em 0;
            width: 100%;
        }
        .markdown-content th,
        .markdown-content td {
            padding: 0.75em 1em;
        }
        .markdown-content img {
            max-width: 100%;
            height: auto;
            margin: 1.5em 0;
        }
        .markdown-content hr {
            border-top: 1px solid;
            margin: 2em 0;
        }
        .hide-scrollbar {
            -ms-overflow-style: none;
            scrollbar-width: none;
        }
        .hide-scrollbar::-webkit-scrollbar {
            display: none;
        }
        .assistant-message {
            background-color: #f9fafb;
            padding: 1em 1.25em;
        }
        .dark .assistant-message {
            background-color: #1e1e1e;
        }
        .typing-animation {
            display: inline-flex;
            align-items: center;
            margin-top: 0.5em;
        }
        .typing-animation span {
            display: block;
            width: 5px;
            height: 5px;
            background-color: currentColor;
            border-radius: 50%;
            margin: 0 1px;
            animation: typing 1.5s infinite ease-in-out;
        }
        .typing-animation span:nth-child(1) {
            animation-delay: 0s;
        }
        .typing-animation span:nth-child(2) {
            animation-delay: 0.2s;
        }
        .typing-animation span:nth-child(3) {
            animation-delay: 0.4s;
        }
        @keyframes typing {
            0%, 60%, 100% {
                transform: translateY(0);
                opacity: 0.6;
            }
            30% {
                transform: translateY(-4px);
                opacity: 1;
            }
        }
    `}} />
);
const UserChat = () => {
    const location = useLocation();
    const navigate = useNavigate();
    const queryParams = new URLSearchParams(location.search);
    const gptId = queryParams.get('gptId');
    const { user, loading: authLoading } = useAuth();
    const { isDarkMode } = useTheme();
    const [isProfileOpen, setIsProfileOpen] = useState(false);
    const [userData, setUserData] = useState(null);
    const [loading, setLoading] = useState({
        gpt: false,
        history: false,
        message: false
    });
    const [gptData, setGptData] = useState(null);
    const [messages, setMessages] = useState([]);
    const [collectionName, setCollectionName] = useState('');
    const [uploadedFiles, setUploadedFiles] = useState([]);
    const [isUploading, setIsUploading] = useState(false);
    const [uploadProgress, setUploadProgress] = useState(0);
    const [userDocuments, setUserDocuments] = useState([]);
    const [hasInteracted, setHasInteracted] = useState(false);
    const [conversationMemory, setConversationMemory] = useState([]);
    const [isInitialLoading, setIsInitialLoading] = useState(false);
    const [streamingMessage, setStreamingMessage] = useState(null);
    const messagesEndRef = useRef(null);
    const [webSearchEnabled, setWebSearchEnabled] = useState(false);
    useEffect(() => {
        messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
    }, [messages]);
    useEffect(() => {
        if (user) {
            setUserData(user);
        }
    }, [user]);
    useEffect(() => {
        // --- Step 1: Basic Guard Clauses ---
        if (!gptId) {
            // If there's no GPT ID, clear everything and stop.
            setGptData(null);
            setMessages([]);
            setConversationMemory([]);
            setIsInitialLoading(false);
            return;
        }
        // --- Step 2: Wait for Authentication to Settle ---
        // If authentication is still loading, do nothing yet. Show loading indicator.
        if (authLoading) {
            setIsInitialLoading(true); // Keep showing loading while waiting
            return;
        }
        // --- Step 3: Handle Post-Auth State (User Loaded or Not) ---
        // If auth is finished, but there's no user, stop loading and show appropriate message.
        if (!authLoading && !user) {
            console.warn("Auth finished, but no user. Aborting fetch.");
            setIsInitialLoading(false); // Stop loading
            setGptData({ _id: gptId, name: "GPT Assistant", description: "Login required to load chat.", model: "gpt-4o-mini" });
            setMessages([]);
            setConversationMemory([]);
            return;
        }
        // --- Step 4: Conditions Met - Proceed with Fetch ---
        // If we reach here: gptId exists, authLoading is false, and user exists.
        setIsInitialLoading(true); // Ensure loading is true before fetch starts
        const fromHistory = location.state?.fromHistory || location.search.includes('loadHistory=true');
        const fetchInitialData = async () => {
            let fetchedGptData = null;
            let gptDataIdToLoad = gptId;
            let historyMessages = [];
            let historyMemory = [];
            try {
                // Fetch GPT Data
                const gptResponse = await axiosInstance.get(`/api/custom-gpts/user/assigned/${gptId}`, { withCredentials: true });
                if (gptResponse.data?.success && gptResponse.data.customGpt) {
                    fetchedGptData = gptResponse.data.customGpt;
                    gptDataIdToLoad = fetchedGptData._id;
                } else {
                    console.warn("[fetchInitialData] Failed GPT fetch:", gptResponse.data);
                    fetchedGptData = { _id: gptId, name: "GPT Assistant", description: "Assistant details unavailable.", model: "gpt-4o-mini" };
                }
                // Set GPT Data *before* history load
                setGptData(fetchedGptData);
                const sanitizedEmail = (user.email || 'user').replace(/[^a-zA-Z0-9]/g, '_');
                const sanitizedGptName = (fetchedGptData.name || 'gpt').replace(/[^a-zA-Z0-9]/g, '_');
                setCollectionName(`kb_${sanitizedEmail}_${sanitizedGptName}_${gptId}`);
                notifyGptOpened(fetchedGptData, user).catch(err => console.warn("[fetchInitialData] Notify error:", err));
                // Load History if needed
                if (fromHistory) {
                    const historyResponse = await axiosInstance.get(`/api/chat-history/conversation/${user._id}/${gptDataIdToLoad}`, { withCredentials: true });
                    if (historyResponse.data?.success && historyResponse.data.conversation?.messages?.length > 0) {
                        const { conversation } = historyResponse.data;
                        // Use a more robust unique key if possible, combining conv id and timestamp/index
                        historyMessages = conversation.messages.map((msg, index) => ({
                            id: `${conversation._id}-${index}-${msg.timestamp || Date.now()}`,
                            role: msg.role,
                            content: msg.content,
                            timestamp: new Date(msg.timestamp || conversation.createdAt)
                        }));
                        historyMemory = conversation.messages.slice(-10).map(msg => ({
                            role: msg.role,
                            content: msg.content,
                            timestamp: msg.timestamp || conversation.createdAt
                        }));
                    } else {
                        historyMessages = [];
                        historyMemory = [];
                    }
                } else {
                    historyMessages = [];
                    historyMemory = [];
                }
                // Set Messages & Memory *after* all fetches are done
                setMessages(historyMessages);
                setConversationMemory(historyMemory);
            } catch (err) {
                console.error("[fetchInitialData] Error during fetch:", err);
                setGptData({ _id: gptId, name: "GPT Assistant", description: "Error loading assistant.", model: "gpt-4o-mini" });
                setCollectionName(`kb_user_${gptId}`);
                setMessages([]);
                setConversationMemory([]);
            } finally {
                // Mark initial loading complete *only* after try/catch finishes
                setIsInitialLoading(false);
            }
        };
        fetchInitialData(); // Execute the fetch logic
        // Cleanup function: Reset loading states if dependencies change mid-fetch
        return () => {
            setIsInitialLoading(false);
            setLoading(prev => ({ ...prev, gpt: false, history: false })); // Clear old flags too
        };
        // Dependencies: Only re-run if these core identifiers change.
    }, [gptId, user, authLoading, location.state, location.search]); // Keep authLoading & user to trigger run *after* auth resolves
    const predefinedPrompts = [
        {
            id: 1,
            title: 'About this GPT',
            prompt: 'What can you tell me about yourself and your capabilities?'
        },
        {
            id: 2,
            title: 'Help me with',
            prompt: 'I need help with a specific task. Can you guide me through it?'
        },
        {
            id: 3,
            title: 'Examples',
            prompt: 'Can you show me some examples of how to use you effectively?'
        },
    ];
    const handlePromptClick = (item) => {
        handleChatSubmit(item.prompt);
    };
    const saveMessageToHistory = async (message, role) => {
        try {
            if (!user?._id || !gptData || !message || !message.trim()) {
                console.warn('Cannot save message - missing data:', {
                    userId: user?._id,
                    gptId: gptData?._id,
                    hasMessage: !!message,
                    role
                });
                return null;
            }
            const payload = {
                userId: user._id,
                gptId: gptData._id,
                gptName: gptData.name || 'AI Assistant',
                message: message.trim(),
                role: role,
                model: gptData.model || 'gpt-4o-mini'
            };
            const response = await axiosInstance.post('/api/chat-history/save', payload, {
                withCredentials: true
            });
            return response.data;
        } catch (error) {
            console.error(`Error saving ${role} message to history:`, error.response?.data || error.message);
            // Return null instead of throwing to prevent breaking the chat flow
            return null;
        }
    };
    const handleChatSubmit = async (message) => {
        if (!message.trim()) return;
        // Set interaction flag to hide files
        setHasInteracted(true);
        try {
            const userMessage = {
                id: Date.now(),
                role: 'user',
                content: message,
                timestamp: new Date()
            };
            setMessages(prev => [...prev, userMessage]);
            // Save user message immediately
            saveMessageToHistory(message, 'user');
            // Keep only the last 10 messages for context
            const recentHistory = [...conversationMemory, { role: 'user', content: message }]
                .slice(-10) // Take the last 10
                .map(msg => ({ role: msg.role, content: msg.content })); // Format for backend
            setConversationMemory(prev => [...prev, { role: 'user', content: message, timestamp: new Date() }].slice(-10));
            // Clear any existing streaming message
            setStreamingMessage(null);
            // Set loading state
            setLoading(prev => ({ ...prev, message: true }));
            // Backend API Call
            try {
                const payload = {
                    message: message,
                    gpt_id: gptId,
                    user_email: user?.email || 'unknown_user',
                    gpt_name: gptData?.name || 'unknown_gpt',
                    history: recentHistory,
                    memory: conversationMemory,
                    user_documents: userDocuments,
                    use_hybrid_search: gptData?.capabilities?.hybridSearch || false,
                    system_prompt: gptData?.instructions || null,
                    web_search_enabled: webSearchEnabled && gptData?.capabilities?.webBrowsing || false
                };
                const response = await fetch(`${pythonApiUrl}/chat-stream`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Accept': 'text/event-stream',
                    },
                    body: JSON.stringify(payload),
                    credentials: 'include'
                });
                if (!response.ok) {
                    throw new Error(`Server responded with ${response.status}: ${response.statusText}`);
                }
                if (response.body) {
                    await handleStreamingResponse(response);
                } else {
                    throw new Error("Received empty response body");
                }
            } catch (error) {
                console.error("Error calling chat stream API:", error);
                setStreamingMessage({
                    id: Date.now() + 1,
                    role: 'assistant',
                    content: `Error: ${error.message}`,
                    isStreaming: false,
                    isLoading: false,
                    isError: true,
                    timestamp: new Date()
                });
                saveMessageToHistory(`Error processing request: ${error.message}`, 'assistant');
            }
        } catch (error) {
            console.error("Error in handleChatSubmit:", error);
        }
    };
    const handleStreamingResponse = async (response) => {
        const reader = response.body.getReader();
        const decoder = new TextDecoder();
        let buffer = "";
        let doneStreaming = false;
        let sourcesInfo = null;
        let streamError = null;
        const messageId = Date.now() + 1;
        console.log(`[Stream ${messageId}] Starting to read stream...`);
        try {
            // Initialize streaming message state
            setStreamingMessage({
                id: messageId,
                role: 'assistant',
                content: '',
                isStreaming: true,
                isError: false,
                timestamp: new Date()
            });
            while (!doneStreaming) {
                const { done, value } = await reader.read();
                if (done) {
                    console.log(`[Stream ${messageId}] Stream reader done.`);
                    doneStreaming = true;
                    break;
                }
                const chunk = decoder.decode(value, { stream: true });
                const lines = chunk.split('\n\n').filter(line => line.trim().startsWith('data: '));
                for (const line of lines) {
                    try {
                        const jsonStr = line.substring(6);
                        const parsed = JSON.parse(jsonStr);
                        console.log(`[Stream ${messageId}] Parsed event:`, parsed);
                        if (parsed.type === 'error' || parsed.error) {
                            streamError = parsed.error || parsed.detail || 'Unknown streaming error';
                            console.error(`[Stream ${messageId}] Streaming Error:`, streamError);
                            buffer = `Error: ${streamError}`;
                            doneStreaming = true;
                            setStreamingMessage(prev => ({
                                ...prev,
                                content: buffer,
                                isStreaming: false,
                                isError: true
                            }));
                            break;
                        }
                        if (parsed.type === 'done') {
                            console.log(`[Stream ${messageId}] Done event received.`);
                            doneStreaming = true;
                            break;
                        }
                        if (parsed.type === 'content') {
                            buffer += parsed.data;
                            setStreamingMessage(prev => ({
                                ...prev,
                                content: buffer,
                                isStreaming: true,
                                isError: false
                            }));
                        }
                        if (parsed.type === 'sources_info') {
                            sourcesInfo = parsed.data;
                            console.log(`[Stream ${messageId}] Sources info:`, sourcesInfo);
                            buffer += `\n\n[Sources Retrieved: ${sourcesInfo.documents_retrieved_count} documents, ${sourcesInfo.retrieval_time_ms}ms]`;
                        }
                    } catch (e) {
                        console.error(`[Stream ${messageId}] Error parsing line:`, e, "Line:", line);
                    }
                }
            }
            if (!buffer && !streamError) {
                console.warn(`[Stream ${messageId}] Stream ended with no content.`);
                buffer = "No response generated. Please try rephrasing your query or check the uploaded documents.";
                streamError = true;
            }
            setStreamingMessage(prev => ({
                ...prev,
                content: buffer,
                isStreaming: false,
                isLoading: false,
                isError: !!streamError
            }));
            await saveMessageToHistory(buffer, 'assistant');
            console.log(`[Stream ${messageId}] Saved final content:`, buffer);
        } catch (err) {
            console.error(`[Stream ${messageId}] Error reading stream:`, err);
            buffer = `Error reading response stream: ${err.message}`;
            setStreamingMessage({
                id: messageId,
                role: 'assistant',
                content: buffer,
                isStreaming: false,
                isLoading: false,
                isError: true,
                timestamp: new Date()
            });
            await saveMessageToHistory(buffer, 'assistant');
        } finally {
            setLoading(prev => ({ ...prev, message: false }));
            console.log(`[Stream ${messageId}] Stream processing complete.`);
        }
    };
    useEffect(() => {
        if (streamingMessage && !streamingMessage.isStreaming) {
            setMessages(prev => {
                const exists = prev.some(m => 
                    m.id === streamingMessage.id || 
                    (m.content === streamingMessage.content && 
                     m.timestamp.getTime() === streamingMessage.timestamp.getTime())
                );
                if (exists) return prev;
                return [...prev, { ...streamingMessage }];
            });
            // Add to conversation memory
            setConversationMemory(prev => [...prev, {
                role: 'assistant',
                content: streamingMessage.content,
                timestamp: new Date().toISOString()
            }]);
            // Clear streaming message with a short delay
            setTimeout(() => {
                setStreamingMessage(null);
                setLoading(prev => ({ ...prev, message: false }));
            }, 100);
        }
    }, [streamingMessage]);
    const toggleProfile = () => {
        setIsProfileOpen(!isProfileOpen);
    };
    const handleGoBack = () => {
        navigate(-1);
    };
    const goToSettings = () => {
        navigate('/user/settings');
        setIsProfileOpen(false);
    };
    const mockUser = {
        name: "Test User",
        email: "test@example.com",
        profilePic: null
    };
    const showWebSearch = gptData?.capabilities?.webBrowsing === true;
    const notifyGptOpened = async (customGpt, userData) => {
        try {
            // Use actual hybridSearch setting
            const useHybridSearch = customGpt.capabilities?.hybridSearch || false;
            const fileUrls = customGpt.knowledgeFiles?.map(file => file.fileUrl).filter(url =>
                url && (url.startsWith('http://') || url.startsWith('https://'))
            ) || [];
            const backendUrl = import.meta.env.VITE_PYTHON_API_URL || 'http://localhost:8000';
            const payload = {
                user_email: userData?.email || 'user@example.com',
                gpt_name: customGpt.name || 'Unnamed GPT',
                gpt_id: customGpt._id,
                file_urls: fileUrls,
                use_hybrid_search: useHybridSearch,
                schema: {
                    model: customGpt.model || "gpt-4o-mini",
                    instructions: customGpt.instructions || "",
                    capabilities: customGpt.capabilities || {},
                    use_hybrid_search: useHybridSearch
                }
            };
            const response = await fetch(`${backendUrl}/gpt-opened`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(payload)
            });
            if (response.ok) {
                const data = await response.json();
                // Store the collection name if provided
                if (data && data.collection_name) {
                    setCollectionName(data.collection_name);
                }
                return true;
            } else {
                console.error("Failed to notify GPT opened:", await response.text());
                return false;
            }
        } catch (err) {
            console.error("Error notifying GPT opened:", err);
            return false;
        }
    };
    // Replace the existing handleFileUpload function with this
    const handleFileUpload = async (files) => {
        if (!files.length || !gptData) return;
        try {
            setIsUploading(true);
            setUploadProgress(0);
            setUploadedFiles(Array.from(files).map(file => ({
                name: file.name,
                size: file.size,
                type: file.type
            })));
            const formData = new FormData();
            for (let i = 0; i < files.length; i++) {
                formData.append('files', files[i]);
            }
            // Add required metadata - match AdminChat.jsx
            formData.append('user_email', userData?.email || 'anonymous');
            formData.append('gpt_id', gptData?._id || gptId);
            formData.append('gpt_name', gptData?.name || 'Assistant');
            formData.append('collection_name', collectionName || gptData._id);
            formData.append('is_user_document', 'true');
            formData.append('system_prompt', gptData?.instructions || '');
            // Get hybridSearch setting from capabilities
            const useHybridSearch = gptData?.capabilities?.hybridSearch || false;
            formData.append('use_hybrid_search', useHybridSearch.toString());
            // Optimized upload with simple progress tracking
            const response = await axios.post(
                `${pythonApiUrl}/upload-chat-files`,
                formData,
                {
                    headers: {
                        'Content-Type': 'multipart/form-data',
                    },
                    withCredentials: true,
                    onUploadProgress: (progressEvent) => {
                        const percentCompleted = Math.round(
                            (progressEvent.loaded * 100) / (progressEvent.total || 100)
                        );
                        setUploadProgress(percentCompleted);
                    }
                }
            );
            setUploadProgress(100);
            setTimeout(() => setIsUploading(false), 500);
            if (response.data.success) {
                setUserDocuments(response.data.file_urls || []);
            } else {
                throw new Error(response.data.message || "Failed to process files");
            }
        } catch (error) {
            console.error("Error uploading files:", error);
            setIsUploading(false);
            setMessages(prev => [...prev, {
                id: Date.now(),
                role: 'system',
                content: `Error uploading files: ${error.message || 'Unknown error'}`,
                timestamp: new Date()
            }]);
        }
    };
    // Add this helper function for file icons
    const getFileIcon = (filename) => {
        if (!filename) return <FaFile className="text-white" />;
        const extension = filename.split('.').pop().toLowerCase();
        switch (extension) {
            case 'pdf':
                return <FaFilePdf className="text-white" />;
            case 'doc':
            case 'docx':
                return <FaFileWord className="text-white" />;
            case 'txt':
                return <FaFileAlt className="text-white" />;
            default:
                return <FaFile className="text-white" />;
        }
    };
    // Add this function to handle removing uploaded files
    const handleRemoveUploadedFile = (indexToRemove) => {
        setUploadedFiles(prevFiles => prevFiles.filter((_, index) => index !== indexToRemove));
    };
    // Add a function to handle starting a new chat
    const handleNewChat = () => {
        setMessages([]);
        setConversationMemory([]);
        setHasInteracted(false);
        setUserDocuments([]);
        setUploadedFiles([]);
    };
    return (
        <>
            <MarkdownStyles />
            <div className={`flex flex-col h-screen overflow-hidden transition-colors duration-300 ${isDarkMode ? 'bg-black text-white' : 'bg-gray-100 text-gray-900'}`}>
                <div className={`flex-shrink-0 px-4 py-3 flex items-center justify-between ${isDarkMode ? 'bg-black border-gray-800' : 'bg-gray-100 border-gray-200'}`}>
                    <div className="flex items-center space-x-2">
                        {gptId && (
                            <button
                                onClick={handleGoBack}
                                className={`p-2 rounded-full transition-colors flex items-center justify-center w-10 h-10 ${isDarkMode ? 'text-gray-400 hover:text-white hover:bg-gray-800' : 'text-gray-500 hover:text-gray-700 hover:bg-gray-200'
                                    }`}
                                aria-label="Go back"
                            >
                                <IoArrowBack size={20} />
                            </button>
                        )}
                        {/* New Chat Button */}
                        <button
                            onClick={handleNewChat}
                            className={`p-2 rounded-full transition-colors flex items-center justify-center w-10 h-10 ${isDarkMode ? 'text-gray-400 hover:text-white hover:bg-gray-800' : 'text-gray-500 hover:text-gray-700 hover:bg-gray-200'
                                }`}
                            aria-label="New Chat"
                        >
                            <IoAddCircleOutline size={24} />
                        </button>
                        {/* Show the GPT name when it's available */}
                        {gptData && (
                            <div className="ml-2 text-sm md:text-base font-medium flex items-center">
                                <span className="mr-1">New Chat</span>
                                {gptData.model && (
                                    <div className={`flex items-center ml-2 text-xs md:text-sm px-2 py-0.5 rounded-full ${isDarkMode ? 'bg-gray-800' : 'bg-gray-100'}`}>
                                        {modelIcons[gptData.model] || null}
                                        <span>{gptData.model === 'gpt-4o-mini' ? 'GPT-4o Mini' : gptData.model}</span>
                                    </div>
                                )}
                            </div>
                        )}
                    </div>
                    <div className="relative">
                        <button
                            onClick={toggleProfile}
                            className={`w-10 h-10 rounded-full overflow-hidden border-2 transition-colors ${isDarkMode ? 'border-white/20 hover:border-white/40' : 'border-gray-300 hover:border-gray-500'
                                }`}
                        >
                            {(userData || mockUser)?.profilePic ? (
                                <img
                                    src={(userData || mockUser).profilePic}
                                    alt="Profile"
                                    className="w-full h-full object-cover"
                                />
                            ) : (
                                <div className={`w-full h-full flex items-center justify-center ${isDarkMode ? 'bg-gray-700' : 'bg-gray-300'}`}>
                                    <IoPersonCircleOutline size={24} className={isDarkMode ? 'text-white' : 'text-gray-600'} />
                                </div>
                            )}
                        </button>
                        {isProfileOpen && (
                            <div className={`absolute top-12 right-0 w-64 rounded-xl shadow-lg border overflow-hidden z-30 ${isDarkMode ? 'bg-[#1e1e1e] border-white/10' : 'bg-white border-gray-200'
                                }`}>
                                <div className={`p-4 border-b ${isDarkMode ? 'border-white/10' : 'border-gray-200'}`}>
                                    <p className={`font-medium ${isDarkMode ? 'text-white' : 'text-gray-900'}`}>
                                        {userData?.name || mockUser.name}
                                    </p>
                                    <p className={`text-sm truncate ${isDarkMode ? 'text-gray-400' : 'text-gray-500'}`}>
                                        {userData?.email || mockUser.email}
                                    </p>
                                </div>
                                <div className="py-1">
                                    <button className={`w-full px-4 py-2.5 text-left flex items-center space-x-3 transition-colors ${isDarkMode ? 'text-gray-300 hover:bg-white/5' : 'text-gray-700 hover:bg-gray-100'
                                        }`}>
                                        <IoPersonOutline size={18} />
                                        <span>Profile</span>
                                    </button>
                                    <button
                                        onClick={goToSettings}
                                        className={`w-full px-4 py-2.5 text-left flex items-center space-x-3 transition-colors ${isDarkMode ? 'text-gray-300 hover:bg-white/5' : 'text-gray-700 hover:bg-gray-100'
                                            }`}
                                    >
                                        <IoSettingsOutline size={18} />
                                        <span>Settings</span>
                                    </button>
                                </div>
                            </div>
                        )}
                    </div>
                </div>
                <div className="flex-1 overflow-y-auto p-4 no-scrollbar">
                    <div className="w-full max-w-3xl mx-auto flex flex-col space-y-4">
                        {/* --- Consolidated Initial Loading Indicator --- */}
                        {isInitialLoading ? (
                            <div className="flex-1 flex flex-col items-center justify-center p-20">
                                <div className={`animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 ${isDarkMode ? 'border-blue-500' : 'border-blue-600'}`}></div>
                                <span className="mt-4 text-sm">
                                    Loading assistant...
                                </span>
                            </div>
                        ) : messages.length === 0 ? (
                            // Welcome Screen (Rendered only after initial load is complete and if no messages)
                            <div className="welcome-screen py-10">
                                {gptId && gptData ? (
                                    // GPT-specific welcome
                                    <div className="text-center">
                                        <div className={`w-16 h-16 rounded-full mx-auto flex items-center justify-center mb-4 ${isDarkMode ? 'bg-gray-700' : 'bg-gray-200'}`}>
                                            {gptData.imageUrl ? (
                                                <img src={gptData.imageUrl} alt={gptData.name} className="w-full h-full object-cover rounded-full" />
                                            ) : (
                                                <span className={`text-2xl ${isDarkMode ? 'text-white' : 'text-gray-600'}`}>{gptData.name?.charAt(0) || '?'}</span>
                                            )}
                                        </div>
                                        <h2 className={`text-xl font-semibold mb-2 ${isDarkMode ? 'text-white' : 'text-gray-900'}`}>{gptData.name}</h2>
                                        <p className={`max-w-md mx-auto ${isDarkMode ? 'text-gray-400' : 'text-gray-600'}`}>{gptData.description || 'Start a conversation...'}</p>
                                        {/* Conversation starter */}
                                        {gptData.conversationStarter && (
                                            <div
                                                onClick={() => handleChatSubmit(gptData.conversationStarter)}
                                                className={`mt-5 max-w-xs mx-auto p-3 border rounded-lg text-left cursor-pointer transition-colors ${isDarkMode
                                                        ? 'bg-gray-800/70 border-gray-700/70 hover:bg-gray-800 hover:border-gray-600/70 text-white'
                                                        : 'bg-gray-200 border-gray-300 hover:bg-gray-300 hover:border-gray-400 text-gray-800'
                                                    }`}
                                            >
                                                <p className="text-sm line-clamp-3">{gptData.conversationStarter}</p>
                                            </div>
                                        )}
                                    </div>
                                ) : (
                                    // Generic welcome
                                    <div className="text-center">
                                        <h1 className={`text-2xl sm:text-3xl md:text-4xl font-bold mb-2 ${isDarkMode ? 'text-white' : 'text-gray-900'}`}>AI Assistant</h1>
                                        <p className={`text-base sm:text-lg md:text-xl font-medium mb-8 ${isDarkMode ? 'text-gray-400' : 'text-gray-600'}`}>How can I assist you today?</p>
                                        {/* Simplified prompts display */}
                                        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 max-w-2xl mx-auto">
                                            {predefinedPrompts.map((item) => (
                                                <div
                                                    key={item.id}
                                                    onClick={() => handlePromptClick(item)}
                                                    className={`p-3 border rounded-lg cursor-pointer text-left ${isDarkMode
                                                            ? 'bg-gray-800 border-gray-700 hover:bg-gray-700'
                                                            : 'bg-white border-gray-200 hover:bg-gray-50'
                                                        }`}
                                                >
                                                    <h3 className={`font-medium mb-1 ${isDarkMode ? 'text-white' : 'text-gray-800'}`}>{item.title}</h3>
                                                    <p className={`text-xs line-clamp-2 ${isDarkMode ? 'text-gray-400' : 'text-gray-500'}`}>{item.prompt}</p>
                                                </div>
                                            ))}
                                        </div>
                                    </div>
                                )}
                            </div>
                        ) : (
                            // Message list (Rendered only after initial load and when messages exist)
                            <>
                                {messages.length > 0 && (
                                    messages
                                        .filter(msg => msg.role !== 'system')
                                        .map((msg) => (
                                            <div
                                                key={msg.id}
                                                className={`flex ${msg.role === 'user' ? 'justify-end' : 'justify-start'}`}
                                            >
                                                {/* Assistant Icon - Render if it's an assistant message */}
                                                {msg.role === 'assistant' && (
                                                    <div className={`flex-shrink-0 w-8 h-8 rounded-full flex items-center justify-center ${isDarkMode ? 'bg-gray-700' : 'bg-gray-300'}`}>
                                                        {gptData?.imageUrl ? (
                                                            <img src={gptData.imageUrl} alt="GPT" className="w-full h-full rounded-full object-cover" />
                                                        ) : (
                                                            <IoSparkles size={16} className={isDarkMode ? 'text-blue-400' : 'text-blue-600'} />
                                                        )}
                                                    </div>
                                                )}
                                                {/* Message content */}
                                                <div
                                                    className={`${msg.role === 'user'
                                                        ? `${isDarkMode ? 'bg-black/10 dark:bg-white/80 text-black dark:text-black rounded-br-none' : 'bg-blue-600 text-white rounded-br-none'} max-w-max`
                                                        : `${msg.isError
                                                            ? (isDarkMode ? 'bg-red-800/70 text-red-100' : 'bg-red-100 text-red-700')
                                                            : 'assistant-message text-black dark:text-white rounded-bl-none'} 
                                                        w-full max-w-3xl`
                                                    } rounded-2xl px-5 py-3`}
                                                >
                                                    {msg.role === 'user' ? (
                                                        <p className="whitespace-pre-wrap">{msg.content}</p>
                                                    ) : (
                                                        <div className="markdown-content">
                                                            <ReactMarkdown
                                                                remarkPlugins={[remarkGfm]}
                                                                rehypePlugins={[rehypeRaw]}
                                                                components={{
                                                                    h1: ({ node, ...props }) => <h1 className="text-xl font-bold my-4" {...props} />,
                                                                    h2: ({ node, ...props }) => <h2 className="text-lg font-bold my-3" {...props} />,
                                                                    h3: ({ node, ...props }) => <h3 className="text-md font-bold my-3" {...props} />,
                                                                    h4: ({ node, ...props }) => <h4 className="font-bold my-2" {...props} />,
                                                                    p: ({ node, ...props }) => <p className="my-3" {...props} />,
                                                                    ul: ({ node, ...props }) => <ul className="list-disc pl-6 my-3" {...props} />,
                                                                    ol: ({ node, ...props }) => <ol className="list-decimal pl-6 my-3" {...props} />,
                                                                    li: ({ node, index, ...props }) => <li className="my-2" key={index} {...props} />,
                                                                    a: ({ node, ...props }) => <a className="text-blue-400 hover:underline" {...props} />,
                                                                    blockquote: ({ node, ...props }) => <blockquote className="border-l-4 border-gray-500 dark:border-gray-400 pl-4 my-4 italic" {...props} />,
                                                                    code({ node, inline, className, children, ...props }) {
                                                                        const match = /language-(\w+)/.exec(className || '');
                                                                        return !inline && match ? (
                                                                            <SyntaxHighlighter
                                                                                style={atomDark}
                                                                                language={match[1]}
                                                                                PreTag="div"
                                                                                className="rounded-md my-3"
                                                                                {...props}
                                                                            >
                                                                                {String(children).replace(/\n$/, '')}
                                                                            </SyntaxHighlighter>
                                                                        ) : (
                                                                            <code className={`${inline ? 'bg-gray-300 dark:bg-gray-600 px-1 py-0.5 rounded text-sm' : ''} ${className}`} {...props}>
                                                                                {children}
                                                                            </code>
                                                                        );
                                                                    },
                                                                    table: ({ node, ...props }) => (
                                                                        <div className="overflow-x-auto my-4">
                                                                            <table className="min-w-full border border-gray-400 dark:border-gray-500" {...props} />
                                                                        </div>
                                                                    ),
                                                                    thead: ({ node, ...props }) => <thead className="bg-gray-300 dark:bg-gray-600" {...props} />,
                                                                    tbody: ({ node, ...props }) => <tbody className="divide-y divide-gray-400 dark:divide-gray-500" {...props} />,
                                                                    tr: ({ node, ...props }) => <tr className="hover:bg-gray-300 dark:hover:bg-gray-600" {...props} />,
                                                                    th: ({ node, ...props }) => <th className="px-4 py-3 text-left font-medium" {...props} />,
                                                                    td: ({ node, ...props }) => <td className="px-4 py-3" {...props} />,
                                                                }}
                                                            >
                                                                {msg.content}
                                                            </ReactMarkdown>
                                                        </div>
                                                    )}
                                                    <div className={`text-xs mt-2 text-right ${msg.role === 'user' ? 'text-blue-50/80' : 'text-gray-400/80'}`}>
                                                    </div>
                                                </div>
                                                {/* User Icon - Render if it's a user message */}
                                                {msg.role === 'user' && (
                                                    <div className={`flex-shrink-0 w-8 h-8 rounded-full overflow-hidden border ${isDarkMode ? 'border-white/20 bg-gray-700' : 'border-gray-300 bg-gray-300'}`}>
                                                        {userData?.profilePic ? (
                                                            <img src={userData.profilePic} alt="You" className="w-full h-full object-cover" />
                                                        ) : (
                                                            <div className={`w-full h-full flex items-center justify-center`}>
                                                                <IoPersonOutline size={16} className={isDarkMode ? 'text-gray-300' : 'text-gray-600'} />
                                                            </div>
                                                        )}
                                                    </div>
                                                )}
                                            </div>
                                        ))
                                )}
                            </>
                        )}
                        {/* Streaming message - displayed when streaming is active */}
                        {streamingMessage && (
                            <div className="flex justify-start items-end space-x-2">
                                <div className={`flex-shrink-0 w-8 h-8 rounded-full flex items-center justify-center ${isDarkMode ? 'bg-gray-700' : 'bg-gray-300'}`}>
                                    {gptData?.imageUrl ? (
                                        <img src={gptData.imageUrl} alt="GPT" className="w-full h-full rounded-full object-cover" />
                                    ) : (
                                        <IoSparkles size={16} className={isDarkMode ? 'text-blue-400' : 'text-blue-600'} />
                                    )}
                                </div>
                                <div
                                    className={`rounded-2xl px-4 py-2 assistant-message text-black dark:text-white rounded-bl-none w-full max-w-3xl ${
                                        streamingMessage.isError ? (isDarkMode ? 'bg-red-800/70 text-red-100' : 'bg-red-100 text-red-700') : ''
                                    }`}
                                >
                                    <div className="markdown-content">
                                        <ReactMarkdown
                                            remarkPlugins={[remarkGfm]}
                                            rehypePlugins={[rehypeRaw]}
                                            components={{
                                                h1: ({ node, ...props }) => <h1 className="text-xl font-bold my-4" {...props} />,
                                                h2: ({ node, ...props }) => <h2 className="text-lg font-bold my-3" {...props} />,
                                                h3: ({ node, ...props }) => <h3 className="text-md font-bold my-3" {...props} />,
                                                h4: ({ node, ...props }) => <h4 className="font-bold my-2" {...props} />,
                                                p: ({ node, ...props }) => <p className="my-3" {...props} />,
                                                ul: ({ node, ...props }) => <ul className="list-disc pl-6 my-3" {...props} />,
                                                ol: ({ node, ...props }) => <ol className="list-decimal pl-6 my-3" {...props} />,
                                                li: ({ node, index, ...props }) => <li className="my-2" key={index} {...props} />,
                                                a: ({ node, ...props }) => <a className="text-blue-400 hover:underline" {...props} />,
                                                blockquote: ({ node, ...props }) => <blockquote className="border-l-4 border-gray-500 dark:border-gray-400 pl-4 my-4 italic" {...props} />,
                                                code({ node, inline, className, children, ...props }) {
                                                    const match = /language-(\w+)/.exec(className || '');
                                                    return !inline && match ? (
                                                        <SyntaxHighlighter
                                                            style={atomDark}
                                                            language={match[1]}
                                                            PreTag="div"
                                                            className="rounded-md my-3"
                                                            {...props}
                                                        >
                                                            {String(children).replace(/\n$/, '')}
                                                        </SyntaxHighlighter>
                                                    ) : (
                                                        <code className={`${inline ? 'bg-gray-300 dark:bg-gray-600 px-1 py-0.5 rounded text-sm' : ''} ${className}`} {...props}>
                                                            {children}
                                                        </code>
                                                    );
                                                },
                                                table: ({ node, ...props }) => (
                                                    <div className="overflow-x-auto my-4">
                                                        <table className="min-w-full border border-gray-400 dark:border-gray-500" {...props} />
                                                    </div>
                                                ),
                                                thead: ({ node, ...props }) => <thead className="bg-gray-300 dark:bg-gray-600" {...props} />,
                                                tbody: ({ node, ...props }) => <tbody className="divide-y divide-gray-400 dark:divide-gray-500" {...props} />,
                                                tr: ({ node, ...props }) => <tr className="hover:bg-gray-300 dark:hover:bg-gray-600" {...props} />,
                                                th: ({ node, ...props }) => <th className="px-4 py-3 text-left font-medium" {...props} />,
                                                td: ({ node, ...props }) => <td className="px-4 py-3" {...props} />,
                                            }}
                                        >
                                            {streamingMessage.content}
                                        </ReactMarkdown>
                                        {streamingMessage.isStreaming && (
                                            <div className="typing-animation mt-2 inline-flex items-center text-gray-400">
                                                <span></span>
                                                <span></span>
                                                <span></span>
                                            </div>
                                        )}
                                    </div>
                                    <div className="text-xs mt-2 text-right text-gray-400/80">
                                        {new Date(streamingMessage.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                                    </div>
                                </div>
                            </div>
                        )}
                        {/* Replace loading indicator with better styling */}
                        {!isInitialLoading && loading.message && !streamingMessage && (
                            <div className="flex justify-start">
                                <div className={`flex-shrink-0 w-8 h-8 rounded-full flex items-center justify-center ${isDarkMode ? 'bg-gray-700' : 'bg-gray-300'}`}>
                                    <IoSparkles size={16} className={isDarkMode ? 'text-blue-400' : 'text-blue-600'} />
                                </div>
                                <div className="rounded-2xl px-4 py-2 assistant-message text-black dark:text-white rounded-bl-none ml-2">
                                    <div className="typing-animation inline-flex items-center text-gray-400">
                                        <span></span>
                                        <span></span>
                                        <span></span>
                                    </div>
                                </div>
                            </div>
                        )}
                        <div ref={messagesEndRef} />
                    </div>
                </div>
                <div className={`flex-shrink-0 p-3  ${isDarkMode ? 'bg-black border-gray-800' : 'bg-gray-100 border-gray-200'}`}>
                    <div className="w-full max-w-3xl mx-auto">
                        {/* File Upload Animation */}
                        {isUploading && (
                            <div className="mb-2 px-2">
                                <div className="flex items-center p-2 bg-blue-50 dark:bg-blue-900/20 rounded-lg border border-blue-100 dark:border-blue-800/30">
                                    <div className="flex-shrink-0 mr-3">
                                        <div className="w-8 h-8 flex items-center justify-center">
                                            <svg className="animate-spin w-5 h-5 text-blue-500 dark:text-blue-400" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                                                <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                                                <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                                            </svg>
                                        </div>
                                    </div>
                                    <div className="flex-1 min-w-0">
                                        <div className="text-xs font-medium text-blue-700 dark:text-blue-300">
                                            {uploadedFiles.length === 1
                                                ? `Uploading ${uploadedFiles[0]?.name}`
                                                : `Uploading ${uploadedFiles.length} files`}
                                        </div>
                                        <div className="mt-1 relative h-1.5 w-full bg-blue-100 dark:bg-blue-800/40 rounded-full overflow-hidden">
                                            <div
                                                className="absolute left-0 top-0 h-full bg-blue-500 dark:bg-blue-400 transition-all duration-300"
                                                style={{ width: `${uploadProgress}%` }}
                                            ></div>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        )}
                        {/* Replace the existing uploaded files display with this improved version */}
                        {uploadedFiles.length > 0 && !isUploading && !hasInteracted && (
                            <div className="mb-2 flex flex-wrap gap-2">
                                {uploadedFiles.map((file, index) => (
                                    <div
                                        key={`${file.name}-${index}`}
                                        className="flex items-center py-1 px-2 bg-gray-50 dark:bg-gray-800/50 rounded-md border border-gray-200 dark:border-gray-700/50 max-w-fit"
                                    >
                                        <div className="mr-1.5 text-gray-500 dark:text-gray-400">
                                            {getFileIcon(file.name)}
                                        </div>
                                        <span className="text-xs font-medium text-gray-700 dark:text-gray-300 truncate max-w-[140px]">
                                            {file.name}
                                        </span>
                                        <div className="text-[10px] text-gray-500 ml-1 whitespace-nowrap">
                                            {file.size ? `${Math.round(file.size / 1024)} KB` : ''}
                                        </div>
                                        <button
                                            onClick={() => handleRemoveUploadedFile(index)}
                                            className="ml-1.5 text-gray-400 hover:text-gray-600 dark:text-gray-500 dark:hover:text-gray-300 p-0.5 rounded-full hover:bg-gray-200 dark:hover:bg-gray-700/50 transition-colors"
                                            aria-label="Remove file"
                                        >
                                            <IoClose size={14} />
                                        </button>
                                    </div>
                                ))}
                            </div>
                        )}
                        <ChatInput
                            onSubmit={handleChatSubmit}
                            onFileUpload={handleFileUpload}
                            isLoading={loading.message}
                            isDarkMode={isDarkMode}
                            showWebSearch={showWebSearch}
                            webSearchEnabled={webSearchEnabled}
                            setWebSearchEnabled={setWebSearchEnabled}
                        />
                    </div>
                </div>
                {isProfileOpen && (
                    <div
                        className="fixed inset-0 z-20"
                        onClick={() => setIsProfileOpen(false)}
                    />
                )}
            </div>
        </>
    );
};
export default UserChat;
````

## File: frontend/src/components/User/UserDashboard.jsx
````javascript
import React, { useState, useEffect, useRef, useMemo, useCallback, memo } from 'react';
import { FiSearch, FiMessageSquare, FiChevronDown, FiChevronUp, FiXCircle, FiHeart, FiFolder, FiPlus } from 'react-icons/fi';
import { useNavigate } from 'react-router-dom';
import { axiosInstance } from '../../api/axiosInstance';
import { useTheme } from '../../context/ThemeContext';
import MoveToFolderModal from './MoveToFolderModal';
import { toast } from 'react-toastify';
// Memoized GPT card component
const GptCard = memo(({ gpt, formatDate, onChatClick, onToggleFavorite, onMoveToFolder, isDarkMode }) => (
    <div
        key={gpt._id}
        className={`rounded-lg overflow-hidden border transition-all flex flex-col group ${isDarkMode
                ? 'bg-gray-800 border-gray-700 hover:border-gray-600 shadow-lg hover:shadow-xl'
                : 'bg-white border-gray-200 hover:border-gray-300 shadow-md hover:shadow-lg'
            }`}
    >
        <div className={`h-24 sm:h-32 relative flex-shrink-0 ${!gpt.imageUrl && (isDarkMode ? 'bg-gradient-to-br from-gray-700 to-gray-900' : 'bg-gradient-to-br from-gray-100 to-gray-300')
            }`}>
            {gpt.imageUrl ? (
                <img
                    src={gpt.imageUrl}
                    alt={gpt.name}
                    className={`w-full h-full object-cover ${isDarkMode ? 'opacity-70' : 'opacity-90'}`}
                    loading="lazy"
                />
            ) : (
                <div className={`w-full h-full flex items-center justify-center ${isDarkMode ? 'bg-gradient-to-br from-blue-900/50 to-purple-900/50' : 'bg-gradient-to-br from-blue-100/50 to-purple-100/50'}`}>
                    <span className={`text-3xl sm:text-4xl ${isDarkMode ? 'text-white/30' : 'text-gray-500/50'}`}>{gpt.name.charAt(0)}</span>
                </div>
            )}
            {/* Favorite Button */}
            <button
                onClick={(e) => { e.stopPropagation(); onToggleFavorite(gpt._id, gpt.isFavorite); }}
                className={`absolute top-2 right-2 p-1.5 rounded-full transition-all ${isDarkMode
                        ? 'bg-black/40 hover:bg-black/60'
                        : 'bg-white/60 hover:bg-white/80'
                    } ${gpt.isFavorite
                        ? 'text-red-500 hover:text-red-400'
                        : 'text-gray-400 hover:text-red-500 dark:text-gray-500 dark:hover:text-red-500'
                    }`}
                title={gpt.isFavorite ? "Remove from favorites" : "Add to favorites"}
            >
                <FiHeart size={16} fill={gpt.isFavorite ? "currentColor" : "none"} />
            </button>
            {/* Move to Folder Button */}
            <button
                onClick={(e) => { e.stopPropagation(); onMoveToFolder(gpt); }}
                className={`absolute top-2 right-10 p-1.5 rounded-full transition-all ${isDarkMode
                        ? 'bg-black/40 hover:bg-black/60 text-gray-400 hover:text-blue-400'
                        : 'bg-white/60 hover:bg-white/80 text-gray-500 hover:text-blue-500'
                    }`}
                title="Move to folder"
            >
                <FiFolder size={16} />
            </button>
        </div>
        <div className="p-3 sm:p-4 flex-grow flex flex-col">
            <div className="flex items-start justify-between mb-1.5 sm:mb-2">
                <h3 className={`font-semibold text-base sm:text-lg line-clamp-1 ${isDarkMode ? 'text-white' : 'text-gray-900'}`}>{gpt.name}</h3>
                <div className={`flex items-center flex-shrink-0 gap-1 px-1.5 sm:px-2 py-0.5 rounded text-[10px] sm:text-xs ${isDarkMode ? 'bg-gray-700 text-gray-200' : 'bg-gray-200 text-gray-600'
                    }`}>
                    <span>{gpt.model || 'N/A'}</span>
                </div>
            </div>
            {gpt.folder && (
                <div className={`flex items-center gap-1 text-xs mb-1.5 ${isDarkMode ? 'text-gray-400' : 'text-gray-500'}`}>
                    <FiFolder size={12} />
                    <span>{gpt.folder}</span>
                </div>
            )}
            <p className={`text-xs sm:text-sm line-clamp-2 flex-grow ${isDarkMode ? 'text-gray-300' : 'text-gray-600'}`}>
                {gpt.description || 'No description available.'}
            </p>
            <div className={`mt-auto pt-2 border-t text-[10px] sm:text-xs flex justify-between items-center ${isDarkMode ? 'border-gray-700 text-gray-400' : 'border-gray-200 text-gray-500'
                }`}>
                <span>Assigned: {formatDate(gpt.assignedAt || new Date())}</span>
                {gpt.capabilities?.webBrowsing && (
                    <span className={`whitespace-nowrap px-1.5 py-0.5 rounded-full ${isDarkMode ? 'bg-green-900/40 text-green-200' : 'bg-green-100 text-green-700'
                        }`}>Web</span>
                )}
            </div>
            <button
                className={`mt-3 w-full py-2 rounded-lg transition-colors text-white text-sm font-medium flex items-center justify-center gap-2 ${isDarkMode ? 'bg-blue-600 hover:bg-blue-700' : 'bg-blue-500 hover:bg-blue-600'
                    }`}
                onClick={(e) => { e.stopPropagation(); onChatClick(gpt._id); }}
            >
                <FiMessageSquare size={16} />
                Chat with GPT
            </button>
        </div>
    </div>
));
const UserDashboard = () => {
    const [assignedGpts, setAssignedGpts] = useState([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);
    const [searchTerm, setSearchTerm] = useState('');
    const [sortOption, setSortOption] = useState('newest');
    const [showSortOptions, setShowSortOptions] = useState(false);
    const sortDropdownRef = useRef(null);
    const navigate = useNavigate();
    const { isDarkMode } = useTheme();
    const [folders, setFolders] = useState(['All']);
    const [selectedFolder, setSelectedFolder] = useState('All');
    const [showMoveModal, setShowMoveModal] = useState(false);
    const [gptToMove, setGptToMove] = useState(null);
    const [showFolderOptions, setShowFolderOptions] = useState(false);
    const folderDropdownRef = useRef(null);
    const fetchAssignedGpts = useCallback(async () => {
        try {
            setLoading(true);
            setError(null);
            const response = await axiosInstance.get(`/api/custom-gpts/user/assigned`, {
                withCredentials: true
            });
            if (response.data.success && Array.isArray(response.data.gpts)) {
                const fetchedGpts = response.data.gpts;
                setAssignedGpts(fetchedGpts);
                const uniqueFolders = [...new Set(fetchedGpts
                    .map(gpt => gpt.folder)
                    .filter(folder => folder)
                )];
                setFolders(prev => [...new Set(['All', ...uniqueFolders])]);
            } else {
                console.warn("API response successful but 'gpts' field is not an array or missing:", response.data);
                setAssignedGpts([]);
                setFolders(['All']);
                setError("No collections found or received unexpected data format.");
            }
        } catch (error) {
            console.error("Error fetching assigned GPTs:", error);
            const errorMsg = error.response?.data?.message || "Failed to load your collections";
            setError(errorMsg);
            setAssignedGpts([]);
            setFolders(['All']);
        } finally {
            setLoading(false);
        }
    }, []);
    useEffect(() => {
        fetchAssignedGpts();
    }, [fetchAssignedGpts]);
    const handleClickOutside = useCallback((event) => {
        if (sortDropdownRef.current && !sortDropdownRef.current.contains(event.target)) {
            setShowSortOptions(false);
        }
        if (folderDropdownRef.current && !folderDropdownRef.current.contains(event.target)) {
            setShowFolderOptions(false);
        }
    }, []);
    useEffect(() => {
        document.addEventListener("mousedown", handleClickOutside);
        return () => document.removeEventListener("mousedown", handleClickOutside);
    }, [handleClickOutside]);
    const filteredGpts = useMemo(() => {
        return assignedGpts
            .filter(gpt =>
                gpt.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
                (gpt.description && gpt.description.toLowerCase().includes(searchTerm.toLowerCase()))
            )
            .filter(gpt => {
                if (selectedFolder === 'All') return true;
                return gpt.folder === selectedFolder;
            })
            .sort((a, b) => {
                const dateA = a.assignedAt ? new Date(a.assignedAt) : new Date(0);
                const dateB = b.assignedAt ? new Date(b.assignedAt) : new Date(0);
                const nameA = a.name || '';
                const nameB = b.name || '';
                switch (sortOption) {
                    case 'newest': return dateB - dateA;
                    case 'oldest': return dateA - dateB;
                    case 'alphabetical': return nameA.localeCompare(nameB);
                    default: return dateB - dateA;
                }
            });
    }, [assignedGpts, searchTerm, sortOption, selectedFolder]);
    const formatDate = useCallback((dateString) => {
        try {
            const date = new Date(dateString);
            if (isNaN(date.getTime())) {
                return 'Unknown Date';
            }
            return date.toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' });
        } catch (e) {
            console.error("Error formatting date:", dateString, e);
            return 'Unknown Date';
        }
    }, []);
    const handleChatClick = useCallback(async (gptId) => {
        if (!gptId) {
            console.error("Invalid GPT ID");
            toast.error("Cannot open chat: Invalid GPT ID.");
            return;
        }
        const selectedGpt = assignedGpts.find(gpt => gpt._id === gptId);
        if (!selectedGpt) {
            console.warn(`GPT with ID ${gptId} not found in local state, navigating anyway.`);
        } else {
            try {
                const backendUrl = import.meta.env.VITE_PYTHON_API_URL;
                if (backendUrl) {
                    const payload = {
                        user_email: "user@example.com",
                        gpt_name: selectedGpt.name || "Unknown GPT",
                        gpt_id: selectedGpt._id,
                        file_urls: selectedGpt.files || [],
                        schema: {
                            model: selectedGpt.model || "gpt-4o-mini"
                        }
                    };
                    fetch(`${backendUrl}/gpt-opened`, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify(payload)
                    }).catch(err => console.warn("Failed to notify backend:", err));
                }
            } catch (err) {
                console.warn("Error during pre-load notification:", err);
            }
        }
        navigate(`/user/chat?gptId=${gptId}`);
    }, [navigate, assignedGpts]);
    const handleSearchChange = useCallback((e) => setSearchTerm(e.target.value), []);
    const toggleSortOptions = useCallback(() => setShowSortOptions(prev => !prev), []);
    const handleSortOptionSelect = useCallback((option) => {
        setSortOption(option);
        setShowSortOptions(false);
    }, []);
    const handleRetry = useCallback(() => fetchAssignedGpts(), [fetchAssignedGpts]);
    const handleToggleFavorite = useCallback(async (gptId, isFavorite) => {
        setAssignedGpts(prev => prev.map(gpt =>
            gpt._id === gptId
                ? { ...gpt, isFavorite: !isFavorite }
                : gpt
        ));
        try {
            const endpoint = `/api/custom-gpts/user/favorites/${gptId}`;
            if (isFavorite) {
                await axiosInstance.delete(endpoint, { withCredentials: true });
                toast.info("Removed from favorites");
            } else {
                await axiosInstance.post(endpoint, {}, { withCredentials: true });
                toast.success("Added to favorites");
            }
        } catch (error) {
            console.error("Error toggling favorite:", error);
            toast.error(`Failed to ${isFavorite ? 'remove from' : 'add to'} favorites`);
            setAssignedGpts(prev => prev.map(gpt =>
                gpt._id === gptId
                    ? { ...gpt, isFavorite: isFavorite }
                    : gpt
            ));
        }
    }, []);
    const handleMoveToFolder = useCallback((gpt) => {
        setGptToMove(gpt);
        setShowMoveModal(true);
    }, []);
    const handleGptMoved = useCallback((updatedGpt, newFolderName) => {
        setAssignedGpts(prev => prev.map(gpt =>
            gpt._id === updatedGpt._id
                ? updatedGpt
                : gpt
        ));
        if (newFolderName && !folders.includes(newFolderName)) {
            setFolders(prevFolders => [...new Set([...prevFolders, newFolderName])]);
            setSelectedFolder(newFolderName);
        } else if (updatedGpt.folder && updatedGpt.folder !== selectedFolder) {
            setSelectedFolder(updatedGpt.folder);
        } else if (!updatedGpt.folder && selectedFolder !== 'All') {
            setSelectedFolder('All');
        }
        toast.success(`Moved "${updatedGpt.name}" to ${updatedGpt.folder || 'No Folder'}`);
    }, [folders]);
    if (loading && assignedGpts.length === 0 && !error) {
        return (
            <div className={`flex items-center justify-center h-full ${isDarkMode ? 'bg-black text-white' : 'bg-gray-50 text-gray-700'}`}>
                <div className={`animate-spin rounded-full h-10 w-10 border-t-2 border-b-2 ${isDarkMode ? 'border-blue-500' : 'border-blue-600'}`}></div>
            </div>
        );
    }
    return (
        <div className={`flex flex-col h-full p-4 sm:p-6 overflow-hidden transition-colors duration-300 ${isDarkMode ? 'bg-black text-white' : 'bg-gray-50 text-gray-900'
            }`}>
            <div className="mb-4 md:mb-6 flex-shrink-0 text-center md:text-left">
                <h1 className="text-xl sm:text-2xl font-bold">User Dashboard</h1>
            </div>
            <div className="flex flex-col sm:flex-row sm:items-center justify-between mb-4 md:mb-6 gap-4 flex-shrink-0">
                <div className="flex flex-col sm:flex-row gap-2 sm:gap-4 flex-grow">
                    <div className="relative flex-grow sm:flex-grow-0">
                        <FiSearch className={`absolute left-3 top-1/2 transform -translate-y-1/2 ${isDarkMode ? 'text-gray-400' : 'text-gray-500'}`} />
                        <input
                            type="text"
                            placeholder="Search Collections..."
                            value={searchTerm}
                            onChange={handleSearchChange}
                            className={`w-full sm:w-52 md:w-64 pl-10 pr-4 py-2 rounded-lg border focus:ring-2 focus:ring-blue-500 focus:border-blue-500 outline-none transition-all text-sm ${isDarkMode
                                    ? 'bg-gray-700 border-gray-600 text-white placeholder-gray-400'
                                    : 'bg-white border-gray-300 text-gray-900 placeholder-gray-500'
                                }`}
                        />
                    </div>
                    <div className="relative" ref={folderDropdownRef}>
                        <button
                            onClick={() => setShowFolderOptions(prev => !prev)}
                            className={`flex items-center justify-between w-full sm:w-40 px-3 py-2 rounded-lg border text-sm transition-colors ${isDarkMode
                                    ? 'bg-gray-700 border-gray-600 text-white hover:bg-gray-600'
                                    : 'bg-white border-gray-300 text-gray-700 hover:bg-gray-50'
                                }`}
                        >
                            <span className="truncate flex items-center gap-2">
                                <FiFolder size={16} />
                                {selectedFolder}
                            </span>
                            {showFolderOptions ? <FiChevronUp size={16} /> : <FiChevronDown size={16} />}
                        </button>
                        {showFolderOptions && (
                            <div className={`absolute z-10 w-full mt-1 rounded-lg shadow-lg border overflow-hidden text-sm max-h-60 overflow-y-auto ${isDarkMode
                                    ? 'bg-gray-800 border-gray-700 text-white'
                                    : 'bg-white border-gray-200 text-gray-700'
                                }`}>
                                {folders.map((folder) => (
                                    <button
                                        key={folder}
                                        className={`block w-full text-left px-3 py-2 transition-colors flex items-center gap-2 ${selectedFolder === folder
                                                ? (isDarkMode ? 'bg-blue-600' : 'bg-blue-100 text-blue-700 font-medium')
                                                : (isDarkMode ? 'hover:bg-gray-700' : 'hover:bg-gray-100')
                                            }`}
                                        onClick={() => {
                                            setSelectedFolder(folder);
                                            setShowFolderOptions(false);
                                        }}
                                    >
                                        <FiFolder size={14} />
                                        {folder}
                                    </button>
                                ))}
                            </div>
                        )}
                    </div>
                </div>
                <div className="relative" ref={sortDropdownRef}>
                    <button
                        onClick={toggleSortOptions}
                        className={`flex items-center justify-between w-full sm:w-36 px-3 py-2 rounded-lg border text-sm transition-colors ${isDarkMode
                                ? 'bg-gray-700 border-gray-600 text-white hover:bg-gray-600'
                                : 'bg-white border-gray-300 text-gray-700 hover:bg-gray-50'
                            }`}
                    >
                        <span className="truncate">Sort: {sortOption.charAt(0).toUpperCase() + sortOption.slice(1)}</span>
                        {showSortOptions ? <FiChevronUp size={16} /> : <FiChevronDown size={16} />}
                    </button>
                    {showSortOptions && (
                        <div className={`absolute z-10 w-full sm:w-36 mt-1 rounded-lg shadow-lg border overflow-hidden text-sm ${isDarkMode
                                ? 'bg-gray-800 border-gray-700 text-white'
                                : 'bg-white border-gray-200 text-gray-700'
                            }`}>
                            {['newest', 'oldest', 'alphabetical'].map((optionValue) => (
                                <button
                                    key={optionValue}
                                    className={`block w-full text-left px-3 py-2 transition-colors ${sortOption === optionValue
                                            ? (isDarkMode ? 'bg-blue-600' : 'bg-blue-100 text-blue-700 font-medium')
                                            : (isDarkMode ? 'hover:bg-gray-700' : 'hover:bg-gray-100')
                                        }`}
                                    onClick={() => handleSortOptionSelect(optionValue)}
                                >
                                    {optionValue.charAt(0).toUpperCase() + optionValue.slice(1)}
                                </button>
                            ))}
                        </div>
                    )}
                </div>
            </div>
            <div className="flex-1 overflow-y-auto pb-6 custom-scrollbar-dark dark:custom-scrollbar">
                {error ? (
                    <div className={`flex flex-col items-center justify-center h-full text-center ${isDarkMode ? 'text-red-400' : 'text-red-600'}`}>
                        <FiXCircle size={40} className="mb-4 opacity-70" />
                        <p className="text-lg mb-4">{error}</p>
                        <button
                            onClick={handleRetry}
                            className={`px-4 py-2 rounded-lg transition-colors text-white ${isDarkMode ? 'bg-blue-600 hover:bg-blue-700' : 'bg-blue-500 hover:bg-blue-600'
                                }`}
                        >
                            Try Again
                        </button>
                    </div>
                ) : filteredGpts.length === 0 ? (
                    <div className={`flex flex-col items-center justify-center h-full text-center ${isDarkMode ? 'text-gray-400' : 'text-gray-500'}`}>
                        <FiMessageSquare size={40} className="mb-4 opacity-50" />
                        <p className="text-lg mb-2">
                            {searchTerm
                                ? `No collections matching "${searchTerm}" ${selectedFolder !== 'All' ? `in folder "${selectedFolder}"` : ''}`
                                : selectedFolder !== 'All'
                                    ? `No GPTs in the "${selectedFolder}" folder`
                                    : "You don't have any collections assigned yet"
                            }
                        </p>
                        <p className="text-sm">
                            {selectedFolder !== 'All' && !searchTerm
                                ? "Try selecting 'All' folders or contact your administrator."
                                : "Assigned GPTs will appear here once assigned by an administrator."
                            }
                        </p>
                    </div>
                ) : (
                    <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-3 xl:grid-cols-4 gap-4 sm:gap-6">
                        {filteredGpts.map(gpt => (
                            <GptCard
                                key={gpt._id}
                                gpt={gpt}
                                formatDate={formatDate}
                                onChatClick={handleChatClick}
                                onToggleFavorite={handleToggleFavorite}
                                onMoveToFolder={handleMoveToFolder}
                                isDarkMode={isDarkMode}
                            />
                        ))}
                    </div>
                )}
            </div>
            {showMoveModal && gptToMove && (
                <MoveToFolderModal
                    isOpen={showMoveModal}
                    onClose={() => { setShowMoveModal(false); setGptToMove(null); }}
                    gpt={gptToMove}
                    existingFolders={folders.filter(f => f !== 'All')}
                    onSuccess={handleGptMoved}
                />
            )}
        </div>
    );
};
export default UserDashboard;
````

## File: frontend/src/components/AuthCallback.jsx
````javascript
import React, { useEffect } from 'react';
import { useSearchParams, useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
const AuthCallback = () => {
    const [searchParams] = useSearchParams();
    const navigate = useNavigate();
    const { handleAuthCallback, setError } = useAuth();
    useEffect(() => {
        const accessToken = searchParams.get('accessToken');
        const userParam = searchParams.get('user');
        const errorParam = searchParams.get('error'); // Check for errors passed back
        if (errorParam) {
            console.error("OAuth Callback Error:", errorParam);
            setError(`Authentication failed: ${errorParam}`);
            navigate('/login', { replace: true });
            return;
        }
        if (accessToken && userParam) {
            try {
                const user = JSON.parse(userParam);
                // Call the context function to handle the tokens and user data
                handleAuthCallback(accessToken, user);
                // Navigation is handled inside handleAuthCallback now
            } catch (e) {
                console.error("Failed to parse user data from callback:", e);
                setError('Authentication callback failed: Invalid data received.');
                navigate('/login', { replace: true });
            }
        } else {
            // Missing token or user data in callback
            console.error("OAuth Callback missing token or user data");
            setError('Authentication callback failed: Missing data.');
            navigate('/login', { replace: true });
        }
        // No need for dependency array re-run, this should only run once on mount
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, []); // Run only once on component mount
    // Display a loading indicator while processing
    return (
        <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '100vh' }}>
            Processing authentication...
        </div>
    );
};
export default AuthCallback;
````

## File: frontend/src/components/ProtectedRoute.jsx
````javascript
import React from 'react';
import { Navigate, useLocation } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
const ProtectedRoute = ({ children, allowedRoles }) => {
    const { user, loading, accessToken } = useAuth();
    const location = useLocation();
    if (loading) {
        return (
            <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '100vh' }}>
                Loading...
            </div>
        );
    }
    const currentToken = accessToken || localStorage.getItem('accessToken');
    if (!currentToken || !user) {
        return <Navigate to="/login" state={{ from: location }} replace />;
    }
    if (allowedRoles && !allowedRoles.includes(user.role)) {
        console.warn(`User role '${user.role}' not authorized for route requiring roles: ${allowedRoles.join(', ')} at ${location.pathname}`);
        return <Navigate to="/unauthorized" replace />;
    }
    return children;
};
export default ProtectedRoute;
````

## File: frontend/src/context/AuthContext.jsx
````javascript
import React, { createContext, useState, useContext, useEffect, useCallback } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { axiosInstance, setAccessToken, getAccessToken, removeAccessToken } from '../api/axiosInstance';
const AuthContext = createContext();
export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [accessToken, _setAccessToken] = useState(() => getAccessToken());
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const navigate = useNavigate();
  const location = useLocation();
  const updateAccessToken = useCallback((token) => {
    if (token) {
      setAccessToken(token);
      _setAccessToken(token);
    } else {
      removeAccessToken();
      _setAccessToken(null);
    }
  }, []);
  const fetchUser = useCallback(async () => {
    const currentToken = getAccessToken();
    if (!currentToken) {
      const savedUser = localStorage.getItem('user');
      if (savedUser) {
        try {
          setUser(JSON.parse(savedUser));
          const response = await axiosInstance.post('/api/auth/refresh');
          if (response.data && response.data.accessToken) {
            updateAccessToken(response.data.accessToken);
          }
        } catch (e) {
          console.error("Failed to use saved user data:", e);
          setUser(null);
          localStorage.removeItem('user');
        }
      } else {
        setUser(null);
      }
      setLoading(false);
      return;
    }
    setLoading(true);
    try {
      const response = await axiosInstance.get('/api/auth/me');
      if (response.data) {
        setUser(response.data);
        localStorage.setItem('user', JSON.stringify(response.data));
      } else {
        updateAccessToken(null);
        setUser(null);
        localStorage.removeItem('user');
      }
    } catch (err) {
      console.error("Error fetching user:", err);
      updateAccessToken(null);
      setUser(null);
      localStorage.removeItem('user');
    } finally {
      setLoading(false);
    }
  }, [updateAccessToken]);
  useEffect(() => {
    if (accessToken) {
      fetchUser();
    } else {
      setLoading(false);
    }
  }, [accessToken, fetchUser]);
  const handleAuthCallback = useCallback((token, userData) => {
    updateAccessToken(token);
    setUser(userData);
    setLoading(false);
    localStorage.setItem('user', JSON.stringify(userData));
    if (userData?.role === 'admin') {
      navigate('/admin', { replace: true });
    } else {
      navigate('/employee', { replace: true });
    }
  }, [navigate, updateAccessToken]);
  const login = async (email, password) => {
    setLoading(true);
    setError(null);
    try {
      const response = await axiosInstance.post('/api/auth/login', { email, password });
      if (response.data?.accessToken && response.data?.user) {
        updateAccessToken(response.data.accessToken);
        setUser(response.data.user);
        if (response.data.user.role === 'admin') {
          navigate('/admin');
        } else {
          navigate('/employee');
        }
      } else {
        setError('Login failed: Invalid response from server.');
        updateAccessToken(null);
        setUser(null);
      }
    } catch (err) {
      setError(err.response?.data?.message || 'Login failed');
      updateAccessToken(null);
      setUser(null);
    } finally {
      setLoading(false);
    }
  };
  const signup = async (name, email, password) => {
    setLoading(true);
    setError(null);
    try {
      const response = await axiosInstance.post('/api/auth/signup', { name, email, password });
      if (response.status === 201) {
        navigate('/login?signup=success');
      } else {
        setError(response.data?.message || 'Signup completed but with unexpected status.');
      }
    } catch (err) {
      setError(err.response?.data?.message || 'Signup failed');
    } finally {
      setLoading(false);
    }
  };
  const logout = async () => {
    setLoading(true);
    setError(null);
    const currentToken = getAccessToken();
    try {
      if (currentToken && user) {
        try {
          await axiosInstance.put('/api/auth/me/inactive');
        } catch (inactiveErr) {
          console.error("Failed to mark user as inactive (proceeding with logout):", inactiveErr.response?.data?.message || inactiveErr.message);
        }
      }
      await axiosInstance.post('/api/auth/logout');
    } catch (err) {
      setError(err.response?.data?.message || 'Logout failed');
    } finally {
      updateAccessToken(null);
      setUser(null);
      delete axiosInstance.defaults.headers.common['Authorization'];
      setLoading(false);
      navigate('/login');
    }
  };
  const googleAuthInitiate = () => {
    setLoading(true);
    try {
      const redirectUrl = `${axiosInstance.defaults.baseURL}/api/auth/google`;
      updateAccessToken(null);
      setUser(null);
      window.location.href = redirectUrl;
    } catch (err) {
      setLoading(false);
      setError('Google authentication initiation failed');
    }
  };
  return (
    <AuthContext.Provider value={{
      user,
      accessToken,
      loading,
      error,
      login,
      signup,
      logout,
      googleAuthInitiate,
      handleAuthCallback,
      fetchUser,
      setError
    }}>
      {children}
    </AuthContext.Provider>
  );
};
export const useAuth = () => {
  return useContext(AuthContext);
};
````

## File: frontend/src/context/ThemeContext.jsx
````javascript
import React, { createContext, useState, useContext, useEffect } from 'react';
const ThemeContext = createContext();
export const ThemeProvider = ({ children }) => {
  const [isDarkMode, setIsDarkMode] = useState(() => {
    const savedTheme = localStorage.getItem('theme');
    return savedTheme ? savedTheme === 'dark' : true; // Default to dark mode
  });
  useEffect(() => {
    // Apply theme when it changes
    document.documentElement.classList.toggle('dark', isDarkMode);
    localStorage.setItem('theme', isDarkMode ? 'dark' : 'light');
  }, [isDarkMode]);
  const toggleTheme = (value) => {
    if (value !== undefined) {
      setIsDarkMode(value);
    } else {
      setIsDarkMode(prev => !prev);
    }
  };
  return (
    <ThemeContext.Provider value={{ isDarkMode, toggleTheme }}>
      {children}
    </ThemeContext.Provider>
  );
};
export const useTheme = () => useContext(ThemeContext);
````

## File: frontend/src/pages/Admin.jsx
````javascript
import React, { useState, useEffect } from 'react';
import { Routes, Route, useLocation, useParams, useNavigate } from 'react-router-dom';
import AdminSidebar from '../components/Admin/AdminSidebar';
import AdminDashboard from '../components/Admin/AdminDashboard';
import TeamManagement from '../components/Admin/TeamManagement';
import CollectionsPage from '../components/Admin/CollectionsPage';
import CreateCustomGpt from '../components/Admin/CreateCustomGpt';
import SettingsPage from '../components/Admin/SettingsPage';
import HistoryPage from '../components/Admin/HistoryPage';
import UserHistoryPage from '../components/Admin/UserHistoryPage';
import AdminChat from '../components/Admin/AdminChat';
// Placeholder components for other sections
const CollectionsComponent = () => <div className="flex-1 p-6"><h1 className="text-2xl font-bold">Collections Page</h1></div>;
const HistoryComponent = () => <div className="flex-1 p-6"><h1 className="text-2xl font-bold">History Page</h1></div>;
const AdminLayout = () => {
    const location = useLocation();
    const navigate = useNavigate();
    const [activeSection, setActiveSection] = useState('dashboard');
    useEffect(() => {
        const path = location.pathname.split('/admin/')[1] || 'dashboard';
        if (path.startsWith('edit-gpt/')) {
            setActiveSection('collections');
        } else if (path.startsWith('create-gpt')) {
            setActiveSection('collections');
        } else {
            setActiveSection(path);
        }
    }, [location.pathname]);
    const handleSidebarNavigate = (sectionId) => {
        navigate(`/admin/${sectionId}`);
    };
    return (
        <div className="flex h-screen overflow-hidden bg-black">
            <AdminSidebar activePage={activeSection} onNavigate={handleSidebarNavigate} />
            <div className="flex-1 overflow-hidden">
                <Routes>
                    <Route index element={<AdminDashboard />} />
                    <Route path="dashboard" element={<AdminDashboard />} />
                    <Route path="collections" element={<CollectionsPage />} />
                    <Route path="create-gpt" element={<CreateCustomGpt onGoBack={() => navigate('/admin/collections')} />} />
                    <Route path="edit-gpt/:gptId" element={<EditGptWrapper />} />
                    <Route path="team" element={<TeamManagement />} />
                    <Route path="settings" element={<SettingsPage />} />
                    <Route path="history" element={<HistoryPage />} />
                    <Route path="history/user/:userId" element={<UserHistoryPage />} />
                    <Route path="chat/:gptId" element={<AdminChat />} />
                    <Route path="*" element={<AdminDashboard />} />
                </Routes>
            </div>
        </div>
    );
};
const EditGptWrapper = () => {
    const { gptId } = useParams();
    const navigate = useNavigate();
    return <CreateCustomGpt editGptId={gptId} onGoBack={() => navigate('/admin/collections')} />;
};
export default AdminLayout;
````

## File: frontend/src/pages/Homepage.jsx
````javascript
import React from 'react';
import { Link } from 'react-router-dom';
const Homepage = () => {
  return (
    <div className="flex flex-col items-center justify-center h-screen">
      <h1 className="text-4xl font-bold">Welcome to the Homepage
        <span className="text-blue-500">Agent Maker</span>
      </h1>
      <Link to="/login" className="mt-4 px-4 py-2 bg-blue-500 text-white rounded hover:bg-blue-600 transition-colors">
        Login
      </Link>
    </div>
  );
};
export default Homepage;
````

## File: frontend/src/pages/LoginPage.jsx
````javascript
import React, { useState, useEffect } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { FcGoogle } from 'react-icons/fc';
import { useAuth } from '../context/AuthContext';
const LoginPage = () => {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const { login, loading, error, setError, googleAuthInitiate } = useAuth();
  const [searchParams] = useSearchParams();
  useEffect(() => {
    setError(null);
    const errorParam = searchParams.get('error');
    if (errorParam) {
      setError(`Login failed: ${errorParam.replace(/_/g, ' ')}`);
    }
    const signupParam = searchParams.get('signup');
    if (signupParam === 'success') {
    }
  }, [setError, searchParams]);
  const handleSubmit = async (e) => {
    e.preventDefault();
    await login(email, password);
  };
  return (
    <div className="flex h-screen w-full bg-white">
      {/* Left side - Image and Text */}
      <div className="hidden lg:flex lg:w-1/2 bg-black items-center justify-center relative">
        <div className="absolute inset-0 bg-black opacity-80"></div>
        <div className="relative z-10 text-white px-12 max-w-lg">
          <h1 className="text-4xl font-bold mb-6">AI-Powered Experience</h1>
          <p className="text-lg opacity-90 mb-8">
            Access your intelligent assistant and unlock the power of advanced AI.
            Let our cutting-edge algorithms transform your workflow and elevate your
            productivity to unprecedented levels.
          </p>
          <div className="flex items-center space-x-3">
            <p className="text-sm uppercase font-bold">Intelligent Solutions</p>
          </div>
        </div>
      </div>
      {/* Right side - Login Form */}
      <div className="w-full lg:w-1/2 flex items-center justify-center px-6 md:px-16 py-12">
        <div className="w-full max-w-md">
          <div className="text-center mb-10">
            <h2 className="text-3xl font-bold text-gray-900 mb-2">Welcome Back</h2>
            <p className="text-gray-600">Please enter your details</p>
          </div>
          {error && (
            <div className="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded mb-4" role="alert">
              {error}
            </div>
          )}
          <form onSubmit={handleSubmit} className="space-y-6">
            <div>
              <label htmlFor="email" className="block text-sm font-medium text-gray-700 mb-1">
                Email
              </label>
              <input
                id="email"
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                className="w-full px-4 py-3 rounded-lg border border-gray-300 focus:outline-none focus:ring-2 focus:ring-gray-700 focus:border-transparent transition-all bg-gray-50"
                placeholder="john@example.com"
                required
              />
            </div>
            <div>
              <div className="flex items-center justify-between mb-1">
                <label htmlFor="password" className="block text-sm font-medium text-gray-700">
                  Password
                </label>
                <a href="#" className="text-sm text-gray-600 hover:text-black">
                  Forgot password?
                </a>
              </div>
              <input
                id="password"
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="w-full px-4 py-3 rounded-lg border border-gray-300 focus:outline-none focus:ring-2 focus:ring-gray-700 focus:border-transparent transition-all bg-gray-50"
                placeholder="••••••••"
                required
              />
            </div>
            <button
              type="submit"
              className={`w-full bg-black hover:bg-gray-800 text-white py-3 rounded-lg font-medium shadow-sm transition-all duration-200 transform hover:translate-y-[-2px] ${loading ? 'opacity-50 cursor-not-allowed' : ''}`}
              disabled={loading}
            >
              {loading ? 'Signing In...' : 'Sign In'}
            </button>
            <div className="flex items-center my-4">
              <div className="flex-1 h-px bg-gray-300"></div>
              <p className="mx-4 text-sm text-gray-500">or</p>
              <div className="flex-1 h-px bg-gray-300"></div>
            </div>
            <div className="">
              <button
                type="button"
                onClick={googleAuthInitiate}
                disabled={loading}
                className="w-full flex items-center justify-center gap-3 bg-white border border-gray-300 py-3 rounded-lg font-medium text-gray-700 hover:bg-gray-50 transition-all shadow-sm disabled:opacity-50"
              >
                <FcGoogle size={20} />
                Sign in with Google
              </button>
            </div>
          </form>
          <p className="text-center mt-8 text-gray-600">
            Don't have an account?{' '}
            <Link to="/signup" className="text-black font-medium hover:underline">
              Sign up
            </Link>
          </p>
        </div>
      </div>
    </div>
  );
};
export default LoginPage;
````

## File: frontend/src/pages/SignupPage.jsx
````javascript
import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { FcGoogle } from 'react-icons/fc';
import { useAuth } from '../context/AuthContext';
const SignupPage = () => {
  const [name, setName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const { signup, loading, error, setError, googleAuthInitiate } = useAuth();
  useEffect(() => {
    setError(null);
  }, [setError]);
  const handleSubmit = async (e) => {
    e.preventDefault();
    await signup(name, email, password);
  };
  return (
    <div className="flex h-screen w-full bg-white">
      {/* Left side - Image and Text */}
      <div className="hidden lg:flex lg:w-1/2 bg-black items-center justify-center relative">
        <div className="absolute inset-0 bg-black opacity-80"></div>
        <div className="relative z-10 text-white px-12 max-w-lg">
          <h1 className="text-4xl font-bold mb-6">Join Our Community</h1>
          <p className="text-lg opacity-90 mb-8">
            Create an account to access exclusive features and personalized experiences.
            Leverage our AI-powered platform to transform the way you work and collaborate.
          </p>
          <div className="flex items-center space-x-3">
            <div className="h-1 w-12 bg-white"></div>
            <p className="text-sm uppercase tracking-widest">Future Technology</p>
          </div>
        </div>
      </div>
      {/* Right side - Signup Form */}
      <div className="w-full lg:w-1/2 flex items-center justify-center px-6 md:px-16 py-12">
        <div className="w-full max-w-md">
          <div className="text-center mb-10">
            <h2 className="text-3xl font-bold text-gray-900 mb-2">Create Account</h2>
            <p className="text-gray-600">Please enter your details</p>
          </div>
          {error && (
            <div className="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded mb-4" role="alert">
              {error}
            </div>
          )}
          <form onSubmit={handleSubmit} className="space-y-6">
            <div>
              <label htmlFor="name" className="block text-sm font-medium text-gray-700 mb-1">
                Full Name
              </label>
              <input
                id="name"
                type="text"
                value={name}
                onChange={(e) => setName(e.target.value)}
                className="w-full px-4 py-3 rounded-lg border border-gray-300 focus:outline-none focus:ring-2 focus:ring-gray-700 focus:border-transparent transition-all bg-gray-50"
                placeholder="John Doe"
                required
              />
            </div>
            <div>
              <label htmlFor="email" className="block text-sm font-medium text-gray-700 mb-1">
                Email
              </label>
              <input
                id="email"
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                className="w-full px-4 py-3 rounded-lg border border-gray-300 focus:outline-none focus:ring-2 focus:ring-gray-700 focus:border-transparent transition-all bg-gray-50"
                placeholder="john@example.com"
                required
              />
            </div>
            <div>
              <label htmlFor="password" className="block text-sm font-medium text-gray-700 mb-1">
                Password
              </label>
              <input
                id="password"
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="w-full px-4 py-3 rounded-lg border border-gray-300 focus:outline-none focus:ring-2 focus:ring-gray-700 focus:border-transparent transition-all bg-gray-50"
                placeholder="••••••••"
                required
              />
            </div>
            <button
              type="submit"
              className={`w-full bg-black hover:bg-gray-800 text-white py-3 rounded-lg font-medium shadow-sm transition-all duration-200 transform hover:translate-y-[-2px] ${loading ? 'opacity-50 cursor-not-allowed' : ''}`}
              disabled={loading}
            >
              {loading ? 'Signing Up...' : 'Sign Up'}
            </button>
            <div className="flex items-center my-4">
              <div className="flex-1 h-px bg-gray-300"></div>
              <p className="mx-4 text-sm text-gray-500">or</p>
              <div className="flex-1 h-px bg-gray-300"></div>
            </div>
            <div>
              <button
                type="button"
                onClick={googleAuthInitiate}
                disabled={loading}
                className="w-full flex items-center justify-center gap-3 bg-white border border-gray-300 py-3 rounded-lg font-medium text-gray-700 hover:bg-gray-50 transition-all shadow-sm disabled:opacity-50"
              >
                <FcGoogle size={20} />
                Sign up with Google
              </button>
            </div>
          </form>
          <p className="text-center mt-8 text-gray-600">
            Already have an account?{' '}
            <Link to="/login" className="text-black font-medium hover:underline">
              Sign in
            </Link>
          </p>
        </div>
      </div>
    </div>
  );
};
export default SignupPage;
````

## File: frontend/src/pages/UnauthorizedPage.jsx
````javascript
import React from 'react';
import { Link } from 'react-router-dom';
const UnauthorizedPage = () => {
    return (
        <div className="flex flex-col items-center justify-center h-screen bg-gray-100 text-gray-800">
            <h1 className="text-6xl font-bold text-red-600 mb-4">403</h1>
            <h2 className="text-3xl font-semibold mb-2">Access Denied</h2>
            <p className="text-lg mb-6 text-center px-4">
                Sorry, you do not have the necessary permissions to access this page.
            </p>
            <Link
                to="/" // Link back to the homepage or a default logged-in page
                className="px-6 py-3 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition duration-300"
            >
                Go Back Home
            </Link>
        </div>
    );
};
export default UnauthorizedPage;
````

## File: frontend/src/pages/UserPage.jsx
````javascript
import React, { useState, useEffect } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import Sidebar from '../components/User/Sidebar';
import UserDashboard from '../components/User/UserDashboard';
import FavoritesPage from '../components/User/FavoritesPage';
import HistoryPage from '../components/User/HistoryPage';
import SettingsPage from '../components/User/SettingsPage';
import UserChat from '../components/User/UserChat';
// Placeholder components for other pages
const Favourites = () => <div className="p-4 sm:p-8 text-white mt-16 md:mt-0"><h1 className="text-2xl">Favourites Page</h1></div>;
const History = () => <div className="p-4 sm:p-8 text-white mt-16 md:mt-0"><h1 className="text-2xl">History Page</h1></div>;
const Layout = () => {
  const [currentPage, setCurrentPage] = useState('dashboard');
  const [isMobile, setIsMobile] = useState(false);
  const location = useLocation();
  const navigate = useNavigate();
  const queryParams = new URLSearchParams(location.search);
  const gptId = queryParams.get('gptId');
  // Check for mobile view
  useEffect(() => {
    const handleResize = () => {
      setIsMobile(window.innerWidth < 768);
    };
    window.addEventListener('resize', handleResize);
    handleResize(); // Check on initial render
    return () => window.removeEventListener('resize', handleResize);
  }, []);
  // Update currentPage based on location path
  useEffect(() => {
    const path = location.pathname.split('/user/')[1] || 'dashboard';
    setCurrentPage(path);
  }, [location.pathname]);
  // Handle sidebar navigation - renamed to match what UserChat.jsx expects
  const handleSidebarNavigation = (pageId) => {
    navigate(`/user/${pageId}`);
  };
  // Determine what content to render in the main area
  const renderMainContent = () => {
    if (gptId) {
      return <UserChat />; // Render chat if gptId is present
    }
    // Otherwise, render the selected page
    switch (currentPage) {
      case 'dashboard':
        return <UserDashboard />;
      case 'favourites':
      case 'favorites':
        return <FavoritesPage />;
      case 'history':
        return <HistoryPage />;
      case 'settings':
        return <SettingsPage />;
      default:
        return <UserDashboard />;
    }
  };
  return (
    <div className="flex h-screen overflow-hidden bg-black">
      {/* Sidebar is always rendered */}
      <Sidebar activePage={currentPage} onNavigate={handleSidebarNavigation} />
      {/* Main content area renders conditionally */}
      <div className={`flex-1 overflow-auto ${isMobile ? 'w-full' : ''}`}>
        {renderMainContent()}
      </div>
    </div>
  );
};
export default Layout;
````

## File: frontend/src/App.jsx
````javascript
import React, { useEffect } from 'react'
import { BrowserRouter as Router, Routes, Route, Navigate, useLocation } from 'react-router-dom'
import { Toaster } from 'react-hot-toast'
import SignupPage from './pages/SignupPage'
import LoginPage from './pages/LoginPage'
import Homepage from './pages/Homepage'
import UserPage from './pages/UserPage'
import Admin from './pages/Admin'
import UnauthorizedPage from './pages/UnauthorizedPage'
import { useAuth } from './context/AuthContext'
import AuthCallback from './components/AuthCallback'
import ProtectedRoute from './components/ProtectedRoute'
function App() {
  useEffect(() => {
    // Initialize Google client
    if (window.google && document.getElementById('google-signin-script')) {
      return; // Already initialized
    }
    // Load the Google Sign-In API script
    const script = document.createElement('script');
    script.id = 'google-signin-script';
    script.src = 'https://accounts.google.com/gsi/client';
    script.async = true;
    script.defer = true;
    document.body.appendChild(script);
    return () => {
      const scriptTag = document.getElementById('google-signin-script');
      if (scriptTag) document.body.removeChild(scriptTag);
    };
  }, []);
  const { user, loading } = useAuth();
  if (loading) {
    // Read initial theme preference directly for the loading screen
    const savedTheme = localStorage.getItem('theme');
    // Default to dark mode if no theme is saved or value is invalid
    const initialIsDarkMode = savedTheme ? savedTheme === 'dark' : true;
    return (
      // Updated: Background color based on initial theme check
      <div className={`flex items-center justify-center h-screen ${initialIsDarkMode ? 'bg-black text-white' : 'bg-gray-100 text-gray-900'}`}>
        {/* Updated: Spinner border color based on initial theme check */}
        <div className={`animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 ${initialIsDarkMode ? 'border-blue-500' : 'border-blue-600'}`}></div>
      </div>
    );
  }
  const getDefaultPathForUser = (loggedInUser) => {
    if (!loggedInUser) return "/";
    // Updated: Changed '/employee' to '/user/dashboard' as the default user path
    return loggedInUser.role === 'admin' ? '/admin/dashboard' : '/user/dashboard';
  };
  return (
    <>
      <Toaster
        position="top-right"
        toastOptions={{
          duration: 4000,
          style: {
            background: '#363636',
            color: '#fff',
          },
          success: {
            duration: 3000,
            iconTheme: {
              primary: '#10B981',
              secondary: '#FFFFFF'
            }
          },
          error: {
            duration: 5000,
            iconTheme: {
              primary: '#EF4444',
              secondary: '#FFFFFF'
            }
          }
        }}
      />
      <Routes>
        {/* Updated: Navigate logged-in users to their default path */}
        <Route path="/" element={!user ? <Homepage /> : <Navigate to={getDefaultPathForUser(user)} replace />} />
        <Route path="/login" element={!user ? <LoginPage /> : <Navigate to={getDefaultPathForUser(user)} replace />} />
        <Route path="/signup" element={!user ? <SignupPage /> : <Navigate to={getDefaultPathForUser(user)} replace />} />
        <Route path="/unauthorized" element={<UnauthorizedPage />} />
        {/* Updated: Changed '/employee' route to '/user/*' to match UserPage structure */}
        <Route path="/user/*" element={
          <ProtectedRoute allowedRoles={['employee', 'admin']}>
            <UserPage />
          </ProtectedRoute>
        } />
        <Route path="/admin/*" element={
          <ProtectedRoute allowedRoles={['admin']}>
            <Admin />
          </ProtectedRoute>
        } />
        <Route path="/auth/callback" element={<AuthCallback />} />
        {/* Fallback route */}
        <Route path="*" element={<Navigate to={getDefaultPathForUser(user)} replace />} />
      </Routes>
    </>
  )
}
export default App
````

## File: frontend/src/index.css
````css
@tailwind base;
@tailwind components;
@tailwind utilities;
/* Custom utility to hide scrollbars */
.no-scrollbar::-webkit-scrollbar {
    display: none;
    /* Safari and Chrome */
}
.no-scrollbar {
    -ms-overflow-style: none;
    /* IE and Edge */
    scrollbar-width: none;
    /* Firefox */
}
/* File upload card animation */
.file-upload-card {
    position: relative;
    overflow: hidden;
    backdrop-filter: blur(10px);
    transition: all 0.3s ease;
}
.file-upload-card::before {
    content: '';
    position: absolute;
    top: 0;
    left: -100%;
    width: 100%;
    height: 100%;
    background: linear-gradient(90deg, transparent, rgba(255, 255, 255, 0.1), transparent);
    animation: shine 1.5s infinite;
}
.file-name-pill {
    display: flex;
    align-items: center;
    padding: 0.5rem 1rem;
    background: rgba(59, 130, 246, 0.1);
    border-radius: 9999px;
    border: 1px solid rgba(59, 130, 246, 0.2);
    max-width: 100%;
}
.file-icon {
    display: flex;
    align-items: center;
    justify-content: center;
    width: 2rem;
    height: 2rem;
    background: linear-gradient(135deg, #3b82f6, #2563eb);
    border-radius: 0.5rem;
    margin-right: 0.75rem;
    flex-shrink: 0;
}
.progress-bar {
    height: 4px;
    background: rgba(59, 130, 246, 0.2);
    border-radius: 2px;
    overflow: hidden;
    margin-top: 0.5rem;
}
.progress-value {
    height: 100%;
    width: 0%;
    background: linear-gradient(90deg, #3b82f6, #818cf8);
    box-shadow: 0 0 10px rgba(59, 130, 246, 0.5);
    transition: width 0.2s ease-out;
    border-radius: 2px;
    position: relative;
}
.progress-value::after {
    content: '';
    position: absolute;
    top: 0;
    right: 0;
    height: 100%;
    width: 20px;
    background: linear-gradient(90deg, transparent, rgba(255, 255, 255, 0.3));
    transform: skewX(-20deg);
    animation: shimmer 1s infinite;
}
/* 
/* Assistant message style */
.assistant-message {
    background: rgba(255, 255, 255, 0.03);
    backdrop-filter: blur(10px);
    border: 1px solid rgba(255, 255, 255, 0.08);
    box-shadow: 0 4px 15px rgba(0, 0, 0, 0.05);
}
/* Animations */
@keyframes shimmer {
    0% {
        transform: translateX(-100%) skewX(-20deg);
    }
    100% {
        transform: translateX(100%) skewX(-20deg);
    }
}
@keyframes shine {
    0% {
        left: -100%;
    }
    100% {
        left: 100%;
    }
}
@keyframes pulse {
    0%,
    100% {
        opacity: 0.6;
    }
    50% {
        opacity: 1;
    }
}
@keyframes bounce-soft {
    0%,
    100% {
        transform: translateY(0);
    }
    50% {
        transform: translateY(-10%);
    }
}
/* File icon styles */
.file-icon-pdf {
    background: linear-gradient(135deg, #f56565, #c53030);
}
.file-icon-docx {
    background: linear-gradient(135deg, #2b6cb0, #1a365d);
}
.file-icon-txt {
    background: linear-gradient(135deg, #4c51bf, #2a4365);
}
/* Glossy button styles from original file */
.glossy-button {
    background: linear-gradient(145deg, #1a1a1a, #000000);
    box-shadow: 0 4px 15px rgba(0, 0, 0, 0.5),
        inset 0 1px 1px rgba(255, 255, 255, 0.1),
        inset 0 -1px 1px rgba(0, 0, 0, 0.3);
    transition: all 0.3s ease;
    position: relative;
    overflow: hidden;
}
.glossy-button:before {
    content: '';
    position: absolute;
    top: 0;
    left: -100%;
    width: 100%;
    height: 100%;
    background: linear-gradient(90deg,
            transparent,
            rgba(255, 255, 255, 0.1),
            transparent);
    transition: 0.5s;
}
.glossy-button:hover:before {
    left: 100%;
}
.glossy-button-outline {
    box-shadow: 0 4px 15px rgba(0, 0, 0, 0.2),
        inset 0 1px 1px rgba(255, 255, 255, 0.1);
    transition: all 0.3s ease;
    position: relative;
    overflow: hidden;
}
.glossy-button-outline:before {
    content: '';
    position: absolute;
    top: 0;
    left: -100%;
    width: 100%;
    height: 100%;
    background: linear-gradient(90deg,
            transparent,
            rgba(255, 255, 255, 0.1),
            transparent);
    transition: 0.5s;
}
.glossy-button-outline:hover:before {
    left: 100%;
}
/* Typing animation */
.typing-animation span {
    display: inline-block;
    width: 6px;
    height: 6px;
    border-radius: 50%;
    margin: 0 2px;
    background-color: currentColor;
    opacity: 0.6;
}
.typing-animation span:nth-child(1) {
    animation: bounce-soft 0.6s infinite 0.1s;
}
.typing-animation span:nth-child(2) {
    animation: bounce-soft 0.6s infinite 0.2s;
}
.typing-animation span:nth-child(3) {
    animation: bounce-soft 0.6s infinite 0.3s;
}
/* Add these styles to your global CSS or component-specific CSS */
.markdown-preview {
    line-height: 1.6;
}
.markdown-preview h1,
.markdown-preview h2,
.markdown-preview h3 {
    margin-top: 0.8em;
    margin-bottom: 0.5em;
    font-weight: 600;
}
.markdown-preview h1 {
    font-size: 1.5em;
}
.markdown-preview h2 {
    font-size: 1.25em;
}
.markdown-preview h3 {
    font-size: 1.1em;
}
.markdown-preview p {
    margin-bottom: 0.75em;
}
.markdown-preview ul,
.markdown-preview ol {
    margin-left: 1.5em;
    margin-bottom: 0.75em;
}
.markdown-preview code {
    background-color: rgba(0, 0, 0, 0.05);
    padding: 0.2em 0.4em;
    border-radius: 3px;
    font-family: monospace;
}
.dark .markdown-preview code {
    background-color: rgba(255, 255, 255, 0.1);
}
.markdown-preview pre {
    background-color: rgba(0, 0, 0, 0.05);
    padding: 0.75em;
    border-radius: 5px;
    overflow-x: auto;
}
.dark .markdown-preview pre {
    background-color: rgba(255, 255, 255, 0.05);
}
.markdown-preview blockquote {
    border-left: 4px solid #e2e8f0;
    padding-left: 1rem;
    margin-left: 0;
    margin-right: 0;
    font-style: italic;
}
.dark .markdown-preview blockquote {
    border-left-color: #4a5568;
}
.typing-animation {
    display: inline-flex;
    align-items: center;
}
.typing-animation span {
    display: block;
    width: 5px;
    height: 5px;
    background-color: currentColor;
    border-radius: 50%;
    margin: 0 1px;
    animation: typing 1.5s infinite ease-in-out;
}
.typing-animation span:nth-child(1) {
    animation-delay: 0s;
}
.typing-animation span:nth-child(2) {
    animation-delay: 0.2s;
}
.typing-animation span:nth-child(3) {
    animation-delay: 0.4s;
}
@keyframes typing {
    0%, 60%, 100% {
        transform: translateY(0);
        opacity: 0.6;
    }
    30% {
        transform: translateY(-4px);
        opacity: 1;
    }
}
````

## File: frontend/src/main.jsx
````javascript
import React from 'react'
import ReactDOM from 'react-dom/client'
import './index.css'
import App from './App.jsx'
import { BrowserRouter } from 'react-router-dom'
import { AuthProvider } from './context/AuthContext'
import { ThemeProvider } from './context/ThemeContext'
ReactDOM.createRoot(document.getElementById('root')).render(
  <React.StrictMode>
    <BrowserRouter>
      <AuthProvider>
        <ThemeProvider>
          <App />
        </ThemeProvider>
      </AuthProvider>
    </BrowserRouter>
  </React.StrictMode>
)
````

## File: frontend/.gitignore
````
# Logs
logs
*.log
npm-debug.log*
yarn-debug.log*
yarn-error.log*
pnpm-debug.log*
lerna-debug.log*

node_modules
dist
dist-ssr
*.local

# Editor directories and files
.vscode/*
!.vscode/extensions.json
.idea
.DS_Store
*.suo
*.ntvs*
*.njsproj
*.sln
*.sw?
.env
.env.local
.env.development.local
.env.test.local
.env.production.local
````

## File: frontend/eslint.config.js
````javascript
import js from '@eslint/js'
import globals from 'globals'
import reactHooks from 'eslint-plugin-react-hooks'
import reactRefresh from 'eslint-plugin-react-refresh'
export default [
  { ignores: ['dist'] },
  {
    files: ['**/*.{js,jsx}'],
    languageOptions: {
      ecmaVersion: 2020,
      globals: globals.browser,
      parserOptions: {
        ecmaVersion: 'latest',
        ecmaFeatures: { jsx: true },
        sourceType: 'module',
      },
    },
    plugins: {
      'react-hooks': reactHooks,
      'react-refresh': reactRefresh,
    },
    rules: {
      ...js.configs.recommended.rules,
      ...reactHooks.configs.recommended.rules,
      'no-unused-vars': ['error', { varsIgnorePattern: '^[A-Z_]' }],
      'react-refresh/only-export-components': [
        'warn',
        { allowConstantExport: true },
      ],
    },
  },
]
````

## File: frontend/index.html
````html
<!doctype html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <link rel="icon" type="image/svg+xml" href="/vite.svg" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Custom-gpt</title>
  </head>
  <body>
    <div id="root"></div>
    <script type="module" src="/src/main.jsx"></script>
  </body>
</html>
````

## File: frontend/package.json
````json
{
  "name": "frontend",
  "private": true,
  "version": "0.0.0",
  "type": "module",
  "scripts": {
    "dev": "vite",
    "build": "vite build",
    "lint": "eslint .",
    "preview": "vite preview"
  },
  "dependencies": {
    "@react-oauth/google": "^0.12.1",
    "@tanstack/react-query": "^5.75.2",
    "axios": "^1.8.4",
    "framer-motion": "^12.6.3",
    "react": "^19.0.0",
    "react-dom": "^19.0.0",
    "react-hot-toast": "^2.5.2",
    "react-icons": "^5.5.0",
    "react-markdown": "^10.1.0",
    "react-router-dom": "^7.4.1",
    "react-syntax-highlighter": "^15.6.1",
    "react-toastify": "^11.0.5",
    "react-window": "^1.8.11",
    "rehype-raw": "^7.0.0",
    "remark-gfm": "^4.0.1",
    "tailwind-scrollbar-hide": "^2.0.0"
  },
  "devDependencies": {
    "@eslint/js": "^9.21.0",
    "@types/react": "^19.0.10",
    "@types/react-dom": "^19.0.4",
    "@vitejs/plugin-react": "^4.3.4",
    "autoprefixer": "^10.4.21",
    "eslint": "^9.21.0",
    "eslint-plugin-react-hooks": "^5.1.0",
    "eslint-plugin-react-refresh": "^0.4.19",
    "globals": "^15.15.0",
    "postcss": "^8.5.3",
    "tailwindcss": "^3.4.17",
    "terser": "^5.31.3",
    "vite": "^6.2.0"
  }
}
````

## File: frontend/postcss.config.js
````javascript
export default {
  plugins: {
    tailwindcss: {},
    autoprefixer: {},
  },
}
````

## File: frontend/README.md
````markdown
# React + Vite

This template provides a minimal setup to get React working in Vite with HMR and some ESLint rules.

Currently, two official plugins are available:

- [@vitejs/plugin-react](https://github.com/vitejs/vite-plugin-react/blob/main/packages/plugin-react) uses [Babel](https://babeljs.io/) for Fast Refresh
- [@vitejs/plugin-react-swc](https://github.com/vitejs/vite-plugin-react/blob/main/packages/plugin-react-swc) uses [SWC](https://swc.rs/) for Fast Refresh

## Expanding the ESLint configuration

If you are developing a production application, we recommend using TypeScript with type-aware lint rules enabled. Check out the [TS template](https://github.com/vitejs/vite/tree/main/packages/create-vite/template-react-ts) for information on how to integrate TypeScript and [`typescript-eslint`](https://typescript-eslint.io) in your project.
````

## File: frontend/tailwind.config.js
````javascript
/** @type {import('tailwindcss').Config} */
export default {
  darkMode: 'class',
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      animation: {
        fadeIn: 'fadeIn 0.3s ease-in-out',
        slideIn: 'slideIn 0.3s ease-out forwards',
      },
      keyframes: {
        fadeIn: {
          '0%': { opacity: '0' },
          '100%': { opacity: '1' },
        },
        slideIn: {
          '0%': { transform: 'translateY(-20px)', opacity: '0' },
          '100%': { transform: 'translateY(0)', opacity: '1' },
        },
      },
    },
  },
  plugins: [
    require('tailwind-scrollbar-hide')
  ],
}
````

## File: frontend/vercel.json
````json
{
    "framework": "vite",
    "buildCommand": "npm run build",
    "devCommand": "npm run dev",
    "outputDirectory": "dist",
    "routes": [
      {
        "src": "/[^.]+",
        "dest": "/",
        "status": 200
      }
    ],
    "github": {
      "silent": true
    }
  }
````

## File: frontend/vite.config.js
````javascript
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  build: {
    minify: 'terser',
    terserOptions: {
      compress: {
        drop_console: true,
      },
    },
    rollupOptions: {
      output: {
        manualChunks: {
          vendor: ['react', 'react-dom', 'react-router-dom'],
          ui: ['react-icons', 'framer-motion'],
        },
      },
    },
  },
})
````

## File: python/.gitignore
````
# Python
__pycache__/
*.py[cod]
*$py.class
*.so
.Python
env/
build/
develop-eggs/
dist/
downloads/
eggs/
.eggs/
lib/
lib64/
parts/
sdist/
var/
*.egg-info/
.installed.cfg
*.egg
venv/
ENV/
.env

# Node/Frontend
node_modules/
npm-debug.log*
yarn-debug.log*
yarn-error.log*
.DS_Store
dist
dist-ssr
*.local

# Project-specific
local_rag_data/
/uploads/
/temp_downloads/

# IDE
.idea/
.vscode/
*.swp
*.swo
.DS_Store

# Logs
logs/
*.log
````

## File: python/main_rag_app.py
````python
from fastapi import FastAPI, UploadFile, File, Form, BackgroundTasks, Body, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse, JSONResponse
import uvicorn
import json
import os
import asyncio
from typing import List, Dict, Any, Optional, Union
import shutil
from pydantic import BaseModel, Field
from dotenv import load_dotenv
import time
from io import BytesIO
from storage import CloudflareR2Storage
from rag import EnhancedRAG
from qdrant_client import QdrantClient
from qdrant_client.http import models as rest
load_dotenv()
app = FastAPI(title="Enhanced RAG API", version="1.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization", "X-Requested-With"],
)
r2_storage = CloudflareR2Storage()
active_rag_sessions: Dict[str, EnhancedRAG] = {}
sessions_lock = asyncio.Lock()
LOCAL_DATA_BASE_PATH = os.getenv("LOCAL_DATA_PATH", "local_rag_data")
LOCAL_KB_INDEX_PATH_TEMPLATE = os.path.join(LOCAL_DATA_BASE_PATH, "kb_indexes", "{gpt_id}")
LOCAL_USER_INDEX_BASE_PATH = os.path.join(LOCAL_DATA_BASE_PATH, "user_indexes")
TEMP_DOWNLOAD_PATH = os.path.join(LOCAL_DATA_BASE_PATH, "temp_downloads")
os.makedirs(os.path.join(LOCAL_DATA_BASE_PATH, "kb_indexes"), exist_ok=True)
os.makedirs(LOCAL_USER_INDEX_BASE_PATH, exist_ok=True)
os.makedirs(TEMP_DOWNLOAD_PATH, exist_ok=True)
# --- Pydantic Models ---
class BaseRAGRequest(BaseModel):
    user_email: str
    gpt_id: str
    gpt_name: Optional[str] = "default_gpt"
class ChatPayload(BaseModel):
    message: str
    history: Optional[List[Dict[str, str]]] = []
    user_document_keys: Optional[List[str]] = Field([], alias="user_documents")
    use_hybrid_search: Optional[bool] = False
    model: Optional[str] = None
    system_prompt: Optional[str] = None
    web_search_enabled: Optional[bool] = False
class ChatStreamRequest(BaseRAGRequest, ChatPayload):
    memory: Optional[List[Dict[str, str]]] = []
class ChatRequest(BaseRAGRequest, ChatPayload):
    pass
class GptContextSetupRequest(BaseRAGRequest):
    kb_document_urls: Optional[List[str]] = []
    default_model: Optional[str] = None
    default_system_prompt: Optional[str] = None
    default_use_hybrid_search: Optional[bool] = False
class FileUploadInfoResponse(BaseModel):
    filename: str
    stored_url_or_key: str
    status: str
    error_message: Optional[str] = None
class GptOpenedRequest(BaseModel):
    user_email: str
    gpt_id: str
    gpt_name: str
    file_urls: List[str] = []
    use_hybrid_search: bool = False
    config_schema: Optional[Dict[str, Any]] = Field(default=None, alias="schema")  # Renamed to avoid shadowing
# --- Helper Functions ---
def get_session_id(user_email: str, gpt_id: str) -> str:
    email_part = user_email.replace('@', '_').replace('.', '_')
    return f"user_{email_part}_gpt_{gpt_id}"
async def get_or_create_rag_instance(
    user_email: str,
    gpt_id: str,
    gpt_name: Optional[str] = "default_gpt",
    default_model: Optional[str] = None,
    default_system_prompt: Optional[str] = None,
    default_use_hybrid_search: Optional[bool] = False
) -> EnhancedRAG:
    async with sessions_lock:
        if gpt_id not in active_rag_sessions:
            print(f"Creating new EnhancedRAG instance for gpt_id: {gpt_id}")
            openai_api_key = os.getenv("OPENAI_API_KEY")
            if not openai_api_key:
                raise ValueError("OPENAI_API_KEY not set in environment.")
            qdrant_url = os.getenv("QDRANT_URL")
            qdrant_api_key = os.getenv("QDRANT_API_KEY")
            if not qdrant_url:
                raise ValueError("QDRANT_URL not set in environment.")
            active_rag_sessions[gpt_id] = EnhancedRAG(
                gpt_id=gpt_id,
                r2_storage_client=r2_storage,
                openai_api_key=openai_api_key,
                default_llm_model_name=default_model or os.getenv("DEFAULT_OPENAI_MODEL", "gpt-4o"),
                qdrant_url=qdrant_url,
                qdrant_api_key=qdrant_api_key,
                temp_processing_path=TEMP_DOWNLOAD_PATH,
                default_system_prompt=default_system_prompt,
                default_use_hybrid_search=default_use_hybrid_search
            )
        else:
            rag_instance = active_rag_sessions[gpt_id]
            if default_model:
                rag_instance.default_llm_model_name = default_model
            if default_system_prompt:
                rag_instance.default_system_prompt = default_system_prompt
            if default_use_hybrid_search is not None:
                rag_instance.default_use_hybrid_search = default_use_hybrid_search
            print(f"Reusing EnhancedRAG instance for gpt_id: {gpt_id}. Updated defaults if provided.")
        return active_rag_sessions[gpt_id]
async def _process_uploaded_file_to_r2(
    file: UploadFile,
    is_user_doc: bool
) -> FileUploadInfoResponse:
    try:
        file_content = await file.read()
        file_bytes_io = BytesIO(file_content)
        success, r2_path_or_error = await asyncio.to_thread(
            r2_storage.upload_file,
            file_data=file_bytes_io,
            filename=file.filename,
            is_user_doc=is_user_doc
        )
        if success:
            print(f"File '{file.filename}' (is_user_doc={is_user_doc}) stored at: {r2_path_or_error}")
            return FileUploadInfoResponse(
                filename=file.filename,
                stored_url_or_key=r2_path_or_error,
                status="success"
            )
        else:
            print(f"Failed to store file '{file.filename}'. Error: {r2_path_or_error}")
            return FileUploadInfoResponse(
                filename=file.filename,
                stored_url_or_key="", status="failure", error_message=r2_path_or_error
            )
    except Exception as e:
        print(f"Exception processing file '{file.filename}': {e}")
        return FileUploadInfoResponse(
            filename=file.filename,
            stored_url_or_key="", status="failure", error_message=str(e)
        )
# --- API Endpoints ---
@app.post("/setup-gpt-context", summary="Initialize/update a GPT's knowledge base from URLs")
async def setup_gpt_context_endpoint(request: GptContextSetupRequest, background_tasks: BackgroundTasks):
    rag_instance = await get_or_create_rag_instance(
        user_email=request.user_email,
        gpt_id=request.gpt_id,
        gpt_name=request.gpt_name,
        default_model=request.default_model,
        default_system_prompt=request.default_system_prompt,
        default_use_hybrid_search=request.default_use_hybrid_search
    )
    if request.kb_document_urls:
        async def _process_kb_urls_task(urls: List[str], rag: EnhancedRAG):
            print(f"BG Task: Processing {len(urls)} KB URLs for gpt_id '{rag.gpt_id}'...")
            r2_kb_keys_or_urls_for_indexing = []
            for url in urls:
                if not (url.startswith('http://') or url.startswith('https://')):
                    print(f"Skipping invalid KB URL: {url}")
                    continue
                success, r2_path = await asyncio.to_thread(
                    r2_storage.download_file_from_url, url=url
                )
                if success:
                    r2_kb_keys_or_urls_for_indexing.append(r2_path)
                    print(f"KB URL '{url}' processed to R2: {r2_path}")
                else:
                    print(f"Failed to process KB URL '{url}'. Error: {r2_path}")
            if r2_kb_keys_or_urls_for_indexing:
                try:
                    await rag.update_knowledge_base_from_r2(r2_kb_keys_or_urls_for_indexing)
                except Exception as e:
                    print(f"Error indexing KB documents for gpt_id '{rag.gpt_id}': {e}")
        background_tasks.add_task(_process_kb_urls_task, request.kb_document_urls, rag_instance)
        return JSONResponse(status_code=202, content={
            "message": f"KB processing for gpt_id '{request.gpt_id}' initiated for {len(request.kb_document_urls)} URLs.",
            "gpt_id": request.gpt_id
        })
    else:
        return JSONResponse(status_code=200, content={
            "message": f"No KB URLs provided. RAG instance for gpt_id '{request.gpt_id}' is ready.",
            "gpt_id": request.gpt_id
        })
@app.post("/upload-documents", summary="Upload documents (KB or User-specific)")
async def upload_documents_endpoint(
    background_tasks: BackgroundTasks,
    files: List[UploadFile] = File(...),
    user_email: str = Form(...),
    gpt_id: str = Form(...),
    is_user_document: str = Form("false"),
):
    is_user_doc_bool = is_user_document.lower() == "true"
    processing_results: List[FileUploadInfoResponse] = []
    r2_keys_or_urls_for_indexing: List[str] = []
    for file_upload in files:
        result = await _process_uploaded_file_to_r2(file_upload, is_user_doc_bool)
        processing_results.append(result)
        if result.status == "success" and result.stored_url_or_key:
            r2_keys_or_urls_for_indexing.append(result.stored_url_or_key)
    if not r2_keys_or_urls_for_indexing:
        return JSONResponse(status_code=400, content={
            "message": "No files were successfully uploaded to R2.",
            "upload_results": [r.model_dump() for r in processing_results]
        })
    rag_instance = await get_or_create_rag_instance(user_email=user_email, gpt_id=gpt_id)
    async def _index_documents_task(rag: EnhancedRAG, keys_or_urls: List[str], is_user_specific: bool, u_email: str, g_id: str):
        doc_type = "user-specific" if is_user_specific else "knowledge base"
        s_id = get_session_id(u_email, g_id)
        print(f"BG Task: Indexing {len(keys_or_urls)} {doc_type} documents for gpt_id '{rag.gpt_id}' (session '{s_id}')...")
        try:
            if is_user_specific:
                await rag.update_user_documents_from_r2(session_id=s_id, r2_keys_or_urls=keys_or_urls)
            else:
                await rag.update_knowledge_base_from_r2(keys_or_urls)
            print(f"BG Task: Indexing complete for {doc_type} documents.")
        except Exception as e:
            print(f"BG Task: Error indexing {doc_type} documents for gpt_id '{rag.gpt_id}': {e}")
    background_tasks.add_task(_index_documents_task, rag_instance, r2_keys_or_urls_for_indexing, is_user_doc_bool, user_email, gpt_id)
    return JSONResponse(status_code=202, content={
        "message": f"{len(r2_keys_or_urls_for_indexing)} files accepted for {'user-specific' if is_user_doc_bool else 'knowledge base'} indexing. Processing in background.",
        "upload_results": [r.model_dump() for r in processing_results]
    })
@app.post("/chat-stream")
async def chat_stream(request: ChatStreamRequest):
    try:
        # Initialize rag_instance
        rag_instance = await get_or_create_rag_instance(
            user_email=request.user_email,
            gpt_id=request.gpt_id,
            gpt_name=request.gpt_name,
            default_model=request.model,
            default_system_prompt=request.system_prompt,
            default_use_hybrid_search=request.use_hybrid_search
        )
        session_id = get_session_id(request.user_email, request.gpt_id)
        print(f"\n{'='*40}")
        print(f"📝 New chat request from user: {request.user_email}")
        print(f"🔍 GPT ID: {request.gpt_id}")
        print(f"💬 Query: '{request.message}'")
        if request.web_search_enabled:
            print(f"🌐 Web search requested: ENABLED")
        else:
            print(f"🌐 Web search requested: DISABLED")
        print(f"{'='*40}\n")
        # Setup SSE headers
        headers = {
            "Content-Type": "text/event-stream",
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
        }
        # Create streaming response generator
        async def generate():
            try:
                async for chunk in rag_instance.query_stream(
                    session_id=session_id,
                    query=request.message,
                    chat_history=request.history,
                    user_r2_document_keys=request.user_document_keys,
                    use_hybrid_search=request.use_hybrid_search,
                    llm_model_name=request.model,
                    system_prompt_override=request.system_prompt,
                    enable_web_search=request.web_search_enabled
                ):
                    yield f"data: {json.dumps(chunk)}\n\n"
            except Exception as e:
                print(f"❌ Error during streaming in /chat-stream: {e}")
                error_chunk = {
                    "type": "error",
                    "data": {"error": str(e)}
                }
                yield f"data: {json.dumps(error_chunk)}\n\n"
        return StreamingResponse(generate(), headers=headers)
    except Exception as e:
        print(f"❌ Error in /chat-stream endpoint: {e}")
        return JSONResponse(
            status_code=500,
            content={"success": False, "error": str(e)}
        )
@app.post("/chat", summary="Handle non-streaming chat requests")
async def chat_endpoint(request: ChatRequest):
    rag_instance = await get_or_create_rag_instance(
        user_email=request.user_email, gpt_id=request.gpt_id, gpt_name=request.gpt_name,
        default_model=request.model,
        default_system_prompt=request.system_prompt,
        default_use_hybrid_search=request.use_hybrid_search
    )
    session_id = get_session_id(request.user_email, request.gpt_id)
    try:
        response_data = await rag_instance.query(
            session_id=session_id,
            query=request.message,
            chat_history=request.history,
            user_r2_document_keys=request.user_document_keys,
            use_hybrid_search=request.use_hybrid_search,
            llm_model_name=request.model,
            system_prompt_override=request.system_prompt,
            enable_web_search=request.web_search_enabled
        )
        return JSONResponse(content={"success": True, "data": response_data})
    except Exception as e:
        print(f"Error in /chat endpoint: {e}")
        return JSONResponse(status_code=500, content={"success": False, "error": str(e)})
@app.post("/gpt-opened", summary="Notify backend when a GPT is opened")
async def gpt_opened_endpoint(request: GptOpenedRequest, background_tasks: BackgroundTasks):
    try:
        rag_instance = await get_or_create_rag_instance(
            user_email=request.user_email,
            gpt_id=request.gpt_id,
            gpt_name=request.gpt_name,
            default_model=request.config_schema.get("model") if request.config_schema else None,
            default_system_prompt=request.config_schema.get("instructions") if request.config_schema else None,
            default_use_hybrid_search=request.config_schema.get("capabilities", {}).get("hybridSearch", False) if request.config_schema else request.use_hybrid_search
        )
        sanitized_email = request.user_email.replace('@', '_').replace('.', '_')
        sanitized_gpt_name = (request.gpt_name or 'gpt').replace(' ', '_').replace('-', '_')
        collection_name = f"kb_{sanitized_email}_{sanitized_gpt_name}_{request.gpt_id}"
        if request.file_urls:
            async def _process_kb_urls_task(urls: List[str], rag: EnhancedRAG):
                r2_kb_keys_or_urls_for_indexing = []
                for url in urls:
                    if url.startswith('http://') or url.startswith('https://'):
                        success, r2_path = await asyncio.to_thread(
                            r2_storage.download_file_from_url, url=url
                        )
                        if success:
                            r2_kb_keys_or_urls_for_indexing.append(r2_path)
                if r2_kb_keys_or_urls_for_indexing:
                    try:
                        await rag.update_knowledge_base_from_r2(r2_kb_keys_or_urls_for_indexing)
                    except Exception as e:
                        print(f"Error indexing KB documents for gpt_id '{rag.gpt_id}': {e}")
            background_tasks.add_task(_process_kb_urls_task, request.file_urls, rag_instance)
        return {"success": True, "collection_name": collection_name}
    except Exception as e:
        print(f"Error in gpt-opened endpoint: {e}")
        return {"success": False, "error": str(e)}
@app.post("/upload-chat-files", summary="Upload files for chat")
async def upload_chat_files_endpoint(
    files: List[UploadFile] = File(...),
    user_email: str = Form(...),
    gpt_id: str = Form(...),
    gpt_name: str = Form(...),
    collection_name: str = Form(...),
    is_user_document: str = Form("true"),
    use_hybrid_search: str = Form("false"),
    optimize_pdfs: str = Form("false"),
):
    is_user_doc_bool = is_user_document.lower() == "true"
    use_hybrid_search_bool = use_hybrid_search.lower() == "true"
    optimize_pdfs_bool = optimize_pdfs.lower() == "true"
    processing_results = []
    file_urls = []
    for file_upload in files:
        result = await _process_uploaded_file_to_r2(file_upload, is_user_doc_bool)
        if result.status == "success" and result.stored_url_or_key:
            file_urls.append(result.stored_url_or_key)
        processing_results.append(result)
    rag_instance = await get_or_create_rag_instance(
        user_email=user_email, 
        gpt_id=gpt_id,
        gpt_name=gpt_name
    )
    if file_urls:
        session_id = get_session_id(user_email, gpt_id)
        try:
            if is_user_doc_bool:
                await rag_instance.update_user_documents_from_r2(session_id=session_id, r2_keys_or_urls=file_urls)
            else:
                await rag_instance.update_knowledge_base_from_r2(file_urls)
            print(f"Indexing complete for {len(file_urls)} {'user-specific' if is_user_doc_bool else 'knowledge base'} documents for session '{session_id}'.")
        except Exception as e:
            print(f"Error indexing chat files for session '{session_id}': {e}")
            return {
                "success": False,
                "message": f"Failed to index {len(file_urls)} files: {str(e)}",
                "file_urls": file_urls,
                "processing": False
            }
    return {
        "success": True,
        "message": f"Processed and indexed {len(file_urls)} files",
        "file_urls": file_urls,
        "processing": len(file_urls) > 0
    }
@app.get("/gpt-collection-info/{param1}/{param2}", summary="Get information about a GPT collection")
async def gpt_collection_info(param1: str, param2: str):
    return {
        "status": "available",
        "timestamp": time.time()
    }
@app.get("/", include_in_schema=False)
async def root_redirect():
    from fastapi.responses import RedirectResponse
    return RedirectResponse(url="/docs")
@app.get("/health", summary="Health check endpoint", tags=["Monitoring"])
async def health_check():
    return {"status": "healthy", "timestamp": time.time()}
@app.post("/dev/reset-gpt-context", summary="DEVELOPMENT ONLY: Clear RAG context for a GPT", tags=["Development"])
async def dev_reset_gpt_context_endpoint(gpt_id: str = Form(...)):
    if os.getenv("ENVIRONMENT_TYPE", "production").lower() != "development":
        return JSONResponse(status_code=403, content={"error": "Endpoint only available in development."})
    async with sessions_lock:
        if gpt_id in active_rag_sessions:
            try:
                rag_instance_to_reset = active_rag_sessions.pop(gpt_id)
                await rag_instance_to_reset.clear_all_context()
                kb_index_path_to_delete = LOCAL_KB_INDEX_PATH_TEMPLATE.format(gpt_id=gpt_id)
                if os.path.exists(kb_index_path_to_delete):
                    shutil.rmtree(kb_index_path_to_delete)
                print(f"DEV: Cleared in-memory RAG context and local KB index for gpt_id '{gpt_id}'. R2 files not deleted.")
                return {"status": "success", "message": f"RAG context for gpt_id '{gpt_id}' cleared from memory and local disk."}
            except Exception as e:
                print(f"DEV: Error clearing context for gpt_id '{gpt_id}': {e}")
                return JSONResponse(status_code=500, content={"status": "error", "message": str(e)})
        else:
            return JSONResponse(status_code=404, content={"status": "not_found", "message": f"No active RAG context for gpt_id '{gpt_id}'."})
if __name__ == "__main__":
    print("Starting RAG API server...")
    print(f"Local data base path: {os.path.abspath(LOCAL_DATA_BASE_PATH)}")
    print(f"OpenAI API Key Loaded: {'Yes' if os.getenv('OPENAI_API_KEY') else 'No - Set OPENAI_API_KEY'}")
    print(f"CORS Origins: {os.getenv('CORS_ALLOWED_ORIGINS', '[\"http://localhost:5173\"]')}")
    uvicorn.run(
        "main_rag_app:app",
        host=os.getenv("HOST", "0.0.0.0"),
        port=int(os.getenv("PORT", 8000)),
        reload=os.getenv("ENVIRONMENT_TYPE", "").lower() == "development",
        timeout_keep_alive=60
    )
# Note: To fix the LangChainDeprecationWarning in rag.py, update the import as follows:
# from langchain_community.chat_message_histories import ChatMessageHistory
# This should be applied in the rag.py file to avoid the deprecation warning.
````

## File: python/rag.py
````python
import os
import shutil
import asyncio
import time
import json
from typing import List, Dict, Any, Optional, AsyncGenerator, Union
from urllib.parse import urlparse
import uuid
import httpx
from dotenv import load_dotenv
# --- Qdrant ---
from qdrant_client import QdrantClient, models as qdrant_models
from langchain_qdrant import QdrantVectorStore
# --- Langchain & OpenAI Core Components ---
from openai import AsyncOpenAI
from langchain_openai import OpenAIEmbeddings
from langchain_text_splitters import RecursiveCharacterTextSplitter
from langchain_core.documents import Document
from langchain_core.retrievers import BaseRetriever
from langchain_core.messages import HumanMessage, AIMessage
# Document Loaders & Transformers
from langchain_community.document_loaders import (
    PyPDFLoader, Docx2txtLoader, BSHTMLLoader, TextLoader, UnstructuredURLLoader
)
from langchain_community.document_transformers import Html2TextTransformer
# Web Search (Tavily)
try:
    from tavily import AsyncTavilyClient
    TAVILY_AVAILABLE = True
except ImportError:
    TAVILY_AVAILABLE = False
    AsyncTavilyClient = None
    print("Tavily Python SDK not found. Web search will be disabled.")
# BM25 (Optional)
try:
    from langchain_community.retrievers import BM25Retriever
    from rank_bm25 import OkapiBM25
    BM25_AVAILABLE = True
except ImportError:
    BM25_AVAILABLE = False
    print("BM25Retriever or rank_bm25 package not found. Hybrid search with BM25 will be limited.")
# Custom local imports
from storage import CloudflareR2Storage
try:
    from langchain_community.chat_message_histories import ChatMessageHistory # Updated import
except ImportError:
    from langchain.memory import ChatMessageHistory # Fallback for older versions, though the target is community
# Add imports for other providers
try:
    import anthropic  # for Claude
    CLAUDE_AVAILABLE = True
except ImportError:
    CLAUDE_AVAILABLE = False
    print("Anthropic Python SDK not found. Claude models will be unavailable.")
try:
    import google.generativeai as genai  # for Gemini
    GEMINI_AVAILABLE = True
except ImportError:
    GEMINI_AVAILABLE = False
    print("Google GenerativeAI SDK not found. Gemini models will be unavailable.")
try:
    from llama_cpp import Llama  # for Llama models
    LLAMA_AVAILABLE = True
except ImportError:
    LLAMA_AVAILABLE = False
    print("llama-cpp-python not found. Llama models will be unavailable.")
try:
    from groq import AsyncGroq
    GROQ_AVAILABLE = True
except ImportError:
    GROQ_AVAILABLE = False
    print("Groq Python SDK not found. Llama models will use Groq as fallback.")
load_dotenv()
# Vector params for OpenAI's text-embedding-ada-002
QDRANT_VECTOR_PARAMS = qdrant_models.VectorParams(size=1536, distance=qdrant_models.Distance.COSINE)
CONTENT_PAYLOAD_KEY = "page_content"
METADATA_PAYLOAD_KEY = "metadata"
class EnhancedRAG:
    def __init__(
        self,
        gpt_id: str,
        r2_storage_client: CloudflareR2Storage,
        openai_api_key: str,
        default_llm_model_name: str = "gpt-4o",
        qdrant_url: Optional[str] = None,
        qdrant_api_key: Optional[str] = None,
        temp_processing_path: str = "local_rag_data/temp_downloads",
        tavily_api_key: Optional[str] = None,
        default_system_prompt: Optional[str] = None,
        default_temperature: float = 0.2,
        max_tokens_llm: int = 4000,
        default_use_hybrid_search: bool = False,
    ):
        self.gpt_id = gpt_id
        self.r2_storage = r2_storage_client
        self.openai_api_key = openai_api_key
        self.tavily_api_key = tavily_api_key or os.getenv("TAVILY_API_KEY")
        self.default_llm_model_name = default_llm_model_name
        self.default_system_prompt = default_system_prompt or (
            "You are a helpful and meticulous AI assistant. "
            "Provide comprehensive, detailed, and accurate answers based *solely* on the context provided. "
            "Structure your response clearly using Markdown. "
            "Use headings (#, ##, ###), subheadings, bullet points (* or -), and numbered lists (1., 2.) where appropriate to improve readability. "
            "For code examples, use Markdown code blocks with language specification (e.g., ```python ... ```). "
            "Feel free to use relevant emojis to make the content more engaging, but do so sparingly and appropriately. "
            "If the context is insufficient or does not contain the answer, clearly state that. "
            "Cite the source of your information if possible (e.g., 'According to document X...'). "
            "Do not make assumptions or use external knowledge beyond the provided context. "
            "Ensure your response is as lengthy and detailed as necessary to fully answer the query, up to the allowed token limit."
        )
        self.default_temperature = default_temperature
        self.max_tokens_llm = max_tokens_llm
        self.default_use_hybrid_search = default_use_hybrid_search
        self.temp_processing_path = temp_processing_path
        os.makedirs(self.temp_processing_path, exist_ok=True)
        self.embeddings_model = OpenAIEmbeddings(api_key=self.openai_api_key)
        # Configure AsyncOpenAI client with custom timeouts
        # Default httpx timeouts are often too short (5s for read/write/connect)
        # OpenAI library itself defaults to 600s total, but being explicit for stream reads is good.
        timeout_config = httpx.Timeout(
            connect=15.0,  # Connection timeout
            read=180.0,    # Read timeout (important for waiting for stream chunks)
            write=15.0,    # Write timeout
            pool=15.0      # Pool timeout
        )
        self.async_openai_client = AsyncOpenAI(
            api_key=self.openai_api_key,
            timeout=timeout_config,
            max_retries=1 # Default is 2, reducing to 1 for faster failure if unrecoverable
        )
        self.qdrant_url = qdrant_url or os.getenv("QDRANT_URL", "http://localhost:6333")
        self.qdrant_api_key = qdrant_api_key or os.getenv("QDRANT_API_KEY")
        if not self.qdrant_url:
            raise ValueError("Qdrant URL must be provided either as a parameter or via QDRANT_URL environment variable.")
        self.qdrant_client = QdrantClient(url=self.qdrant_url, api_key=self.qdrant_api_key, timeout=20.0)
        print(f"Qdrant client initialized for URL: {self.qdrant_url}")
        self.text_splitter = RecursiveCharacterTextSplitter(
            chunk_size=1000, chunk_overlap=200, length_function=len
        )
        self.html_transformer = Html2TextTransformer()
        self.kb_collection_name = f"kb_{self.gpt_id}".replace("-", "_").lower()
        self.kb_retriever: Optional[BaseRetriever] = self._get_qdrant_retriever_sync(self.kb_collection_name)
        self.user_collection_retrievers: Dict[str, BaseRetriever] = {}
        self.user_memories: Dict[str, ChatMessageHistory] = {}
        self.tavily_client = None
        if self.tavily_api_key:
            try:
                if TAVILY_AVAILABLE:
                    self.tavily_client = AsyncTavilyClient(api_key=self.tavily_api_key)
                    print(f"✅ Tavily client initialized successfully with API key")
                else:
                    print(f"❌ Tavily package not available. Install it with: pip install tavily-python")
            except Exception as e:
                print(f"❌ Error initializing Tavily client: {e}")
        else:
            print(f"❌ No Tavily API key provided. Web search will be disabled.")
        # Initialize clients for other providers
        self.anthropic_client = None
        self.gemini_client = None
        self.llama_model = None
        # Setup Claude client if available
        self.claude_api_key = os.getenv("ANTHROPIC_API_KEY")
        if CLAUDE_AVAILABLE and self.claude_api_key:
            self.anthropic_client = anthropic.AsyncAnthropic(api_key=self.claude_api_key)
            print(f"✅ Claude client initialized successfully")
        # Setup Gemini client if available
        self.gemini_api_key = os.getenv("GOOGLE_API_KEY")
        if GEMINI_AVAILABLE and self.gemini_api_key:
            genai.configure(api_key=self.gemini_api_key)
            self.gemini_client = genai
            print(f"✅ Gemini client initialized successfully")
        # Setup Llama if available (local model)
        if LLAMA_AVAILABLE:
            # This would need a model path - could be configurable
            llama_model_path = os.getenv("LLAMA_MODEL_PATH")
            if llama_model_path and os.path.exists(llama_model_path):
                self.llama_model = Llama(model_path=llama_model_path)
                print(f"✅ Llama model loaded successfully")
        # Initialize Groq client
        self.groq_api_key = os.getenv("GROQ_API_KEY")
        self.groq_client = None
        if GROQ_AVAILABLE and self.groq_api_key:
            self.groq_client = AsyncGroq(api_key=self.groq_api_key)
            print(f"✅ Groq client initialized successfully")
        # Model context length mapping
        self.model_context_limits = {
            "gpt-4": 8192,
            "gpt-4o": 128000,
            "gpt-3.5": 16384,
            "claude": 100000,
            "gemini": 32768,
            "llama": 128000  # Using Groq's llama-70b context window
        }
    def _get_user_qdrant_collection_name(self, session_id: str) -> str:
        safe_session_id = "".join(c if c.isalnum() else '_' for c in session_id)
        return f"user_{safe_session_id}".replace("-", "_").lower()
    def _ensure_qdrant_collection_exists_sync(self, collection_name: str):
        try:
            self.qdrant_client.get_collection(collection_name=collection_name)
        except Exception as e:
            if "not found" in str(e).lower() or ("status_code=404" in str(e) if hasattr(e, "status_code") else False):
                print(f"Qdrant collection '{collection_name}' not found. Creating...")
                self.qdrant_client.create_collection(
                    collection_name=collection_name,
                    vectors_config=QDRANT_VECTOR_PARAMS
                )
                print(f"Qdrant collection '{collection_name}' created.")
            else:
                print(f"Error checking/creating Qdrant collection '{collection_name}': {e} (Type: {type(e)})")
                raise
    def _get_qdrant_retriever_sync(self, collection_name: str, search_k: int = 5) -> Optional[BaseRetriever]:
        self._ensure_qdrant_collection_exists_sync(collection_name)
        try:
            qdrant_store = QdrantVectorStore(
                client=self.qdrant_client,
                collection_name=collection_name,
                embedding=self.embeddings_model,
                content_payload_key=CONTENT_PAYLOAD_KEY,
                metadata_payload_key=METADATA_PAYLOAD_KEY
            )
            print(f"Initialized Qdrant retriever for collection: {collection_name}")
            return qdrant_store.as_retriever(search_kwargs={'k': search_k})
        except Exception as e:
            print(f"Failed to create Qdrant retriever for collection '{collection_name}': {e}")
            return None
    async def _get_user_retriever(self, session_id: str, search_k: int = 3) -> Optional[BaseRetriever]:
        collection_name = self._get_user_qdrant_collection_name(session_id)
        if session_id not in self.user_collection_retrievers or self.user_collection_retrievers.get(session_id) is None:
            await asyncio.to_thread(self._ensure_qdrant_collection_exists_sync, collection_name)
            self.user_collection_retrievers[session_id] = self._get_qdrant_retriever_sync(collection_name, search_k=search_k)
            if self.user_collection_retrievers[session_id]:
                print(f"User documents Qdrant retriever for session '{session_id}' (collection '{collection_name}') initialized.")
            else:
                print(f"Failed to initialize user documents Qdrant retriever for session '{session_id}'.")
        retriever = self.user_collection_retrievers.get(session_id)
        if retriever and hasattr(retriever, 'search_kwargs'):
            retriever.search_kwargs['k'] = search_k
        return retriever
    async def _get_user_memory(self, session_id: str) -> ChatMessageHistory:
        if session_id not in self.user_memories:
            self.user_memories[session_id] = ChatMessageHistory()
            print(f"Initialized new memory for session: {session_id}")
        return self.user_memories[session_id]
    async def _download_and_split_one_doc(self, r2_key_or_url: str) -> List[Document]:
        unique_suffix = uuid.uuid4().hex[:8]
        base_filename = os.path.basename(urlparse(r2_key_or_url).path) or f"doc_{hash(r2_key_or_url)}_{unique_suffix}"
        temp_file_path = os.path.join(self.temp_processing_path, f"{self.gpt_id}_{base_filename}")
        loaded_docs: List[Document] = []
        try:
            is_full_url = r2_key_or_url.startswith("http://") or r2_key_or_url.startswith("https://")
            r2_object_key_to_download = ""
            if is_full_url:
                parsed_url = urlparse(r2_key_or_url)
                is_our_r2_url = self.r2_storage.account_id and self.r2_storage.bucket_name and \
                                f"{self.r2_storage.bucket_name}.{self.r2_storage.account_id}.r2.cloudflarestorage.com" in parsed_url.netloc
                if is_our_r2_url:
                    r2_object_key_to_download = parsed_url.path.lstrip('/')
                else:
                    try:
                        loader = UnstructuredURLLoader(urls=[r2_key_or_url], mode="elements", strategy="fast", continue_on_failure=True, show_progress=False)
                        loaded_docs = await asyncio.to_thread(loader.load)
                        if loaded_docs and loaded_docs[0].page_content.startswith("Error fetching URL"): return []
                    except Exception as e_url: print(f"Error UnstructuredURLLoader {r2_key_or_url}: {e_url}"); return []
            else:
                r2_object_key_to_download = r2_key_or_url
            if not loaded_docs and r2_object_key_to_download:
                download_success = await asyncio.to_thread(
                    self.r2_storage.download_file, r2_object_key_to_download, temp_file_path
                )
                if not download_success: print(f"Failed R2 download: {r2_object_key_to_download}"); return []
                _, ext = os.path.splitext(temp_file_path); ext = ext.lower()
                loader: Any = None
                if ext == ".pdf": loader = PyPDFLoader(temp_file_path)
                elif ext == ".docx": loader = Docx2txtLoader(temp_file_path)
                elif ext in [".html", ".htm"]: loader = BSHTMLLoader(temp_file_path, open_encoding='utf-8')
                else: loader = TextLoader(temp_file_path, autodetect_encoding=True)
                loaded_docs = await asyncio.to_thread(loader.load)
                if ext in [".html", ".htm"] and loaded_docs:
                    loaded_docs = self.html_transformer.transform_documents(loaded_docs)
            if loaded_docs:
                for doc in loaded_docs:
                    doc.metadata["source"] = r2_key_or_url 
                return self.text_splitter.split_documents(loaded_docs)
            return []
        except Exception as e:
            print(f"Error processing source '{r2_key_or_url}': {e}")
            return []
        finally:
            if os.path.exists(temp_file_path):
                try: os.remove(temp_file_path)
                except Exception as e_del: print(f"Error deleting temp file {temp_file_path}: {e_del}")
    async def _index_documents_to_qdrant_batch(self, docs_to_index: List[Document], collection_name: str):
        if not docs_to_index: return
        try:
            await asyncio.to_thread(self._ensure_qdrant_collection_exists_sync, collection_name)
            qdrant_store = QdrantVectorStore(
                client=self.qdrant_client,
                collection_name=collection_name,
                embedding=self.embeddings_model,
                content_payload_key=CONTENT_PAYLOAD_KEY,
                metadata_payload_key=METADATA_PAYLOAD_KEY
            )
            print(f"Adding {len(docs_to_index)} document splits to Qdrant collection '{collection_name}' via Langchain wrapper...")
            await asyncio.to_thread(
                qdrant_store.add_documents,
                documents=docs_to_index,
                batch_size=100
            )
            print(f"Successfully added/updated {len(docs_to_index)} splits in Qdrant collection '{collection_name}'.")
        except Exception as e:
            print(f"Error adding documents to Qdrant collection '{collection_name}' using Langchain wrapper: {e}")
            raise
    async def update_knowledge_base_from_r2(self, r2_keys_or_urls: List[str]):
        print(f"Updating KB for gpt_id '{self.gpt_id}' (collection '{self.kb_collection_name}') with {len(r2_keys_or_urls)} R2 documents...")
        processing_tasks = [self._download_and_split_one_doc(key_or_url) for key_or_url in r2_keys_or_urls]
        results_list_of_splits = await asyncio.gather(*processing_tasks)
        all_splits: List[Document] = [split for sublist in results_list_of_splits for split in sublist]
        if not all_splits:
            print(f"No content extracted from R2 sources for KB collection {self.kb_collection_name}.")
            if not self.kb_retriever:
                self.kb_retriever = self._get_qdrant_retriever_sync(self.kb_collection_name)
            return
        await self._index_documents_to_qdrant_batch(all_splits, self.kb_collection_name)
        self.kb_retriever = self._get_qdrant_retriever_sync(self.kb_collection_name)
        print(f"Knowledge Base for gpt_id '{self.gpt_id}' update process finished.")
    async def update_user_documents_from_r2(self, session_id: str, r2_keys_or_urls: List[str]):
        # Clear existing documents and retriever for this user session first
        print(f"Clearing existing user-specific context for session '{session_id}' before update...")
        await self.clear_user_session_context(session_id)
        user_collection_name = self._get_user_qdrant_collection_name(session_id)
        print(f"Updating user documents for session '{session_id}' (collection '{user_collection_name}') with {len(r2_keys_or_urls)} R2 docs...")
        processing_tasks = [self._download_and_split_one_doc(key_or_url) for key_or_url in r2_keys_or_urls]
        results_list_of_splits = await asyncio.gather(*processing_tasks)
        all_splits: List[Document] = [split for sublist in results_list_of_splits for split in sublist]
        if not all_splits:
            print(f"No content extracted from R2 sources for user collection {user_collection_name}.")
            # Ensure retriever is (re)initialized even if empty, after clearing
            self.user_collection_retrievers[session_id] = self._get_qdrant_retriever_sync(user_collection_name)
            return
        await self._index_documents_to_qdrant_batch(all_splits, user_collection_name)
        # Re-initialize the retriever for the session now that new documents are indexed
        self.user_collection_retrievers[session_id] = self._get_qdrant_retriever_sync(user_collection_name)
        print(f"User documents for session '{session_id}' update process finished.")
    async def clear_user_session_context(self, session_id: str):
        user_collection_name = self._get_user_qdrant_collection_name(session_id)
        try:
            print(f"Attempting to delete Qdrant collection: '{user_collection_name}' for session '{session_id}'")
            # Ensure the client is available for the deletion call
            if not self.qdrant_client:
                print(f"Qdrant client not initialized. Cannot delete collection {user_collection_name}.")
            else:
                await asyncio.to_thread(self.qdrant_client.delete_collection, collection_name=user_collection_name)
                print(f"Qdrant collection '{user_collection_name}' deleted.")
        except Exception as e:
            if "not found" in str(e).lower() or \
               (hasattr(e, "status_code") and e.status_code == 404) or \
               "doesn't exist" in str(e).lower() or \
               "collectionnotfound" in str(type(e)).lower() or \
               (hasattr(e, "error_code") and "collection_not_found" in str(e.error_code).lower()): # More robust error checking
                print(f"Qdrant collection '{user_collection_name}' not found during clear, no need to delete.")
            else:
                print(f"Error deleting Qdrant collection '{user_collection_name}': {e} (Type: {type(e)})")
        if session_id in self.user_collection_retrievers: del self.user_collection_retrievers[session_id]
        if session_id in self.user_memories: del self.user_memories[session_id]
        print(f"User session context (retriever, memory, Qdrant collection artifacts) cleared for session_id: {session_id}")
        # After deleting the collection, it's good practice to ensure a new empty one is ready if needed immediately.
        # This will be handled by _get_qdrant_retriever_sync when it's called next.
    async def _get_retrieved_documents(
        self, 
        retriever: Optional[BaseRetriever], 
        query: str, 
        k_val: int = 3,
        is_hybrid_search_active: bool = False,
        is_user_doc: bool = False
    ) -> List[Document]:
        # Enhanced user document search - increase candidate pool for user docs
        candidate_k = k_val * 3 if is_user_doc else (k_val * 2 if is_hybrid_search_active and BM25_AVAILABLE else k_val)
        # Expanded candidate retrieval
        if hasattr(retriever, 'search_kwargs'):
            original_k = retriever.search_kwargs.get('k', k_val)
            retriever.search_kwargs['k'] = candidate_k
        # Vector retrieval
        docs = await retriever.ainvoke(query) if hasattr(retriever, 'ainvoke') else await asyncio.to_thread(retriever.invoke, query)
        # Stage 2: Apply BM25 re-ranking if hybrid search is active
        if is_hybrid_search_active and BM25_AVAILABLE and docs:
            print(f"Hybrid search active: Applying BM25 re-ranking to {len(docs)} vector search candidates")
            # BM25 re-ranking function
            def bm25_process(documents_for_bm25, q, target_k):
                bm25_ret = BM25Retriever.from_documents(documents_for_bm25, k=target_k)
                return bm25_ret.get_relevant_documents(q)
            # Execute BM25 re-ranking
            try:
                loop = asyncio.get_event_loop()
                bm25_reranked_docs = await loop.run_in_executor(None, bm25_process, docs, query, k_val)
                return bm25_reranked_docs
            except Exception as e:
                print(f"BM25 re-ranking error: {e}. Falling back to vector search results.")
                return docs[:k_val]
        else:
            # For user docs, return more results to provide deeper context
            return docs[:int(k_val * 1.5)] if is_user_doc else docs[:k_val]
    def _format_docs_for_llm_context(self, documents: List[Document], source_name: str) -> str:
        if not documents: return ""
        # Enhanced formatting with clear section headers
        formatted_sections = []
        # Sort documents to prioritize web search results for fresher information
        web_docs = []
        other_docs = []
        for doc in documents:
            source_type = doc.metadata.get("source_type", "")
            if source_type == "web_search" or "Web Search" in doc.metadata.get("source", ""):
                web_docs.append(doc)
            else:
                other_docs.append(doc)
        # Process web search documents first
        if web_docs:
            formatted_sections.append("## 🌐 WEB SEARCH RESULTS")
            for doc in web_docs:
                source = doc.metadata.get('source', source_name)
                title = doc.metadata.get('title', '')
                url = doc.metadata.get('url', '')
                # Create a more visually distinct header for each web document
                header = f"📰 **WEB SOURCE: {title}**"
                if url: header += f"\n🔗 **URL: {url}**"
                formatted_sections.append(f"{header}\n\n{doc.page_content}")
        # Process other documents
        if other_docs:
            if web_docs:  # Only add this separator if we have web docs
                formatted_sections.append("## 📚 KNOWLEDGE BASE & USER DOCUMENTS")
            for doc in other_docs:
                source = doc.metadata.get('source', source_name)
                score = f"Score: {doc.metadata.get('score', 'N/A'):.2f}" if 'score' in doc.metadata else ""
                title = doc.metadata.get('title', '')
                # Create a more visually distinct header for each document
                if "user" in source.lower():
                    header = f"📄 **USER DOCUMENT: {source}**"
                else:
                    header = f"📚 **KNOWLEDGE BASE: {source}**"
                if title: header += f" - **{title}**"
                if score: header += f" - {score}"
                formatted_sections.append(f"{header}\n\n{doc.page_content}")
        return "\n\n---\n\n".join(formatted_sections)
    async def _get_web_search_docs(self, query: str, enable_web_search: bool, num_results: int = 3) -> List[Document]:
        if not enable_web_search or not self.tavily_client: 
            print(f"🌐 Web search is DISABLED for this query.")
            return []
        print(f"🌐 Web search is ENABLED. Searching web for: '{query}'")
        try:
            search_response = await self.tavily_client.search(
                query=query, 
                search_depth="advanced",  # Changed from "basic" to "advanced" for more comprehensive search
                max_results=num_results,
                include_raw_content=True,
                include_domains=[]  # Can be customized to limit to specific domains
            )
            results = search_response.get("results", [])
            web_docs = []
            if results:
                print(f"🌐 Web search returned {len(results)} results")
                for i, res in enumerate(results):
                    content_text = res.get("raw_content") or res.get("content", "")
                    title = res.get("title", "N/A")
                    url = res.get("url", "N/A")
                    if content_text:
                        print(f"🌐 Web result #{i+1}: '{title}' - {url[:60]}...")
                        web_docs.append(Document(
                            page_content=content_text[:4000],
                            metadata={
                                "source": f"Web Search: {title}",
                                "source_type": "web_search", 
                                "title": title, 
                                "url": url
                            }
                        ))
            return web_docs
        except Exception as e: 
            print(f"❌ Error during web search: {e}")
            return []
    async def _generate_llm_response(
        self, session_id: str, query: str, all_context_docs: List[Document],
        chat_history_messages: List[Dict[str, str]], llm_model_name_override: Optional[str],
        system_prompt_override: Optional[str], stream: bool = False
    ) -> Union[AsyncGenerator[str, None], str]:
        current_llm_model = llm_model_name_override or self.default_llm_model_name
        current_system_prompt = system_prompt_override or self.default_system_prompt
        # Get the base model type and context limit
        base_model_type = None
        if current_llm_model.startswith("gpt-4"):
            base_model_type = "gpt-4"
        elif current_llm_model.startswith("gpt-3.5"):
            base_model_type = "gpt-3.5"
        elif current_llm_model.startswith("claude"):
            base_model_type = "claude"
        elif current_llm_model.startswith("gemini"):
            base_model_type = "gemini"
        elif current_llm_model.startswith("llama"):
            base_model_type = "llama"
        else:
            base_model_type = "gpt-4"  # Default fallback
        # Get model context limit
        max_model_tokens = self.model_context_limits.get(base_model_type, 8192)
        # More aggressive token management for smaller context windows - special handling for web search
        has_web_results = any("web_search" in doc.metadata.get("source_type", "") for doc in all_context_docs)
        if base_model_type == "gpt-4" and max_model_tokens <= 8192:
            # For original GPT-4, be extremely conservative
            if has_web_results:
                # With web search, reserve even more space
                adjusted_max_tokens = min(self.max_tokens_llm, int(max_model_tokens * 0.15))  # Only 15% for output
                max_context_tokens = max_model_tokens - adjusted_max_tokens - 1500  # Even larger buffer
            else:
                # More conservative for regular queries too
                adjusted_max_tokens = min(self.max_tokens_llm, int(max_model_tokens * 0.20))  # Only 20% for output
                max_context_tokens = max_model_tokens - adjusted_max_tokens - 1200
        else:
            # For models with larger context windows
            adjusted_max_tokens = min(self.max_tokens_llm, int(max_model_tokens * 0.33))
            max_context_tokens = max_model_tokens - adjusted_max_tokens - 500
        print(f"Model: {current_llm_model}, Context limit: {max_model_tokens}, Max output: {adjusted_max_tokens}")
        print(f"Web search present: {has_web_results}, Using more conservative limits: {has_web_results}")
        # Estimate token count and limit documents if needed
        estimated_prompt_tokens = len(current_system_prompt.split()) * 1.3  # Rough estimate
        estimated_history_tokens = sum(len(msg["content"].split()) for msg in chat_history_messages) * 1.3
        # Process and limit documents to avoid context overflow
        formatted_docs = []
        total_est_tokens = estimated_prompt_tokens + estimated_history_tokens + 500  # Buffer for query and formatting
        print(f"Estimated token count before docs: {total_est_tokens}")
        # Prioritize web search results (they're often more relevant)
        web_docs = []
        kb_docs = []
        user_docs = []
        # Sort documents by type for prioritization
        for doc in all_context_docs:
            source_type = doc.metadata.get("source_type", "")
            source = str(doc.metadata.get("source", "")).lower()
            if "web_search" in source_type or "web search" in source:
                web_docs.append(doc)
            elif "user" in source:
                user_docs.append(doc)
            else:
                kb_docs.append(doc)
        # Apply a more aggressive token estimate for web content (tends to be longer)
        web_multiplier = 1.5  # Web content often has more formatting, links, etc.
        # Add documents in priority order with stricter limits for web search
        # Add web search results first (most directly relevant to query)
        for doc in web_docs:
            doc_tokens = len(doc.page_content.split()) * web_multiplier
            if total_est_tokens + doc_tokens > max_context_tokens:
                print(f"⚠️ Token limit would be exceeded. Limiting context to {len(formatted_docs)} documents.")
                break
            formatted_docs.append(doc)
            total_est_tokens += doc_tokens
        # Add user docs next (usually more specific than KB)
        for doc in user_docs:
            doc_tokens = len(doc.page_content.split()) * 1.3
            if total_est_tokens + doc_tokens > max_context_tokens:
                print(f"⚠️ Token limit would be exceeded. Limiting context to {len(formatted_docs)} documents.")
                break
            formatted_docs.append(doc)
            total_est_tokens += doc_tokens
        # Add KB docs last
        for doc in kb_docs:
            doc_tokens = len(doc.page_content.split()) * 1.3
            if total_est_tokens + doc_tokens > max_context_tokens:
                print(f"⚠️ Token limit would be exceeded. Limiting context to {len(formatted_docs)} documents.")
                break
            formatted_docs.append(doc)
            total_est_tokens += doc_tokens
        print(f"Using {len(formatted_docs)} documents out of {len(all_context_docs)} available (est. tokens: {total_est_tokens})")
        print(f"Adjusted max output tokens: {adjusted_max_tokens} (from original: {self.max_tokens_llm})")
        # Use adjusted_max_tokens instead of self.max_tokens_llm
        current_max_tokens = adjusted_max_tokens
        # Continue with your existing code using formatted_docs instead of all_context_docs
        context_str = self._format_docs_for_llm_context(formatted_docs, "Retrieved Context")
        if not context_str.strip():
            context_str = "No relevant context could be found from any available source for this query. Please ensure documents are uploaded and relevant to your question."
        # Enhanced user message with stronger formatting guidance
        user_query_message_content = (
            f"📚 **CONTEXT:**\n{context_str}\n\n"
            f"Based on the above context and any relevant chat history, provide a detailed, well-structured response to this query:\n\n"
            f"**QUERY:** {query}\n\n"
            f"Requirements for your response:\n"
            f"1. 🎯 Start with a relevant emoji and descriptive headline\n"
            f"2. 📋 Organize with clear headings and subheadings\n"
            f"3. 📊 Include bullet points or numbered lists where appropriate\n"
            f"4. 💡 Highlight key insights or important information\n"
            f"5. 📝 Reference specific information from the provided documents\n"
            f"6. 🔍 Use appropriate emojis (about 1-2 per section) to make content engaging\n"
            f"7. 📚 Make your response comprehensive, detailed and precise\n"
        )
        messages = [{"role": "system", "content": current_system_prompt}]
        messages.extend(chat_history_messages)
        messages.append({"role": "user", "content": user_query_message_content})
        user_memory = await self._get_user_memory(session_id)
        # Determine which provider to use based on model name prefix
        if current_llm_model.startswith("gpt-"):
            # Use OpenAI (existing implementation)
            if stream:
                async def stream_generator():
                    full_response_content = ""
                    print("Stream generator started")
                    try:
                        print(f"Starting OpenAI stream with model: {current_llm_model}, max_tokens: {current_max_tokens}")
                        response_stream = await self.async_openai_client.chat.completions.create(
                            model=current_llm_model, messages=messages, temperature=self.default_temperature,
                            max_tokens=current_max_tokens, 
                            stream=True
                        )
                        print("OpenAI stream created successfully")
                        async for chunk in response_stream:
                            content_piece = chunk.choices[0].delta.content
                            if content_piece:
                                print(f"Stream chunk received: {content_piece[:20]}...")
                                full_response_content += content_piece
                                yield content_piece
                        print(f"Stream complete, total response length: {len(full_response_content)}")
                    except Exception as e_stream:
                        if "context_length_exceeded" in str(e_stream) or "maximum context length" in str(e_stream):
                            print(f"Context length exceeded, retrying with reduced context...")
                            # Cut the context in half
                            context_str_reduced = context_str[:len(context_str)//2] + "\n... [Content truncated to fit token limits] ...\n"
                            user_query_message_reduced = (
                                f"📚 **CONTEXT (truncated):**\n{context_str_reduced}\n\n"
                                f"Based on the above context and any relevant chat history, provide a detailed, well-structured response to this query:\n\n"
                                f"**QUERY:** {query}\n\n"
                                f"Requirements for your response:\n"
                                f"1. 🎯 Start with a relevant emoji and descriptive headline\n"
                                f"2. 📋 Organize with clear headings and subheadings\n"
                                f"3. 📊 Include bullet points or numbered lists where appropriate\n"
                                f"4. 💡 Highlight key insights or important information\n"
                                f"Note: Some context was truncated due to length limits. Please respond based on available information."
                            )
                            reduced_messages = [{"role": "system", "content": current_system_prompt}]
                            reduced_messages.extend(chat_history_messages)
                            reduced_messages.append({"role": "user", "content": user_query_message_reduced})
                            try:
                                # Retry with reduced context and max tokens
                                reduced_max_tokens = int(current_max_tokens * 0.8)
                                yield "\n[Context length exceeded. Retrying with reduced context...]\n\n"
                                retry_stream = await self.async_openai_client.chat.completions.create(
                                    model=current_llm_model, 
                                    messages=reduced_messages, 
                                    temperature=self.default_temperature,
                                    max_tokens=reduced_max_tokens,
                                    stream=True
                                )
                                async for chunk in retry_stream:
                                    content_piece = chunk.choices[0].delta.content
                                    if content_piece:
                                        full_response_content += content_piece
                                        yield content_piece
                            except Exception as retry_error:
                                print(f"Error in retry attempt: {retry_error}")
                                yield f"\n[Error: {str(e_stream)}]\n[Retry failed: {str(retry_error)}]\n"
                        else:
                            print(f"LLM streaming error: {e_stream}")
                            yield f"\n[Error: {str(e_stream)}]\n"
                    finally:
                        print(f"Saving response to memory, length: {len(full_response_content)}")
                        await asyncio.to_thread(user_memory.add_user_message, query)
                        await asyncio.to_thread(user_memory.add_ai_message, full_response_content)
                return stream_generator()
            else:
                response_content = ""
                try:
                    completion = await self.async_openai_client.chat.completions.create(
                        model=current_llm_model, messages=messages, temperature=self.default_temperature,
                        max_tokens=current_max_tokens, # Ensure max_tokens is used here as well
                        stream=False
                    )
                    response_content = completion.choices[0].message.content or ""
                except Exception as e_nostream:
                    print(f"LLM non-streaming error: {e_nostream}")
                    response_content = f"Error: {str(e_nostream)}"
                await asyncio.to_thread(user_memory.add_user_message, query)
                await asyncio.to_thread(user_memory.add_ai_message, response_content)
                return response_content
        elif current_llm_model.startswith("claude") and CLAUDE_AVAILABLE and self.anthropic_client:
            # Use Claude implementation
            if stream:
                async def claude_stream_generator():
                    full_response_content = ""
                    try:
                        # Format messages for Claude - system message needs special handling
                        system_content = current_system_prompt
                        claude_messages = []
                        # Extract regular messages (not system)
                        for msg in chat_history_messages:
                            if msg["role"] != "system":
                                claude_messages.append(msg)
                        # Add user query
                        claude_messages.append({"role": "user", "content": user_query_message_content})
                        # Claude streaming call with system as a separate parameter
                        response_stream = await self.anthropic_client.messages.create(
                            model="claude-3-opus-20240229" if "claude" == current_llm_model else current_llm_model,
                            max_tokens=current_max_tokens,
                            system=system_content,  # System as a separate parameter
                            messages=claude_messages,  # Without system message in the array
                            stream=True
                        )
                        async for chunk in response_stream:
                            if chunk.type == "content_block_delta" and chunk.delta.text:
                                content_piece = chunk.delta.text
                                full_response_content += content_piece
                                yield content_piece
                    except Exception as e_stream:
                        print(f"Claude streaming error: {e_stream}")
                        yield f"\n[Error: {str(e_stream)}]\n"
                    finally:
                        await asyncio.to_thread(user_memory.add_user_message, query)
                        await asyncio.to_thread(user_memory.add_ai_message, full_response_content)
                return claude_stream_generator()
            else:
                # Non-streaming Claude implementation
                response_content = ""
                try:
                    # Format messages for Claude - system message needs special handling
                    system_content = current_system_prompt
                    claude_messages = []
                    # Extract regular messages (not system)
                    for msg in chat_history_messages:
                        if msg["role"] != "system":
                            claude_messages.append(msg)
                    # Add user query
                    claude_messages.append({"role": "user", "content": user_query_message_content})
                    # Claude API call with system as a separate parameter
                    response = await self.anthropic_client.messages.create(
                        model="claude-3-opus-20240229" if "claude" == current_llm_model else current_llm_model,
                        max_tokens=current_max_tokens,
                        system=system_content,  # System as a separate parameter
                        messages=claude_messages  # Without system message in the array
                    )
                    response_content = response.content[0].text
                except Exception as e_nostream:
                    print(f"Claude non-streaming error: {e_nostream}")
                    response_content = f"Error: {str(e_nostream)}"
                await asyncio.to_thread(user_memory.add_user_message, query)
                await asyncio.to_thread(user_memory.add_ai_message, response_content)
                return response_content
        elif current_llm_model.startswith("gemini") and GEMINI_AVAILABLE and self.gemini_client:
            # Implement Gemini client call
            if stream:
                async def gemini_stream_generator():
                    full_response_content = ""
                    try:
                        # Convert messages to Gemini format
                        gemini_messages = []
                        for msg in messages:
                            if msg["role"] == "system":
                                # Prepend system message to first user message
                                continue
                            elif msg["role"] == "user":
                                gemini_messages.append({"role": "user", "parts": [{"text": msg["content"]}]})
                            elif msg["role"] == "assistant":
                                gemini_messages.append({"role": "model", "parts": [{"text": msg["content"]}]})
                        # Add system message to first user message if needed
                        if messages[0]["role"] == "system" and len(gemini_messages) > 0:
                            for i, msg in enumerate(gemini_messages):
                                if msg["role"] == "user":
                                    gemini_messages[i]["parts"][0]["text"] = f"{messages[0]['content']}\n\n{gemini_messages[i]['parts'][0]['text']}"
                                    break
                        # Always use gemini-1.5-flash regardless of the specific gemini model requested
                        # This model has higher quotas and better rate limits
                        model = self.gemini_client.GenerativeModel(model_name="gemini-1.5-flash")
                        print(f"Using gemini-1.5-flash with higher quotas")
                        response_stream = await model.generate_content_async(
                            gemini_messages,
                            generation_config={"temperature": self.default_temperature, "max_output_tokens": current_max_tokens},
                            stream=True
                        )
                        async for chunk in response_stream:
                            if hasattr(chunk, "text"):
                                content_piece = chunk.text
                                if content_piece:
                                    full_response_content += content_piece
                                    yield content_piece
                    except Exception as e_stream:
                        print(f"Gemini streaming error: {e_stream}")
                        # If we still hit rate limits, fall back to OpenAI
                        if "429" in str(e_stream) or "quota" in str(e_stream).lower():
                            print("Falling back to OpenAI gpt-gpt-3.5 due to Gemini rate limits")
                            try:
                                yield "\n[Gemini rate limit reached, switching to GPT-3.5...]\n\n"
                                fallback_stream = await self.async_openai_client.chat.completions.create(
                                    model="gpt-gpt-3.5", 
                                    messages=messages, 
                                    temperature=self.default_temperature,
                                    max_tokens=current_max_tokens, 
                                    stream=True
                                )
                                async for chunk in fallback_stream:
                                    content_piece = chunk.choices[0].delta.content
                                    if content_piece:
                                        full_response_content += content_piece
                                        yield content_piece
                            except Exception as fallback_error:
                                yield f"\n[Error in fallback model: {str(fallback_error)}]\n"
                        else:
                            yield f"\n[Error: {str(e_stream)}]\n"
                    finally:
                        await asyncio.to_thread(user_memory.add_user_message, query)
                        await asyncio.to_thread(user_memory.add_ai_message, full_response_content)
                return gemini_stream_generator()
        elif current_llm_model.startswith("llama") and LLAMA_AVAILABLE and self.llama_model:
            # Implement Llama model call (local)
            if stream:
                async def llama_stream_generator():
                    full_response_content = ""
                    try:
                        # Format prompt for Llama
                        prompt = f"<s>[INST] {current_system_prompt}\n\n"
                        for msg in chat_history_messages:
                            role = msg["role"]
                            content = msg["content"]
                            if role == "user":
                                prompt += f"{content} [/INST]\n"
                            else:
                                prompt += f"{content} </s><s>[INST] "
                        prompt += f"{user_query_message_content} [/INST]\n"
                        # Call Llama in a thread to not block async
                        loop = asyncio.get_event_loop()
                        result = await loop.run_in_executor(
                            None, 
                            lambda: self.llama_model.create_completion(
                                prompt=prompt,
                                max_tokens=current_max_tokens,
                                temperature=self.default_temperature,
                                stream=True
                            )
                        )
                        for chunk in result:
                            if "text" in chunk:
                                content_piece = chunk["text"]
                                full_response_content += content_piece
                                yield content_piece
                    except Exception as e_stream:
                        print(f"Llama streaming error: {e_stream}")
                        yield f"\n[Error: {str(e_stream)}]\n"
                    finally:
                        await asyncio.to_thread(user_memory.add_user_message, query)
                        await asyncio.to_thread(user_memory.add_ai_message, full_response_content)
                return llama_stream_generator()
            else:
                response_content = ""
                try:
                    # Format prompt for Llama (similar to above)
                    prompt = f"<s>[INST] {current_system_prompt}\n\n"
                    for msg in chat_history_messages:
                        role = msg["role"]
                        content = msg["content"]
                        if role == "user":
                            prompt += f"{content} [/INST]\n"
                        else:
                            prompt += f"{content} </s><s>[INST] "
                    prompt += f"{user_query_message_content} [/INST]\n"
                    # Call Llama in a thread to not block async
                    loop = asyncio.get_event_loop()
                    result = await loop.run_in_executor(
                        None, 
                        lambda: self.llama_model.create_completion(
                            prompt=prompt,
                            max_tokens=current_max_tokens,
                            temperature=self.default_temperature,
                            stream=False
                        )
                    )
                    response_content = result["text"] if "text" in result else ""
                except Exception as e_nostream:
                    print(f"Llama non-streaming error: {e_nostream}")
                    response_content = f"Error: {str(e_nostream)}"
                await asyncio.to_thread(user_memory.add_user_message, query)
                await asyncio.to_thread(user_memory.add_ai_message, response_content)
                return response_content
        elif current_llm_model.startswith("llama") and GROQ_AVAILABLE and self.groq_client:
            # Map "llama" to Groq's Llama model
            groq_model = "llama3-8b-8192"  # Using a model that exists in Groq
            if stream:
                async def groq_stream_generator():
                    full_response_content = ""
                    try:
                        groq_messages = [{"role": "system", "content": current_system_prompt}]
                        groq_messages.extend(chat_history_messages)
                        groq_messages.append({"role": "user", "content": user_query_message_content})
                        response_stream = await self.groq_client.chat.completions.create(
                            model=groq_model,
                            messages=groq_messages,
                            temperature=self.default_temperature,
                            max_tokens=adjusted_max_tokens,
                            stream=True
                        )
                        async for chunk in response_stream:
                            content_piece = chunk.choices[0].delta.content
                            if content_piece:
                                full_response_content += content_piece
                                yield content_piece
                    except Exception as e_stream:
                        print(f"Groq streaming error: {e_stream}")
                        yield f"\n[Error: {str(e_stream)}]\n"
                    finally:
                        await asyncio.to_thread(user_memory.add_user_message, query)
                        await asyncio.to_thread(user_memory.add_ai_message, full_response_content)
                return groq_stream_generator()
            else:
                # Non-streaming Groq implementation
                response_content = ""
                try:
                    groq_messages = [{"role": "system", "content": current_system_prompt}]
                    groq_messages.extend(chat_history_messages)
                    groq_messages.append({"role": "user", "content": user_query_message_content})
                    completion = await self.groq_client.chat.completions.create(
                        model=groq_model,
                        messages=groq_messages,
                        temperature=self.default_temperature,
                        max_tokens=current_max_tokens,
                        stream=False
                    )
                    response_content = completion.choices[0].message.content or ""
                except Exception as e_nostream:
                    print(f"Groq non-streaming error: {e_nostream}")
                    response_content = f"Error: {str(e_nostream)}"
                await asyncio.to_thread(user_memory.add_user_message, query)
                await asyncio.to_thread(user_memory.add_ai_message, response_content)
                return response_content
        else:
            # Fallback to OpenAI if model not supported or client not available
            print(f"Model {current_llm_model} not supported or client not available. Falling back to OpenAI gpt-4o.")
            current_llm_model = "gpt-4o"
            # Continue with OpenAI implementation
    async def _get_formatted_chat_history(self, session_id: str) -> List[Dict[str,str]]:
        user_memory = await self._get_user_memory(session_id)
        history_messages = []
        for msg in user_memory.messages:
            role = "user" if isinstance(msg, HumanMessage) else "assistant"
            history_messages.append({"role": role, "content": msg.content})
        return history_messages
    async def query_stream(
        self, session_id: str, query: str, chat_history: Optional[List[Dict[str, str]]] = None,
        user_r2_document_keys: Optional[List[str]] = None, use_hybrid_search: Optional[bool] = None,
        llm_model_name: Optional[str] = None, system_prompt_override: Optional[str] = None,
        enable_web_search: Optional[bool] = False
    ) -> AsyncGenerator[Dict[str, Any], None]:
        print(f"\n{'='*80}\nStarting streaming query for session: {session_id}")
        start_time = time.time()
        # Print search configuration to terminal with debug info
        print(f"\n📊 SEARCH CONFIGURATION:")
        print(f"📌 Debug - Raw enable_web_search param value: {enable_web_search} (type: {type(enable_web_search)})")
        # Determine effective hybrid search setting
        actual_use_hybrid_search = use_hybrid_search if use_hybrid_search is not None else self.default_use_hybrid_search
        if actual_use_hybrid_search:
            print(f"🔄 Hybrid search: ACTIVE (BM25 Available: {BM25_AVAILABLE})")
        else:
            print(f"🔄 Hybrid search: INACTIVE")
        # Web search status with extra debug info
        if enable_web_search:
            if self.tavily_client:
                print(f"🌐 Web search: ENABLED with Tavily API")
                print(f"🌐 Tavily API key present: {bool(self.tavily_api_key)}")
            else:
                print(f"🌐 Web search: REQUESTED but Tavily API not available")
                print(f"🌐 Tavily API key present: {bool(self.tavily_api_key)}")
                print(f"🌐 TAVILY_AVAILABLE global: {TAVILY_AVAILABLE}")
        else:
            print(f"🌐 Web search: DISABLED (param value: {enable_web_search})")
        # Model information
        current_model = llm_model_name or self.default_llm_model_name
        print(f"🧠 Using model: {current_model}")
        print(f"{'='*80}")
        formatted_chat_history = await self._get_formatted_chat_history(session_id)
        retrieval_query = query
        print(f"\n📝 Processing query: '{retrieval_query}'")
        all_retrieved_docs: List[Document] = []
        # First get user document context with deeper search (higher k-value)
        user_session_retriever = await self._get_user_retriever(session_id)
        user_session_docs = await self._get_retrieved_documents(
            user_session_retriever, 
            retrieval_query, 
            k_val=3,  # Change from 5 to 3
            is_hybrid_search_active=actual_use_hybrid_search,
            is_user_doc=True  # Flag as user doc for deeper search
        )
        if user_session_docs: 
            print(f"📄 Retrieved {len(user_session_docs)} user-specific documents")
            all_retrieved_docs.extend(user_session_docs)
        else:
            print(f"📄 No user-specific documents found")
        # Then add knowledge base context
        kb_docs = await self._get_retrieved_documents(
            self.kb_retriever, 
            retrieval_query, 
            k_val=5, 
            is_hybrid_search_active=actual_use_hybrid_search
        )
        if kb_docs: 
            print(f"📚 Retrieved {len(kb_docs)} knowledge base documents")
            all_retrieved_docs.extend(kb_docs)
        else:
            print(f"📚 No knowledge base documents found")
        # Add web search results if enabled - MOVED EARLIER in the process
        if enable_web_search and self.tavily_client:
            web_docs = await self._get_web_search_docs(retrieval_query, True, num_results=4)
            if web_docs:
                print(f"🌐 Retrieved {len(web_docs)} web search documents")
                all_retrieved_docs.extend(web_docs)
        # Process any adhoc document keys
        if user_r2_document_keys:
            print(f"📎 Processing {len(user_r2_document_keys)} ad-hoc document keys")
            adhoc_load_tasks = [self._download_and_split_one_doc(r2_key) for r2_key in user_r2_document_keys]
            results_list_of_splits = await asyncio.gather(*adhoc_load_tasks)
            adhoc_docs_count = 0
            for splits_from_one_doc in results_list_of_splits:
                adhoc_docs_count += len(splits_from_one_doc)
                all_retrieved_docs.extend(splits_from_one_doc) 
            print(f"📎 Added {adhoc_docs_count} splits from ad-hoc documents")
        # Deduplicate the documents
        unique_docs_content = set()
        deduplicated_docs = []
        for doc in all_retrieved_docs:
            if doc.page_content not in unique_docs_content:
                deduplicated_docs.append(doc)
                unique_docs_content.add(doc.page_content)
        all_retrieved_docs = deduplicated_docs
        print(f"\n🔍 Retrieved {len(all_retrieved_docs)} total unique documents")
        # Count documents by source type
        source_counts = {}
        for doc in all_retrieved_docs:
            source_type = doc.metadata.get("source_type", "unknown")
            if "web" in source_type:
                source_type = "web_search"
            elif "user" in str(doc.metadata.get("source", "")):
                source_type = "user_document"
            else:
                source_type = "knowledge_base"
            source_counts[source_type] = source_counts.get(source_type, 0) + 1
        for src_type, count in source_counts.items():
            if src_type == "web_search":
                print(f"🌐 Web search documents: {count}")
            elif src_type == "user_document":
                print(f"📄 User documents: {count}")
            elif src_type == "knowledge_base":
                print(f"📚 Knowledge base documents: {count}")
            else:
                print(f"📃 {src_type} documents: {count}")
        print("\n🧠 Starting LLM stream generation...")
        llm_stream_generator = await self._generate_llm_response(
            session_id, query, all_retrieved_docs, formatted_chat_history,
            llm_model_name, system_prompt_override, stream=True
        )
        print("🔄 LLM stream initialized, beginning content streaming")
        async for content_chunk in llm_stream_generator:
            yield {"type": "content", "data": content_chunk}
        print("✅ Stream complete, sending done signal")
        total_time = int((time.time() - start_time) * 1000)
        print(f"⏱️ Total processing time: {total_time}ms")
        yield {"type": "done", "data": {"total_time_ms": total_time}}
        print(f"{'='*80}\n")
    async def query(
        self, session_id: str, query: str, chat_history: Optional[List[Dict[str, str]]] = None,
        user_r2_document_keys: Optional[List[str]] = None, use_hybrid_search: Optional[bool] = None,
        llm_model_name: Optional[str] = None, system_prompt_override: Optional[str] = None,
        enable_web_search: Optional[bool] = False
    ) -> Dict[str, Any]:
        start_time = time.time()
        # Determine effective hybrid search setting
        actual_use_hybrid_search = use_hybrid_search if use_hybrid_search is not None else self.default_use_hybrid_search
        if actual_use_hybrid_search:
            print(f"Hybrid search is ACTIVE for this query (session: {session_id}). BM25 Available: {BM25_AVAILABLE}")
        else:
            print(f"Hybrid search is INACTIVE for this query (session: {session_id}).")
        formatted_chat_history = await self._get_formatted_chat_history(session_id)
        retrieval_query = query
        all_retrieved_docs: List[Document] = []
        kb_docs = await self._get_retrieved_documents(
            self.kb_retriever, 
            retrieval_query, 
            k_val=5, 
            is_hybrid_search_active=actual_use_hybrid_search
        )
        if kb_docs: all_retrieved_docs.extend(kb_docs)
        user_session_retriever = await self._get_user_retriever(session_id)
        user_session_docs = await self._get_retrieved_documents(
            user_session_retriever, 
            retrieval_query, 
            k_val=3,  # Change from 5 to 3
            is_hybrid_search_active=actual_use_hybrid_search
        )
        if user_session_docs: all_retrieved_docs.extend(user_session_docs)
        if user_r2_document_keys:
            adhoc_load_tasks = [self._download_and_split_one_doc(r2_key) for r2_key in user_r2_document_keys]
            results_list_of_splits = await asyncio.gather(*adhoc_load_tasks)
            for splits_from_one_doc in results_list_of_splits: all_retrieved_docs.extend(splits_from_one_doc)
        if enable_web_search and self.tavily_client:
            web_docs = await self._get_web_search_docs(retrieval_query, True, num_results=3)
            if web_docs: all_retrieved_docs.extend(web_docs)
        unique_docs_content = set()
        deduplicated_docs = []
        for doc in all_retrieved_docs:
            if doc.page_content not in unique_docs_content:
                deduplicated_docs.append(doc); unique_docs_content.add(doc.page_content)
        all_retrieved_docs = deduplicated_docs
        source_names_used = list(set([doc.metadata.get("source", "Unknown") for doc in all_retrieved_docs if doc.metadata]))
        if not source_names_used and all_retrieved_docs: source_names_used.append("Processed Documents")
        elif not all_retrieved_docs: source_names_used.append("No Context Found")
        answer_content = await self._generate_llm_response(
            session_id, query, all_retrieved_docs, formatted_chat_history,
            llm_model_name, system_prompt_override, stream=False
        )
        return {
            "answer": answer_content, "sources": source_names_used,
            "retrieval_details": {"documents_retrieved_count": len(all_retrieved_docs)},
            "total_time_ms": int((time.time() - start_time) * 1000)
        }
    async def clear_knowledge_base(self):
        print(f"Clearing KB for gpt_id '{self.gpt_id}' (collection '{self.kb_collection_name}')...")
        try:
            await asyncio.to_thread(self.qdrant_client.delete_collection, collection_name=self.kb_collection_name)
        except Exception as e:
            if "not found" in str(e).lower() or ("status_code" in dir(e) and e.status_code == 404):
                print(f"KB Qdrant collection '{self.kb_collection_name}' not found, no need to delete.")
            else: print(f"Error deleting KB Qdrant collection '{self.kb_collection_name}': {e}")
        self.kb_retriever = None
        await asyncio.to_thread(self._ensure_qdrant_collection_exists_sync, self.kb_collection_name)
        print(f"Knowledge Base for gpt_id '{self.gpt_id}' cleared and empty collection ensured.")
    async def clear_all_context(self):
        await self.clear_knowledge_base()
        active_session_ids = list(self.user_collection_retrievers.keys())
        for session_id in active_session_ids:
            await self.clear_user_session_context(session_id)
        self.user_collection_retrievers.clear(); self.user_memories.clear()
        if os.path.exists(self.temp_processing_path):
            try:
                await asyncio.to_thread(shutil.rmtree, self.temp_processing_path)
                os.makedirs(self.temp_processing_path, exist_ok=True)
            except Exception as e: print(f"Error clearing temp path '{self.temp_processing_path}': {e}")
        print(f"All context (KB, all user sessions, temp files) cleared for gpt_id '{self.gpt_id}'.")
async def main_test_rag_qdrant():
    print("Ensure QDRANT_URL and OPENAI_API_KEY are set in .env for this test.")
    if not (os.getenv("OPENAI_API_KEY") and os.getenv("QDRANT_URL")):
        print("Skipping test: OPENAI_API_KEY or QDRANT_URL not set.")
        return
    class DummyR2Storage:
        async def download_file(self, key: str, local_path: str) -> bool:
            with open(local_path, "w") as f:
                f.write("This is a test document for RAG.")
            return True
        async def upload_file(self, file_data, filename: str, is_user_doc: bool = False):
            return True, f"test/{filename}"
        async def download_file_from_url(self, url: str):
            return True, f"test/doc_from_url_{url[-10:]}"
    rag = EnhancedRAG(
        gpt_id="test_gpt",
        r2_storage_client=DummyR2Storage(),
        openai_api_key=os.getenv("OPENAI_API_KEY"),
        qdrant_url=os.getenv("QDRANT_URL"),
        qdrant_api_key=os.getenv("QDRANT_API_KEY")
    )
    await rag.update_knowledge_base_from_r2(["test/doc1.txt"])
    session_id = "test_session"
    await rag.update_user_documents_from_r2(session_id, ["test/doc2.txt"])
    async for chunk in rag.query_stream(session_id, "What is in the test document?", enable_web_search=False):
        print(chunk)
if __name__ == "__main__":
    print(f"rag.py loaded. Qdrant URL: {os.getenv('QDRANT_URL')}. Tavily available: {TAVILY_AVAILABLE}. BM25 available: {BM25_AVAILABLE}")
````

## File: python/requirements.txt
````
# Core dependencies
fastapi>=0.103.1
uvicorn[standard]>=0.23.0
pydantic>=2.0.0
python-multipart>=0.0.6
python-dotenv>=1.0.1
openai>=1.0.0
httpx>=0.24.0

# Vector database and embeddings
# faiss-cpu==1.7.4  # Temporarily disable to avoid build errors
# chromadb==0.4.18 # Temporarily disable to avoid hnswlib build errors
rank_bm25>=0.2.2
qdrant-client>=1.7.0

# RAG framework
langchain>=0.0.329
langchain-openai>=0.0.2
langchain-community>=0.0.16
langchain-core>=0.1.15
langchain-text-splitters>=0.0.1
langchain-qdrant>=0.0.1
# langchain-chroma>=0.0.1 # Also disable if chromadb is disabled

# Web search
tavily-python>=0.2.2

# Document processing
pypdf>=3.0.0
python-docx>=0.8.11
bs4>=0.0.1
html2text>=2020.1.16
unstructured>=0.10.30

# Cloud storage
boto3>=1.28.0

# Async processing
aiohttp>=3.8.0
aiofiles>=23.1.0

# Text processing
tiktoken>=0.5.0
beautifulsoup4>=4.11.0
lxml>=4.9.0
requests>=2.28.0
scikit-learn>=1.0.0

# Performance optimization
pydantic>=2.0.0
uvicorn[standard]>=0.23.0
asyncio>=3.4.3

# Utility
tqdm>=4.64.0
tenacity>=8.2.0

# Multiple LLM providers
anthropic>=0.8.0  # For Claude models
google-generativeai>=0.3.0  # For Gemini models
groq>=0.4.0  # For Groq API (Llama models)

# Optional - uncomment if needed
# llama-cpp-python>=0.2.0  # Uncomment if using local Llama models

# Retry utilities for API rate limits
tenacity>=8.2.0
````
