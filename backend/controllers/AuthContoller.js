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
        let key = Buffer.from(ENCRYPTION_KEY);
        if (key.length !== 32) {
            const newKey = Buffer.alloc(32);
            key.copy(newKey, 0, 0, Math.min(key.length, 32));
            key = newKey;
        }
        
        const textParts = text.split(':');
        const iv = Buffer.from(textParts.shift(), 'hex');
        const encryptedText = Buffer.from(textParts.join(':'), 'hex');
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

const inviteTeamMember = async (req, res) => {
  try {
    const { email, role } = req.body;
    
    if (!req.user || req.user.role !== 'admin') {
      return res.status(403).json({ 
        success: false, 
        message: 'Only admins can send invitations' 
      });
    }
    
    // Check if user already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ 
        success: false, 
        message: 'User with this email already exists' 
      });
    }
    
    // Generate a unique invitation token
    const token = crypto.randomBytes(20).toString('hex');
    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + 7); // Token valid for 7 days
    
    // Create invitation record
    const invitation = new Invitation({
      email,
      role,
      token,
      expiresAt,
      invitedBy: req.user._id
    });
    
    await invitation.save();
    
    // Send email invitation - include the role in the URL for proper redirection
    const inviteUrl = `${process.env.FRONTEND_URL}/register?token=${token}&role=${role}`;
    
    // Update the mail template to indicate the redirect path based on role
    const mailOptions = {
      from: process.env.EMAIL_FROM,
      to: email,
      subject: 'Invitation to join the team',
      html: `
        <h1>You've been invited to join the team</h1>
        <p>You've been invited by ${req.user.name} to join as a ${role}.</p>
        <p>Click the link below to create your account:</p>
        <a href="${inviteUrl}" style="padding: 10px 15px; background-color: #3182ce; color: white; border-radius: 5px; text-decoration: none;">Accept Invitation</a>
        <p>This invitation expires in 7 days.</p>
        <p>After registration, you will be redirected to the ${role === 'admin' ? 'admin' : 'employee'} dashboard.</p>
      `
    };
    
    try {
      await transporter.sendMail(mailOptions);
      
      return res.status(200).json({
        success: true,
        message: 'Invitation sent successfully'
      });
    } catch (emailError) {
      console.error('Error sending invitation email:', emailError);
      
      // If email sending fails, delete the invitation
      await Invitation.findByIdAndDelete(invitation._id);
      
      return res.status(500).json({
        success: false,
        message: 'Failed to send invitation email'
      });
    }
  } catch (error) {
    console.error('Error sending invitation:', error);
    return res.status(500).json({
      success: false,
      message: 'Error sending invitation'
    });
  }
};


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
          .select('name email role createdAt') // Explicitly select fields
          .sort({ createdAt: -1 })
          .skip(skip)
          .limit(limit)
          .lean(), // Convert to plain JS objects
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
                decryptedKeys[key] = decrypt(value);
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

module.exports = { Signup, Login, Logout, googleAuth, googleAuthCallback, refreshTokenController, getCurrentUser, getAllUsers, inviteTeamMember, setInactive, removeTeamMember, getUsersWithGptCounts, getUserGptCount, getUserActivity, updateUserProfile, updateUserProfilePicture, changePassword, getApiKeys, saveApiKeys, updatePassword };
