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
