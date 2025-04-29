const express = require('express');
const router = express.Router();
const { Signup, Login, Logout, googleAuth, googleAuthCallback, refreshTokenController, getCurrentUser, getAllUsers, inviteTeamMember, getPendingInvitesCount, setInactive, removeTeamMember, getUsersWithGptCounts, getUserGptCount, getUserActivity, getUserNotes, addUserNote, deleteUserNote } = require('../controllers/AuthContoller');
const passport = require('passport');
const { protectRoute } = require('../middleware/authMiddleware'); // Imports protectRoute

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

router.post('/invite', protectRoute, inviteTeamMember);

router.get('/pending-invites/count', protectRoute, getPendingInvitesCount);

router.put('/me/inactive', protectRoute, setInactive); 

router.delete('/users/:userId', protectRoute, removeTeamMember);

router.get('/users/with-gpt-counts', protectRoute, getUsersWithGptCounts);
router.get('/users/:userId/gpt-count', protectRoute, getUserGptCount);

router.get('/users/:userId/activity', protectRoute, getUserActivity);
router.get('/users/:userId/notes', protectRoute, getUserNotes);
router.post('/users/:userId/notes', protectRoute, addUserNote);
router.delete('/users/:userId/notes/:noteId', protectRoute, deleteUserNote);

module.exports = router;
