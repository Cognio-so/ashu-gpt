const express = require('express');
const router = express.Router();
const { inviteTeamMember, getPendingInvitesCount, verifyInvitation } = require('../controllers/InvitationController');
const { protectRoute } = require('../middleware/authMiddleware');

router.post('/invite', protectRoute, inviteTeamMember);
router.get('/pending-invites/count', protectRoute, getPendingInvitesCount);
router.get('/verify-invitation/:token', verifyInvitation);

module.exports = router; 