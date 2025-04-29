const express = require('express');
const router = express.Router();
const InvitationController = require('../controllers/InvitationController');
const { protectRoute } = require('../middleware/authMiddleware');

router.post('/invite', protectRoute, InvitationController.inviteTeamMember);
router.get('/pending-invites/count', protectRoute, InvitationController.getPendingInvitesCount);
router.get('/verify-invitation/:token', InvitationController.verifyInvitation);

module.exports = router; 