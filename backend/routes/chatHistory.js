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