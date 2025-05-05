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