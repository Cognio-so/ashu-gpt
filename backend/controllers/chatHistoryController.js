const ChatHistory = require('../models/ChatHistory');
const mongoose = require('mongoose');

exports.saveMessage = async (req, res) => {
    try {
        const { userId, gptId, gptName, message, role, model } = req.body;
        
        console.log('Saving message to DB:', { userId, gptId, role, messageLength: message?.length });

        if (!userId || !gptId || !message || !role) {
            return res.status(400).json({ 
                success: false, 
                message: 'Missing required fields',
                received: { hasUserId: !!userId, hasGptId: !!gptId, hasMessage: !!message, hasRole: !!role }
            });
        }

        // Find existing conversation or create new one
        let conversation = await ChatHistory.findOne({ userId, gptId });
        console.log('Found existing conversation:', !!conversation);
        
        if (!conversation) {
            conversation = new ChatHistory({
                userId,
                gptId,
                gptName,
                model: model || 'gpt-4o-mini',
                messages: [],
                lastMessage: ''
            });
            console.log('Created new conversation');
        }

        // Add new message
        conversation.messages.push({
            role,
            content: message,
            timestamp: new Date()
        });
        console.log(`Added ${role} message to conversation`);

        // Update last message (always update for display purposes)
        if (role === 'user') {
            conversation.lastMessage = message;
        }
        
        conversation.updatedAt = new Date();
        const savedConversation = await conversation.save();
        console.log('Conversation saved with message count:', savedConversation.messages.length);

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