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