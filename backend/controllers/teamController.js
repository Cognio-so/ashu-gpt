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