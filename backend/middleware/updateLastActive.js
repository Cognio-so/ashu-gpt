const User = require('../models/User');

// Middleware to update lastActive timestamp for authenticated users
const updateLastActive = async (req, res, next) => {
    try {
        // Only update if user is authenticated
        if (req.user && req.user._id) {
            // Update the lastActive field to the current time
            await User.findByIdAndUpdate(
                req.user._id,
                { lastActive: new Date() },
                { new: true }
            );
        }
        next();
    } catch (error) {
        console.error("Error updating lastActive status:", error);
        next(); // Continue even if there's an error with the update
    }
};

module.exports = updateLastActive; 