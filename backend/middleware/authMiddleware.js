const jwt = require('jsonwebtoken');
const User = require('../models/User');
const connectDB = require('../lib/db');

const protectRoute = async (req, res, next) => {
    let token;
    
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
        token = req.headers.authorization.split(' ')[1];
    } 
    else if (req.cookies && req.cookies.token) {
        token = req.cookies.token;
    }
    
    if (!token) {
        return res.status(401).json({
            success: false,
            message: 'Please log in to access this resource'
        });
    }
    
    try {
        // Verify the token
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        
        // Find user by id (excluding password)
        const user = await User.findById(decoded.userId).select('-password');
        
        if (!user) {
            return res.status(401).json({
                success: false,
                message: 'User not found'
            });
        }
        
        // Add user to request object
        req.user = user;
        next();
    } catch (error) {
        console.error('JWT verification failed:', error.message);
        return res.status(401).json({
            success: false,
            message: 'Invalid or expired token. Please log in again.'
        });
    }
};

module.exports = { protectRoute };
