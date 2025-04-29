const jwt = require('jsonwebtoken');

// Generates Access Token (short-lived)
const generateAccessToken = (userId) => {
    return jwt.sign({ userId }, process.env.JWT_SECRET, { expiresIn: '15m' }); // e.g., 15 minutes
};

const generateRefreshTokenAndSetCookie = (res, userId) => {
    const refreshToken = jwt.sign(
        { userId },
        process.env.REFRESH_TOKEN_SECRET,
        { expiresIn: '7d' }
    );
    
    // Set the cookie with more permissive settings
    res.cookie('refreshToken', refreshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production', // Only use secure in production
        sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax', // Use 'none' in production, 'lax' in development
        maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days in milliseconds
        path: '/' // Ensure cookie is available across your domain
    });
    
    return refreshToken;
};

// Clears the Refresh Token cookie
const clearRefreshTokenCookie = (res) => {
    res.cookie('refreshToken', '', {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: process.env.NODE_ENV === 'production' ? 'None' : 'Lax',
        path: '/api/auth/refresh',
        expires: new Date(0), // Set expiry date to the past
    });
};

module.exports = { generateAccessToken, generateRefreshTokenAndSetCookie, clearRefreshTokenCookie };
