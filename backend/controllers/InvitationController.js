const crypto = require('crypto');
const User = require('../models/User');
const Invitation = require('../models/Invitation');
const { sendEmail } = require('../lib/emailService');

/**
 * Invite a team member
 * @route POST /api/auth/invite
 * @access Private (Admin only)
 */
exports.inviteTeamMember = async (req, res) => {
  try {
    const { email, role } = req.body;
    
    // Verify the current user is an admin
    if (!req.user || req.user.role !== 'admin') {
      return res.status(403).json({ 
        success: false, 
        message: 'Only admins can send invitations' 
      });
    }
    
    // Check if user already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ 
        success: false, 
        message: 'User with this email already exists' 
      });
    }
    
    // Check if invitation already exists and is pending
    const existingInvitation = await Invitation.findOne({ 
      email, 
      status: 'pending',
      expiresAt: { $gt: new Date() }
    });
    
    if (existingInvitation) {
      return res.status(400).json({ 
        success: false, 
        message: 'An invitation has already been sent to this email' 
      });
    }
    
    // Generate a unique invitation token
    const token = crypto.randomBytes(20).toString('hex');
    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + 7); // Token valid for 7 days
    
    // Create invitation record
    const invitation = new Invitation({
      email,
      role,
      token,
      expiresAt,
      invitedBy: req.user._id
    });
    
    await invitation.save();
    
    // Create invite URL
    const inviteUrl = `${process.env.FRONTEND_URL}/register?token=${token}`;
    
    // Send email invitation
    try {
      await sendEmail({
        to: email,
        subject: 'Invitation to join the team',
        html: `
          <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #e0e0e0; border-radius: 5px;">
            <h1 style="color: #333;">You've been invited to join the team</h1>
            <p>You've been invited by ${req.user.name} to join as a ${role}.</p>
            <p>Click the button below to create your account:</p>
            <a href="${inviteUrl}" style="display: inline-block; padding: 10px 20px; background-color: #3182ce; color: white; border-radius: 5px; text-decoration: none; margin: 15px 0;">Accept Invitation</a>
            <p style="color: #666; font-size: 0.9em;">This invitation expires in 7 days.</p>
            <hr style="border: none; border-top: 1px solid #e0e0e0; margin: 20px 0;">
            <p style="color: #999; font-size: 0.8em;">If you're having trouble with the button above, copy and paste this URL into your browser: <br> ${inviteUrl}</p>
          </div>
        `
      });
      
      return res.status(200).json({
        success: true,
        message: 'Invitation sent successfully'
      });
    } catch (emailError) {
      // If email fails, delete the invitation
      await Invitation.findByIdAndDelete(invitation._id);
      
      console.error('Error sending invitation email:', emailError);
      return res.status(500).json({
        success: false,
        message: 'Failed to send invitation email'
      });
    }
  } catch (error) {
    console.error('Error creating invitation:', error);
    return res.status(500).json({
      success: false,
      message: 'Error creating invitation'
    });
  }
};

/**
 * Get count of pending invitations
 * @route GET /api/auth/pending-invites/count
 * @access Private (Admin only)
 */
exports.getPendingInvitesCount = async (req, res) => {
  try {
    // Verify the current user is an admin
    if (!req.user || req.user.role !== 'admin') {
      return res.status(403).json({ 
        success: false, 
        message: 'Only admins can view pending invitations' 
      });
    }
    
    const count = await Invitation.countDocuments({ 
      status: 'pending',
      expiresAt: { $gt: new Date() }
    });
    
    return res.status(200).json({
      success: true,
      count
    });
  } catch (error) {
    console.error('Error getting pending invites count:', error);
    return res.status(500).json({
      success: false,
      message: 'Error getting pending invites count'
    });
  }
};

/**
 * Verify invitation token
 * @route GET /api/auth/verify-invitation/:token
 * @access Public
 */
exports.verifyInvitation = async (req, res) => {
  try {
    const { token } = req.params;
    
    const invitation = await Invitation.findOne({ 
      token,
      status: 'pending',
      expiresAt: { $gt: new Date() }
    });
    
    if (!invitation) {
      return res.status(400).json({
        success: false,
        message: 'Invalid or expired invitation'
      });
    }
    
    return res.status(200).json({
      success: true,
      invitation: {
        email: invitation.email,
        role: invitation.role
      }
    });
  } catch (error) {
    console.error('Error verifying invitation:', error);
    return res.status(500).json({
      success: false,
      message: 'Error verifying invitation'
    });
  }
}; 