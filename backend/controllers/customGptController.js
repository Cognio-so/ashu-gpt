const CustomGpt = require('../models/CustomGpt');
const { uploadToR2, deleteFromR2 } = require('../lib/r2');
const multer = require('multer');
const fs = require('fs');
const path = require('path');
const UserGptAssignment = require('../models/UserGptAssignment');
const User = require('../models/User');
const UserFavorite = require('../models/UserFavorite');


// Configure multer for memory storage
const storage = multer.memoryStorage();
const upload = multer({
  storage,
  limits: { fileSize: 20 * 1024 * 1024 } // 20MB limit
});

// Define specific field handlers
const handleImageUpload = upload.single('image');
const handleKnowledgeUpload = upload.array('knowledgeFiles', 5);

// New combined middleware for handling both optional fields
const handleCombinedUpload = upload.fields([
  { name: 'image', maxCount: 1 },
  { name: 'knowledgeFiles', maxCount: 5 }
]);

// Create a new custom GPT
const createCustomGpt = async (req, res) => {


  try {
    const { name, description, instructions, conversationStarter, model, capabilities } = req.body;

    // Validate required fields manually for clarity (optional but helpful)
    if (!name || !description || !instructions) {
      console.error("Validation Error: Missing required fields (name, description, instructions)");
      return res.status(400).json({ success: false, message: 'Missing required fields: name, description, instructions' });
    }
    if (!req.user?._id) {
      console.error("Auth Error: req.user._id is missing");
      return res.status(401).json({ success: false, message: 'Authentication error, user ID not found' });
    }

    let parsedCapabilities;
    try {
      parsedCapabilities = JSON.parse(capabilities || '{"webBrowsing": true}');
    } catch (parseError) {
      console.error("Error parsing capabilities JSON:", parseError);
      return res.status(400).json({ success: false, message: 'Invalid format for capabilities' });
    }

    // Create the custom GPT object
    const customGptData = {
      name,
      description,
      instructions,
      conversationStarter,
      model,
      capabilities: parsedCapabilities,
      createdBy: req.user._id,
      imageUrl: null,       // Initialize explicitly
      knowledgeFiles: []  // Initialize explicitly
    };

    const customGpt = new CustomGpt(customGptData);

    // Access files from req.files
    const imageFile = req.files?.image?.[0];
    const knowledgeUploads = req.files?.knowledgeFiles || [];

    // Upload image if provided
    if (imageFile) {
      try {
        const { fileUrl } = await uploadToR2(
          imageFile.buffer,
          imageFile.originalname,
          'images/gpt'
        );
        customGpt.imageUrl = fileUrl;
      } catch (uploadError) {
        console.error("Error during image upload to R2:", uploadError);
        // Decide if you want to stop or continue without the image
        return res.status(500).json({ success: false, message: 'Failed during image upload', error: uploadError.message });
      }
    }

    // Upload knowledge files if provided
    if (knowledgeUploads.length > 0) {
      try {
        const knowledgeFilesData = await Promise.all(
          knowledgeUploads.map(async (file) => {
            const { fileUrl } = await uploadToR2(
              file.buffer,
              file.originalname,
              'knowledge'
            );
            return {
              name: file.originalname,
              fileUrl,
              fileType: file.mimetype,
            };
          })
        );
        customGpt.knowledgeFiles = knowledgeFilesData;
      } catch (uploadError) {
        console.error("Error during knowledge file upload to R2:", uploadError);
        // Decide if you want to stop or continue without the knowledge files
        return res.status(500).json({ success: false, message: 'Failed during knowledge file upload', error: uploadError.message });
      }
    }


    // Explicitly log the save operation and force a database test
    const savedGpt = await customGpt.save();

    // DIRECT DATABASE VERIFICATION - force a fresh read from DB
    const verifyResult = await CustomGpt.findById(savedGpt._id);
    if (verifyResult) {
    } else {
      console.error("VERIFICATION FAILED: Document not found in DB after save!");
    }

    res.status(201).json({
      success: true,
      message: 'Custom GPT created successfully',
      customGpt: savedGpt
    });

  } catch (error) {
    // Log the specific error
    console.error('--- Error caught in createCustomGpt catch block ---');
    console.error("Error Name:", error.name);
    console.error("Error Message:", error.message);
    console.error("Full Error Object:", error);

    // Check for Mongoose validation errors specifically
    if (error.name === 'ValidationError') {
      // Extract cleaner validation messages
      const validationErrors = Object.values(error.errors).map(err => err.message);
      console.error("Validation Errors:", validationErrors);
      return res.status(400).json({
        success: false,
        message: 'Validation failed',
        errors: validationErrors
      });
    }

    res.status(500).json({
      success: false,
      message: 'Failed to create custom GPT',
      error: error.message // Send a generic message or specific if safe
    });
  }
};

// Get all custom GPTs for the current user
const getUserCustomGpts = async (req, res) => {
  try {
    const customGpts = await CustomGpt.find({ createdBy: req.user._id });
    res.status(200).json({
      success: true,
      customGpts
    });
  } catch (error) {
    console.error('Error fetching user custom GPTs:', error);
    return res.status(500).json({
      success: false,
      message: 'Error fetching custom GPTs'
    });
  }
};

// Get a specific custom GPT by ID
const getCustomGptById = async (req, res) => {
  try {
    // Check if id is valid before attempting to find
    if (!req.params.id || req.params.id === 'undefined') {
      return res.status(400).json({
        success: false,
        message: 'Invalid GPT ID provided'
      });
    }

    const customGpt = await CustomGpt.findById(req.params.id);

    if (!customGpt) {
      return res.status(404).json({
        success: false,
        message: 'Custom GPT not found'
      });
    }

    // Check if the user owns this GPT
    if (customGpt.createdBy.toString() !== req.user._id.toString()) {
      return res.status(403).json({
        success: false,
        message: 'Not authorized to access this custom GPT'
      });
    }

    res.status(200).json({
      success: true,
      customGpt
    });
  } catch (error) {
    console.error('Error fetching custom GPT:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch custom GPT',
      error: error.message
    });
  }
};

// Update a custom GPT
const updateCustomGpt = async (req, res) => {
  try {
    let customGpt = await CustomGpt.findById(req.params.id);

    if (!customGpt) {
      return res.status(404).json({
        success: false,
        message: 'Custom GPT not found'
      });
    }

    // Check if the user owns this GPT
    if (customGpt.createdBy.toString() !== req.user._id.toString()) {
      return res.status(403).json({
        success: false,
        message: 'Not authorized to update this custom GPT'
      });
    }

    const { name, description, instructions, conversationStarter, model, capabilities } = req.body;

    // Update basic fields
    customGpt.name = name || customGpt.name;
    customGpt.description = description || customGpt.description;
    customGpt.instructions = instructions || customGpt.instructions;
    customGpt.conversationStarter = conversationStarter ?? customGpt.conversationStarter;
    customGpt.model = model || customGpt.model;

    if (capabilities) {
      customGpt.capabilities = JSON.parse(capabilities);
    }

    // Access files from req.files (now an object)
    const imageFile = req.files?.image ? req.files.image[0] : null;
    const knowledgeUploads = req.files?.knowledgeFiles || [];

    // Upload new image if provided
    if (imageFile) {
      // Delete old image if exists
      if (customGpt.imageUrl) {
        // Extract key from imageUrl
        const key = customGpt.imageUrl.replace(process.env.R2_PUBLIC_URL + '/', '');
        await deleteFromR2(key);
      }

      const { fileUrl } = await uploadToR2(
        imageFile.buffer,
        imageFile.originalname,
        'images/gpt'
      );
      customGpt.imageUrl = fileUrl;
    }

    // Handle knowledge files if provided
    if (knowledgeUploads.length > 0) {
      // Delete old files if needed and specified in request
      if (req.body.replaceKnowledge === 'true' && customGpt.knowledgeFiles.length > 0) {
        for (const file of customGpt.knowledgeFiles) {
          const key = file.fileUrl.replace(process.env.R2_PUBLIC_URL + '/', '');
          await deleteFromR2(key);
        }
        customGpt.knowledgeFiles = [];
      }

      // Upload new files
      const newKnowledgeFilesData = await Promise.all(
        knowledgeUploads.map(async (file) => {
          const { fileUrl } = await uploadToR2(
            file.buffer,
            file.originalname,
            'knowledge'
          );
          return {
            name: file.originalname,
            fileUrl,
            fileType: file.mimetype,
          };
        })
      );

      customGpt.knowledgeFiles = [
        ...customGpt.knowledgeFiles,
        ...newKnowledgeFilesData
      ];
    }

    await customGpt.save();

    res.status(200).json({
      success: true,
      message: 'Custom GPT updated successfully',
      customGpt
    });
  } catch (error) {
    console.error('Error updating custom GPT:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to update custom GPT',
      error: error.message
    });
  }
};

// Delete a custom GPT
const deleteCustomGpt = async (req, res) => {
  try {
    const customGpt = await CustomGpt.findById(req.params.id);

    if (!customGpt) {
      return res.status(404).json({
        success: false,
        message: 'Custom GPT not found'
      });
    }

    // Check if the user owns this GPT
    if (customGpt.createdBy.toString() !== req.user._id.toString()) {
      return res.status(403).json({
        success: false,
        message: 'Not authorized to delete this custom GPT'
      });
    }

    // Delete associated files from R2
    if (customGpt.imageUrl) {
      const imageKey = customGpt.imageUrl.replace(process.env.R2_PUBLIC_URL + '/', '');
      await deleteFromR2(imageKey);
    }

    // Delete knowledge files
    for (const file of customGpt.knowledgeFiles) {
      const fileKey = file.fileUrl.replace(process.env.R2_PUBLIC_URL + '/', '');
      await deleteFromR2(fileKey);
    }

    // Delete the custom GPT from database
    await CustomGpt.findByIdAndDelete(req.params.id);

    res.status(200).json({
      success: true,
      message: 'Custom GPT deleted successfully'
    });
  } catch (error) {
    console.error('Error deleting custom GPT:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to delete custom GPT',
      error: error.message
    });
  }
};

// Delete a specific knowledge file
const deleteKnowledgeFile = async (req, res) => {
  try {
    const { id, fileIndex } = req.params;

    const customGpt = await CustomGpt.findById(id);

    if (!customGpt) {
      return res.status(404).json({
        success: false,
        message: 'Custom GPT not found'
      });
    }

    // Check if the user owns this GPT
    if (customGpt.createdBy.toString() !== req.user._id.toString()) {
      return res.status(403).json({
        success: false,
        message: 'Not authorized to modify this custom GPT'
      });
    }

    // Check if the file exists
    if (!customGpt.knowledgeFiles[fileIndex]) {
      return res.status(404).json({
        success: false,
        message: 'Knowledge file not found'
      });
    }

    // Delete the file from R2
    const fileKey = customGpt.knowledgeFiles[fileIndex].fileUrl.replace(process.env.R2_PUBLIC_URL + '/', '');
    await deleteFromR2(fileKey);

    // Remove the file from the array
    customGpt.knowledgeFiles.splice(fileIndex, 1);
    await customGpt.save();

    res.status(200).json({
      success: true,
      message: 'Knowledge file deleted successfully',
      customGpt
    });
  } catch (error) {
    console.error('Error deleting knowledge file:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to delete knowledge file',
      error: error.message
    });
  }
};

const getAllCustomGpts = async (req, res) => {
  try {
    // Only show GPTs created by the admin (current user)
    const filter = { createdBy: req.user._id };

    const customGpts = await CustomGpt.find(filter); 
    res.status(200).json({
      success: true,
      customGpts
    });
  } catch (error) {
    console.error('Error fetching all accessible custom GPTs:', error);
    return res.status(500).json({
      success: false,
      message: 'Error fetching custom GPTs'
    });
  }
};

const getUserAssignedGpts = async (req, res) => {
  try {
    const userId = req.params.userId || req.user._id;  // Allow using either parameter or current user
    
    
    // Check for assignments in UserGptAssignment collection
    const assignments = await UserGptAssignment.find({ userId }).lean();
    
    if (assignments.length === 0) {
      return res.status(200).json({
        success: true,
        gpts: []
      });
    }
    
    // Get GPT details for each assignment
    const gptIds = assignments.map(assignment => assignment.gptId);
    
    const gpts = await CustomGpt.find({ _id: { $in: gptIds } }).lean();
    
    // Add assignment dates and folder to each GPT
    const gptsWithDetails = gpts.map(gpt => {
      const assignment = assignments.find(a => a.gptId.toString() === gpt._id.toString());
      return {
        ...gpt,
        assignedAt: assignment?.createdAt || new Date(),
        folder: assignment?.folder || null
      };
    });
    
    // Get user's favorites to mark the favorite GPTs
    const userFavorites = await UserFavorite.find({ user: userId }).distinct('gpt');
    
    // Add isFavorite flag to each GPT
    const gptsWithFavorites = gptsWithDetails.map(gpt => {
      return {
        ...gpt,
        isFavorite: userFavorites.some(favId => 
          favId.toString() === gpt._id.toString()
        )
      };
    });
    
    return res.status(200).json({
      success: true,
      gpts: gptsWithFavorites
    });
  } catch (error) {
    console.error(`Error in getUserAssignedGpts: ${error.message}`);
    console.error(error.stack);
    return res.status(500).json({ 
      success: false, 
      message: `Failed to fetch assigned GPTs: ${error.message}`
    });
  }
};

const assignGptToUser = async (req, res) => {
  try {
    const { userId } = req.params;
    const { gptId } = req.body;

    if (req.user.role !== 'admin') {
      return res.status(403).json({
        success: false,
        message: 'Only admins can assign GPTs'
      });
    }

    const userExists = await User.exists({ _id: userId });
    if (!userExists) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    const gptExists = await CustomGpt.exists({ _id: gptId });
    if (!gptExists) {
      return res.status(404).json({
        success: false,
        message: 'GPT not found'
      });
    }

    // Check if assignment already exists
    const existingAssignment = await UserGptAssignment.findOne({ userId, gptId });
    if (existingAssignment) {
      return res.status(200).json({
        success: true,
        message: 'GPT is already assigned to this user'
      });
    }

    await UserGptAssignment.create({
      userId,
      gptId,
      assignedBy: req.user._id
    });

    return res.status(200).json({
      success: true,
      message: 'GPT assigned successfully'
    });
  } catch (error) {
    console.error('Error assigning GPT:', error);
    return res.status(500).json({
      success: false,
      message: 'Error assigning GPT'
    });
  }
};

const unassignGptFromUser = async (req, res) => {
  try {
    const { userId, gptId } = req.params;

    if (req.user.role !== 'admin') {
      return res.status(403).json({
        success: false,
        message: 'Only admins can unassign GPTs'
      });
    }

    const result = await UserGptAssignment.findOneAndDelete({ userId, gptId });

    if (!result) {
      return res.status(404).json({
        success: false,
        message: 'Assignment not found'
      });
    }

    return res.status(200).json({
      success: true,
      message: 'GPT unassigned successfully'
    });
  } catch (error) {
    console.error('Error unassigning GPT:', error);
    return res.status(500).json({
      success: false,
      message: 'Error unassigning GPT'
    });
  }
};

const getUserGptCount = async (req, res) => {
  try {
    // Only admins can access this
    if (req.user.role !== 'admin') {
      return res.status(403).json({
        success: false,
        message: 'Not authorized to access user GPT counts'
      });
    }

    // Get all users
    const users = await User.find().select('_id');

    const userGptCounts = {};

    users.forEach(user => {
      userGptCounts[user._id.toString()] = 0;
    });

    const assignments = await UserGptAssignment.aggregate([
      {
        $group: {
          _id: '$userId',
          count: { $sum: 1 }
        }
      }
    ]);

    assignments.forEach(assignment => {
      userGptCounts[assignment._id.toString()] = assignment.count;
    });

    return res.status(200).json({
      success: true,
      userGptCounts
    });
  } catch (error) {
    console.error('Error fetching user GPT counts:', error);
    return res.status(500).json({
      success: false,
      message: 'Error fetching user GPT counts'
    });
  }
};

// Get assigned GPT by ID
const getAssignedGptById = async (req, res) => {
  try {
    const gptId = req.params.id;
    const userId = req.user._id;

    if (!gptId || gptId === 'undefined') {
      return res.status(400).json({
        success: false,
        message: 'Invalid GPT ID provided'
      });
    }

    // First, check if this GPT is assigned to the user
    const assignment = await UserGptAssignment.findOne({
      userId: userId,
      gptId: gptId
    });

    if (!assignment) {
      return res.status(403).json({
        success: false,
        message: 'Not authorized to access this GPT or GPT not assigned to user'
      });
    }

    // If assignment exists, get the GPT details
    const customGpt = await CustomGpt.findById(gptId);

    if (!customGpt) {
      return res.status(404).json({
        success: false,
        message: 'Custom GPT not found'
      });
    }

    return res.status(200).json({
      success: true,
      customGpt
    });
  } catch (error) {
    console.error('Error fetching assigned GPT by ID:', error);
    return res.status(500).json({
      success: false,
      message: 'Error fetching assigned GPT'
    });
  }
};

// New controller function to update the folder
const updateGptFolder = async (req, res) => {
  try {
    const { id } = req.params;
    const { folder } = req.body; // folder can be a string or null/undefined

    // Validate folder name slightly (optional, prevent overly long names etc.)
    if (folder && typeof folder === 'string' && folder.length > 100) {
      return res.status(400).json({
        success: false,
        message: 'Folder name is too long (max 100 characters).'
      });
    }

    const customGpt = await CustomGpt.findById(id);

    if (!customGpt) {
      return res.status(404).json({
        success: false,
        message: 'Custom GPT not found'
      });
    }

    // Check if the user owns this GPT or is an admin (adjust authorization as needed)
    // Assuming only the creator can modify it for now
    if (customGpt.createdBy.toString() !== req.user._id.toString()) {
      // Maybe allow admins too?
      // if (customGpt.createdBy.toString() !== req.user._id.toString() && req.user.role !== 'admin') {
      return res.status(403).json({
        success: false,
        message: 'Not authorized to modify this custom GPT'
      });
    }

    // Update the folder - set to null if folder is null/empty string, otherwise use the string
    customGpt.folder = folder || null; 
    
    await customGpt.save();

    res.status(200).json({
      success: true,
      message: 'GPT folder updated successfully',
      customGpt: { // Send back minimal updated info if needed
        _id: customGpt._id,
        folder: customGpt.folder
      } 
    });

  } catch (error) {
    console.error('Error updating GPT folder:', error);
    // Handle potential validation errors from Mongoose if you add stricter schema rules
    if (error.name === 'ValidationError') {
      return res.status(400).json({ success: false, message: error.message });
    }
    res.status(500).json({
      success: false,
      message: 'Failed to update GPT folder',
      error: error.message
    });
  }
};

// Get user's favorite GPTs
const getUserFavorites = async (req, res) => {
    try {
        const userId = req.user._id;
        
        // Find all favorites for this user
        const favorites = await UserFavorite.find({ user: userId })
            .populate({
                path: 'gpt',
                // Select necessary fields, potentially removing assignedAt if it's not directly on CustomGpt
                select: 'name description model imageUrl capabilities files' 
            })
            .lean(); // Use lean for better performance

        if (!favorites.length) {
            return res.status(200).json({ success: true, gpts: [] });
        }
        
        // Get GPT IDs from favorites
        const gptIds = favorites.map(fav => fav.gpt._id);
        
        // Find the corresponding assignments to get folder info
        const assignments = await UserGptAssignment.find({ 
            userId: userId, 
            gptId: { $in: gptIds } 
        }).lean();
        
        // Create a map for easy lookup: gptId -> folder
        const assignmentFolderMap = assignments.reduce((map, assignment) => {
            map[assignment.gptId.toString()] = assignment.folder || null;
            return map;
        }, {});

        // Extract the GPT data and add folder info
        const gpts = favorites.map(fav => {
            const gptObject = fav.gpt; // Already a plain object due to .lean()
            gptObject.isFavorite = true;
            // Assign folder from the map, default to null if not found (shouldn't happen ideally)
            gptObject.folder = assignmentFolderMap[gptObject._id.toString()] || null; 
            // Note: You might want createdAt from the favorite record, not the GPT itself
            gptObject.createdAt = fav.createdAt; // Use favorite creation date
            return gptObject;
        });
        
        return res.status(200).json({
            success: true,
            gpts
        });
    } catch (error) {
        console.error('Error fetching user favorites:', error);
        return res.status(500).json({
            success: false,
            message: 'Failed to fetch favorite GPTs',
            error: error.message
        });
    }
};

// Add a GPT to user's favorites
const addToFavorites = async (req, res) => {
    try {
        const userId = req.user._id;
        const { gptId } = req.params;
        
        // Check if the GPT exists and is assigned to the user
        const isAssigned = await UserGptAssignment.exists({ 
            userId: userId,
            gptId: gptId
        });
        
        if (!isAssigned) {
            return res.status(404).json({
                success: false,
                message: 'GPT not found or not assigned to you'
            });
        }
        
        // Create a new favorite (the unique index will prevent duplicates)
        await UserFavorite.create({
            user: userId,
            gpt: gptId
        });
        
        return res.status(201).json({
            success: true,
            message: 'GPT added to favorites'
        });
    } catch (error) {
        // If it's a duplicate key error, just return success
        if (error.code === 11000) {
            return res.status(200).json({
                success: true,
                message: 'GPT is already in favorites'
            });
        }
        
        console.error('Error adding to favorites:', error);
        return res.status(500).json({
            success: false,
            message: 'Failed to add GPT to favorites',
            error: error.message
        });
    }
};

// Remove a GPT from user's favorites
const removeFromFavorites = async (req, res) => {
    try {
        const userId = req.user._id;
        const { gptId } = req.params;
        
        // Delete the favorite
        const result = await UserFavorite.deleteOne({
            user: userId,
            gpt: gptId
        });
        
        if (result.deletedCount === 0) {
            return res.status(404).json({
                success: false,
                message: 'GPT not found in favorites'
            });
        }
        
        return res.status(200).json({
            success: true,
            message: 'GPT removed from favorites'
        });
    } catch (error) {
        console.error('Error removing from favorites:', error);
        return res.status(500).json({
            success: false,
            message: 'Failed to remove GPT from favorites',
            error: error.message
        });
    }
};

// Update GPT folder for user assignment
const updateUserGptFolder = async (req, res) => {
  try {
    const userId = req.user._id;
    const { gptId } = req.params;
    const { folder } = req.body; // folder can be a string or null/undefined

    // Validate folder name slightly (optional, prevent overly long names etc.)
    if (folder && typeof folder === 'string' && folder.length > 100) {
      return res.status(400).json({
        success: false,
        message: 'Folder name is too long (max 100 characters).'
      });
    }

    // Find the assignment
    const assignment = await UserGptAssignment.findOne({ 
      userId: userId, 
      gptId: gptId 
    });

    if (!assignment) {
      return res.status(404).json({
        success: false,
        message: 'GPT assignment not found'
      });
    }

    // Update the folder - set to null if folder is null/empty string, otherwise use the string
    assignment.folder = folder || null;
    await assignment.save();

    return res.status(200).json({
      success: true,
      message: 'Folder updated successfully',
      assignment: {
        gptId: assignment.gptId,
        folder: assignment.folder
      }
    });
  } catch (error) {
    console.error('Error updating assignment folder:', error);
    return res.status(500).json({
      success: false,
      message: 'Failed to update folder',
      error: error.message
    });
  }
};

module.exports = {
  createCustomGpt,
  getUserCustomGpts,
  getCustomGptById,
  updateCustomGpt,
  deleteCustomGpt,
  deleteKnowledgeFile,
  uploadMiddleware: handleCombinedUpload,
  getAllCustomGpts,
  getUserAssignedGpts,
  assignGptToUser,
  unassignGptFromUser,
  getUserGptCount,
  getAssignedGptById,
  updateGptFolder,
  getUserFavorites,
  addToFavorites,
  removeFromFavorites,
  updateUserGptFolder
}; 