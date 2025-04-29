import React, { useState, useEffect } from 'react';
import { FiX, FiFolder, FiPlus } from 'react-icons/fi';
import { axiosInstance } from '../../api/axiosInstance';
import { toast } from 'react-toastify';

const MoveToFolderModal = ({ isOpen, onClose, gpt, existingFolders = [], onSuccess }) => {
    const [targetFolder, setTargetFolder] = useState('');
    const [newFolderName, setNewFolderName] = useState('');
    const [isCreatingNew, setIsCreatingNew] = useState(false);
    const [isLoading, setIsLoading] = useState(false);

    // Reset state when modal opens or gpt changes
    useEffect(() => {
        if (isOpen) {
            setTargetFolder(gpt?.folder || ''); // Pre-select current folder or empty
            setNewFolderName('');
            setIsCreatingNew(false);
            setIsLoading(false);
        }
    }, [isOpen, gpt]);

    const handleFolderChange = (e) => {
        const value = e.target.value;
        setTargetFolder(value);
        if (value === '__CREATE_NEW__') {
            setIsCreatingNew(true);
            setNewFolderName(''); // Clear any previous input
        } else {
            setIsCreatingNew(false);
        }
    };

    const handleMove = async () => {
        let finalFolderName = isCreatingNew ? newFolderName.trim() : targetFolder;

        // Basic validation for new folder name
        if (isCreatingNew && !finalFolderName) {
            toast.error("Please enter a name for the new folder.");
            return;
        }
        
        // Prevent moving to 'All' or 'Uncategorized' pseudo-folders
        if (finalFolderName === 'All' || finalFolderName === 'Uncategorized') {
             toast.error("Cannot move to 'All' or 'Uncategorized'. Choose or create a specific folder.");
             return;
        }

        // If selecting 'Uncategorized' from dropdown, set folder to null/empty
        if (!isCreatingNew && finalFolderName === '') {
            finalFolderName = null; // Represent unassigning folder
        }
        
        setIsLoading(true);
        try {
            // **BACKEND CALL** (We'll create this endpoint next)
            await axiosInstance.patch(`/api/custom-gpts/${gpt._id}/folder`, 
                { folder: finalFolderName }, // Send null if unassigning
                { withCredentials: true }
            );
            
            onSuccess(gpt, finalFolderName); // Notify parent component

        } catch (err) {
            console.error("Error moving GPT:", err);
            toast.error(err.response?.data?.message || "Failed to move GPT.");
        } finally {
            setIsLoading(false);
        }
    };

    if (!isOpen || !gpt) return null;

    return (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 dark:bg-black/80 backdrop-blur-sm">
            <div className="relative bg-white dark:bg-gray-800 w-full max-w-md rounded-lg shadow-xl border border-gray-200 dark:border-gray-700">
                {/* Header */}
                <div className="flex justify-between items-center p-4 border-b border-gray-200 dark:border-gray-700">
                    <h3 className="text-lg font-semibold text-gray-900 dark:text-white">Move GPT to Folder</h3>
                    <button 
                        onClick={onClose}
                        className="text-gray-400 hover:text-gray-600 dark:text-gray-500 dark:hover:text-white transition-colors rounded-full p-1 hover:bg-gray-200 dark:hover:bg-gray-700"
                        disabled={isLoading}
                    >
                        <FiX size={20} />
                    </button>
                </div>

                {/* Body */}
                <div className="p-6 space-y-4">
                    <p className="text-sm text-gray-600 dark:text-gray-300">
                        Move <span className="font-medium text-gray-900 dark:text-white">{gpt.name}</span> to:
                    </p>
                    
                    {/* Folder Selection Dropdown */}
                    <div className="relative">
                        <FiFolder className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400 dark:text-gray-500" />
                        <select
                            value={isCreatingNew ? '__CREATE_NEW__' : targetFolder}
                            onChange={handleFolderChange}
                            className="w-full pl-10 pr-4 py-2 rounded-lg bg-white dark:bg-gray-700 border border-gray-300 dark:border-gray-600 text-gray-900 dark:text-white text-sm appearance-none cursor-pointer focus:ring-2 focus:ring-blue-500 focus:border-transparent outline-none"
                            disabled={isLoading}
                        >
                            <option value="">Uncategorized</option> 
                            {existingFolders.sort().map(folder => (
                                <option key={folder} value={folder}>
                                    {folder}
                                </option>
                            ))}
                            <option value="__CREATE_NEW__">-- Create New Folder --</option>
                        </select>
                    </div>

                    {/* New Folder Name Input (conditional) */}
                    {isCreatingNew && (
                        <div className="relative">
                             <FiPlus className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400 dark:text-gray-500" />
                            <input
                                type="text"
                                placeholder="Enter new folder name..."
                                value={newFolderName}
                                onChange={(e) => setNewFolderName(e.target.value)}
                                className="w-full pl-10 pr-4 py-2 rounded-lg bg-white dark:bg-gray-700 border border-gray-300 dark:border-gray-600 text-gray-900 dark:text-white text-sm focus:ring-2 focus:ring-blue-500 focus:border-transparent outline-none"
                                disabled={isLoading}
                                autoFocus
                            />
                        </div>
                    )}
                </div>

                {/* Footer */}
                <div className="flex justify-end gap-3 p-4 border-t border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-800/50 rounded-b-lg">
                    <button
                        onClick={onClose}
                        disabled={isLoading}
                        className="px-4 py-2 rounded-md text-sm font-medium text-gray-700 dark:text-gray-300 bg-white dark:bg-gray-700 border border-gray-300 dark:border-gray-600 hover:bg-gray-50 dark:hover:bg-gray-600 disabled:opacity-50"
                    >
                        Cancel
                    </button>
                    <button
                        onClick={handleMove}
                        disabled={isLoading || (isCreatingNew && !newFolderName.trim())}
                        className="px-4 py-2 rounded-md text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center"
                    >
                        {isLoading ? (
                            <div className="animate-spin rounded-full h-4 w-4 border-t-2 border-b-2 border-white"></div>
                        ) : (
                            'Move GPT'
                        )}
                    </button>
                </div>
            </div>
        </div>
    );
};

export default MoveToFolderModal; 