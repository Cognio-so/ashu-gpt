import React, { useState, useEffect, useRef, useCallback } from 'react';
import { FiFolder, FiFolderPlus, FiX, FiCheck, FiPlus } from 'react-icons/fi';
import { axiosInstance } from '../../api/axiosInstance';
import { useTheme } from '../../context/ThemeContext';

const MoveToFolderModal = ({ isOpen, onClose, gpt, existingFolders, onSuccess }) => {
    const [selectedFolder, setSelectedFolder] = useState(gpt.folder || 'Uncategorized');
    const [newFolder, setNewFolder] = useState('');
    const [isCreatingNew, setIsCreatingNew] = useState(false);
    const [isLoading, setIsLoading] = useState(false);
    const [error, setError] = useState(null);
    const modalRef = useRef(null);
    const { isDarkMode } = useTheme();

    useEffect(() => {
        // Reset state when modal opens
        if (isOpen) {
            setSelectedFolder(gpt.folder || 'Uncategorized');
            setNewFolder('');
            setIsCreatingNew(false);
            setError(null);
        }
    }, [isOpen, gpt]);

    // Handle click outside to close
    useEffect(() => {
        const handleClickOutside = (e) => {
            if (modalRef.current && !modalRef.current.contains(e.target)) {
                onClose();
            }
        };

        if (isOpen) {
            document.addEventListener('mousedown', handleClickOutside);
        }

        return () => {
            document.removeEventListener('mousedown', handleClickOutside);
        };
    }, [isOpen, onClose]);

    // Handle escape key to close
    useEffect(() => {
        const handleEscKey = (e) => {
            if (e.key === 'Escape') {
                onClose();
            }
        };

        if (isOpen) {
            document.addEventListener('keydown', handleEscKey);
        }

        return () => {
            document.removeEventListener('keydown', handleEscKey);
        };
    }, [isOpen, onClose]);

    const handleSubmit = useCallback(async (e) => {
        e.preventDefault();
        setIsLoading(true);
        setError(null);

        try {
            // Ensure folderName is null if 'Uncategorized' or empty string is chosen/created
            let finalFolderName = isCreatingNew ? newFolder.trim() : selectedFolder;
            if (finalFolderName === 'Uncategorized' || finalFolderName === '') {
                finalFolderName = null;
            }

            // Call backend API to update the folder on the UserGptAssignment record
            const response = await axiosInstance.patch(`/api/custom-gpts/user/assigned/${gpt._id}/folder`,
                { folder: finalFolderName }, // Send finalFolderName (can be null)
                { withCredentials: true }
            );

            if (response.data.success) {
                // Pass the updated GPT info (including the new folder) back to parent
                // Also pass the potentially new folder name if one was created
                onSuccess({ ...gpt, folder: response.data.assignment.folder }, isCreatingNew ? finalFolderName : null);
                onClose();
            } else {
                setError(response.data.message || 'Failed to move GPT to folder');
            }
        } catch (error) {
            console.error('Error moving GPT to folder:', error);
            setError(error.response?.data?.message || 'An error occurred while moving GPT to folder');
        } finally {
            setIsLoading(false);
        }
    }, [gpt, selectedFolder, newFolder, isCreatingNew, onSuccess, onClose]);

    if (!isOpen) return null;

    return (
        <div className={`fixed inset-0 z-50 flex items-center justify-center bg-black/50 backdrop-blur-sm transition-opacity ${isOpen ? 'opacity-100' : 'opacity-0 pointer-events-none'}`}>
            <div
                ref={modalRef}
                className={`w-full max-w-md rounded-lg shadow-xl p-6 transition-transform ${isDarkMode ? 'bg-gray-800 text-white' : 'bg-white text-gray-800'
                    } ${isOpen ? 'scale-100' : 'scale-95'}`}
            >
                <div className="flex justify-between items-center mb-5">
                    <h3 className="text-lg font-semibold flex items-center gap-2">
                        <FiFolder />
                        Move to Folder
                    </h3>
                    <button
                        onClick={onClose}
                        className={`p-1.5 rounded-full transition-colors ${isDarkMode
                                ? 'hover:bg-gray-700 text-gray-400 hover:text-white'
                                : 'hover:bg-gray-100 text-gray-500 hover:text-gray-700'
                            }`}
                    >
                        <FiX size={18} />
                    </button>
                </div>

                <p className={`text-sm mb-5 ${isDarkMode ? 'text-gray-300' : 'text-gray-600'}`}>
                    Moving: <span className="font-medium">{gpt.name}</span>
                </p>

                {error && (
                    <div className={`mb-4 p-2 rounded-md text-sm ${isDarkMode ? 'bg-red-900/40 text-red-300 border border-red-800/50' : 'bg-red-50 text-red-600 border border-red-100'
                        }`}>
                        {error}
                    </div>
                )}

                <form onSubmit={handleSubmit}>
                    <div className="mb-4">
                        <label className={`block mb-2 text-sm font-medium ${isDarkMode ? 'text-gray-300' : 'text-gray-700'}`}>
                            Select Folder
                        </label>

                        <div className="grid grid-cols-2 gap-2 mb-3">
                            {['Uncategorized', ...existingFolders].map(folder => (
                                <button
                                    key={folder}
                                    type="button"
                                    onClick={() => {
                                        setSelectedFolder(folder);
                                        setIsCreatingNew(false);
                                    }}
                                    className={`flex items-center p-2 rounded-md transition-colors ${selectedFolder === folder && !isCreatingNew
                                            ? (isDarkMode ? 'bg-blue-600 text-white' : 'bg-blue-100 text-blue-700')
                                            : (isDarkMode ? 'bg-gray-700 hover:bg-gray-600' : 'bg-gray-100 hover:bg-gray-200')
                                        }`}
                                >
                                    <FiFolder className="mr-2" size={16} />
                                    <span className="truncate">{folder}</span>
                                </button>
                            ))}

                            <button
                                type="button"
                                onClick={() => setIsCreatingNew(true)}
                                className={`flex items-center p-2 rounded-md transition-colors ${isCreatingNew
                                        ? (isDarkMode ? 'bg-blue-600 text-white' : 'bg-blue-100 text-blue-700')
                                        : (isDarkMode ? 'bg-gray-700 hover:bg-gray-600' : 'bg-gray-100 hover:bg-gray-200')
                                    }`}
                            >
                                <FiPlus className="mr-2" size={16} />
                                <span>New Folder</span>
                            </button>
                        </div>

                        {isCreatingNew && (
                            <div className="mt-3">
                                <label className={`block mb-2 text-sm font-medium ${isDarkMode ? 'text-gray-300' : 'text-gray-700'}`}>
                                    New Folder Name
                                </label>
                                <input
                                    type="text"
                                    value={newFolder}
                                    onChange={(e) => setNewFolder(e.target.value)}
                                    className={`w-full p-2 rounded-md border ${isDarkMode
                                            ? 'bg-gray-700 border-gray-600 text-white'
                                            : 'bg-white border-gray-300 text-gray-900'
                                        }`}
                                    placeholder="Enter folder name"
                                    required
                                />
                            </div>
                        )}
                    </div>

                    <div className="flex justify-end space-x-3">
                        <button
                            type="button"
                            onClick={onClose}
                            className={`px-4 py-2 rounded-md transition-colors ${isDarkMode
                                    ? 'bg-gray-700 hover:bg-gray-600 text-white'
                                    : 'bg-gray-200 hover:bg-gray-300 text-gray-700'
                                }`}
                            disabled={isLoading}
                        >
                            Cancel
                        </button>
                        <button
                            type="submit"
                            className={`px-4 py-2 rounded-md transition-colors text-white ${isDarkMode
                                    ? 'bg-blue-600 hover:bg-blue-700'
                                    : 'bg-blue-500 hover:bg-blue-600'
                                } ${isLoading ? 'opacity-70 cursor-not-allowed' : ''}`}
                            disabled={isLoading || (isCreatingNew && !newFolder.trim())}
                        >
                            {isLoading ? 'Moving...' : 'Move'}
                        </button>
                    </div>
                </form>
            </div>
        </div>
    );
};

export default MoveToFolderModal; 