import React, { useState, useEffect, useRef, useCallback, useMemo, memo } from 'react';
import axios from 'axios';
import { FiEdit, FiTrash2, FiSearch, FiChevronDown, FiChevronUp, FiPlus, FiInfo, FiFolder, FiFolderPlus } from 'react-icons/fi';
import { SiOpenai, SiGooglegemini } from 'react-icons/si';
import { FaRobot } from 'react-icons/fa6';
import { BiLogoMeta } from 'react-icons/bi';
import { RiOpenaiFill } from 'react-icons/ri';
import { useNavigate } from 'react-router-dom';
import { axiosInstance } from '../../api/axiosInstance';
import { useTheme } from '../../context/ThemeContext';
import { toast } from 'react-toastify';
import MoveToFolderModal from './MoveToFolderModal';

// Model icons mapping
const modelIcons = {
    'gpt-4': <RiOpenaiFill className="text-green-500" size={18} />,
    'gpt-3.5': <SiOpenai className="text-green-400" size={16} />,
    'claude': <FaRobot className="text-purple-400" size={16} />,
    'gemini': <SiGooglegemini className="text-blue-400" size={16} />,
    'llama': <BiLogoMeta className="text-blue-500" size={18} />
};

// Memoized GPT card component
const GptCard = memo(({ gpt, onDelete, onEdit, formatDate, onNavigate, isDarkMode, onMoveToFolder }) => (
    <div
        key={gpt._id}
        className="bg-white dark:bg-gray-800 rounded-lg overflow-hidden border border-gray-200 dark:border-gray-700 hover:border-blue-400/50 dark:hover:border-gray-600 transition-all shadow-md hover:shadow-lg flex flex-col cursor-pointer group"
        onClick={() => onNavigate(`/admin/chat/${gpt._id}`)}
    >
        <div className="h-24 sm:h-32 bg-gradient-to-br from-gray-100 to-gray-300 dark:from-gray-700 dark:to-gray-900 relative flex-shrink-0 overflow-hidden">
            {gpt.imageUrl ? (
                <img
                    src={gpt.imageUrl}
                    alt={gpt.name}
                    className="w-full h-full object-cover opacity-80 dark:opacity-70 group-hover:scale-105 transition-transform duration-300"
                    loading="lazy"
                />
            ) : (
                <div className="w-full h-full flex items-center justify-center bg-gradient-to-br from-blue-50/50 to-purple-100/50 dark:from-blue-900/30 dark:to-purple-900/30">
                    <span className={`text-3xl sm:text-4xl ${isDarkMode ? 'text-white/30' : 'text-gray-500/40'}`}>{gpt.name.charAt(0)}</span>
                </div>
            )}

            <div className="absolute top-2 right-2 flex gap-1.5 opacity-0 group-hover:opacity-100 transition-opacity duration-200">
                <button
                    onClick={(e) => { e.stopPropagation(); onMoveToFolder(gpt); }}
                    className="p-1.5 sm:p-2 bg-white/80 dark:bg-gray-900/70 text-gray-700 dark:text-gray-200 rounded-full hover:bg-green-500 hover:text-white dark:hover:bg-green-700/80 transition-colors shadow"
                    title="Move to Folder"
                >
                    <FiFolderPlus size={14} />
                </button>
                <button
                    onClick={(e) => { e.stopPropagation(); onEdit(gpt._id); }}
                    className="p-1.5 sm:p-2 bg-white/80 dark:bg-gray-900/70 text-gray-700 dark:text-gray-200 rounded-full hover:bg-blue-500 hover:text-white dark:hover:bg-blue-700/80 transition-colors shadow"
                    title="Edit GPT"
                >
                    <FiEdit size={14} />
                </button>
                <button
                    onClick={(e) => { e.stopPropagation(); onDelete(gpt._id); }}
                    className="p-1.5 sm:p-2 bg-white/80 dark:bg-gray-900/70 text-gray-700 dark:text-gray-200 rounded-full hover:bg-red-500 hover:text-white dark:hover:bg-red-700/80 transition-colors shadow"
                    title="Delete GPT"
                >
                    <FiTrash2 size={14} />
                </button>
            </div>
        </div>

        <div className="p-3 sm:p-4 flex flex-col flex-grow">
            <div className="flex items-start justify-between mb-1.5 sm:mb-2">
                <h3 className="font-semibold text-base sm:text-lg line-clamp-1 text-gray-900 dark:text-white">{gpt.name}</h3>
                <div className="flex items-center flex-shrink-0 gap-1 bg-gray-100 dark:bg-gray-700 px-1.5 sm:px-2 py-0.5 rounded text-[10px] sm:text-xs text-gray-600 dark:text-gray-300">
                    {React.cloneElement(modelIcons[gpt.model] || <FaRobot className="text-gray-500" />, { size: 12 })}
                    <span className="hidden sm:inline">{gpt.model}</span>
                </div>
            </div>

            <p className="text-gray-600 dark:text-gray-300 text-xs sm:text-sm h-10 sm:h-12 line-clamp-2 sm:line-clamp-3 mb-3">{gpt.description}</p>
            <div className="mt-auto pt-2 border-t border-gray-100 dark:border-gray-700 text-[10px] sm:text-xs text-gray-500 dark:text-gray-400 flex justify-between items-center">
                <span>Created: {formatDate(gpt.createdAt)}</span>
                {gpt.knowledgeFiles?.length > 0 && (
                    <span className="whitespace-nowrap">{gpt.knowledgeFiles.length} {gpt.knowledgeFiles.length === 1 ? 'file' : 'files'}</span>
                )}
            </div>
            {gpt.folder && (
                <div className="flex items-center gap-1 text-xs text-gray-500 dark:text-gray-400 mb-1.5">
                    <FiFolder size={12} />
                    <span>{gpt.folder}</span>
                </div>
            )}
        </div>
    </div>
));

const CollectionsPage = () => {
    const [customGpts, setCustomGpts] = useState([]);
    const [folders, setFolders] = useState(['All', 'Uncategorized']); // Default folders
    const [selectedFolder, setSelectedFolder] = useState('All');
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);
    const [searchTerm, setSearchTerm] = useState('');
    const [sortOption, setSortOption] = useState('newest');
    const [showSortOptions, setShowSortOptions] = useState(false);
    const sortDropdownRef = useRef(null);
    const { isDarkMode } = useTheme();
    const navigate = useNavigate();
    const [showMoveModal, setShowMoveModal] = useState(false);
    const [gptToMove, setGptToMove] = useState(null);

    const fetchCustomGpts = useCallback(async () => {
        try {
            setLoading(true);
            setError(null);
            const response = await axiosInstance.get(`/api/custom-gpts`, { withCredentials: true });

            if (response.data.success && response.data.customGpts) {
                setCustomGpts(response.data.customGpts);
                // Extract unique folders from GPTs
                const uniqueFolders = [...new Set(response.data.customGpts
                    .filter(gpt => gpt.folder)
                    .map(gpt => gpt.folder))];
                setFolders(prev => [...new Set(['All', 'Uncategorized', ...uniqueFolders])]);
            } else {
                const message = response.data.message || "Failed to fetch custom GPTs";
                setError(message);
                toast.error(message);
            }
        } catch (err) {
            console.error("Error fetching custom GPTs:", err);
            const message = err.response?.data?.message || "Error connecting to server";
            setError(message);
            toast.error(message);
        } finally {
            setLoading(false);
        }
    }, []);

    useEffect(() => {
        fetchCustomGpts();
    }, [fetchCustomGpts]);

    const handleClickOutside = useCallback((event) => {
        if (sortDropdownRef.current && !sortDropdownRef.current.contains(event.target)) {
            setShowSortOptions(false);
        }
    }, []);

    useEffect(() => {
        document.addEventListener("mousedown", handleClickOutside);
        return () => document.removeEventListener("mousedown", handleClickOutside);
    }, [handleClickOutside]);

    const handleDelete = useCallback(async (id) => {
        if (window.confirm("Are you sure you want to delete this GPT?")) {
            setLoading(true);
            try {
                const response = await axiosInstance.delete(`/api/custom-gpts/${id}`, { withCredentials: true });
                if (response.data.success) {
                    toast.success(`GPT deleted successfully.`);
                    fetchCustomGpts();
                } else {
                    toast.error(response.data.message || "Failed to delete GPT");
                }
            } catch (err) {
                console.error("Error deleting custom GPT:", err);
                toast.error(err.response?.data?.message || "Error deleting GPT");
            } finally {
                setLoading(false);
            }
        }
    }, [fetchCustomGpts]);

    const handleEdit = useCallback((id) => {
        navigate(`/admin/edit-gpt/${id}`);
    }, [navigate]);

    const handleCreateNew = useCallback(() => {
        navigate('/admin/create-gpt');
    }, [navigate]);

    const handleNavigate = useCallback((path) => {
        navigate(path);
    }, [navigate]);

    const formatDate = useCallback((dateString) => {
        return new Date(dateString).toLocaleDateString('en-US', {
            year: 'numeric',
            month: 'short',
            day: 'numeric'
        });
    }, []);

    const handleSearchChange = useCallback((e) => {
        setSearchTerm(e.target.value);
    }, []);

    const toggleSortOptions = useCallback(() => {
        setShowSortOptions(prev => !prev);
    }, []);

    const handleSortOptionSelect = useCallback((option) => {
        setSortOption(option);
        setShowSortOptions(false);
    }, []);

    // Function to open the move modal
    const handleMoveToFolder = useCallback((gpt) => {
        setGptToMove(gpt);
        setShowMoveModal(true);
    }, []);

    // Function called when a GPT is successfully moved
    const handleGptMoved = useCallback((movedGpt, newFolderName) => {
        // Update the local state
        setCustomGpts(prevGpts =>
            prevGpts.map(gpt =>
                gpt._id === movedGpt._id ? { ...gpt, folder: newFolderName || null } : gpt
            )
        );
        // Add the new folder to the list if it's not already there
        if (newFolderName && !folders.includes(newFolderName)) {
            setFolders(prevFolders => [...prevFolders, newFolderName]);
        }

        setShowMoveModal(false);
        setGptToMove(null);
        toast.success(`GPT "${movedGpt.name}" moved successfully.`);
    }, [folders]); // Include folders in dependency array


    const filteredGpts = useMemo(() => {
        return customGpts
            .filter(gpt => {
                if (!gpt || !gpt.name || !gpt.description || !gpt.model) return false;

                // Folder filtering
                if (selectedFolder === 'All') return true;
                if (selectedFolder === 'Uncategorized') return !gpt.folder;
                return gpt.folder === selectedFolder;
            })
            .filter(gpt => {
                if (!searchTerm) return true;
                const searchLower = searchTerm.toLowerCase();
                return (
                    gpt.name.toLowerCase().includes(searchLower) ||
                    gpt.description.toLowerCase().includes(searchLower) ||
                    gpt.model.toLowerCase().includes(searchLower)
                );
            })
            .sort((a, b) => {
                const dateA = a.createdAt ? new Date(a.createdAt) : 0;
                const dateB = b.createdAt ? new Date(b.createdAt) : 0;
                const nameA = a.name || '';
                const nameB = b.name || '';

                switch (sortOption) {
                    case 'newest': return dateB - dateA;
                    case 'oldest': return dateA - dateB;
                    case 'alphabetical': return nameA.localeCompare(nameB);
                    default: return dateB - dateA;
                }
            });
    }, [customGpts, searchTerm, sortOption, selectedFolder]);

    if (loading && customGpts.length === 0) {
        return (
            <div className="flex items-center justify-center h-full bg-white dark:bg-black text-gray-600 dark:text-gray-400">
                <div className="animate-spin rounded-full h-10 w-10 border-t-2 border-b-2 border-blue-500"></div>
            </div>
        );
    }

    if (error && customGpts.length === 0) {
        return (
            <div className="flex flex-col items-center justify-center h-full bg-white dark:bg-black text-gray-600 dark:text-gray-400 p-6">
                <FiInfo size={40} className="mb-4 text-red-500" />
                <h2 className="text-xl font-semibold mb-2 text-gray-800 dark:text-gray-200">Loading Failed</h2>
                <p className="text-center mb-4">{error}</p>
                <button
                    onClick={fetchCustomGpts}
                    className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors"
                >
                    Retry
                </button>
            </div>
        );
    }

    return (
        <div className="flex flex-col h-full bg-gray-50 dark:bg-black text-black dark:text-white p-4 sm:p-6 overflow-hidden">
            {/* Header */}
            <div className="mb-4 md:mb-6 flex-shrink-0 text-center sm:text-left ">
                <h1 className="text-xl sm:text-2xl font-bold text-gray-900 dark:text-white">Collections</h1>
                <p className="text-sm text-gray-500 dark:text-gray-400 mt-1">Manage your custom GPTs</p>
            </div>

            {/* Controls: Folder, Search, Sort, Create */}
            <div className="flex flex-col md:flex-row md:items-center justify-between mb-4 md:mb-6 gap-3 md:gap-4 flex-shrink-0">
                <div className="flex flex-col sm:flex-row sm:items-center gap-3 w-full md:w-auto">
                    {/* Folder Dropdown */}
                    <div className="relative">
                        <select
                            value={selectedFolder}
                            onChange={(e) => setSelectedFolder(e.target.value)}
                            className="w-full sm:w-36 px-3 py-2 rounded-lg bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-700 text-gray-700 dark:text-gray-300 text-sm hover:bg-gray-50 dark:hover:bg-gray-700 appearance-none cursor-pointer"
                            aria-label="Select Folder"
                        >
                            {folders.map(folder => (
                                <option key={folder} value={folder}>
                                    {folder}
                                </option>
                            ))}
                        </select>
                        <FiFolder className="absolute right-3 top-1/2 transform -translate-y-1/2 text-gray-400 dark:text-gray-500 pointer-events-none" />
                    </div>

                    {/* Search Input */}
                    <div className="relative flex-grow sm:flex-grow-0">
                        <FiSearch className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400 dark:text-gray-500" />
                        <input
                            type="text"
                            placeholder="Search GPTs..."
                            value={searchTerm}
                            onChange={handleSearchChange}
                            className="w-full sm:w-52 md:w-64 pl-10 pr-4 py-2 rounded-lg bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-700 focus:ring-2 focus:ring-blue-500 focus:border-transparent outline-none transition-all text-sm text-black dark:text-white placeholder-gray-500 dark:placeholder-gray-400"
                            aria-label="Search GPTs"
                        />
                    </div>

                    {/* Sort Dropdown */}
                    <div className="relative" ref={sortDropdownRef}>
                        <button
                            onClick={toggleSortOptions}
                            className="flex items-center justify-between w-full sm:w-36 px-3 py-2 rounded-lg bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-700 text-gray-700 dark:text-gray-300 text-sm hover:bg-gray-50 dark:hover:bg-gray-700"
                            aria-haspopup="true"
                            aria-expanded={showSortOptions}
                        >
                            <span className="truncate">Sort: {sortOption.charAt(0).toUpperCase() + sortOption.slice(1)}</span>
                            {showSortOptions ? <FiChevronUp size={16} /> : <FiChevronDown size={16} />}
                        </button>
                        {showSortOptions && (
                            <div className="absolute left-0 mt-2 w-36 bg-white dark:bg-gray-800 rounded-md shadow-lg ring-1 ring-black ring-opacity-5 dark:ring-gray-700 z-10 overflow-hidden">
                                {['newest', 'oldest', 'alphabetical'].map((option) => (
                                    <button
                                        key={option}
                                        onClick={() => handleSortOptionSelect(option)}
                                        className={`w-full text-left px-4 py-2 text-sm ${sortOption === option ? 'font-semibold text-white dark:text-blue-400 bg-blue-50 dark:bg-blue-900/30' : 'text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700'}`}
                                    >
                                        {option.charAt(0).toUpperCase() + option.slice(1)}
                                    </button>
                                ))}
                            </div>
                        )}
                    </div>
                </div>

                {/* Create Button */}
                <button
                    onClick={handleCreateNew}
                    className="flex items-center gap-2 px-4 py-2 bg-black dark:bg-white hover:bg-gray-100 dark:hover:bg-gray-700 text-black dark:text- rounded-lg font-medium text-sm transition-colors flex-shrink-0 whitespace-nowrap"
                >
                    <FiPlus size={18} /> Create New GPT
                </button>
            </div>

            {/* GPT Grid */}
            <div className="flex-1 overflow-y-auto pb-4 scrollbar-hide">
                {filteredGpts.length > 0 ? (
                    <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-3 xl:grid-cols-4 gap-4">
                        {filteredGpts.map((gpt) => (
                            <GptCard
                                key={gpt._id}
                                gpt={gpt}
                                onDelete={handleDelete}
                                onEdit={handleEdit}
                                formatDate={formatDate}
                                onNavigate={handleNavigate}
                                isDarkMode={isDarkMode}
                                onMoveToFolder={handleMoveToFolder}
                            />
                        ))}
                    </div>
                ) : (
                    <div className="flex flex-col items-center justify-center h-full text-center text-gray-500 dark:text-gray-400 pt-10">
                        <FaRobot size={48} className="mb-4 text-gray-400 dark:text-gray-500" />
                        <h3 className="text-lg font-semibold text-gray-700 dark:text-gray-300">No GPTs Found</h3>
                        <p className="max-w-xs mt-1">
                            {searchTerm
                                ? `No GPTs match your search "${searchTerm}" in ${selectedFolder === 'All' ? 'any folder' : `the '${selectedFolder}' folder`}.`
                                : `No GPTs found in ${selectedFolder === 'All' ? 'your collections' : `the '${selectedFolder}' folder`}.`}
                        </p>
                        {!searchTerm && selectedFolder === 'All' && (
                            <button
                                onClick={handleCreateNew}
                                className="mt-4 flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg font-medium text-sm transition-colors"
                            >
                                <FiPlus size={18} /> Create Your First GPT
                            </button>
                        )}
                    </div>
                )}
            </div>

            {/* Move to Folder Modal */}
            {showMoveModal && gptToMove && (
                <MoveToFolderModal
                    isOpen={showMoveModal}
                    onClose={() => { setShowMoveModal(false); setGptToMove(null); }}
                    gpt={gptToMove}
                    existingFolders={folders.filter(f => f !== 'All' && f !== 'Uncategorized')}
                    onSuccess={handleGptMoved}
                />
            )}
        </div>
    );
};

export default CollectionsPage;