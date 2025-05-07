import React, { useState, useEffect, useRef, useMemo, useCallback, memo } from 'react';
import { FiSearch, FiMessageSquare, FiHeart, FiChevronDown, FiChevronUp, FiXCircle, FiFolder, FiPlus } from 'react-icons/fi';
import { useNavigate } from 'react-router-dom';
import { axiosInstance } from '../../api/axiosInstance';
import { useTheme } from '../../context/ThemeContext';
import MoveToFolderModal from './MoveToFolderModal';
import { toast } from 'react-toastify';

// Memoized Favorite Card Component
const FavoriteCard = memo(({ gpt, formatDate, onChatClick, onRemoveFavorite, onMoveToFolder, isDarkMode }) => (
    <div
        key={gpt._id}
        className={`rounded-lg overflow-hidden border transition-all flex flex-col group ${isDarkMode
            ? 'bg-gray-800 border-gray-700 hover:border-gray-600 shadow-lg hover:shadow-xl'
            : 'bg-white border-gray-200 hover:border-gray-300 shadow-md hover:shadow-lg'
            }`}
    >
        <div className={`h-24 sm:h-32 relative flex-shrink-0 ${!gpt.imageUrl && (isDarkMode ? 'bg-gradient-to-br from-gray-700 to-gray-900' : 'bg-gradient-to-br from-gray-100 to-gray-300')
            }`}>
            {gpt.imageUrl ? (
                <img
                    src={gpt.imageUrl}
                    alt={gpt.name}
                    className={`w-full h-full object-cover ${isDarkMode ? 'opacity-70' : 'opacity-90'}`}
                    loading="lazy"
                />
            ) : (
                <div className={`w-full h-full flex items-center justify-center ${isDarkMode ? 'bg-gradient-to-br from-purple-900/50 to-blue-900/50' : 'bg-gradient-to-br from-purple-100/50 to-blue-100/50'}`}>
                    <span className={`text-3xl sm:text-4xl ${isDarkMode ? 'text-white/30' : 'text-gray-500/50'}`}>{gpt.name.charAt(0)}</span>
                </div>
            )}

            <button
                onClick={(e) => { e.stopPropagation(); onRemoveFavorite(gpt._id); }}
                className={`absolute top-2 right-2 p-1.5 rounded-full transition-all ${isDarkMode ? 'bg-black/40 hover:bg-black/60 text-red-500 hover:text-red-400' : 'bg-white/60 hover:bg-white/80 text-red-500 hover:text-red-600'
                    }`}
                title="Remove from favorites"
            >
                <FiHeart size={16} fill="currentColor" />
            </button>

            <button
                onClick={(e) => { e.stopPropagation(); onMoveToFolder(gpt); }}
                className={`absolute top-2 right-10 p-1.5 rounded-full transition-all ${isDarkMode ? 'bg-black/40 hover:bg-black/60 text-gray-400 hover:text-blue-400' : 'bg-white/60 hover:bg-white/80 text-gray-500 hover:text-blue-500'
                    }`}
                title="Move to folder"
            >
                <FiFolder size={16} />
            </button>
        </div>

        <div className="p-3 sm:p-4 flex-grow flex flex-col">
            <div className="flex items-start justify-between mb-1.5 sm:mb-2">
                <h3 className={`font-semibold text-base sm:text-lg line-clamp-1 ${isDarkMode ? 'text-white' : 'text-gray-900'}`}>{gpt.name}</h3>
                <div className={`flex items-center flex-shrink-0 gap-1 px-1.5 sm:px-2 py-0.5 rounded text-[10px] sm:text-xs ${isDarkMode ? 'bg-gray-700 text-gray-200' : 'bg-gray-200 text-gray-600'
                    }`}>
                    <span>{gpt.model || 'N/A'}</span>
                </div>
            </div>

            {gpt.folder && (
                <div className={`flex items-center gap-1 text-xs mb-1.5 ${isDarkMode ? 'text-gray-400' : 'text-gray-500'}`}>
                    <FiFolder size={12} />
                    <span>{gpt.folder}</span>
                </div>
            )}

            <p className={`text-xs sm:text-sm line-clamp-2 flex-grow ${isDarkMode ? 'text-gray-300' : 'text-gray-600'}`}>
                {gpt.description || 'No description available.'}
            </p>

            <div className={`mt-auto pt-2 border-t text-[10px] sm:text-xs flex justify-between items-center ${isDarkMode ? 'border-gray-700 text-gray-400' : 'border-gray-200 text-gray-500'
                }`}>
                <span>Favorited: {formatDate(gpt.createdAt || new Date())}</span>
                {gpt.capabilities?.webBrowsing && (
                    <span className={`whitespace-nowrap px-1.5 py-0.5 rounded-full ${isDarkMode ? 'bg-green-900/40 text-green-200' : 'bg-green-100 text-green-700'
                        }`}>Web</span>
                )}
            </div>

            <button
                className={`mt-3 w-full py-2 rounded-lg transition-colors text-white text-sm font-medium flex items-center justify-center gap-2 ${isDarkMode ? 'bg-blue-600 hover:bg-blue-700' : 'bg-blue-500 hover:bg-blue-600'
                    }`}
                onClick={(e) => { e.stopPropagation(); onChatClick(gpt._id); }}
            >
                <FiMessageSquare size={16} />
                Chat with GPT
            </button>
        </div>
    </div>
));

const FavoritesPage = () => {
    const [favoriteGpts, setFavoriteGpts] = useState([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);
    const [searchTerm, setSearchTerm] = useState('');
    const [sortOption, setSortOption] = useState('newest');
    const [showSortOptions, setShowSortOptions] = useState(false);
    const sortDropdownRef = useRef(null);
    const navigate = useNavigate();
    const { isDarkMode } = useTheme();
    const [showMoveModal, setShowMoveModal] = useState(false);
    const [gptToMove, setGptToMove] = useState(null);
    const [folders, setFolders] = useState(['All']);
    const [selectedFolder, setSelectedFolder] = useState('All');
    const [showFolderOptions, setShowFolderOptions] = useState(false);
    const folderDropdownRef = useRef(null);

    const fetchFavoriteGpts = useCallback(async () => {
        try {
            setLoading(true);
            setError(null);

            const response = await axiosInstance.get('/api/custom-gpts/user/favorites', {
                withCredentials: true
            });

            if (response.data.success && Array.isArray(response.data.gpts)) {
                const fetchedGpts = response.data.gpts;
                setFavoriteGpts(fetchedGpts);

                const uniqueFolders = [...new Set(fetchedGpts
                    .map(gpt => gpt.folder)
                    .filter(folder => folder)
                )];
                setFolders(prev => [...new Set(['All', ...uniqueFolders])]);

            } else {
                console.warn("API response successful but 'gpts' field is not an array or missing:", response.data);
                setFavoriteGpts([]);
                setFolders(['All']);
                setError("No favorites found or received unexpected data format.");
            }
        } catch (error) {
            console.error("Error fetching favorite GPTs:", error);
            const errorMsg = error.response?.data?.message || "Failed to load your favorite GPTs";
            setError(errorMsg);
            setFavoriteGpts([]);
            setFolders(['All']);
        } finally {
            setLoading(false);
        }
    }, []);

    useEffect(() => {
        fetchFavoriteGpts();
    }, [fetchFavoriteGpts]);

    useEffect(() => {
        const handleClickOutside = (event) => {
            if (sortDropdownRef.current && !sortDropdownRef.current.contains(event.target)) {
                setShowSortOptions(false);
            }
            if (folderDropdownRef.current && !folderDropdownRef.current.contains(event.target)) {
                setShowFolderOptions(false);
            }
        };

        document.addEventListener("mousedown", handleClickOutside);
        return () => document.removeEventListener("mousedown", handleClickOutside);
    }, []);

    const filteredGpts = useMemo(() => {
        return favoriteGpts
            .filter(gpt =>
                gpt.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
                (gpt.description && gpt.description.toLowerCase().includes(searchTerm.toLowerCase()))
            )
            .filter(gpt => {
                if (selectedFolder === 'All') return true;
                return gpt.folder === selectedFolder;
            })
            .sort((a, b) => {
                const dateA = a.createdAt ? new Date(a.createdAt) : new Date(0);
                const dateB = b.createdAt ? new Date(b.createdAt) : new Date(0);
                const nameA = a.name || '';
                const nameB = b.name || '';

                switch (sortOption) {
                    case 'newest': return dateB - dateA;
                    case 'oldest': return dateA - dateB;
                    case 'alphabetical': return nameA.localeCompare(nameB);
                    default: return dateB - dateA;
                }
            });
    }, [favoriteGpts, searchTerm, sortOption, selectedFolder]);

    const formatDate = useCallback((dateString) => {
        try {
            const date = new Date(dateString);
            if (isNaN(date.getTime())) return 'Invalid Date';
            return date.toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' });
        } catch (e) {
            console.error("Error formatting date:", dateString, e);
            return 'Unknown Date';
        }
    }, []);

    const handleChatClick = useCallback((gptId) => {
        navigate(`/user/chat?gptId=${gptId}`);
    }, [navigate]);

    const handleRemoveFavorite = useCallback(async (gptId) => {
        const originalFavorites = [...favoriteGpts];
        setFavoriteGpts(prev => prev.filter(gpt => gpt._id !== gptId));

        try {
            await axiosInstance.delete(`/api/custom-gpts/user/favorites/${gptId}`, {
                withCredentials: true
            });
            toast.info("Removed from favorites");
        } catch (error) {
            console.error("Error removing favorite:", error);
            toast.error("Failed to remove favorite");
            setFavoriteGpts(originalFavorites);
        }
    }, [favoriteGpts]);

    const handleSearchChange = useCallback((e) => {
        setSearchTerm(e.target.value);
    }, []);

    const toggleSortOptions = useCallback(() => {
        setShowSortOptions(prev => !prev);
    }, []);

    const selectSortOption = useCallback((option) => {
        setSortOption(option);
        setShowSortOptions(false);
    }, []);

    const handleRetry = useCallback(() => {
        fetchFavoriteGpts();
    }, [fetchFavoriteGpts]);

    const handleMoveToFolder = useCallback((gpt) => {
        setGptToMove(gpt);
        setShowMoveModal(true);
    }, []);

    const handleGptMoved = useCallback((updatedGpt, newFolderName) => {
        setFavoriteGpts(prev => prev.map(gpt =>
            gpt._id === updatedGpt._id
                ? updatedGpt
                : gpt
        ));
        if (newFolderName && !folders.includes(newFolderName)) {
            setFolders(prevFolders => [...new Set([...prevFolders, newFolderName])]);
            setSelectedFolder(newFolderName);
        } else if (updatedGpt.folder && updatedGpt.folder !== selectedFolder) {
            setSelectedFolder(updatedGpt.folder);
        } else if (!updatedGpt.folder && selectedFolder !== 'All') {
            setSelectedFolder('All');
        }

        toast.success(`Moved "${updatedGpt.name}" to ${updatedGpt.folder || 'No Folder'}`);
    }, [folders]);

    if (loading && favoriteGpts.length === 0) {
        return (
            <div className={`flex items-center justify-center h-full ${isDarkMode ? 'bg-black text-white' : 'bg-gray-50 text-gray-700'}`}>
                <div className={`animate-spin rounded-full h-10 w-10 border-t-2 border-b-2 ${isDarkMode ? 'border-blue-500' : 'border-blue-600'}`}></div>
            </div>
        );
    }

    return (
        <div className={`flex flex-col h-full p-4 sm:p-6 overflow-hidden transition-colors duration-300 ${isDarkMode ? 'bg-black text-white' : 'bg-gray-50 text-gray-900'
            }`}>
            <div className="mb-4 md:mb-6 flex-shrink-0 text-center md:text-left">
                <h1 className="text-xl sm:text-2xl font-bold">Your Favorites</h1>
                <p className={`text-sm mt-1 ${isDarkMode ? 'text-gray-400' : 'text-gray-600'}`}>
                    GPTs you've marked as favorites for quick access
                </p>
            </div>

            <div className="flex flex-col sm:flex-row sm:items-center justify-between mb-4 md:mb-6 gap-4 flex-shrink-0">
                <div className="flex flex-col sm:flex-row gap-2 sm:gap-4 flex-grow">
                    <div className="relative flex-grow sm:flex-grow-0">
                        <FiSearch className={`absolute left-3 top-1/2 transform -translate-y-1/2 ${isDarkMode ? 'text-gray-400' : 'text-gray-500'}`} />
                        <input
                            type="text"
                            placeholder="Search favorites..."
                            value={searchTerm}
                            onChange={handleSearchChange}
                            className={`w-full sm:w-52 md:w-64 pl-10 pr-4 py-2 rounded-lg border focus:ring-2 focus:ring-blue-500 focus:border-blue-500 transition-all text-sm ${isDarkMode
                                ? 'bg-gray-700 border-gray-600 text-white placeholder-gray-400'
                                : 'bg-white border-gray-300 text-gray-900 placeholder-gray-500'
                                }`}
                        />
                    </div>

                    <div className="relative" ref={folderDropdownRef}>
                        <button
                            onClick={() => setShowFolderOptions(prev => !prev)}
                            className={`flex items-center justify-between w-full sm:w-40 px-3 py-2 rounded-lg border text-sm transition-colors ${isDarkMode
                                ? 'bg-gray-700 border-gray-600 text-white hover:bg-gray-600'
                                : 'bg-white border-gray-300 text-gray-700 hover:bg-gray-50'
                                }`}
                        >
                            <span className="truncate flex items-center gap-2">
                                <FiFolder size={16} />
                                {selectedFolder}
                            </span>
                            {showFolderOptions ? <FiChevronUp size={16} /> : <FiChevronDown size={16} />}
                        </button>

                        {showFolderOptions && (
                            <div className={`absolute z-10 w-full mt-1 rounded-lg shadow-lg border overflow-hidden text-sm max-h-60 overflow-y-auto ${isDarkMode
                                ? 'bg-gray-800 border-gray-700 text-white'
                                : 'bg-white border-gray-200 text-gray-700'
                                }`}>
                                {folders.map((folder) => (
                                    <button
                                        key={folder}
                                        className={`block w-full text-left px-3 py-2 transition-colors flex items-center gap-2 ${selectedFolder === folder
                                            ? (isDarkMode ? 'bg-blue-600' : 'bg-blue-100 text-blue-700 font-medium')
                                            : (isDarkMode ? 'hover:bg-gray-700' : 'hover:bg-gray-100')
                                            }`}
                                        onClick={() => {
                                            setSelectedFolder(folder);
                                            setShowFolderOptions(false);
                                        }}
                                    >
                                        <FiFolder size={14} />
                                        {folder}
                                    </button>
                                ))}
                            </div>
                        )}
                    </div>
                </div>

                <div className="relative" ref={sortDropdownRef}>
                    <button
                        onClick={toggleSortOptions}
                        className={`flex items-center justify-between w-full sm:w-36 px-3 py-2 rounded-lg border text-sm transition-colors ${isDarkMode
                            ? 'bg-gray-700 border-gray-600 text-white hover:bg-gray-600'
                            : 'bg-white border-gray-300 text-gray-700 hover:bg-gray-50'
                            }`}
                    >
                        <span className="truncate">Sort: {sortOption.charAt(0).toUpperCase() + sortOption.slice(1)}</span>
                        {showSortOptions ? <FiChevronUp size={16} /> : <FiChevronDown size={16} />}
                    </button>

                    {showSortOptions && (
                        <div className={`absolute z-10 w-full sm:w-36 mt-1 rounded-lg shadow-lg border overflow-hidden text-sm ${isDarkMode
                            ? 'bg-gray-800 border-gray-700 text-white'
                            : 'bg-white border-gray-200 text-gray-700'
                            }`}>
                            {['newest', 'oldest', 'alphabetical'].map((optionValue) => (
                                <button
                                    key={optionValue}
                                    className={`block w-full text-left px-3 py-2 transition-colors ${sortOption === optionValue
                                        ? (isDarkMode ? 'bg-blue-600' : 'bg-blue-100 text-blue-700 font-medium')
                                        : (isDarkMode ? 'hover:bg-gray-700' : 'hover:bg-gray-100')
                                        }`}
                                    onClick={() => selectSortOption(optionValue)}
                                >
                                    {optionValue.charAt(0).toUpperCase() + optionValue.slice(1)}
                                </button>
                            ))}
                        </div>
                    )}
                </div>
            </div>

            <div className="flex-1 overflow-y-auto pb-6 custom-scrollbar-dark dark:custom-scrollbar">
                {error ? (
                    <div className={`flex flex-col items-center justify-center h-full text-center ${isDarkMode ? 'text-red-400' : 'text-red-600'}`}>
                        <FiXCircle size={40} className="mb-4 opacity-70" />
                        <p className="text-lg mb-4">{error}</p>
                        <button
                            onClick={handleRetry}
                            className={`px-4 py-2 rounded-lg transition-colors text-white ${isDarkMode ? 'bg-blue-600 hover:bg-blue-700' : 'bg-blue-500 hover:bg-blue-600'
                                }`}
                        >
                            Try Again
                        </button>
                    </div>
                ) : filteredGpts.length === 0 ? (
                    <div className={`flex flex-col items-center justify-center h-full text-center ${isDarkMode ? 'text-gray-400' : 'text-gray-500'}`}>
                        <FiHeart size={40} className={`mb-4 opacity-50 ${isDarkMode ? 'text-gray-600' : 'text-gray-400'}`} />
                        <p className="text-lg mb-2">
                            {searchTerm ? `No favorites matching "${searchTerm}"` : "You don't have any favorite GPTs yet"}
                        </p>
                        <p className="text-sm">
                            {searchTerm ? "Try a different search term." : "Add GPTs to your favorites for quick access."}
                        </p>
                        {!searchTerm && (
                            <button
                                onClick={() => navigate('/user/collections')}
                                className={`mt-6 px-4 py-2 rounded-lg transition-colors text-white ${isDarkMode ? 'bg-blue-600 hover:bg-blue-700' : 'bg-blue-500 hover:bg-blue-600'
                                    }`}
                            >
                                Browse Collections
                            </button>
                        )}
                    </div>
                ) : (
                    <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4 sm:gap-6">
                        {filteredGpts.map((gpt) => (
                            <FavoriteCard
                                key={gpt._id}
                                gpt={gpt}
                                formatDate={formatDate}
                                onChatClick={handleChatClick}
                                onRemoveFavorite={handleRemoveFavorite}
                                onMoveToFolder={handleMoveToFolder}
                                isDarkMode={isDarkMode}
                            />
                        ))}
                    </div>
                )}
            </div>

            {showMoveModal && gptToMove && (
                <MoveToFolderModal
                    isOpen={showMoveModal}
                    onClose={() => { setShowMoveModal(false); setGptToMove(null); }}
                    gpt={gptToMove}
                    existingFolders={folders.filter(f => f !== 'All')}
                    onSuccess={handleGptMoved}
                />
            )}
        </div>
    );
};

export default FavoritesPage; 