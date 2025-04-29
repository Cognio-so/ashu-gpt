import React, { useState, useEffect, useRef, useMemo, useCallback, memo } from 'react';
import axios from 'axios';
import { FiSearch, FiMessageSquare, FiChevronDown, FiChevronUp, FiXCircle } from 'react-icons/fi';
import { useNavigate } from 'react-router-dom';
import { axiosInstance } from '../../api/axiosInstance';
import { useTheme } from '../../context/ThemeContext';

// Memoized GPT card component
const GptCard = memo(({ gpt, formatDate, onChatClick, isDarkMode }) => (
  <div 
    key={gpt._id} 
    className={`rounded-lg overflow-hidden border transition-all flex flex-col ${
      isDarkMode 
        ? 'bg-gray-800 border-gray-700 hover:border-gray-600 shadow-lg hover:shadow-xl' 
        : 'bg-white border-gray-200 hover:border-gray-300 shadow-md hover:shadow-lg'
    }`}
  >
    <div className={`h-24 sm:h-32 relative flex-shrink-0 ${
        !gpt.imageUrl && (isDarkMode ? 'bg-gradient-to-br from-gray-700 to-gray-900' : 'bg-gradient-to-br from-gray-100 to-gray-300')
    }`}>
      {gpt.imageUrl ? (
        <img 
          src={gpt.imageUrl} 
          alt={gpt.name} 
          className={`w-full h-full object-cover ${isDarkMode ? 'opacity-70' : 'opacity-90'}`}
          loading="lazy"
        />
      ) : (
        <div className={`w-full h-full flex items-center justify-center ${isDarkMode ? 'bg-gradient-to-br from-blue-900/50 to-purple-900/50' : 'bg-gradient-to-br from-blue-100/50 to-purple-100/50'}`}>
          <span className={`text-3xl sm:text-4xl ${isDarkMode ? 'text-white/30' : 'text-gray-500/50'}`}>{gpt.name.charAt(0)}</span>
        </div>
      )}
    </div>
    
    <div className="p-3 sm:p-4 flex-grow flex flex-col">
      <div className="flex items-start justify-between mb-1.5 sm:mb-2">
        <h3 className={`font-semibold text-base sm:text-lg line-clamp-1 ${isDarkMode ? 'text-white' : 'text-gray-900'}`}>{gpt.name}</h3>
        <div className={`flex items-center flex-shrink-0 gap-1 px-1.5 sm:px-2 py-0.5 rounded text-[10px] sm:text-xs ${
            isDarkMode ? 'bg-gray-700 text-gray-200' : 'bg-gray-200 text-gray-600'
        }`}>
          <span>{gpt.model}</span>
        </div>
      </div>
      
      <p className={`text-xs sm:text-sm line-clamp-2 mb-auto ${isDarkMode ? 'text-gray-300' : 'text-gray-600'}`}>
        {gpt.description || 'No description available.'}
      </p>
      
      <div className={`mt-auto pt-2 border-t text-[10px] sm:text-xs flex justify-between items-center ${
          isDarkMode ? 'border-gray-700 text-gray-400' : 'border-gray-200 text-gray-500'
      }`}>
        <span>Assigned: {formatDate(gpt.assignedAt || new Date())}</span>
        {gpt.capabilities?.webBrowsing && (
          <span className={`whitespace-nowrap px-1.5 py-0.5 rounded-full ${
            isDarkMode ? 'bg-green-900/40 text-green-200' : 'bg-green-100 text-green-700'
          }`}>Web</span>
        )}
      </div>
      
      <button 
        className={`mt-3 w-full py-2 rounded-lg transition-colors text-white text-sm font-medium flex items-center justify-center gap-2 ${
            isDarkMode ? 'bg-blue-600 hover:bg-blue-700' : 'bg-blue-500 hover:bg-blue-600'
        }`}
        onClick={(e) => onChatClick(gpt._id, e)}
      >
        <FiMessageSquare size={16} />
        Chat with GPT
      </button>
    </div>
  </div>
));

const CollectionsPage = () => {
    const [assignedGpts, setAssignedGpts] = useState([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);
    const [searchTerm, setSearchTerm] = useState('');
    const [sortOption, setSortOption] = useState('newest');
    const [showSortOptions, setShowSortOptions] = useState(false);
    const sortDropdownRef = useRef(null);
    const navigate = useNavigate();
    const { isDarkMode } = useTheme();
    
    const fetchAssignedGpts = useCallback(async () => {
        try {
            setLoading(true);
            setError(null);
            const response = await axiosInstance.get(`/api/custom-gpts/user/assigned`, {
                withCredentials: true
            });
            
            if (response.data.success && Array.isArray(response.data.gpts)) {
                setAssignedGpts(response.data.gpts);
            } else {
                console.warn("API response successful but 'gpts' field is not an array or missing:", response.data);
                setAssignedGpts([]);
                setError("No collections found or received unexpected data format.");
            }
        } catch (error) {
            console.error("Error fetching assigned GPTs:", error);
            const errorMsg = error.response?.data?.message || "Failed to load your collections";
            setError(errorMsg);
            setAssignedGpts([]);
        } finally {
            setLoading(false);
        }
    }, []);
    
    useEffect(() => {
        fetchAssignedGpts();
    }, [fetchAssignedGpts]);

    const handleClickOutside = useCallback((event) => {
        if (sortDropdownRef.current && !sortDropdownRef.current.contains(event.target)) {
            setShowSortOptions(false);
        }
    }, []);

    useEffect(() => {
        document.addEventListener("mousedown", handleClickOutside);
        return () => document.removeEventListener("mousedown", handleClickOutside);
    }, [handleClickOutside]);
    
    const filteredGpts = useMemo(() => {
        return assignedGpts
            .filter(gpt => 
                gpt.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
                (gpt.description && gpt.description.toLowerCase().includes(searchTerm.toLowerCase()))
            )
            .sort((a, b) => {
                const dateA = a.assignedAt ? new Date(a.assignedAt) : new Date(0); 
                const dateB = b.assignedAt ? new Date(b.assignedAt) : new Date(0);

                switch (sortOption) {
                    case 'newest': return dateB - dateA;
                    case 'oldest': return dateA - dateB;
                    case 'alphabetical': return a.name.localeCompare(b.name);
                    default: return dateB - dateA;
                }
            });
    }, [assignedGpts, searchTerm, sortOption]);
    
    const formatDate = useCallback((dateString) => {
        try {
            const date = new Date(dateString);
            if (isNaN(date)) return 'Invalid Date';
            return date.toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' });
        } catch (e) {
            console.error("Error formatting date:", dateString, e);
            return 'Unknown Date';
        }
    }, []);

    const handleChatClick = useCallback(async (gptId, e) => {
        e.stopPropagation();
        
        // Validate gptId
        if (!gptId) {
            console.error("Invalid GPT ID");
            return;
        }
        
        // Find the selected GPT data
        const selectedGpt = assignedGpts.find(gpt => gpt._id === gptId);
        
        // Even if we can't find the GPT data, still allow navigation
        // but log the error for debugging
        if (!selectedGpt) {
            console.warn("GPT not found in collection, navigating anyway");
            navigate(`/user/chat?gptId=${gptId}`);
            return;
        }
        
        try {
            // Notify backend that this GPT is being opened (pre-load)
            const backendUrl = import.meta.env.VITE_PYTHON_API_URL || 'http://localhost:8000';
            
            // Only attempt notification if we have a backend URL
            if (backendUrl) {
                try {
                    const payload = {
                        user_email: "user@example.com", // Fallback email
                        gpt_name: selectedGpt.name || "Unknown GPT",
                        gpt_id: selectedGpt._id,
                        file_urls: selectedGpt.files || [],
                        schema: {
                            model: selectedGpt.model || "gpt-4o-mini"
                        }
                    };
                    
                    // Non-blocking notification
                    fetch(`${backendUrl}/gpt-opened`, {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                        },
                        body: JSON.stringify(payload)
                    }).then(response => {
                        if (response.ok) {
                            console.log("GPT opened notification sent before navigation");
                        } else {
                            console.warn("Backend responded with error, will retry in chat");
                        }
                    }).catch(err => {
                        console.warn("Failed to notify backend about GPT opening, will retry in chat:", err);
                    });
                } catch (notifyErr) {
                    console.warn("Error preparing GPT notification:", notifyErr);
                    // Continue to navigation
                }
            }
        } catch (err) {
            console.error("Error with pre-loading GPT:", err);
            // Continue to navigation
        } finally {
            // Always navigate to the chat page
            navigate(`/user/chat?gptId=${gptId}`);
        }
    }, [navigate, assignedGpts]);
    
    const handleSearchChange = useCallback((e) => setSearchTerm(e.target.value), []);
    const toggleSortOptions = useCallback(() => setShowSortOptions(prev => !prev), []);
    const handleSortOptionSelect = useCallback((option) => {
        setSortOption(option);
        setShowSortOptions(false);
    }, []);
    
    const handleRetry = useCallback(() => fetchAssignedGpts(), [fetchAssignedGpts]);
    
    if (loading && assignedGpts.length === 0 && !error) {
        return (
            <div className={`flex items-center justify-center h-full ${isDarkMode ? 'bg-black text-white' : 'bg-gray-50 text-gray-700'}`}>
                <div className={`animate-spin rounded-full h-10 w-10 border-t-2 border-b-2 ${isDarkMode ? 'border-blue-500' : 'border-blue-600'}`}></div>
            </div>
        );
    }

    return (
        <div className={`flex flex-col h-full p-4 sm:p-6 overflow-hidden transition-colors duration-300 ${
            isDarkMode ? 'bg-black text-white' : 'bg-gray-50 text-gray-900'
        }`}>
            <div className="mb-4 md:mb-6 flex-shrink-0 text-center md:text-left">
                <h1 className="text-xl sm:text-2xl font-bold">Your Collections</h1>
            </div>
            
            <div className="flex flex-col sm:flex-row sm:items-center justify-between mb-4 md:mb-6 gap-4 flex-shrink-0">
                <div className="relative flex-grow sm:flex-grow-0">
                    <FiSearch className={`absolute left-3 top-1/2 transform -translate-y-1/2 ${isDarkMode ? 'text-gray-400' : 'text-gray-500'}`} />
                    <input
                        type="text"
                        placeholder="Search GPTs..."
                        value={searchTerm}
                        onChange={handleSearchChange}
                        className={`w-full sm:w-52 md:w-64 pl-10 pr-4 py-2 rounded-lg border focus:ring-2 focus:ring-blue-500 focus:border-blue-500 transition-all text-sm ${
                            isDarkMode 
                                ? 'bg-gray-700 border-gray-600 text-white placeholder-gray-400' 
                                : 'bg-white border-gray-300 text-gray-900 placeholder-gray-500'
                        }`}
                    />
                </div>
                
                <div className="relative" ref={sortDropdownRef}>
                    <button 
                        onClick={toggleSortOptions}
                        className={`flex items-center justify-between w-full sm:w-36 px-3 py-2 rounded-lg border text-sm transition-colors ${
                            isDarkMode 
                                ? 'bg-gray-700 border-gray-600 text-white hover:bg-gray-600' 
                                : 'bg-white border-gray-300 text-gray-700 hover:bg-gray-50'
                        }`}
                    >
                        <span className="truncate">Sort: {sortOption.charAt(0).toUpperCase() + sortOption.slice(1)}</span>
                        {showSortOptions ? <FiChevronUp size={16}/> : <FiChevronDown size={16}/>}
                    </button>
                    
                    {showSortOptions && (
                        <div className={`absolute z-10 w-full sm:w-36 mt-1 rounded-lg shadow-lg border overflow-hidden text-sm ${
                            isDarkMode 
                                ? 'bg-gray-800 border-gray-700 text-white' 
                                : 'bg-white border-gray-200 text-gray-700'
                        }`}>
                            {['newest', 'oldest', 'alphabetical'].map((optionValue) => (
                                <button 
                                    key={optionValue}
                                    className={`block w-full text-left px-3 py-2 transition-colors ${
                                        sortOption === optionValue 
                                            ? (isDarkMode ? 'bg-blue-600' : 'bg-blue-100 text-blue-700 font-medium') 
                                            : (isDarkMode ? 'hover:bg-gray-700' : 'hover:bg-gray-100')
                                    }`}
                                    onClick={() => handleSortOptionSelect(optionValue)}
                                >
                                    {optionValue.charAt(0).toUpperCase() + optionValue.slice(1)}
                                </button>
                            ))}
                        </div>
                    )}
                </div>
            </div>
            
            <div className="flex-1 overflow-y-auto pb-6 no-scrollbar">
                {error ? (
                    <div className={`flex flex-col items-center justify-center h-full text-center ${isDarkMode ? 'text-red-400' : 'text-red-600'}`}>
                        <FiXCircle size={40} className="mb-4 opacity-70"/>
                        <p className="text-lg mb-4">{error}</p>
                        <button
                            onClick={handleRetry}
                            className={`px-4 py-2 rounded-lg transition-colors text-white ${
                                isDarkMode ? 'bg-blue-600 hover:bg-blue-700' : 'bg-blue-500 hover:bg-blue-600'
                            }`}
                        >
                            Try Again
                        </button>
                    </div>
                ) : filteredGpts.length === 0 ? (
                    <div className={`flex flex-col items-center justify-center h-full text-center ${isDarkMode ? 'text-gray-400' : 'text-gray-500'}`}>
                         <FiMessageSquare size={40} className="mb-4 opacity-50"/>
                        <p className="text-lg mb-2">
                            {searchTerm ? `No collections matching "${searchTerm}"` : "You don't have any collections yet"}
                        </p>
                        <p className="text-sm">
                            Assigned GPTs will appear here.
                        </p>
                    </div>
                ) : (
                    <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-3 xl:grid-cols-4 gap-4 sm:gap-6">
                        {filteredGpts.map(gpt => (
                            <GptCard 
                                key={gpt._id} 
                                gpt={gpt} 
                                formatDate={formatDate} 
                                onChatClick={handleChatClick}
                                isDarkMode={isDarkMode} 
                            />
                        ))}
                    </div>
                )}
            </div>
        </div>
    );
};

export default CollectionsPage; 