import React, { useState, useEffect, useMemo, useCallback, memo } from 'react';
import { FiSearch, FiMessageSquare, FiClock, FiCalendar, FiTrash2, FiXCircle, FiExternalLink } from 'react-icons/fi';
import { IoEllipse } from 'react-icons/io5';
import { useNavigate } from 'react-router-dom';
import { useTheme } from '../../context/ThemeContext';

// Mock data moved outside component to prevent recreation on each render
const mockConversations = [
    {
        id: 'conv1',
        gptId: 'gpt1',
        gptName: 'Customer Support Assistant',
        lastMessage: 'How can I request a refund for my recent purchase?',
        timestamp: new Date(Date.now() - 2 * 60 * 60 * 1000), // 2 hours ago
        messageCount: 12,
        model: 'GPT-4',
        summary: 'Discussion about refund policies and procedures'
    },
    {
        id: 'conv2',
        gptId: 'gpt2',
        gptName: 'Product Recommendation Agent',
        lastMessage: 'I need a new laptop for video editing under $1500',
        timestamp: new Date(Date.now() - 2 * 24 * 60 * 60 * 1000), // 2 days ago
        messageCount: 8,
        model: 'GPT-3.5',
        summary: 'Recommendations for video editing laptops'
    },
    {
        id: 'conv3',
        gptId: 'gpt3',
        gptName: 'Content Writing Assistant',
        lastMessage: 'Can you help me write a blog post about artificial intelligence?',
        timestamp: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000), // 1 week ago
        messageCount: 15,
        model: 'GPT-4',
        summary: 'Creating a blog post about AI advancements'
    },
    {
        id: 'conv4',
        gptId: 'gpt4',
        gptName: 'Travel Planning Assistant',
        lastMessage: 'I want to plan a 2-week trip to Japan in the spring',
        timestamp: new Date(Date.now() - 14 * 24 * 60 * 60 * 1000), // 2 weeks ago
        messageCount: 22,
        model: 'GPT-4',
        summary: 'Planning a comprehensive trip to Japan'
    },
    {
        id: 'conv5',
        gptId: 'gpt5',
        gptName: 'Health & Fitness Coach',
        lastMessage: 'What exercises are best for improving core strength?',
        timestamp: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000), // 1 month ago
        messageCount: 7,
        model: 'GPT-3.5',
        summary: 'Discussion about core strength exercises'
    }
];

// Memoized Conversation Item Component
const ConversationItem = memo(({ conv, formatTimestamp, onContinue, onDelete, isDarkMode }) => (
    <div 
        className={`p-4 rounded-lg border mb-3 cursor-pointer transition-all group ${
            isDarkMode 
                ? 'bg-gray-800/50 border-gray-700 hover:bg-gray-700/70 hover:border-gray-600' 
                : 'bg-white border-gray-200 hover:bg-gray-50 hover:border-gray-300'
        }`}
        onClick={() => onContinue(conv)}
    >
        <div className="flex items-center justify-between mb-2">
            <h3 className={`font-semibold truncate mr-4 group-hover:text-blue-600 dark:group-hover:text-blue-400 transition-colors ${isDarkMode ? 'text-white' : 'text-gray-800'}`}>{conv.gptName}</h3>
            <span className={`text-xs flex-shrink-0 ${isDarkMode ? 'text-gray-400' : 'text-gray-500'}`}>
                {formatTimestamp(conv.timestamp)}
            </span>
        </div>
        <p className={`text-sm line-clamp-2 mb-3 ${isDarkMode ? 'text-gray-300' : 'text-gray-600'}`}>
            <span className={isDarkMode ? 'text-gray-500' : 'text-gray-400'}>Last:</span> {conv.lastMessage}
        </p>
        <div className="flex items-center justify-between text-xs">
            <div className="flex items-center gap-3">
                <span className={`flex items-center gap-1 ${isDarkMode ? 'text-gray-400' : 'text-gray-500'}`}>
                    <FiMessageSquare size={13}/> {conv.messageCount} msgs
                </span>
                <span className={`px-1.5 py-0.5 rounded flex items-center gap-1 ${isDarkMode ? 'bg-gray-700 text-gray-200' : 'bg-gray-100 text-gray-600'}`}>
                    {conv.model}
                </span>
            </div>
            <button 
                onClick={(e) => onDelete(conv, e)}
                className={`p-1 rounded-full opacity-0 group-hover:opacity-100 focus:opacity-100 transition-opacity ${
                    isDarkMode 
                        ? 'text-red-400 hover:bg-red-900/30' 
                        : 'text-red-500 hover:bg-red-100'
                }`}
                title="Delete conversation"
            >
                <FiTrash2 size={16} />
            </button>
        </div>
        <FiExternalLink className={`absolute top-3 right-3 opacity-0 group-hover:opacity-50 transition-opacity ${isDarkMode ? 'text-gray-500' : 'text-gray-400'}`} size={14}/>
    </div>
));

const HistoryPage = () => {
    const [conversations, setConversations] = useState([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);
    const [searchTerm, setSearchTerm] = useState('');
    const [filterPeriod, setFilterPeriod] = useState('all');
    const [showDeleteConfirm, setShowDeleteConfirm] = useState(false);
    const [selectedConversation, setSelectedConversation] = useState(null);
    const navigate = useNavigate();
    const { isDarkMode } = useTheme();
    
    useEffect(() => {
        const fetchConversationHistory = async () => {
            try {
                setLoading(true);
                setError(null);
                await new Promise(resolve => setTimeout(resolve, 500)); 
                setConversations(mockConversations);
            } catch (error) {
                console.error("Error fetching conversation history:", error);
                setError("Failed to load your conversation history");
            } finally {
                setLoading(false);
            }
        };
        
        fetchConversationHistory();
    }, []);
    
    const filteredConversations = useMemo(() => {
        let filtered = [...conversations];
        
        if (searchTerm) {
            const lowerSearchTerm = searchTerm.toLowerCase();
            filtered = filtered.filter(conv => 
                conv.gptName.toLowerCase().includes(lowerSearchTerm) ||
                conv.lastMessage.toLowerCase().includes(lowerSearchTerm) ||
                (conv.summary && conv.summary.toLowerCase().includes(lowerSearchTerm))
            );
        }
        
        if (filterPeriod !== 'all') {
            const now = new Date();
            let cutoffDate;
            switch (filterPeriod) {
                case 'today': cutoffDate = new Date(now.getFullYear(), now.getMonth(), now.getDate()); break;
                case 'week': {
                    const startOfToday = new Date(now.getFullYear(), now.getMonth(), now.getDate());
                    cutoffDate = new Date(startOfToday.setDate(startOfToday.getDate() - 7));
                    break;
                }
                case 'month': {
                    const startOfToday = new Date(now.getFullYear(), now.getMonth(), now.getDate());
                    cutoffDate = new Date(startOfToday.setMonth(startOfToday.getMonth() - 1));
                    break;
                }
                default: cutoffDate = null;
            }
            if (cutoffDate) {
                filtered = filtered.filter(conv => new Date(conv.timestamp) >= cutoffDate);
            }
        }
        
        return filtered.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
    }, [conversations, searchTerm, filterPeriod]);
    
    const formatTimestamp = useCallback((timestamp) => {
        try {
            const date = new Date(timestamp);
            if (isNaN(date)) return 'Invalid Date';
            const now = new Date();
            const diffMs = now - date;
            const diffDays = Math.floor(diffMs / (1000 * 60 * 60 * 24));
            
            if (diffDays === 0) return date.toLocaleTimeString([], { hour: 'numeric', minute: '2-digit', hour12: true }).toLowerCase();
            if (diffDays === 1) return 'Yesterday';
            if (diffDays < 7) return `${diffDays} days ago`;
            return date.toLocaleDateString([], { month: 'short', day: 'numeric' });
        } catch (e) {
            console.error("Error formatting timestamp:", timestamp, e);
            return 'Unknown Date';
        }
    }, []);
    
    const handleContinueConversation = useCallback((conv) => {
        navigate(`/user/chat?gptId=${conv.gptId}`);
    }, [navigate]);
    
    const confirmDeleteConversation = useCallback((conv, e) => {
        e.stopPropagation();
        setSelectedConversation(conv);
        setShowDeleteConfirm(true);
    }, []);
    
    const handleDeleteConversation = useCallback(() => {
        if (!selectedConversation) return;
        setConversations(prev => prev.filter(c => c.id !== selectedConversation.id));
        setShowDeleteConfirm(false);
        setSelectedConversation(null);
    }, [selectedConversation]);
    
    const cancelDelete = useCallback(() => {
        setShowDeleteConfirm(false);
        setSelectedConversation(null);
    }, []);
    
    const handleSearchChange = useCallback((e) => setSearchTerm(e.target.value), []);
    const handleFilterChange = useCallback((e) => setFilterPeriod(e.target.value), []);

    const handleRetry = useCallback(() => {
        setLoading(true);
        setError(null);
        setTimeout(() => {
            setConversations(mockConversations);
            setLoading(false);
        }, 500);
    }, []);

    if (loading && conversations.length === 0 && !error) {
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
            <div className="mb-5 flex-shrink-0 text-center md:text-left">
                <h1 className="text-xl sm:text-2xl font-bold">Conversation History</h1>
                <p className={`text-sm mt-1 ${isDarkMode ? 'text-gray-400' : 'text-gray-600'}`}>
                    View and continue your previous conversations
                </p>
            </div>
            
            <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between mb-6 gap-4 flex-shrink-0">
                <div className="relative w-full sm:w-auto sm:flex-1 max-w-lg">
                    <FiSearch className={`absolute left-3 top-1/2 transform -translate-y-1/2 ${isDarkMode ? 'text-gray-400' : 'text-gray-500'}`} size={18} />
                    <input
                        type="text"
                        placeholder="Search conversations (name, message, summary)..."
                        value={searchTerm}
                        onChange={handleSearchChange}
                        className={`w-full pl-10 pr-4 py-2.5 rounded-lg border focus:ring-2 focus:ring-blue-500 focus:border-blue-500 transition-all text-sm sm:text-base ${
                            isDarkMode 
                                ? 'bg-gray-700 border-gray-600 text-white placeholder-gray-400' 
                                : 'bg-white border-gray-300 text-gray-900 placeholder-gray-500'
                        }`}
                    />
                </div>
                
                <div className="flex items-center gap-2 self-end sm:self-center">
                    <FiCalendar className={isDarkMode ? 'text-gray-400' : 'text-gray-500'} size={16} />
                    <select
                        value={filterPeriod}
                        onChange={handleFilterChange}
                        className={`border rounded-lg py-1.5 px-3 focus:ring-1 focus:ring-blue-500 focus:border-blue-500 outline-none transition-colors text-sm appearance-none pr-8 ${
                            isDarkMode 
                                ? 'bg-gray-700 border-gray-600 text-white' 
                                : 'bg-white border-gray-300 text-gray-900'
                        }`}
                        style={{ backgroundImage: `url('data:image/svg+xml;utf8,<svg fill="${isDarkMode ? 'white' : 'black'}" height="20" viewBox="0 0 20 20" width="20" xmlns="http://www.w3.org/2000/svg"><path d="M7 10l5 5 5-5z"/><path d="M0 0h24v24H0z" fill="none"/></svg>')`, backgroundRepeat: 'no-repeat', backgroundPosition: 'right 0.5rem center', backgroundSize: '1em 1em' }}
                    >
                        <option value="all">All Time</option>
                        <option value="today">Today</option>
                        <option value="week">This Week</option>
                        <option value="month">This Month</option>
                    </select>
                </div>
            </div>
            
            <div className="flex-1 overflow-y-auto no-scrollbar pb-4">
                {loading ? (
                    <div className="space-y-3 animate-pulse">
                        {[...Array(4)].map((_, i) => (
                            <div key={i} className={`p-4 rounded-lg border ${isDarkMode ? 'bg-gray-800/50 border-gray-700' : 'bg-white border-gray-200'}`}>
                                <div className="flex items-center justify-between mb-2">
                                    <div className={`h-4 rounded w-1/3 ${isDarkMode ? 'bg-gray-700' : 'bg-gray-300'}`}></div>
                                    <div className={`h-3 rounded w-1/4 ${isDarkMode ? 'bg-gray-700' : 'bg-gray-300'}`}></div>
                                </div>
                                <div className={`h-3 rounded w-full mb-3 ${isDarkMode ? 'bg-gray-700' : 'bg-gray-300'}`}></div>
                                <div className="flex items-center justify-between text-xs">
                                    <div className="flex items-center gap-3">
                                        <div className={`h-3 rounded w-16 ${isDarkMode ? 'bg-gray-700' : 'bg-gray-300'}`}></div>
                                        <div className={`h-4 px-4 py-0.5 rounded ${isDarkMode ? 'bg-gray-700' : 'bg-gray-200'}`}></div>
                                    </div>
                                    <div className={`h-6 w-6 rounded-full ${isDarkMode ? 'bg-gray-700' : 'bg-gray-200'}`}></div>
                                </div>
                            </div>
                        ))}
                    </div>
                ) : error ? (
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
                ) : filteredConversations.length === 0 ? (
                    <div className={`flex flex-col items-center justify-center h-full text-center py-12 ${isDarkMode ? 'text-gray-400' : 'text-gray-500'}`}>
                        <FiClock size={40} className={`mb-4 opacity-50 ${isDarkMode ? 'text-gray-600' : 'text-gray-400'}`} />
                        <p className="text-lg mb-2">
                            {searchTerm || filterPeriod !== 'all' ? `No conversations matching criteria` : "No conversation history yet"}
                        </p>
                        <p className="text-sm max-w-md">
                            {searchTerm || filterPeriod !== 'all'
                                ? "Try adjusting your search or time filter." 
                                : "Start chatting with GPTs to build your history."}
                        </p>
                        
                        {!searchTerm && filterPeriod === 'all' && (
                            <button 
                                onClick={() => navigate('/user/collections')}
                                className={`mt-6 px-4 py-2 rounded-lg transition-colors text-white ${
                                    isDarkMode ? 'bg-blue-600 hover:bg-blue-700' : 'bg-blue-500 hover:bg-blue-600'
                                }`}
                            >
                                Browse Collections
                            </button>
                        )}
                    </div>
                ) : (
                    <div className="space-y-3">
                        {filteredConversations.map((conv) => (
                            <ConversationItem 
                                key={conv.id} 
                                conv={conv} 
                                formatTimestamp={formatTimestamp} 
                                onContinue={handleContinueConversation} 
                                onDelete={confirmDeleteConversation}
                                isDarkMode={isDarkMode}
                            />
                        ))}
                    </div>
                )}
            </div>

            {showDeleteConfirm && selectedConversation && (
                <div className="fixed inset-0 bg-black/60 dark:bg-black/80 flex items-center justify-center z-50 p-4">
                    <div className={`p-6 rounded-lg shadow-xl w-full max-w-sm border ${
                        isDarkMode ? 'bg-gray-800 border-gray-700' : 'bg-white border-gray-200'
                    }`}>
                        <h3 className={`text-lg font-semibold mb-2 ${isDarkMode ? 'text-white' : 'text-gray-900'}`}>Delete Conversation?</h3>
                        <p className={`text-sm mb-5 ${isDarkMode ? 'text-gray-300' : 'text-gray-600'}`}>
                            Are you sure you want to delete the conversation with "{selectedConversation.gptName}"? This action cannot be undone.
                        </p>
                        <div className="flex justify-end gap-3">
                            <button 
                                onClick={cancelDelete} 
                                className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
                                    isDarkMode 
                                        ? 'bg-gray-600 hover:bg-gray-500 text-white' 
                                        : 'bg-gray-100 hover:bg-gray-200 text-gray-700 border border-gray-300'
                                }`}
                            >
                                Cancel
                            </button>
                            <button 
                                onClick={handleDeleteConversation} 
                                className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors bg-red-600 hover:bg-red-700 text-white`}
                            >
                                Delete
                            </button>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
};

export default HistoryPage; 