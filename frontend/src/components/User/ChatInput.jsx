import React, { useState, useRef, useEffect } from 'react';
import { IoSendSharp } from 'react-icons/io5';
import { HiMiniPaperClip } from 'react-icons/hi2';
import { FiGlobe } from 'react-icons/fi';

const ChatInput = ({ onSubmit, onFileUpload, isLoading, isDarkMode, showWebSearch, webSearchEnabled, setWebSearchEnabled }) => {
    const [inputMessage, setInputMessage] = useState('');
    const textareaRef = useRef(null);
    const fileInputRef = useRef(null);

    // More robust auto-resize textarea
    const resizeTextarea = () => {
        if (textareaRef.current) {
            // Reset height to get accurate scrollHeight
            textareaRef.current.style.height = '0px';
            const scrollHeight = textareaRef.current.scrollHeight;
            // Apply minimum height (40px) and max height (e.g., 120px or 200px)
            const minHeight = 40;
            const maxHeight = window.innerWidth < 640 ? 120 : 200; // Example responsive max-height
            textareaRef.current.style.height = Math.min(maxHeight, Math.max(minHeight, scrollHeight)) + 'px';
        }
    };

    // Auto-resize when input changes
    useEffect(() => {
        resizeTextarea();
    }, [inputMessage]);

    // Also resize on window resize
    useEffect(() => {
        window.addEventListener('resize', resizeTextarea);
        // Initial resize
        resizeTextarea();
        return () => window.removeEventListener('resize', resizeTextarea);
    }, []);

    const handleSubmit = (e) => {
        e.preventDefault();
        if (inputMessage.trim() && !isLoading) { // Don't submit if loading
            onSubmit(inputMessage);
            setInputMessage('');

            // Reset height after clearing input
            setTimeout(() => {
                if (textareaRef.current) {
                    textareaRef.current.style.height = '40px'; // Reset to min-height
                }
            }, 0);
        }
    };

    // Function to handle click on the paperclip icon
    const handleUploadClick = () => {
        fileInputRef.current.click(); // Trigger click on the hidden file input
    };

    // Function to handle file selection
    const handleFileChange = (e) => {
        const files = e.target.files;
        if (files && files.length > 0) {
            if (onFileUpload) {
                onFileUpload(files);
            }
            e.target.value = null;
        }
    };

    // Add this function to toggle web search
    const toggleWebSearch = () => {
        if (setWebSearchEnabled) {
            setWebSearchEnabled(!webSearchEnabled);
        }
    };

    return (
        <div className="w-full">
            <form onSubmit={handleSubmit}>
                <div className={`rounded-2xl sm:rounded-3xl shadow-md ${isDarkMode ? 'bg-[#1e1e1e]' : 'bg-white'
                    }`}>
                    <div className={`flex flex-col px-3 sm:px-4 py-2 sm:py-3 rounded-2xl sm:rounded-3xl border ${isDarkMode ? 'border-gray-700/50' : 'border-gray-200'
                        }`}>
                        <textarea
                            ref={textareaRef}
                            className={`w-full bg-transparent border-0 outline-none resize-none overflow-y-auto min-h-[40px] text-sm sm:text-base no-scrollbar ${isDarkMode ? 'text-white placeholder-gray-500' : 'text-gray-900 placeholder-gray-400'
                                }`}
                            placeholder="Ask anything..."
                            value={inputMessage}
                            onChange={(e) => setInputMessage(e.target.value)}
                            rows={1}
                            onKeyDown={(e) => {
                                if (e.key === 'Enter' && !e.shiftKey) {
                                    e.preventDefault();
                                    handleSubmit(e);
                                }
                            }}
                            disabled={isLoading}
                            style={{ maxHeight: window.innerWidth < 640 ? '120px' : '200px' }}
                        />

                        <div className="flex justify-between items-center mt-1 sm:mt-2">
                            <div className="flex items-center gap-1">
                                <input
                                    type="file"
                                    ref={fileInputRef}
                                    onChange={handleFileChange}
                                    style={{ display: 'none' }}
                                    multiple
                                    disabled={isLoading}
                                />
                                {showWebSearch && (
                                    <button
                                        type="button"
                                        onClick={toggleWebSearch}
                                        className={`rounded-full w-7 h-7 sm:w-8 sm:h-8 flex items-center justify-center transition-colors ${
                                            webSearchEnabled 
                                                ? `${isDarkMode ? 'text-blue-400 bg-blue-900/30' : 'text-blue-500 bg-blue-100'}`
                                                : `${isDarkMode ? 'text-gray-400 hover:bg-gray-700/50' : 'text-gray-500 hover:bg-gray-200'}`
                                        }`}
                                        title={webSearchEnabled ? "Web search enabled" : "Enable web search"}
                                        disabled={isLoading}
                                    >
                                        <FiGlobe size={16} className="sm:text-[18px]" />
                                    </button>
                                )}
                                <button
                                    type="button"
                                    onClick={handleUploadClick}
                                    className={`rounded-full w-7 h-7 sm:w-8 sm:h-8 flex items-center justify-center transition-colors ${isDarkMode
                                            ? 'text-gray-400 hover:bg-gray-700/50'
                                            : 'text-gray-500 hover:bg-gray-200'
                                        }`}
                                    disabled={isLoading}
                                >
                                    <HiMiniPaperClip size={18} className="sm:text-[20px]" />
                                </button>
                            </div>

                            <button
                                type="submit"
                                className={`rounded-full w-7 h-7 sm:w-8 sm:h-8 flex items-center justify-center transition-colors ${isDarkMode
                                        ? 'bg-gray-700 hover:bg-gray-600 text-white'
                                        : 'bg-blue-500 hover:bg-blue-600 text-white'
                                    } disabled:opacity-50 disabled:cursor-not-allowed`}
                                disabled={!inputMessage.trim() || isLoading}
                            >
                                {isLoading ? (
                                    <div className="animate-spin rounded-full h-4 w-4 border-t-2 border-b-2 border-white"></div>
                                ) : (
                                    <IoSendSharp size={16} className="sm:text-[18px]" />
                                )}
                            </button>
                        </div>
                    </div>
                </div>
            </form>
        </div>
    );
};

export default ChatInput; 