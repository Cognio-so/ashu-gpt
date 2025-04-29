import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import ChatInput from './ChatInput';
import { useAuth } from '../../context/AuthContext';
import { useTheme } from '../../context/ThemeContext';
import { IoPersonCircleOutline, IoSettingsOutline, IoPersonOutline, IoMoon, IoSunny } from 'react-icons/io5';
import { useNavigate } from 'react-router-dom';

const UserDashboard = () => {
    const { user, loading } = useAuth();
    const { isDarkMode, toggleTheme } = useTheme();
    const [isProfileOpen, setIsProfileOpen] = useState(false);
    const [userData, setUserData] = useState(null);
    const navigate = useNavigate();
    
    // Use effect to debug and handle user data changes
    useEffect(() => {
        if (user) {
            setUserData(user);
        }
    }, [user, loading]);
    
    const predefinedPrompts = [
        {
            id: 1,
            title: 'Create an Agent',
            prompt: 'I want to create a new AI agent for customer service tasks. What capabilities should I include?'
        },
        {
            id: 2,
            title: 'Configure Agent Settings',
            prompt: 'Help me configure the response patterns and permissions for my marketing assistant agent.'
        },
        {
            id: 3,
            title: 'Agent Performance',
            prompt: 'Can you show me analytics on how my support agents have been performing this month?'
        },
    ]

    const handlePromptClick = (item) => {
        console.log("Prompt clicked:", item.prompt);
        // TODO: Navigate to chat with this prompt
    }

    const handleChatSubmit = (message) => {
        console.log("Message submitted:", message);
        // TODO: Navigate to chat with this message or handle inline chat
    }
    
    const toggleProfile = () => {
        setIsProfileOpen(!isProfileOpen);
    }

    const goToSettings = () => {
        navigate('/user/settings'); // Navigate to settings page
        setIsProfileOpen(false); // Close dropdown
    };

    const handleThemeToggle = () => {
        toggleTheme();
    }

    // For development/testing only
    const mockUser = {
        name: "Test User",
        email: "test@example.com",
        profilePic: null
    };

    return (
        <div className={`flex flex-col items-center justify-center min-h-screen p-3 sm:p-5 md:p-8 w-full relative transition-colors duration-300 ${
            isDarkMode ? 'bg-black text-white' : 'bg-gray-100 text-gray-900'
        }`}>
            
            {/* Container for Top Right Icons */}
            <div className="absolute top-4 right-4 z-20 flex items-center space-x-3">
                {/* Theme Toggle Button */}
                <button 
                    onClick={handleThemeToggle}
                    className={`w-10 h-10 rounded-full flex items-center justify-center transition-colors ${
                        isDarkMode 
                            ? 'bg-gray-800 hover:bg-gray-700 text-white border border-gray-700' 
                            : 'bg-white hover:bg-gray-100 text-gray-800 border border-gray-200 shadow-sm'
                    }`}
                    aria-label={isDarkMode ? "Switch to light mode" : "Switch to dark mode"}
                >
                    {isDarkMode ? (
                        <IoSunny size={20} className="text-amber-300" />
                    ) : (
                        <IoMoon size={20} className="text-blue-600" />
                    )}
                </button>

                {/* Profile Button and Dropdown Area */}
                <div className="relative"> 
                    <button 
                        onClick={toggleProfile}
                        className={`w-10 h-10 rounded-full overflow-hidden border-2 transition-colors ${
                            isDarkMode ? 'border-white/20 hover:border-white/40' : 'border-gray-300 hover:border-gray-500'
                        }`}
                    >
                        {userData?.profilePic ? (
                            <img 
                                src={userData.profilePic} 
                                alt="Profile" 
                                className="w-full h-full object-cover"
                            />
                        ) : (
                            <div className={`w-full h-full flex items-center justify-center ${isDarkMode ? 'bg-gray-700' : 'bg-gray-300'}`}>
                                <IoPersonCircleOutline size={24} className={isDarkMode ? 'text-white' : 'text-gray-600'} />
                            </div>
                        )}
                    </button>
                    
                    {/* Profile Dropdown - positioned relative to the new inner div */}
                    {isProfileOpen && (
                        <div className={`absolute top-12 right-0 w-64 rounded-xl shadow-lg border overflow-hidden z-30 ${
                            isDarkMode ? 'bg-[#1e1e1e] border-white/10' : 'bg-white border-gray-200'
                        }`}>
                            <div className={`p-4 border-b ${isDarkMode ? 'border-white/10' : 'border-gray-200'}`}>
                                <p className={`font-medium ${isDarkMode ? 'text-white' : 'text-gray-900'}`}>
                                    {userData?.name || mockUser.name}
                                </p>
                                <p className={`text-sm truncate ${isDarkMode ? 'text-gray-400' : 'text-gray-500'}`}>
                                    {userData?.email || mockUser.email}
                                </p>
                            </div>
                            <div className="py-1">
                                <button className={`w-full px-4 py-2.5 text-left flex items-center space-x-3 transition-colors ${
                                    isDarkMode ? 'text-gray-300 hover:bg-white/5' : 'text-gray-700 hover:bg-gray-100'
                                }`}>
                                    <IoPersonOutline size={18} />
                                    <span>Profile</span>
                                </button>
                                <button 
                                    onClick={goToSettings} 
                                    className={`w-full px-4 py-2.5 text-left flex items-center space-x-3 transition-colors ${
                                        isDarkMode ? 'text-gray-300 hover:bg-white/5' : 'text-gray-700 hover:bg-gray-100'
                                    }`}
                                >
                                    <IoSettingsOutline size={18} />
                                    <span>Settings</span>
                                </button>
                            </div>
                        </div>
                    )}
                </div> 
            </div>
            
            {/* Rest of the dashboard */}
            <div className='text-center mb-6 sm:mb-8 md:mb-12 mt-16 md:mt-0 px-2'>
                <h1 className={`text-2xl sm:text-3xl md:text-4xl font-bold ${isDarkMode ? 'text-white' : 'text-gray-900'}`}>Welcome to AI Agent</h1>
                <span className={`text-base sm:text-lg md:text-xl font-medium mt-2 block ${isDarkMode ? 'text-gray-300' : 'text-gray-600'}`}>How can I assist you today?</span>
            </div>
            
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3 sm:gap-4 md:gap-6 w-full max-w-xs sm:max-w-2xl lg:max-w-3xl xl:max-w-3xl px-2 sm:px-4">
                {predefinedPrompts.map((item) => (
                    <motion.div
                        key={item.id}
                        className={`group relative backdrop-blur-xl border rounded-xl p-3 cursor-pointer transition-all duration-150 text-left ${
                            isDarkMode 
                                ? 'bg-white/[0.05] border-white/20 hover:bg-white/[0.08] shadow-[0_0_15px_rgba(204,43,94,0.2)] hover:shadow-[0_0_20px_rgba(204,43,94,0.4)]' 
                                : 'bg-white border-gray-200 hover:bg-gray-50 shadow-md hover:shadow-lg'
                        }`}
                        whileHover={{ scale: 1.03, transition: { duration: 0.15 } }}
                        whileTap={{ scale: 0.98 }}
                        onClick={() => handlePromptClick(item)}
                    >
                        <div className="relative z-10">
                            <h3 className={`font-medium text-sm sm:text-base mb-1 ${isDarkMode ? 'text-white' : 'text-gray-800'}`}>{item.title}</h3>
                            <p className={`text-xs sm:text-sm line-clamp-2 ${isDarkMode ? 'text-gray-400' : 'text-gray-500'}`}>{item.prompt}</p>
                        </div>
                    </motion.div>
                ))}
            </div>
            {/* Close profile dropdown when clicking outside */}
            {isProfileOpen && (
                <div 
                    className="fixed inset-0 z-10" 
                    onClick={() => setIsProfileOpen(false)}
                />
            )}
        </div>
    )
}

export default UserDashboard;


