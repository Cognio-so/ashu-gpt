import React from 'react';
import { FaCircle, FaUsers, FaCommentDots } from 'react-icons/fa';
import { FiCode, FiEdit, FiTrash2, FiFolderPlus, FiFolder } from 'react-icons/fi';
import { SiOpenai, SiGooglegemini } from 'react-icons/si';
import { FaRobot } from 'react-icons/fa6';
import { BiLogoMeta } from 'react-icons/bi';
import { RiOpenaiFill } from 'react-icons/ri';
import { useNavigate } from 'react-router-dom';
import { useTheme } from '../../context/ThemeContext';

// Model icons mapping
const modelIcons = {
    'gpt-4': <RiOpenaiFill className="text-green-500" size={18} />,
    'gpt-3.5': <SiOpenai className="text-green-400" size={16} />,
    'claude': <FaRobot className="text-purple-400" size={16} />,
    'gemini': <SiGooglegemini className="text-blue-400" size={16} />,
    'llama': <BiLogoMeta className="text-blue-500" size={18} />
};

const AgentCard = ({ agentId, agentImage, agentName, status, userCount, messageCount, modelType, createdAt, hideActionIcons = false }) => {
    const navigate = useNavigate();
    const { isDarkMode } = useTheme();

    const statusDotColor = status === 'online'
        ? (isDarkMode ? 'bg-green-400' : 'bg-green-500')
        : (isDarkMode ? 'bg-red-500' : 'bg-red-600');

    const statusTextColor = status === 'online'
        ? (isDarkMode ? 'text-green-300' : 'text-green-600')
        : (isDarkMode ? 'text-red-300' : 'text-red-600');

    const formatDate = (dateString) => {
        if (!dateString) return '';
        return new Date(dateString).toLocaleDateString('en-US', {
            year: 'numeric',
            month: 'short',
            day: 'numeric'
        });
    };

    return (
        <div
            key={agentId}
            className="bg-white dark:bg-gray-800 rounded-lg overflow-hidden border border-gray-200 dark:border-gray-700 hover:border-blue-400/50 dark:hover:border-gray-600 transition-all shadow-md hover:shadow-lg flex flex-col cursor-pointer group"
            onClick={() => navigate(`/admin/chat/${agentId}`)}
        >
            <div className="h-24 sm:h-32 bg-gradient-to-br from-gray-100 to-gray-300 dark:from-gray-700 dark:to-gray-900 relative flex-shrink-0 overflow-hidden">
                {agentImage ? (
                    <img
                        src={agentImage}
                        alt={agentName}
                        className="w-full h-full object-cover opacity-80 dark:opacity-70 group-hover:scale-105 transition-transform duration-300"
                        loading="lazy"
                    />
                ) : (
                    <div className="w-full h-full flex items-center justify-center bg-gradient-to-br from-blue-50/50 to-purple-100/50 dark:from-blue-900/30 dark:to-purple-900/30">
                        <span className={`text-3xl sm:text-4xl ${isDarkMode ? 'text-white/30' : 'text-gray-500/40'}`}>{agentName.charAt(0)}</span>
                    </div>
                )}

                <div className="absolute top-2 right-2 flex gap-1.5 opacity-0 group-hover:opacity-100 transition-opacity duration-200">
                    {!hideActionIcons && (
                        <>
                            <button
                                onClick={(e) => { e.stopPropagation(); }}
                                className="p-1.5 sm:p-2 bg-white/80 dark:bg-gray-900/70 text-gray-700 dark:text-gray-200 rounded-full hover:bg-green-500 hover:text-white dark:hover:bg-green-700/80 transition-colors shadow"
                                title="Move to Folder"
                            >
                                <FiFolderPlus size={14} />
                            </button>
                            <button
                                onClick={(e) => { e.stopPropagation(); }}
                                className="p-1.5 sm:p-2 bg-white/80 dark:bg-gray-900/70 text-gray-700 dark:text-gray-200 rounded-full hover:bg-blue-500 hover:text-white dark:hover:bg-blue-700/80 transition-colors shadow"
                                title="Edit GPT"
                            >
                                <FiEdit size={14} />
                            </button>
                            <button
                                onClick={(e) => { e.stopPropagation(); }}
                                className="p-1.5 sm:p-2 bg-white/80 dark:bg-gray-900/70 text-gray-700 dark:text-gray-200 rounded-full hover:bg-red-500 hover:text-white dark:hover:bg-red-700/80 transition-colors shadow"
                                title="Delete GPT"
                            >
                                <FiTrash2 size={14} />
                            </button>
                        </>
                    )}
                </div>
            </div>

            <div className="p-3 sm:p-4 flex flex-col flex-grow">
                <div className="flex items-start justify-between mb-1.5 sm:mb-2">
                    <h3 className="font-semibold text-base sm:text-lg line-clamp-1 text-gray-900 dark:text-white">{agentName}</h3>
                    <div className="flex items-center flex-shrink-0 gap-1 bg-gray-100 dark:bg-gray-700 px-1.5 sm:px-2 py-0.5 rounded text-[10px] sm:text-xs text-gray-600 dark:text-gray-300">
                        {React.cloneElement(modelIcons[modelType] || <FaRobot className="text-gray-500" />, { size: 12 })}
                        <span className="hidden sm:inline">{modelType}</span>
                    </div>
                </div>

                <div className="mt-auto pt-2 border-t border-gray-100 dark:border-gray-700 text-[10px] sm:text-xs text-gray-500 dark:text-gray-400 flex justify-between items-center">
                    <span>Created: {formatDate(createdAt)}</span>
                    <div className="flex items-center gap-2">
                        <span className="whitespace-nowrap">{userCount} users</span>
                        <span className="whitespace-nowrap">{messageCount} msgs</span>
                    </div>
                </div>
            </div>
        </div>
    );
};

export default React.memo(AgentCard); 