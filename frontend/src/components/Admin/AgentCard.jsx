import React from 'react';
import { FaCircle, FaUsers, FaCommentDots } from 'react-icons/fa';
import { FiCode } from 'react-icons/fi';
import { useNavigate } from 'react-router-dom';
import { useTheme } from '../../context/ThemeContext';

const AgentCard = ({ agentId, agentImage, agentName, status, userCount, messageCount, modelType }) => {
    const navigate = useNavigate();
    const { isDarkMode } = useTheme();

    const statusDotColor = status === 'online'
        ? (isDarkMode ? 'bg-green-400' : 'bg-green-500')
        : (isDarkMode ? 'bg-red-500' : 'bg-red-600');

    const statusTextColor = status === 'online'
        ? (isDarkMode ? 'text-green-300' : 'text-green-600')
        : (isDarkMode ? 'text-red-300' : 'text-red-600');

    return (
        <div
            className="bg-white dark:bg-gray-800 rounded-lg p-3 sm:p-4 border border-gray-200 dark:border-gray-700 shadow-sm hover:shadow-md transition-all duration-300 hover:border-blue-400/50 dark:hover:border-gray-600 group cursor-pointer"
            onClick={() => navigate(`/admin/chat/${agentId}`)}
        >
            <div className="flex items-center mb-2 sm:mb-3">
                <div className="relative flex-shrink-0">
                    <img src={agentImage} alt={agentName} className="w-8 h-8 sm:w-10 sm:h-10 rounded-full mr-2 sm:mr-3 object-cover border border-gray-300 dark:border-gray-600" />
                    <div className={`absolute bottom-0 right-2 w-2.5 h-2.5 rounded-full border-2 ${isDarkMode ? 'border-gray-800' : 'border-white'} ${statusDotColor}`}></div>
                </div>
                <h3 className="text-sm sm:text-base font-semibold text-gray-900 dark:text-white truncate group-hover:text-blue-600 dark:group-hover:text-blue-400 transition-colors" title={agentName}>{agentName}</h3>
            </div>
            <div className="flex items-center gap-3 sm:gap-4 text-gray-500 dark:text-gray-400 text-xs sm:text-[0.8rem]">
                <div className="flex items-center gap-1" title={`${userCount} Users`}>
                    <FaUsers className="text-[0.7rem] sm:text-xs"/>
                    <span>{userCount}</span>
                </div>
                <div className="flex items-center gap-1" title={`${messageCount} Messages`}>
                    <FaCommentDots className="text-[0.7rem] sm:text-xs" />
                    <span>{messageCount}</span>
                </div>
                <div className="ml-auto flex items-center gap-1 px-1.5 sm:px-2 py-0.5 bg-gray-100 dark:bg-gray-700 rounded text-[0.65rem] sm:text-xs text-gray-600 dark:text-gray-300" title={`Model: ${modelType}`}>
                    <FiCode size={12}/>
                    <span className="hidden sm:inline">{modelType}</span>
                    <span className="sm:hidden">{modelType.substring(0, 5)}..</span>
                </div>
            </div>
        </div>
    );
};

export default React.memo(AgentCard); 