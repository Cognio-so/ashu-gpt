import React, { useState, useEffect } from 'react';
import AgentCard from './AgentCard';
import { useNavigate } from 'react-router-dom';
import { useTheme } from '../../context/ThemeContext';
import { FiUser, FiMessageSquare, FiCode, FiMoreHorizontal, FiExternalLink } from 'react-icons/fi';
import { FixedSizeGrid } from 'react-window';

const CategorySection = ({ title, agentCount, agents, virtualized = false, hideActionIcons = false }) => {
    // Detect mobile view
    const [isMobileView, setIsMobileView] = useState(false);
    const navigate = useNavigate();
    const { isDarkMode } = useTheme();

    useEffect(() => {
        const handleResize = () => {
            setIsMobileView(window.innerWidth < 640);
        };

        window.addEventListener('resize', handleResize);
        handleResize();

        return () => window.removeEventListener('resize', handleResize);
    }, []);

    // Mobile agent item component with theme styles
    const MobileAgentItem = ({ agent, onClick }) => {
        const statusColor = agent.status === 'online' || agent.status === 'Active'
            ? (isDarkMode ? 'bg-green-400' : 'bg-green-500')
            : (isDarkMode ? 'bg-red-500' : 'bg-red-600');

        return (
            <div
                className="p-3 border-b border-gray-200 dark:border-gray-700/50 w-full flex items-center cursor-pointer hover:bg-gray-50 dark:hover:bg-gray-700/30 transition-colors group"
                onClick={onClick}
            >
                <div className="flex-shrink-0 mr-3 relative">
                    <img src={agent.image} alt={agent.name} className="w-10 h-10 rounded-full object-cover border border-gray-300 dark:border-gray-600" />
                    <div className={`absolute bottom-0 right-0 w-2.5 h-2.5 rounded-full border-2 ${isDarkMode ? 'border-gray-800/50' : 'border-white'} ${statusColor}`}></div>
                </div>
                <div className="flex-grow overflow-hidden">
                    <div className="flex items-center justify-between">
                        <h3 className="font-medium text-gray-900 dark:text-white truncate pr-2 group-hover:text-blue-600 dark:group-hover:text-blue-400 transition-colors" title={agent.name}>{agent.name}</h3>
                    </div>
                    <div className="flex items-center text-gray-500 dark:text-gray-400 text-xs mt-1 gap-3 flex-wrap">
                        <span className="flex items-center gap-1" title={`${agent.userCount} Users`}><FiUser size={12} /> {agent.userCount}</span>
                        <span className="flex items-center gap-1" title={`${agent.messageCount} Messages`}><FiMessageSquare size={12} /> {agent.messageCount}</span>
                        <span className="flex items-center gap-1 text-xs px-1.5 py-0.5 bg-gray-100 dark:bg-gray-700 rounded text-gray-600 dark:text-gray-300" title={`Model: ${agent.modelType}`}><FiCode size={12} /> {agent.modelType}</span>
                    </div>
                </div>
                <div className="ml-2 flex-shrink-0 opacity-0 group-hover:opacity-100 transition-opacity">
                    <FiExternalLink className="text-gray-400 dark:text-gray-500" size={14} />
                </div>
            </div>
        );
    };

    // Calculate rows and columns based on viewport width
    const columnCount = window.innerWidth < 640 ? 1 :
        window.innerWidth < 1024 ? 2 :
            window.innerWidth < 1280 ? 3 : 4;

    const rowCount = Math.ceil(agents.length / columnCount);

    return (
        <div className="mb-8">
            <div className="flex items-center justify-between mb-4">
                <h3 className="text-base sm:text-lg font-semibold text-gray-900 dark:text-white">{title}</h3>
                <span className="text-xs md:text-sm text-gray-500 dark:text-gray-400">{agentCount} agents</span>
            </div>

            {virtualized ? (
                <FixedSizeGrid
                    columnCount={columnCount}
                    columnWidth={300}
                    height={400}
                    rowCount={rowCount}
                    rowHeight={220}
                    width={columnCount * 300}
                    className="mx-auto"
                >
                    {({ columnIndex, rowIndex, style }) => {
                        const index = rowIndex * columnCount + columnIndex;
                        if (index >= agents.length) return null;

                        const agent = agents[index];
                        return (
                            <div style={style}>
                                <AgentCard
                                    key={agent.id || agent.name}
                                    agentId={agent.id}
                                    agentImage={agent.image}
                                    agentName={agent.name}
                                    status={agent.status}
                                    userCount={agent.userCount}
                                    messageCount={agent.messageCount}
                                    modelType={agent.modelType}
                                    hideActionIcons={hideActionIcons}
                                />
                            </div>
                        );
                    }}
                </FixedSizeGrid>
            ) : (
                <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-3 md:gap-4">
                    {agents.map((agent) => (
                        <AgentCard
                            key={agent.id || agent.name}
                            agentId={agent.id}
                            agentImage={agent.image}
                            agentName={agent.name}
                            status={agent.status}
                            userCount={agent.userCount}
                            messageCount={agent.messageCount}
                            modelType={agent.modelType}
                            hideActionIcons={hideActionIcons}
                        />
                    ))}
                </div>
            )}
        </div>
    );
};

export default React.memo(CategorySection); 