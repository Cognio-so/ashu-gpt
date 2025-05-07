import React, { useState, useRef, useEffect, useMemo, lazy, Suspense } from 'react';
import AdminSidebar from './AdminSidebar';
const CreateCustomGpt = lazy(() => import('./CreateCustomGpt'));
import { FiSearch, FiChevronDown, FiChevronUp, FiMenu } from 'react-icons/fi';
import AgentCard from './AgentCard';
import CategorySection from './CategorySection';
import { axiosInstance } from '../../api/axiosInstance';
import { useTheme } from '../../context/ThemeContext';

const defaultAgentImage = '/img.png';

const AdminDashboard = ({ userName = "Admin User" }) => {
    const [showCreateGpt, setShowCreateGpt] = useState(false);
    const [searchTerm, setSearchTerm] = useState('');
    const [isSortOpen, setIsSortOpen] = useState(false);
    const [sortOption, setSortOption] = useState('Default');
    const sortOptions = ['Default', 'Latest', 'Older'];
    const dropdownRef = useRef(null);
    const [showSidebar, setShowSidebar] = useState(false);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);
    const [agentsData, setAgentsData] = useState({
        featured: [],
        productivity: [],
        education: [],
        entertainment: []
    });
    const [gptCreated, setGptCreated] = useState(false);
    const { isDarkMode } = useTheme();

    const applySorting = (data, sortOpt) => {
        if (sortOpt === 'Default') return data;
        const sortedData = { ...data };
        const sortFn = sortOpt === 'Latest'
            ? (a, b) => new Date(b.createdAt) - new Date(a.createdAt)
            : (a, b) => new Date(a.createdAt) - new Date(b.createdAt);
        Object.keys(sortedData).forEach(category => {
            if (Array.isArray(sortedData[category])) {
                sortedData[category] = [...sortedData[category]].sort(sortFn);
            }
        });
        return sortedData;
    };

    useEffect(() => {
        const fetchAgents = async () => {
            try {
                setLoading(true);
                const response = await axiosInstance.get(`/api/custom-gpts`, {
                    withCredentials: true
                });
                if (response.data.success && response.data.customGpts) {
                    const sortedGpts = [...response.data.customGpts].sort((a, b) =>
                        new Date(b.createdAt) - new Date(a.createdAt)
                    );
                    const categorizedData = {
                        featured: [],
                        productivity: [],
                        education: [],
                        entertainment: []
                    };
                    categorizedData.featured = sortedGpts.slice(0, 4).map(gpt => ({
                        id: gpt._id,
                        image: gpt.imageUrl || defaultAgentImage,
                        name: gpt.name,
                        status: gpt.status || 'unknown',
                        userCount: gpt.userCount || 0,
                        messageCount: gpt.messageCount || 0,
                        modelType: gpt.model,
                        createdAt: gpt.createdAt
                    }));
                    sortedGpts.forEach(gpt => {
                        const text = (gpt.description + ' ' + gpt.name).toLowerCase();
                        const agent = {
                            id: gpt._id,
                            image: gpt.imageUrl || defaultAgentImage,
                            name: gpt.name,
                            status: gpt.status || 'unknown',
                            userCount: gpt.userCount || 0,
                            messageCount: gpt.messageCount || 0,
                            modelType: gpt.model,
                            createdAt: gpt.createdAt
                        };
                        if (categorizedData.featured.some(a => a.name === gpt.name)) {
                            return;
                        }
                        if (text.includes('work') || text.includes('task') || text.includes('productivity')) {
                            categorizedData.productivity.push(agent);
                        } else if (text.includes('learn') || text.includes('study') || text.includes('education')) {
                            categorizedData.education.push(agent);
                        } else if (text.includes('game') || text.includes('movie') || text.includes('fun')) {
                            categorizedData.entertainment.push(agent);
                        } else {
                            const categories = ['productivity', 'education', 'entertainment'];
                            const randomCategory = categories[Math.floor(Math.random() * categories.length)];
                            categorizedData[randomCategory].push(agent);
                        }
                    });
                    setAgentsData(categorizedData);
                } else {
                    setError(response.data.message || "Failed to load agents data: Invalid response format");
                }
            } catch (err) {
                console.error("Error fetching agents:", err);
                setError(`Failed to load agents data. ${err.response?.data?.message || err.message || ''}`);
            } finally {
                setLoading(false);
            }
        };
        fetchAgents();
    }, [gptCreated]);

    useEffect(() => {
        const handleResize = () => {
            if (window.innerWidth >= 640) {
                setShowSidebar(false);
            }
        };
        window.addEventListener('resize', handleResize);
        return () => window.removeEventListener('resize', handleResize);
    }, []);

    const filteredAgentsData = useMemo(() => {
        const searchTermLower = searchTerm.toLowerCase().trim();
        if (!searchTermLower) {
            return applySorting(agentsData, sortOption);
        }
        const filtered = {};
        Object.keys(agentsData).forEach(category => {
            filtered[category] = agentsData[category].filter(agent =>
                agent.name.toLowerCase().includes(searchTermLower) ||
                (agent.modelType && agent.modelType.toLowerCase().includes(searchTermLower))
            );
        });
        return applySorting(filtered, sortOption);
    }, [searchTerm, agentsData, sortOption]);

    useEffect(() => {
        function handleClickOutside(event) {
            if (dropdownRef.current && !dropdownRef.current.contains(event.target)) {
                setIsSortOpen(false);
            }
        }
        document.addEventListener("mousedown", handleClickOutside);
        return () => {
            document.removeEventListener("mousedown", handleClickOutside);
        };
    }, [dropdownRef]);

    const handleSortChange = (option) => {
        setSortOption(option);
        setIsSortOpen(false);
    };

    const hasSearchResults = Object.values(filteredAgentsData).some(
        category => category.length > 0
    );

    if (loading) {
        return (
            <div className="flex h-screen bg-black text-white items-center justify-center">
                <div className="animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-white"></div>
            </div>
        );
    }

    if (error) {
        return (
            <div className="flex h-screen bg-black text-white items-center justify-center">
                <div className="text-center p-4">
                    <p className="text-red-400 mb-4">{error}</p>
                    <button
                        onClick={() => window.location.reload()}
                        className="bg-white text-black px-6 py-2 rounded-full font-medium hover:bg-gray-200 transition-all"
                    >
                        Retry
                    </button>
                </div>
            </div>
        );
    }

    return (
        <div className="flex h-screen bg-black text-white font-sans">
            {/* Mobile Sidebar Overlay */}
            {showSidebar && (
                <div
                    className="fixed inset-0 bg-black/80 z-40 sm:hidden"
                    onClick={() => setShowSidebar(false)}
                />
            )}

            {/* Main Content */}
            <div className="flex-1 flex flex-col h-full overflow-hidden">
                {!showCreateGpt ? (
                    <>
                        {/* Header Section */}
                        <div className="bg-black px-4 sm:px-8 py-6 border-b border-gray-800 flex-shrink-0">
                            {/* Desktop Header */}
                            <div className="hidden sm:flex items-center justify-between">
                                <h1 className="text-2xl font-bold">Admin Dashboard</h1>
                                <div className="flex items-center gap-4">
                                    <div className="relative">
                                        <FiSearch className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400" />
                                        <input
                                            type="text"
                                            placeholder="Search GPTs..."
                                            value={searchTerm}
                                            onChange={(e) => setSearchTerm(e.target.value)}
                                            className="w-64 pl-10 pr-4 py-2 rounded-full bg-gray-900 border border-gray-700 focus:ring-2 focus:ring-white focus:border-white transition-all text-white placeholder-gray-400"
                                        />
                                    </div>
                                    <button
                                        onClick={() => setShowCreateGpt(true)}
                                        className="bg-white text-black px-6 py-2 rounded-full font-medium hover:bg-gray-200 transition-all"
                                    >
                                        Create GPT
                                    </button>
                                </div>
                            </div>
                            {/* Mobile Header */}
                            <div className="block sm:hidden">
                                <div className="flex items-center mb-4">
                                    <button
                                        onClick={() => setShowSidebar(!showSidebar)}
                                        className="p-2 rounded-full hover:bg-gray-800"
                                    >
                                        <FiMenu size={24} />
                                    </button>
                                    <h1 className="flex-1 text-center text-xl font-bold">Admin Dashboard</h1>
                                    <div className="w-10"></div>
                                </div>
                                <div className="flex items-center gap-3">
                                    <div className="flex-1 relative">
                                        <FiSearch className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400" />
                                        <input
                                            type="text"
                                            placeholder="Search GPTs..."
                                            value={searchTerm}
                                            onChange={(e) => setSearchTerm(e.target.value)}
                                            className="w-full pl-10 pr-4 py-2 rounded-full bg-gray-900 border border-gray-700 focus:ring-2 focus:ring-white text-white placeholder-gray-400"
                                        />
                                    </div>
                                    <button
                                        onClick={() => setShowCreateGpt(true)}
                                        className="bg-white text-black px-4 py-2 rounded-full font-medium hover:bg-gray-200"
                                    >
                                        Create
                                    </button>
                                </div>
                            </div>
                        </div>

                        {/* Main Content Area */}
                        <div className="flex-1 flex flex-col p-4 sm:p-8 overflow-hidden bg-black">
                            {searchTerm && !hasSearchResults ? (
                                <div className="text-center py-12 text-gray-400">
                                    No agents found for "{searchTerm}"
                                </div>
                            ) : (
                                <>
                                    {/* Featured Agents Section */}
                                    {filteredAgentsData.featured && filteredAgentsData.featured.length > 0 && (
                                        <div className="mb-8 flex-shrink-0">
                                            <h2 className="text-xl font-semibold mb-4">Featured Agents</h2>
                                            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4">
                                                {filteredAgentsData.featured.map((agent) => (
                                                    <AgentCard
                                                        key={agent.id || agent.name}
                                                        agentId={agent.id}
                                                        agentImage={agent.image}
                                                        agentName={agent.name}
                                                        status={agent.status}
                                                        userCount={agent.userCount}
                                                        messageCount={agent.messageCount}
                                                        modelType={agent.modelType}
                                                        hideActionIcons={true}
                                                    />
                                                ))}
                                            </div>
                                        </div>
                                    )}

                                    {/* Categories Header and Sort */}
                                    <div className="flex items-center justify-between mb-6 flex-shrink-0">
                                        <h2 className="text-xl font-semibold">Categories</h2>
                                        <div className="relative" ref={dropdownRef}>
                                            <button
                                                onClick={() => setIsSortOpen(!isSortOpen)}
                                                className="flex items-center text-sm text-gray-400 hover:text-white py-2 px-4 bg-gray-900 rounded-full border border-gray-700"
                                            >
                                                Sort: {sortOption}
                                                {isSortOpen ? <FiChevronUp className="ml-2" /> : <FiChevronDown className="ml-2" />}
                                            </button>
                                            {isSortOpen && (
                                                <div className="absolute top-full right-0 mt-2 w-36 bg-gray-900 rounded-lg shadow-lg z-10 border border-gray-700">
                                                    <ul>
                                                        {sortOptions.map((option) => (
                                                            <li key={option}>
                                                                <button
                                                                    onClick={() => handleSortChange(option)}
                                                                    className={`block w-full text-left px-4 py-2 text-sm ${sortOption === option ? 'bg-white text-black' : 'text-gray-300 hover:bg-gray-800'} transition-all`}
                                                                >
                                                                    {option}
                                                                </button>
                                                            </li>
                                                        ))}
                                                    </ul>
                                                </div>
                                            )}
                                        </div>
                                    </div>

                                    {/* Scrollable Categories */}
                                    <div className="flex-1 overflow-y-auto [scrollbar-width:none] [-ms-overflow-style:none] [&::-webkit-scrollbar]:hidden">
                                        {Object.entries(filteredAgentsData).map(([category, agents]) => {
                                            if (category === 'featured' || agents.length === 0) return null;
                                            const categoryTitle = category
                                                .replace(/([A-Z])/g, ' $1')
                                                .replace(/^./, (str) => str.toUpperCase());
                                            return (
                                                <CategorySection
                                                    key={category}
                                                    title={categoryTitle}
                                                    agentCount={agents.length}
                                                    agents={agents}
                                                    hideActionIcons={true}
                                                />
                                            );
                                        })}
                                    </div>
                                </>
                            )}
                        </div>
                    </>
                ) : (
                    <div className="h-full">
                        <Suspense fallback={<div className="flex h-full items-center justify-center text-gray-400">Loading Editor...</div>}>
                            <CreateCustomGpt
                                onGoBack={() => setShowCreateGpt(false)}
                                onGptCreated={() => {
                                    setGptCreated(prev => !prev);
                                    setShowCreateGpt(false);
                                }}
                            />
                        </Suspense>
                    </div>
                )}
            </div>
        </div>
    );
};

export default AdminDashboard;