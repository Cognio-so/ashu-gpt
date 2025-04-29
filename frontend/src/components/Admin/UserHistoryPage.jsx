import React, { useState, useEffect, useRef } from 'react';
import { useParams, useNavigate, useLocation } from 'react-router-dom';
import {
    IoArrowBack,
    IoTimeOutline,
    IoSearchOutline,
    IoFilterOutline,
    IoChevronDown,
    IoEllipse,
    IoChatbubbleEllipsesOutline,
    IoCheckmark
} from 'react-icons/io5';
import { FiUser, FiUsers, FiBox, FiCalendar, FiMail, FiActivity } from 'react-icons/fi';
import { useTheme } from '../../context/ThemeContext';

// Use mockTeamMembers from HistoryPage or define locally if preferred
// Updated IDs to be numerical strings to match potential URL params
const mockTeamMembers = [
    { id: '1', name: 'Alice Johnson', email: 'alice@example.com', role: 'Engineer', department: 'Engineering', status: 'Active', position: 'Senior Engineer', joined: new Date(Date.now() - 2592000000).toISOString(), lastActive: new Date(Date.now() - 3600000).toISOString() }, // ~30d / 1h
    { id: '2', name: 'Bob Williams', email: 'bob@example.com', role: 'Designer', department: 'Design', status: 'Active', position: 'Lead Designer', joined: new Date(Date.now() - 5184000000).toISOString(), lastActive: new Date(Date.now() - 86400000).toISOString() }, // ~60d / 1d
    { id: '3', name: 'Charlie Brown', email: 'charlie@example.com', role: 'Product Manager', department: 'Product', status: 'Inactive', position: 'Product Lead', joined: new Date(Date.now() - 7776000000).toISOString(), lastActive: new Date(Date.now() - 604800000).toISOString() }, // ~90d / 7d
    { id: '4', name: 'Diana Davis', email: 'diana@example.com', role: 'Marketer', department: 'Marketing', status: 'Active', position: 'Marketing Specialist', joined: new Date(Date.now() - 10368000000).toISOString(), lastActive: new Date(Date.now() - 172800000).toISOString() }, // ~120d / 2d
    { id: '5', name: 'Eve Smith', email: 'eve@example.com', role: 'Sales', department: 'Sales', status: 'Active', position: 'Sales Manager', joined: new Date(Date.now() - 12592000000).toISOString(), lastActive: new Date(Date.now() - 3600000).toISOString() }, // ~30d / 1h
    { id: '6', name: 'Frank White', email: 'frank@example.com', role: 'Engineer', department: 'Engineering', status: 'Active', position: 'Senior Engineer', joined: new Date(Date.now() - 15552000000).toISOString(), lastActive: new Date(Date.now() - 14400000).toISOString() }, // ~180d / 4h
    { id: '7', name: 'Grace Green', email: 'grace@example.com', role: 'Designer', department: 'Design', status: 'Inactive', position: 'Lead Designer', joined: new Date(Date.now() - 18528000000).toISOString(), lastActive: new Date(Date.now() - 28800000).toISOString() }, // ~210d / 5h
    { id: '8', name: 'Henry Black', email: 'henry@example.com', role: 'Product Manager', department: 'Product', status: 'Active', position: 'Product Lead', joined: new Date(Date.now() - 21600000000).toISOString(), lastActive: new Date(Date.now() - 10800000).toISOString() }, // ~240d / 6h
    { id: '9', name: 'Ivy Blue', email: 'ivy@example.com', role: 'Marketer', department: 'Marketing', status: 'Inactive', position: 'Marketing Specialist', joined: new Date(Date.now() - 24672000000).toISOString(), lastActive: new Date(Date.now() - 14400000).toISOString() }, // ~270d / 7h
    { id: '10', name: 'John Doe', email: 'john@example.com', role: 'Engineer', department: 'Engineering', status: 'Active', position: 'Senior Engineer', joined: new Date(Date.now() - 27744000000).toISOString(), lastActive: new Date(Date.now() - 3600000).toISOString() }, // ~300d / 8h
    { id: '11', name: 'Kate Red', email: 'kate@example.com', role: 'Sales', department: 'Sales', status: 'Active', position: 'Sales Manager', joined: new Date(Date.now() - 30720000000).toISOString(), lastActive: new Date(Date.now() - 14400000).toISOString() }, // ~330d / 9h
    { id: '12', name: 'Luke Yellow', email: 'luke@example.com', role: 'Engineer', department: 'Engineering', status: 'Inactive', position: 'Senior Engineer', joined: new Date(Date.now() - 33792000000).toISOString(), lastActive: new Date(Date.now() - 28800000).toISOString() }, // ~360d / 10h
    
];

const UserHistoryPage = () => {
    const { userId } = useParams();
    const navigate = useNavigate();
    const location = useLocation();
    const { isDarkMode } = useTheme();

    const [isLoading, setIsLoading] = useState(false);
    const [user, setUser] = useState(null);
    const [conversations, setConversations] = useState([]);
    const [filteredConversations, setFilteredConversations] = useState([]);
    const [searchQuery, setSearchQuery] = useState('');
    const [filterOpen, setFilterOpen] = useState(false);
    const [filterOptions, setFilterOptions] = useState({
        dateRange: 'all',
    });

    const filterDropdownRef = useRef(null);
    const queryParams = new URLSearchParams(location.search);
    const previousView = queryParams.get('view') || 'team';

    // Fetch user data and conversations
    useEffect(() => {
        const fetchUserData = async () => {
            setIsLoading(true);
            try {
                // Find user from MOCK team members data
                const foundUser = mockTeamMembers.find(member => member.id.toString() === userId);

                if (foundUser) {
                    setUser(foundUser);
                    // Generate mock conversations for this user
                    const mockConversations = generateMockConversations(foundUser.id);
                    setConversations(mockConversations);
                    setFilteredConversations(mockConversations);
                } else {
                     console.warn(`User with ID ${userId} not found in mock data.`);
                     // Optionally navigate back or show an error message
                     navigate(`/admin/history?view=${previousView}`);
                 }

                setIsLoading(false);
            } catch (error) {
                console.error("Error fetching user data:", error);
                setIsLoading(false);
                 // Optionally navigate back or show an error message
                 navigate(`/admin/history?view=${previousView}`);
            }
        };

        fetchUserData();
    }, [userId, navigate, previousView]); // Add dependencies

    // Filter conversations based on search and date range
    useEffect(() => {
        let filtered = [...conversations];

        if (searchQuery) {
            const lowerQuery = searchQuery.toLowerCase();
            filtered = filtered.filter(convo =>
                convo.title.toLowerCase().includes(lowerQuery) ||
                convo.summary.toLowerCase().includes(lowerQuery) ||
                 (convo.gptName && convo.gptName.toLowerCase().includes(lowerQuery)) // Search by GPT name too
            );
        }

        if (filterOptions.dateRange !== 'all') {
            const now = new Date();
            let cutoffDate;

            if (filterOptions.dateRange === 'today') {
                 cutoffDate = new Date(now.getFullYear(), now.getMonth(), now.getDate());
             } else if (filterOptions.dateRange === 'week') {
                  // Go back 7 days from the start of today
                  const startOfToday = new Date(now.getFullYear(), now.getMonth(), now.getDate());
                  cutoffDate = new Date(startOfToday.setDate(startOfToday.getDate() - 7));
              } else if (filterOptions.dateRange === 'month') {
                  // Go back 1 month from the start of today
                  const startOfToday = new Date(now.getFullYear(), now.getMonth(), now.getDate());
                  cutoffDate = new Date(startOfToday.setMonth(startOfToday.getMonth() - 1));
              }


            if (cutoffDate) {
                 filtered = filtered.filter(convo => new Date(convo.timestamp) >= cutoffDate);
             }
        }

        setFilteredConversations(filtered);
    }, [searchQuery, filterOptions, conversations]);

    // Generate mock conversation data
    const generateMockConversations = (currentUserId) => { // Accept userId
        const titles = [
            'Project requirements discussion', 'Customer feedback review',
            'Design brainstorming session', 'Marketing strategy planning',
            'Budget allocation meeting', 'Team performance review',
            'New feature exploration', 'Product roadmap planning',
            'API Integration Query', 'User Onboarding Flow', 'Competitor Analysis'
        ];
         const gptNames = [ // Assume these are the names of GPTs used
             'Support Bot', 'Research Assistant', 'Code Helper', 'Data Analyst', null // Represent direct interaction or unknown
         ];

        const mockData = [];
        const numConversations = Math.floor(Math.random() * 10) + 5; // 5 to 14 conversations

        for (let i = 0; i < numConversations; i++) {
            const title = titles[Math.floor(Math.random() * titles.length)];
            const gptName = gptNames[Math.floor(Math.random() * gptNames.length)];

            const now = new Date();
            const daysAgo = Math.floor(Math.random() * 45); // More realistic range
            const hoursAgo = Math.floor(Math.random() * 24);
            const minutesAgo = Math.floor(Math.random() * 60);
            const timestamp = new Date(now);
            timestamp.setDate(timestamp.getDate() - daysAgo);
            timestamp.setHours(timestamp.getHours() - hoursAgo);
            timestamp.setMinutes(timestamp.getMinutes() - minutesAgo);


            const messageCount = Math.floor(Math.random() * 20) + 5;

            mockData.push({
                id: `conv-${currentUserId}-${i}`, // Make ID more specific
                title,
                summary: `Conversation with ${messageCount} messages ${gptName ? `using ${gptName}` : ''}`,
                messageCount,
                gptName, // Store which GPT was used (or null)
                timestamp: timestamp.toISOString(),
            });
        }

        return mockData.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
    };

     // Format timestamp (minor adjustment for clarity)
    const formatTimestamp = (timestamp) => {
        if (!timestamp) return 'N/A';
        const date = new Date(timestamp);
        const now = new Date();

        // Check if the date is today
        const isToday = date.toDateString() === now.toDateString();
        // Check if the date was yesterday
        const yesterday = new Date(now);
        yesterday.setDate(now.getDate() - 1);
        const isYesterday = date.toDateString() === yesterday.toDateString();

        const timeString = date.toLocaleTimeString([], {
            hour: 'numeric',
            minute: '2-digit',
            hour12: true
        }).toLowerCase(); // Ensure lowercase am/pm

        if (isToday) {
            return `Today, ${timeString}`;
        } else if (isYesterday) {
            return `Yesterday, ${timeString}`;
        } else {
            // Format for older dates
            return date.toLocaleDateString(undefined, {
                month: 'short',
                day: 'numeric',
                year: date.getFullYear() !== now.getFullYear() ? 'numeric' : undefined, // Show year if not current year
            }) + `, ${timeString}`; // Add time back
        }
    };

     // Format date only
     const formatDateOnly = (dateString) => {
        if (!dateString) return 'N/A';
        const date = new Date(dateString);
        return date.toLocaleDateString('en-US', {
            year: 'numeric',
            month: 'short',
            day: 'numeric'
        });
    };


     // Format relative time for Last Active
    const formatRelativeTime = (dateString) => {
        if (!dateString) return 'Never';
        const date = new Date(dateString);
        const now = new Date();
        const diffTime = now - date; // Difference in milliseconds
        const diffSeconds = Math.floor(diffTime / 1000);
        const diffMinutes = Math.floor(diffSeconds / 60);
        const diffHours = Math.floor(diffMinutes / 60);
        const diffDays = Math.floor(diffHours / 24);

        if (diffDays > 30) return formatDateOnly(dateString); // Older than a month, show date
        if (diffDays >= 1) return `${diffDays} day${diffDays > 1 ? 's' : ''} ago`;
        if (diffHours >= 1) return `${diffHours} hour${diffHours > 1 ? 's' : ''} ago`;
        if (diffMinutes >= 1) return `${diffMinutes} min${diffMinutes > 1 ? 's' : ''} ago`;
        return 'Just now';
    };


    // Set date range filter
    const setDateRangeFilter = (range) => {
        setFilterOptions(prev => ({ ...prev, dateRange: range }));
        setFilterOpen(false);
    };

    // Click outside handling for filter dropdown
    useEffect(() => {
        function handleClickOutside(event) {
            if (filterDropdownRef.current && !filterDropdownRef.current.contains(event.target)) {
                setFilterOpen(false);
            }
        }
        document.addEventListener("mousedown", handleClickOutside);
        return () => document.removeEventListener("mousedown", handleClickOutside);
    }, [filterDropdownRef]); // Dependency is correct


    // CSS for hiding scrollbars (Keep this definition)
    const scrollbarHideStyles = `
      .hide-scrollbar::-webkit-scrollbar { display: none; }
      .hide-scrollbar { -ms-overflow-style: none; scrollbar-width: none; }
    `;

     // Render loading state for user profile
     const renderProfileLoading = () => (
        <div className="animate-pulse">
             <div className="flex items-center mb-6">
                {/* Apply theme pulse colors */}
                 <div className="h-14 w-14 rounded-full bg-gray-200 dark:bg-gray-700 mr-4 flex-shrink-0"></div>
                 <div className="flex-1">
                     <div className="h-6 bg-gray-200 dark:bg-gray-700 rounded w-3/4 mb-2"></div>
                     <div className="h-4 bg-gray-200 dark:bg-gray-700 rounded w-1/2"></div>
                 </div>
             </div>
             <div className="mb-6 space-y-3">
                {/* Apply theme pulse colors */}
                 <div className="flex gap-3">
                     <div className="h-5 bg-gray-200 dark:bg-gray-700 rounded-full w-16"></div>
                     <div className="h-5 bg-gray-200 dark:bg-gray-700 rounded w-24"></div>
                 </div>
                 <div className="h-4 bg-gray-200 dark:bg-gray-700 rounded w-full"></div>
                 <div className="h-4 bg-gray-200 dark:bg-gray-700 rounded w-5/6"></div>
             </div>
              {/* Pulse for stats cards */}
             <div className="space-y-3">
                 <div className="h-16 bg-gray-200 dark:bg-gray-700 rounded-lg"></div>
                 <div className="h-16 bg-gray-200 dark:bg-gray-700 rounded-lg"></div>
                 <div className="h-16 bg-gray-200 dark:bg-gray-700 rounded-lg"></div>
             </div>
         </div>
     );

      // Render loading state for conversation list
      const renderConversationLoading = () => (
        <div className="space-y-3"> {/* Reduced spacing */}
             {[...Array(5)].map((_, i) => (
                 // Apply theme pulse colors
                 <div key={i} className="flex items-center p-4 bg-white dark:bg-gray-800/60 rounded-lg shadow-sm animate-pulse border border-gray-200 dark:border-gray-700/50">
                     <div className="w-8 h-8 rounded-full bg-gray-200 dark:bg-gray-700 mr-4 flex-shrink-0"></div>
                     <div className="flex-1 space-y-2">
                         <div className="h-3 bg-gray-200 dark:bg-gray-700 rounded w-3/4"></div>
                         <div className="h-3 bg-gray-200 dark:bg-gray-700 rounded w-1/2"></div>
                     </div>
                       <div className="h-3 bg-gray-200 dark:bg-gray-700 rounded w-1/4 ml-4"></div>
                 </div>
             ))}
         </div>
     );


    return (
        // Apply theme colors to main container
        <div className="flex flex-col h-full bg-white dark:bg-black text-black dark:text-white overflow-hidden">
            <style>{scrollbarHideStyles}</style>

            {/* Back button */}
             {/* Apply theme colors */}
            <div className="px-6 pt-6 pb-3 flex-shrink-0 border-b border-gray-200 dark:border-gray-800">
                <button
                    onClick={() => navigate(`/admin/history?view=${previousView}`)}
                    className="flex items-center text-gray-500 dark:text-gray-400 hover:text-blue-600 dark:hover:text-blue-400 transition-colors text-sm"
                >
                    <IoArrowBack size={16} className="mr-1" />
                    <span>Back to History</span>
                </button>
            </div>

            {/* Main content area */}
            <div className="flex-1 overflow-hidden flex flex-col lg:flex-row">
                {/* Left side - User profile */}
                {/* Apply theme colors and border */}
                <div className="lg:w-[320px] xl:w-[360px] p-6 border-b lg:border-b-0 lg:border-r border-gray-200 dark:border-gray-700 overflow-y-auto hide-scrollbar bg-gray-50 dark:bg-gray-900/40 flex-shrink-0">
                    {isLoading ? renderProfileLoading() : user ? (
                        <>
                            <div className="flex items-center mb-6">
                                 {/* Apply theme color to avatar placeholder */}
                                 <div className="h-14 w-14 rounded-full bg-gradient-to-br from-blue-500 to-purple-600 flex items-center justify-center text-white text-xl font-medium mr-4 flex-shrink-0">
                                    {user.name.charAt(0)}
                                </div>
                                <div className="overflow-hidden"> {/* Prevent long names/emails overflowing */}
                                    {/* Apply theme text colors */}
                                    <h1 className="text-xl lg:text-2xl font-semibold text-gray-900 dark:text-white truncate" title={user.name}>{user.name}</h1>
                                    <p className="text-sm text-gray-500 dark:text-gray-400 truncate" title={user.email}>{user.email}</p>
                                </div>
                            </div>

                            <div className="mb-6">
                                {/* Apply theme colors to status/role badges */}
                                <div className="flex items-center gap-2 mb-3 flex-wrap"> {/* Reduced gap */}
                                     <span className={`px-2.5 py-0.5 inline-flex items-center text-xs leading-5 font-semibold rounded-full ${
                                        user.status === 'Active'
                                             ? 'bg-green-100 dark:bg-green-900/50 text-green-800 dark:text-green-300'
                                             : 'bg-red-100 dark:bg-red-900/50 text-red-800 dark:text-red-300'
                                     }`}>
                                          <IoEllipse className={`mr-1.5 ${user.status === 'Active' ? 'text-green-500' : 'text-red-500'}`} size={8} />
                                        {user.status}
                                    </span>
                                    <span className="text-gray-500 dark:text-gray-400 text-xs flex items-center bg-gray-100 dark:bg-gray-700 px-2 py-0.5 rounded-full">
                                        <FiUser className="mr-1" size={12} />
                                        {user.role}
                                    </span>
                                </div>

                                {/* Apply theme text colors to details */}
                                <div className="space-y-2 text-sm">
                                    <div className="flex items-start"> {/* Use items-start for potential wrap */}
                                        <FiBox className="mr-2 mt-0.5 text-gray-400 dark:text-gray-500 flex-shrink-0" size={14} />
                                        <span className="text-gray-600 dark:text-gray-400 mr-1">Department:</span>
                                        <span className="font-medium text-gray-800 dark:text-gray-200">{user.department}</span>
                                    </div>
                                    <div className="flex items-start">
                                        <FiUsers className="mr-2 mt-0.5 text-gray-400 dark:text-gray-500 flex-shrink-0" size={14} />
                                        <span className="text-gray-600 dark:text-gray-400 mr-1">Position:</span>
                                        <span className="font-medium text-gray-800 dark:text-gray-200">{user.position || 'N/A'}</span>
                                    </div>
                                      <div className="flex items-start">
                                        <FiCalendar className="mr-2 mt-0.5 text-gray-400 dark:text-gray-500 flex-shrink-0" size={14} />
                                        <span className="text-gray-600 dark:text-gray-400 mr-1">Joined:</span>
                                        <span className="font-medium text-gray-800 dark:text-gray-200">{formatDateOnly(user.joined)}</span>
                                    </div>
                                     <div className="flex items-start">
                                        <FiActivity className="mr-2 mt-0.5 text-gray-400 dark:text-gray-500 flex-shrink-0" size={14} />
                                        <span className="text-gray-600 dark:text-gray-400 mr-1">Last Active:</span>
                                        <span className="font-medium text-gray-800 dark:text-gray-200">{formatRelativeTime(user.lastActive)}</span>
                                    </div>
                                </div>
                            </div>
                             {/* Add other relevant info if needed */}
                             {/* Example Stats Card */}
                             <div className="bg-white dark:bg-gray-800/50 rounded-lg p-4 border border-gray-200 dark:border-gray-700/60">
                                <h3 className="text-sm font-medium text-gray-600 dark:text-gray-300 mb-3">Usage Overview</h3>
                                <div className="flex justify-between items-center text-sm">
                                    <span className="text-gray-500 dark:text-gray-400">Total Conversations:</span>
                                    <span className="font-medium text-gray-800 dark:text-gray-200">{conversations.length}</span>
                                </div>
                                <div className="flex justify-between items-center text-sm mt-1">
                                    <span className="text-gray-500 dark:text-gray-400">GPTs Assigned:</span>
                                    <span className="font-medium text-gray-800 dark:text-gray-200">{user?.assignedGPTs || 0}</span>
                                </div>
                             </div>
                        </>
                    ) : (
                         <p className="text-center text-gray-500 dark:text-gray-400 py-10">User not found.</p>
                     )}
                </div>

                {/* Right side - Conversation history */}
                 {/* Apply theme background */}
                <div className="flex-1 flex flex-col overflow-hidden bg-white dark:bg-black">
                    {/* Search and Filter */}
                    {/* Apply theme border */}
                    <div className="px-6 py-3 border-b border-gray-200 dark:border-gray-700 flex flex-col sm:flex-row items-center gap-3 sm:gap-4 flex-shrink-0">
                         <div className="text-sm font-medium text-gray-800 dark:text-gray-200 flex-shrink-0">
                             Conversation History ({filteredConversations.length})
                         </div>
                         <div className="flex-grow flex items-center gap-3 w-full sm:w-auto justify-end">
                             <div className="relative flex-grow max-w-xs w-full">
                                 {/* Apply theme colors to search */}
                                 <IoSearchOutline className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400 dark:text-gray-500" size={16} />
                                <input
                                    type="text"
                                    placeholder="Search conversations..."
                                    value={searchQuery}
                                    onChange={(e) => setSearchQuery(e.target.value)}
                                     className="w-full pl-9 pr-4 py-1.5 rounded-lg border border-gray-300 dark:border-gray-700 bg-white dark:bg-gray-800 focus:ring-1 focus:ring-blue-500 focus:border-blue-500 outline-none text-sm text-black dark:text-white placeholder-gray-500 dark:placeholder-gray-400"
                                />
                            </div>
                            <div className="relative" ref={filterDropdownRef}>
                                <button
                                    onClick={() => setFilterOpen(!filterOpen)}
                                     // Apply theme colors to filter button
                                     className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-gray-300 dark:border-gray-700 bg-white dark:bg-gray-800 text-sm text-gray-700 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-700 flex-shrink-0"
                                >
                                    <IoFilterOutline size={14} /> Date
                                    <IoChevronDown size={14} className={`transition-transform ${filterOpen ? 'rotate-180' : ''}`} />
                                </button>
                                 {filterOpen && (
                                    // Apply theme colors to filter dropdown
                                    <div className="absolute right-0 mt-2 w-40 bg-white dark:bg-gray-800 rounded-lg shadow-xl border border-gray-200 dark:border-gray-700 z-20 overflow-hidden">
                                         {[{ label: 'All Time', value: 'all' }, { label: 'Today', value: 'today' }, { label: 'Last 7 Days', value: 'week' }, { label: 'Last 30 Days', value: 'month' }].map(range => (
                                            <button
                                                key={range.value}
                                                onClick={() => setDateRangeFilter(range.value)}
                                                // Apply theme colors to date options
                                                className={`w-full text-left px-3 py-1.5 text-sm flex justify-between items-center transition-colors ${
                                                    filterOptions.dateRange === range.value
                                                        ? 'bg-blue-50 dark:bg-blue-900/30 text-blue-700 dark:text-blue-300 font-medium'
                                                        : 'text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700'
                                                }`}
                                            >
                                                {range.label}
                                                 {filterOptions.dateRange === range.value && <IoCheckmark size={16} />}
                                            </button>
                                        ))}
                                    </div>
                                )}
                            </div>
                         </div>
                    </div>

                    {/* Conversation List */}
                     {/* Apply theme background */}
                     <div className="flex-1 overflow-y-auto p-4 md:p-6 bg-gray-50 dark:bg-gray-900/50 custom-scrollbar-dark dark:custom-scrollbar">
                        {isLoading ? renderConversationLoading() : filteredConversations.length > 0 ? (
                            <ul className="space-y-3">
                                {filteredConversations.map((convo) => (
                                    // Apply theme colors to conversation item
                                    <li key={convo.id} className="flex items-center p-4 bg-white dark:bg-gray-800 rounded-lg shadow-sm border border-gray-200 dark:border-gray-700/50 transition-colors hover:bg-gray-50 dark:hover:bg-gray-700/60 cursor-pointer group">
                                        {/* Icon */}
                                         {/* Apply theme colors */}
                                         <div className="w-8 h-8 rounded-full flex items-center justify-center mr-4 bg-blue-100 dark:bg-blue-900/50 text-blue-600 dark:text-blue-300 flex-shrink-0">
                                             <IoChatbubbleEllipsesOutline size={16} />
                                         </div>
                                        {/* Details */}
                                        <div className="flex-1 overflow-hidden">
                                             {/* Apply theme text colors */}
                                            <p className="text-sm font-medium text-gray-900 dark:text-gray-100 truncate group-hover:text-blue-600 dark:group-hover:text-blue-400 transition-colors" title={convo.title}>{convo.title}</p>
                                             <p className="text-xs text-gray-500 dark:text-gray-400 truncate" title={convo.summary}>{convo.summary}</p>
                                        </div>
                                         {/* Timestamp */}
                                        <div className="ml-4 text-right flex-shrink-0">
                                             {/* Apply theme text color */}
                                            <p className="text-xs text-gray-500 dark:text-gray-400 whitespace-nowrap">{formatTimestamp(convo.timestamp)}</p>
                                             {/* Optionally show message count */}
                                             {/* <p className="text-xs text-gray-400 dark:text-gray-500">{convo.messageCount} messages</p> */}
                                        </div>
                                    </li>
                                ))}
                            </ul>
                        ) : (
                            // Empty State
                             // Apply theme text colors
                            <div className="text-center py-12 px-4">
                                <IoTimeOutline className="mx-auto h-12 w-12 text-gray-400 dark:text-gray-500" />
                                <h3 className="mt-2 text-lg font-medium text-gray-900 dark:text-white">No Conversations Found</h3>
                                <p className="mt-1 text-sm text-gray-500 dark:text-gray-400 max-w-md mx-auto">
                                    {searchQuery || filterOptions.dateRange !== 'all' ? 'Try adjusting your search or filters.' : `No conversation history available for ${user?.name || 'this user'}.`}
                                </p>
                            </div>
                        )}
                    </div>
                </div>
            </div>
        </div>
    );
};

export default UserHistoryPage; 