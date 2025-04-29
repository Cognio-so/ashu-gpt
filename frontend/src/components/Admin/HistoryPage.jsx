import React, { useState, useEffect, useRef } from 'react';
import { 
  IoPersonOutline, 
  IoPeopleOutline, 
  IoTimeOutline,
  IoSearchOutline,
  IoFilterOutline,
  IoChevronDown,
  IoEllipse,
  IoArrowBack
} from 'react-icons/io5';
import { useNavigate, useLocation } from 'react-router-dom';
import { useTheme } from '../../context/ThemeContext'; // Import useTheme

// Import team member data
import { teamMembers } from './teamData';
import { axiosInstance } from '../../api/axiosInstance';


const HistoryPage = () => {
  const navigate = useNavigate();
  const location = useLocation();
  const { isDarkMode } = useTheme(); // Get theme state
  
  // Initialize view type from URL parameter or default to 'personal'
  const queryParams = new URLSearchParams(location.search);
  const initialView = queryParams.get('view') || 'personal';
  
  const [viewType, setViewType] = useState(initialView);
  const [isLoading, setIsLoading] = useState(false);
  const [activities, setActivities] = useState([]);
  const [filteredActivities, setFilteredActivities] = useState([]);
  const [searchQuery, setSearchQuery] = useState('');
  const [filterOpen, setFilterOpen] = useState(false);
  const [filterOptions, setFilterOptions] = useState({
    actionTypes: {
      create: true,
      edit: true,
      delete: true,
      settings: true,
    },
    dateRange: 'all',
  });
  
  const filterDropdownRef = useRef(null);

  useEffect(() => {
    const fetchActivityData = async () => {
      setIsLoading(true);
      try {
        setTimeout(() => {
          const mockData = generateMockData(viewType);
          setActivities(mockData);
          setFilteredActivities(mockData);
          setIsLoading(false);
        }, 800);
      } catch (error) {
        console.error("Error fetching activity data:", error);
        setIsLoading(false);
      }
    };

    fetchActivityData();
  }, [viewType]);

  // Filter activities based on search query and filter options
  useEffect(() => {
    let filtered = [...activities];
    
    // Apply search filter
    if (searchQuery) {
      filtered = filtered.filter(activity => 
        activity.action.toLowerCase().includes(searchQuery.toLowerCase()) ||
        activity.details.toLowerCase().includes(searchQuery.toLowerCase()) ||
        (activity.user && activity.user.name.toLowerCase().includes(searchQuery.toLowerCase()))
      );
    }
    
    // Apply action type filters
    filtered = filtered.filter(activity => {
      const actionType = getActionType(activity.action);
      return filterOptions.actionTypes[actionType];
    });
    
    // Apply date range filter
    if (filterOptions.dateRange !== 'all') {
      const now = new Date();
      let cutoffDate;
      
      if (filterOptions.dateRange === 'today') {
        cutoffDate = new Date(now.setHours(0, 0, 0, 0));
      } else if (filterOptions.dateRange === 'week') {
        cutoffDate = new Date(now.setDate(now.getDate() - 7));
      } else if (filterOptions.dateRange === 'month') {
        cutoffDate = new Date(now.setMonth(now.getMonth() - 1));
      }
      
      filtered = filtered.filter(activity => new Date(activity.timestamp) >= cutoffDate);
    }
    
    setFilteredActivities(filtered);
  }, [searchQuery, filterOptions, activities]);

  // Helper function to determine action type
  const getActionType = (action) => {
    if (action.includes('Created') || action.includes('Added')) return 'create';
    if (action.includes('Edited') || action.includes('Updated') || action.includes('Modified')) return 'edit';
    if (action.includes('Deleted') || action.includes('Removed')) return 'delete';
    if (action.includes('Changed settings') || action.includes('Updated settings')) return 'settings';
    return 'edit'; // Default
  };

  // Generate random mock data using actual team member data
  const generateMockData = (type) => {
    const actions = [
      'Created new custom GPT',
      'Edited custom GPT settings',
      'Updated API keys',
      'Changed settings',
      'Deleted inactive GPT',
      'Added new team member',
      'Modified user permissions',
      'Updated profile information'
    ];
    
    let users = [];
    
    if (type === 'personal') {
      users = [{ id: '1', name: 'You', email: 'you@gptnexus.com', avatar: null }];
    } else {
      // Filter out admin users from team view
      users = teamMembers
        .filter(member => member.role !== 'Admin')
        .map(member => ({
          id: member.id.toString(),
          name: member.name,
          email: member.email,
          avatar: null,
          department: member.department,
          position: member.position,
          role: member.role,
          status: member.status
        }));
    }
    
    const gptNames = [
      'Research Assistant',
      'Code Helper',
      'Creative Writer',
      'Data Analyst',
      'Customer Support',
      'Language Tutor'
    ];
    
    const mockData = [];
    
    // Generate some random activities
    for (let i = 0; i < 25; i++) {
      const userIndex = type === 'personal' ? 0 : Math.floor(Math.random() * users.length);
      const actionIndex = Math.floor(Math.random() * actions.length);
      const action = actions[actionIndex];
      
      let details = '';
      if (action.includes('GPT')) {
        const gptName = gptNames[Math.floor(Math.random() * gptNames.length)];
        details = `"${gptName}" GPT`;
      } else if (action.includes('team member')) {
        details = users[Math.floor(Math.random() * users.length)].name;
      } else if (action.includes('permissions')) {
        details = `for ${users[Math.floor(Math.random() * users.length)].name}`;
      } else {
        details = 'Global settings';
      }
      
      // Generate a random date within the last 45 days
      const now = new Date();
      const daysAgo = Math.floor(Math.random() * 45);
      const hoursAgo = Math.floor(Math.random() * 24);
      const minutesAgo = Math.floor(Math.random() * 60);
      const timestamp = new Date(now);
      timestamp.setDate(timestamp.getDate() - daysAgo);
      timestamp.setHours(timestamp.getHours() - hoursAgo);
      timestamp.setMinutes(timestamp.getMinutes() - minutesAgo);
      
      mockData.push({
        id: i + 1,
        user: users[userIndex],
        action,
        details,
        timestamp: timestamp.toISOString(),
      });
    }
    
    // Sort by timestamp, most recent first
    return mockData.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
  };

  // Format the timestamp
  const formatTimestamp = (timestamp) => {
    const date = new Date(timestamp);
    const now = new Date();
    const diffTime = Math.abs(now - date);
    const diffDays = Math.floor(diffTime / (1000 * 60 * 60 * 24));
    const diffHours = Math.floor(diffTime / (1000 * 60 * 60));
    
    // Simplified timestamp format
    if (diffDays === 0) {
      if (diffHours < 1) {
        return 'Just now';
      } else if (diffHours < 2) {
        return '1 hour ago';
      } else if (diffHours < 24) {
        return `${diffHours} hours ago`;
      }
      return 'Today';
    } else if (diffDays === 1) {
      return 'Yesterday';
    } else if (diffDays < 7) {
      return `${diffDays} days ago`;
    } else {
      return date.toLocaleDateString(undefined, {
        month: 'short',
        day: 'numeric',
        year: 'numeric'
      });
    }
  };

  // Toggle filter options
  const toggleFilterOption = (type, value) => {
    setFilterOptions(prev => ({
      ...prev,
      actionTypes: {
        ...prev.actionTypes,
        [type]: value
      }
    }));
  };

  // Set date range filter
  const setDateRangeFilter = (range) => {
    setFilterOptions(prev => ({
      ...prev,
      dateRange: range
    }));
    setFilterOpen(false); // Close on selection
  };

  // Click outside hook for filter dropdown
  useEffect(() => {
    function handleClickOutside(event) {
      if (filterDropdownRef.current && !filterDropdownRef.current.contains(event.target)) {
        setFilterOpen(false);
      }
    }
    document.addEventListener("mousedown", handleClickOutside);
    return () => document.removeEventListener("mousedown", handleClickOutside);
  }, [filterDropdownRef]);

  // When view type changes, update URL
  useEffect(() => {
    // Update URL when view type changes without navigating
    const newUrl = `/admin/history?view=${viewType}`;
    window.history.replaceState(null, '', newUrl);
  }, [viewType]);

  // CSS for hiding scrollbars
  const scrollbarHideStyles = `
    .hide-scrollbar::-webkit-scrollbar {
      display: none;
    }
    .hide-scrollbar {
      -ms-overflow-style: none;  /* IE and Edge */
      scrollbar-width: none;  /* Firefox */
    }
  `;

  return (
    <div className={`flex flex-col h-full ${isDarkMode ? 'dark' : ''} bg-white dark:bg-black text-gray-900 dark:text-gray-100 overflow-hidden`}>
      {/* Add hidden scrollbar styles */}
      <style>{scrollbarHideStyles}</style>
      
      {/* Header section */}
      <div className="px-6 pt-6 pb-5 flex-shrink-0 border-b border-gray-300 dark:border-gray-800">
        <h1 className="text-2xl font-semibold text-gray-900 dark:text-white">Activity History</h1>
        <p className="text-sm text-gray-500 dark:text-gray-400 mt-1">Track actions and changes across your workspace</p>
      </div>
      
      {/* Controls section */}
      <div className="px-6 py-4 flex-shrink-0 border-b border-gray-300 dark:border-gray-800">
        <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-4">
          {/* View switcher */}
          <div className="inline-flex items-center p-1 rounded-lg bg-gray-100 dark:bg-gray-900 border border-gray-300 dark:border-gray-700 self-center sm:self-start">
            <button
              onClick={() => setViewType('personal')}
              className={`flex items-center px-3 py-1.5 rounded text-sm transition-all ${
                viewType === 'personal'
                  ? 'bg-gray-300 dark:bg-gray-700 text-gray-900 dark:text-white font-medium'
                  : 'text-gray-500 dark:text-gray-400 hover:text-gray-800 dark:hover:text-white hover:bg-gray-200 dark:hover:bg-gray-800'
              }`}
            >
              <IoPersonOutline size={16} className="mr-1.5" />
              <span>Personal</span>
            </button>
            <button
              onClick={() => setViewType('team')}
              className={`flex items-center px-3 py-1.5 rounded text-sm transition-all ${
                viewType === 'team'
                  ? 'bg-gray-300 dark:bg-gray-700 text-gray-900 dark:text-white font-medium'
                  : 'text-gray-500 dark:text-gray-400 hover:text-gray-800 dark:hover:text-white hover:bg-gray-200 dark:hover:bg-gray-800'
              }`}
            >
              <IoPeopleOutline size={16} className="mr-1.5" />
              <span>Team</span>
            </button>
          </div>
          
          {/* Search and filter */}
          <div className="flex flex-1 sm:justify-end max-w-lg gap-2 self-center w-full sm:w-auto">
            <div className="relative flex-1 sm:max-w-xs">
              <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                <IoSearchOutline className="text-gray-400 dark:text-gray-500" size={18} />
              </div>
              <input
                type="text"
                className="w-full pl-10 pr-3 py-2 bg-gray-100 dark:bg-gray-900 border border-gray-300 dark:border-gray-700 rounded-lg text-gray-900 dark:text-gray-100 text-sm placeholder-gray-500 dark:placeholder-gray-500 focus:outline-none focus:ring-1 focus:ring-gray-500 focus:border-gray-500"
                placeholder="Search activities..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
              />
            </div>
            
            <div className="relative" ref={filterDropdownRef}>
              <button
                onClick={() => setFilterOpen(!filterOpen)}
                className="flex items-center px-3 py-2 bg-gray-100 dark:bg-gray-900 border border-gray-300 dark:border-gray-700 rounded-lg text-sm text-gray-600 dark:text-gray-300 hover:bg-gray-200 dark:hover:bg-gray-800 hover:border-gray-400 dark:hover:border-gray-600 transition-colors"
              >
                <IoFilterOutline size={16} className="mr-1.5" />
                <span>Filter</span>
                <IoChevronDown size={14} className={`ml-1 transition-transform ${filterOpen ? 'rotate-180' : ''}`} />
              </button>
              
              {/* Filter Dropdown */}
              {filterOpen && (
                <div className="absolute right-0 mt-2 w-60 rounded-lg bg-gray-100 dark:bg-gray-900 border border-gray-300 dark:border-gray-700 shadow-2xl z-20 p-4">
                  <div className="mb-4">
                    <h3 className="text-gray-700 dark:text-gray-300 font-medium text-sm mb-2">Action Types</h3>
                    <div className="space-y-1.5">
                      {Object.keys(filterOptions.actionTypes).map((type) => (
                        <label key={type} className="flex items-center text-sm">
                          <input
                            type="checkbox"
                            className="form-checkbox h-4 w-4 rounded bg-gray-200 dark:bg-gray-700 border-gray-400 dark:border-gray-600 text-blue-500 focus:ring-blue-500 focus:ring-offset-gray-100 dark:focus:ring-offset-gray-900"
                            checked={filterOptions.actionTypes[type]}
                            onChange={(e) => toggleFilterOption(type, e.target.checked)}
                          />
                          <span className="ml-2 text-gray-700 dark:text-gray-300 capitalize">{type}</span>
                        </label>
                      ))}
                    </div>
                  </div>
                  
                  <div>
                    <h3 className="text-gray-700 dark:text-gray-300 font-medium text-sm mb-2">Time Period</h3>
                    <div className="grid grid-cols-2 gap-2">
                      {['today', 'week', 'month', 'all'].map((range) => (
                        <button
                          key={range}
                          className={`px-2 py-1 rounded text-xs font-medium transition-colors ${
                            filterOptions.dateRange === range
                              ? 'bg-blue-600 text-white'
                              : 'bg-gray-200 dark:bg-gray-800 text-gray-600 dark:text-gray-400 hover:bg-gray-300 dark:hover:bg-gray-700 hover:text-gray-800 dark:hover:text-gray-200'
                          }`}
                          onClick={() => setDateRangeFilter(range)}
                        >
                          {range === 'all' ? 'All Time' : `Last ${range}`}
                        </button>
                      ))}
                    </div>
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
      
      {/* Timeline content - add hide-scrollbar class */}
      <div className="flex-1 overflow-y-auto py-6 px-4 flex justify-center hide-scrollbar">
        {isLoading ? (
          <div className="flex items-center justify-center h-full">
            <div className="rounded-full h-10 w-10 border-t-2 border-b-2 border-blue-500 animate-spin"></div>
          </div>
        ) : filteredActivities.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-full text-center text-gray-500 dark:text-gray-500 px-4">
            <div className="border-2 border-gray-300 dark:border-gray-800 rounded-full p-4 mb-4">
              <IoTimeOutline size={32} className="text-gray-400 dark:text-gray-600" />
            </div>
            <h3 className="text-lg font-medium text-gray-700 dark:text-gray-300 mb-1">No Activities Found</h3>
            <p className="text-sm max-w-sm">
              {searchQuery || filterOptions.dateRange !== 'all' || !Object.values(filterOptions.actionTypes).every(v => v)
                ? "No activities match your current filters. Try adjusting your search or filter criteria."
                : `No activities recorded yet for the ${viewType} view. Changes will appear here.`
              }
            </p>
          </div>
        ) : (
          <div className="w-full max-w-4xl">
            <div className="space-y-3 relative border-l border-gray-300 dark:border-gray-800 ml-4">
              {filteredActivities.map((activity) => (
                <div 
                  key={activity.id} 
                  className="relative bg-gray-100 dark:bg-gray-800 hover:bg-gray-200 dark:hover:bg-gray-750 border border-gray-300 dark:border-gray-700 rounded-lg p-4 ml-4 transition-colors"
                >
                  {/* Timeline marker dot */}
                  <div className="absolute -left-[10px] top-[50%] transform -translate-y-1/2 flex items-center justify-center w-5 h-5 rounded-full bg-gray-200 dark:bg-gray-700 border-2 border-gray-300 dark:border-gray-600">
                    <IoEllipse size={6} className="text-gray-500 dark:text-gray-400"/> 
                  </div>
                  
                  {/* Activity content */}
                  <div className="flex justify-between items-start gap-4">
                    <div>
                      {viewType === 'team' && (
                        <div className="mb-1.5 flex items-center">
                          <span 
                            className="font-semibold text-gray-900 dark:text-white cursor-pointer hover:underline"
                            onClick={() => navigate(`/admin/history/user/${activity.user.id}?view=${viewType}`)}
                          >
                            {activity.user.name}
                          </span>
                        </div>
                      )}
                      
                      <p className="text-sm">
                        <span className="text-gray-700 dark:text-gray-300">{activity.action}</span>
                        {activity.details && (
                          <> <span className="font-medium text-gray-900 dark:text-white">{activity.details}</span></>
                        )}
                      </p>
                    </div>
                    
                    <div className="text-xs text-gray-500 dark:text-gray-500 whitespace-nowrap">
                      {formatTimestamp(activity.timestamp)}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default HistoryPage;