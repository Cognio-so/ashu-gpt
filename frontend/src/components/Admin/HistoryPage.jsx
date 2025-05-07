import React, { useState, useEffect, useRef } from 'react';
import {
  IoPersonOutline,
  IoPeopleOutline,
  IoTimeOutline,
  IoSearchOutline,
  IoFilterOutline,
  IoChevronDown,
  IoEllipse,
  IoArrowBack,
  IoChatbubblesOutline
} from 'react-icons/io5';
import { useNavigate, useLocation } from 'react-router-dom';
import { useTheme } from '../../context/ThemeContext'; // Import useTheme
import { useAuth } from '../../context/AuthContext';
import { axiosInstance } from '../../api/axiosInstance';

// Import team member data
import { teamMembers } from './teamData';

const HistoryPage = () => {
  const navigate = useNavigate();
  const location = useLocation();
  const { isDarkMode } = useTheme(); // Get theme state
  const { user } = useAuth();

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
      chat: true,
    },
    dateRange: 'all',
  });

  const filterDropdownRef = useRef(null);

  // Fetch real chat history data
  useEffect(() => {
    const fetchActivityData = async () => {
      if (!user?._id) return;

      setIsLoading(true);
      try {
        // For personal view - fetch user's own chat history
        if (viewType === 'personal') {
          const response = await axiosInstance.get(
            `/api/chat-history/user/${user._id}`,
            { withCredentials: true }
          );

          if (response.data.success && response.data.conversations) {
            const conversations = response.data.conversations;

            // Format conversations for display
            const formattedHistory = conversations.map(convo => ({
              id: convo._id,
              user: { id: user._id, name: user.name || 'You', email: user.email || '' },
              action: 'Chat conversation',
              details: `with ${convo.gptName || 'AI Assistant'}`,
              timestamp: convo.updatedAt || convo.createdAt,
              conversation: convo,
              type: 'chat'
            }));

            setActivities(formattedHistory);
            setFilteredActivities(formattedHistory);
          } else {
            setActivities([]);
            setFilteredActivities([]);
          }
        }
        // For team view - fetch all team chat history except current user's
        else if (viewType === 'team') {
          try {
            // Check if user is an admin
            if (user.role !== 'admin') {
              setViewType('personal');
              return;
            }

            const response = await axiosInstance.get(
              `/api/chat-history/team`,
              { withCredentials: true }
            );

            if (response.data.success && response.data.conversations) {
              const conversations = response.data.conversations;

              // Filter out the current admin's own conversations if desired
              const teamConversations = conversations.filter(
                convo => convo.userId !== user._id
              );

              // Group conversations by user ID
              const userActivityMap = new Map();

              teamConversations.forEach(convo => {
                const userId = convo.userId;
                if (!userId) return; // Skip conversations without a user ID

                if (!userActivityMap.has(userId)) {
                  userActivityMap.set(userId, {
                    userId: userId,
                    userName: convo.userName || 'Team Member',
                    userEmail: convo.userEmail || '',
                    conversationCount: 0,
                    lastActivityTimestamp: new Date(0), // Initialize for comparison
                    lastGptName: '',
                  });
                }

                const userData = userActivityMap.get(userId);
                userData.conversationCount += 1;

                const currentTimestamp = new Date(convo.updatedAt || convo.createdAt);
                if (currentTimestamp > userData.lastActivityTimestamp) {
                  userData.lastActivityTimestamp = currentTimestamp;
                  userData.lastGptName = convo.gptName || 'AI Assistant';
                }
              });

              // Convert map to an array of user summaries
              const userSummaries = Array.from(userActivityMap.values());

              // Sort users by last activity (most recent first)
              userSummaries.sort((a, b) =>
                b.lastActivityTimestamp - a.lastActivityTimestamp
              );

              // Format for display
              const formattedHistory = userSummaries.map(summary => ({
                id: summary.userId, // Use userId as the key/id for the summary item
                user: {
                  id: summary.userId,
                  name: summary.userName,
                  email: summary.userEmail
                },
                action: `Had ${summary.conversationCount} conversation(s)`,
                details: `Last interaction with ${summary.lastGptName}`,
                timestamp: summary.lastActivityTimestamp,
                type: 'user_summary' // New type to differentiate rendering
              }));

              setActivities(formattedHistory);
              setFilteredActivities(formattedHistory);

            } else {
              setActivities([]);
              setFilteredActivities([]);
            }
          } catch (error) {
            console.warn("Team history view error:", error);

            // Handle errors appropriately
            if (error.response?.status === 403) {
              setViewType('personal');
            } else {
              setViewType('personal');
            }
          }
        }
      } catch (error) {
        console.error("Error fetching activity data:", error);
        setActivities([]);
        setFilteredActivities([]);
      } finally {
        setIsLoading(false);
      }
    };

    fetchActivityData();
  }, [user, viewType]);

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
    if (action.includes('Chat conversation')) return 'chat';
    if (action.includes('Created') || action.includes('Added')) return 'create';
    if (action.includes('Edited') || action.includes('Updated') || action.includes('Modified')) return 'edit';
    if (action.includes('Deleted') || action.includes('Removed')) return 'delete';
    if (action.includes('Changed settings') || action.includes('Updated settings')) return 'settings';
    return 'chat'; // Default to chat as most activities will be chats now
  };

  // Handle chat history item click
  const handleChatHistoryClick = (conversation) => {
    if (conversation && conversation.gptId) {
      navigate(`/admin/chat/${conversation.gptId}?loadHistory=true&conversationId=${conversation._id}`);
    }
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

  // Determine if team view is available
  const isTeamViewAvailable = user?.role === 'admin';

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
              className={`flex items-center px-3 py-1.5 rounded text-sm transition-all ${viewType === 'personal'
                  ? 'bg-gray-300 dark:bg-gray-700 text-gray-900 dark:text-white font-medium'
                  : 'text-gray-500 dark:text-gray-400 hover:text-gray-800 dark:hover:text-white hover:bg-gray-200 dark:hover:bg-gray-800'
                }`}
            >
              <IoPersonOutline size={16} className="mr-1.5" />
              <span>Personal</span>
            </button>
            <button
              onClick={() => isTeamViewAvailable ? setViewType('team') : null}
              className={`flex items-center px-3 py-1.5 rounded text-sm transition-all ${viewType === 'team'
                  ? 'bg-gray-300 dark:bg-gray-700 text-gray-900 dark:text-white font-medium'
                  : isTeamViewAvailable
                    ? 'text-gray-500 dark:text-gray-400 hover:text-gray-800 dark:hover:text-white hover:bg-gray-200 dark:hover:bg-gray-800'
                    : 'text-gray-400 dark:text-gray-600 cursor-not-allowed'
                }`}
              title={isTeamViewAvailable ? 'View team history' : 'Requires admin privileges'}
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
                          className={`px-2 py-1 rounded text-xs font-medium transition-colors ${filterOptions.dateRange === range
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
                : viewType === 'team'
                  ? "No team activities found. Team member activity will appear here."
                  : "No personal activities recorded yet. Your chat history will appear here."
              }
            </p>
          </div>
        ) : (
          <div className="w-full max-w-4xl">
            <div className="space-y-3 relative border-l border-gray-300 dark:border-gray-800 ml-4">
              {filteredActivities.map((activity) => (
                <div
                  key={activity.id}
                  className={`relative bg-gray-100 dark:bg-gray-800 hover:bg-gray-200 dark:hover:bg-gray-750 border border-gray-300 dark:border-gray-700 rounded-lg p-4 ml-4 transition-colors ${(activity.type === 'user_summary' || activity.type === 'chat') ? 'cursor-pointer group' : ''
                    } ${activity.type === 'user_summary' ? '' : activity.isSecondaryUserConvo ? 'ml-8 border-l-4 border-l-blue-500/30' : ''}`}

                  onClick={() => {
                    if (activity.type === 'user_summary') {
                      navigate(`/admin/history/user/${activity.user.id}?view=${viewType}`);
                    } else if (activity.type === 'chat' && activity.conversation) {
                      navigate(`/admin/chat/${activity.conversation.gptId}?conversationId=${activity.conversation._id}`);
                    }
                  }}
                >
                  <div className="absolute -left-[10px] top-[50%] transform -translate-y-1/2 flex items-center justify-center w-5 h-5 rounded-full bg-gray-200 dark:bg-gray-700 border-2 border-gray-300 dark:border-gray-600">
                    {activity.type === 'user_summary' ? (
                      <IoPersonOutline size={10} className="text-purple-500" />
                    ) : activity.type === 'chat' && activity.isSecondaryUserConvo ? (
                      <IoChatbubblesOutline size={10} className={'text-blue-400'} />
                    ) : activity.type === 'chat' ? (
                      <IoChatbubblesOutline size={10} className={'text-blue-500'} />
                    ) : (
                      <IoEllipse size={6} className="text-gray-500 dark:text-gray-400" />
                    )}
                  </div>

                  <div className="flex justify-between items-start gap-4">
                    <div>
                      {(activity.type === 'user_summary' || (viewType === 'personal' && activity.type === 'chat') || (viewType === 'team' && !activity.isSecondaryUserConvo)) && activity.user && (
                        <div className="mb-1.5 flex items-center">
                          <span
                            className={`font-semibold text-gray-900 dark:text-white ${activity.type === 'user_summary' ? 'cursor-pointer group-hover:underline' : ''}`}
                            onClick={(e) => {
                              if (activity.type === 'user_summary') {
                                e.stopPropagation();
                                navigate(`/admin/history/user/${activity.user.id}?view=${viewType}`);
                              }
                            }}
                          >
                            {viewType === 'personal' ? 'You' : activity.user?.name || 'Team Member'}

                            {activity.type === 'user_summary' && activity.totalUserConversations > 1 && (
                              <span className="ml-2 text-xs font-normal text-gray-500 dark:text-gray-400">
                                ({activity.totalUserConversations} conversations)
                              </span>
                            )}
                          </span>
                        </div>
                      )}

                      {viewType === 'team' && activity.isSecondaryUserConvo && (
                        <div className="text-xs text-gray-500 dark:text-gray-400 mb-1">
                          Same user, different conversation
                        </div>
                      )}

                      <p className="text-sm">
                        <span className="text-gray-700 dark:text-gray-300">{activity.action}</span>

                        {activity.details && (
                          <> - <span className="font-medium text-gray-900 dark:text-white">{activity.details}</span></>
                        )}
                      </p>

                      {activity.type === 'chat' && activity.conversation?.messages && activity.conversation.messages.length > 0 && (
                        <div className="mt-2 bg-gray-200 dark:bg-gray-700 rounded p-2 text-xs text-gray-600 dark:text-gray-300">
                          <div className="line-clamp-1">
                            <span className="font-semibold">Last message: </span>
                            {activity.conversation.lastMessage || activity.conversation.messages[activity.conversation.messages.length - 1].content.substring(0, 50)}
                          </div>
                          <div className="mt-1 text-gray-500 dark:text-gray-400 text-[10px] group-hover:text-blue-600 dark:group-hover:text-blue-400 transition-colors">
                            Click to view conversation
                          </div>
                        </div>
                      )}
                    </div>

                    <div className="text-xs text-gray-500 dark:text-gray-500 whitespace-nowrap flex-shrink-0">
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