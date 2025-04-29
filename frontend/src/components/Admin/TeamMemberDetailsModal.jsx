import React, { useState, useEffect, useRef } from 'react';
import { 
    IoClose, 
    IoPersonCircleOutline,
    IoMailOutline,
    IoBriefcaseOutline,
    IoCalendarOutline,
    IoTimeOutline,
    IoShieldCheckmarkOutline,
    IoAppsOutline,
    IoAdd,
    IoTrashOutline
} from 'react-icons/io5';
import { FiBox, FiMessageSquare, FiActivity, FiTrash2, FiEdit, FiPlus } from 'react-icons/fi';
import { axiosInstance } from '../../api/axiosInstance';
import { toast } from 'react-toastify';
import AssignGptsModal from './AssignGptsModal';
import { useTheme } from '../../context/ThemeContext';

const TeamMemberDetailsModal = ({ isOpen, onClose, member }) => {
    const [activeTab, setActiveTab] = useState('profile');
    const [memberGpts, setMemberGpts] = useState([]);
    const [userActivity, setUserActivity] = useState([]);
    const [userNotes, setUserNotes] = useState([]);
    const [loading, setLoading] = useState({
        gpts: false,
        activity: false,
        notes: false
    });
    const [noteText, setNoteText] = useState('');
    const [showAssignGptsModal, setShowAssignGptsModal] = useState(false);
    const { isDarkMode } = useTheme();
    
    // IMPROVEMENT 1: Cache data between tab switches
    const dataCache = useRef({
        gpts: null,
        activity: null,
        notes: null
    });

    // IMPROVEMENT 2: Combined data fetching function with caching
    const fetchTabData = async (tabName) => {
        // Skip if we already have cached data
        if (dataCache.current[tabName]) {
            if (tabName === 'gpts') setMemberGpts(dataCache.current.gpts);
            if (tabName === 'activity') setUserActivity(dataCache.current.activity);
            if (tabName === 'notes') setUserNotes(dataCache.current.notes);
            return;
        }

        // Set loading state just for this tab
        setLoading(prev => ({ ...prev, [tabName]: true }));
        
        try {
            let response;
            
            switch (tabName) {
                case 'gpts':
                    response = await axiosInstance.get(`/api/custom-gpts/team/members/${member.id}/gpts`, {
                        withCredentials: true
                    });
                    if (response.data && response.data.gpts) {
                        setMemberGpts(response.data.gpts);
                        dataCache.current.gpts = response.data.gpts;
                    }
                    break;
                    
                case 'activity':
                    response = await axiosInstance.get(`/api/auth/users/${member.id}/activity`, {
                        withCredentials: true
                    });
                    if (response.data && response.data.activities) {
                        setUserActivity(response.data.activities);
                        dataCache.current.activity = response.data.activities;
                    }
                    break;
                    
                case 'notes':
                    response = await axiosInstance.get(`/api/auth/users/${member.id}/notes`, {
                        withCredentials: true
                    });
                    if (response.data && response.data.notes) {
                        setUserNotes(response.data.notes);
                        dataCache.current.notes = response.data.notes;
                    }
                    break;
            }
        } catch (error) {
            console.error(`Error fetching ${tabName}:`, error);
            // Don't use sample data - just show error state
        } finally {
            setLoading(prev => ({ ...prev, [tabName]: false }));
        }
    };

    // IMPROVEMENT 3: Efficient tab switching - only load data when needed
    useEffect(() => {
        if (!isOpen || !member) return;
        
        // When tab changes, fetch data for that tab if needed
        fetchTabData(activeTab);
        
    }, [isOpen, member, activeTab]);

    // IMPROVEMENT 4: Clear cache when modal closes or member changes
    useEffect(() => {
        if (!isOpen) {
            // Reset cache when modal closes
            dataCache.current = {
                gpts: null,
                activity: null,
                notes: null
            };
        }
    }, [isOpen, member?.id]);

    // Handle adding a new note - update cache
    const handleAddNote = async () => {
        if (!noteText.trim()) return;
        
        try {
            const response = await axiosInstance.post(`/api/auth/users/${member.id}/notes`, {
                text: noteText.trim()
            }, {
                withCredentials: true
            });
            
            if (response.data && response.data.note) {
                const newNotes = [response.data.note, ...userNotes];
                setUserNotes(newNotes);
                dataCache.current.notes = newNotes; // Update cache
                setNoteText('');
                toast.success('Note added successfully');
            }
        } catch (error) {
            console.error("Error adding note:", error);
            toast.error('Failed to add note');
        }
    };

    // Handle removing a note - update cache
    const handleRemoveNote = async (noteId) => {
        try {
            await axiosInstance.delete(`/api/auth/users/${member.id}/notes/${noteId}`, {
                withCredentials: true
            });
            
            const updatedNotes = userNotes.filter(note => note.id !== noteId);
            setUserNotes(updatedNotes);
            dataCache.current.notes = updatedNotes; // Update cache
            toast.success('Note removed successfully');
        } catch (error) {
            console.error("Error removing note:", error);
            toast.error('Failed to remove note');
        }
    };

    // Handle removing a GPT assignment - update cache
    const handleRemoveGpt = async (gptId) => {
        try {
            await axiosInstance.delete(`/api/custom-gpts/team/members/${member.id}/gpts/${gptId}`, {
                withCredentials: true
            });
            
            const updatedGpts = memberGpts.filter(gpt => gpt._id !== gptId);
            setMemberGpts(updatedGpts);
            dataCache.current.gpts = updatedGpts; // Update cache
            toast.success('GPT unassigned successfully');
        } catch (error) {
            console.error("Error removing GPT assignment:", error);
            toast.error('Failed to unassign GPT');
        }
    };

    // IMPROVEMENT 5: Optimized handler for GPT assignment changes
    const handleGptAssignmentChange = async () => {
        try {
            const response = await axiosInstance.get(`/api/custom-gpts/team/members/${member.id}/gpts`, {
                withCredentials: true
            });
            
            if (response.data && response.data.gpts) {
                setMemberGpts(response.data.gpts);
                dataCache.current.gpts = response.data.gpts; // Update cache
            }
        } catch (error) {
            console.error("Error refreshing assigned GPTs:", error);
        }
    };

    // Add this function to handle assigning GPTs
    const handleAssignGpts = () => {
        console.log("Assign GPTs button clicked. Member:", member);
        setShowAssignGptsModal(true);
    };

    if (!isOpen || !member) return null;

    // Format date for display
    const formatDate = (dateString) => {
        if (!dateString) return 'N/A';
        const date = new Date(dateString);
        return date.toLocaleDateString('en-US', {
            year: 'numeric',
            month: 'short',
            day: 'numeric'
        });
    };

    // Format relative time
    const formatRelativeTime = (dateString) => {
        if (!dateString) return 'N/A';
        
        const date = new Date(dateString);
        const now = new Date();
        const diffInSeconds = Math.floor((now - date) / 1000);
        
        if (diffInSeconds < 60) return 'Just now';
        if (diffInSeconds < 3600) return `${Math.floor(diffInSeconds / 60)} minutes ago`;
        if (diffInSeconds < 86400) return `${Math.floor(diffInSeconds / 3600)} hours ago`;
        if (diffInSeconds < 172800) return 'Yesterday';
        
        return formatDate(dateString);
    };

    // Tab content components with theme styles
    const renderProfileTab = () => (
        <div className="space-y-6 py-6 px-1">
            {/* Profile Header */}
            <div className="flex items-center space-x-4">
                <div className="h-16 w-16 rounded-full bg-gradient-to-br from-blue-500 to-purple-600 flex items-center justify-center text-white text-2xl font-medium flex-shrink-0">
                    {member.name.charAt(0)}
                </div>
                <div>
                    <h2 className="text-xl font-semibold text-gray-900 dark:text-white">{member.name}</h2>
                    <p className="text-gray-500 dark:text-gray-400">{member.position || 'No position set'}</p>
                </div>
            </div>

            {/* Member Info Sections */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="bg-gray-50 dark:bg-gray-700/50 rounded-lg p-4 border border-gray-200 dark:border-gray-600/50">
                    <h3 className="text-sm font-medium text-gray-600 dark:text-gray-300 mb-3 flex items-center">
                        <IoPersonCircleOutline className="mr-2" size={18} />
                        Personal Information
                    </h3>
                    <div className="space-y-3">
                        <div>
                            <p className="text-xs text-gray-500 dark:text-gray-400">Email</p>
                            <p className="text-sm text-gray-800 dark:text-white truncate" title={member.email}>{member.email}</p>
                        </div>
                        <div>
                            <p className="text-xs text-gray-500 dark:text-gray-400">Department</p>
                            <p className="text-sm text-gray-800 dark:text-white">{member.department}</p>
                        </div>
                        <div>
                            <p className="text-xs text-gray-500 dark:text-gray-400">Position</p>
                            <p className="text-sm text-gray-800 dark:text-white">{member.position || 'Not set'}</p>
                        </div>
                    </div>
                </div>

                <div className="bg-gray-50 dark:bg-gray-700/50 rounded-lg p-4 border border-gray-200 dark:border-gray-600/50">
                    <h3 className="text-sm font-medium text-gray-600 dark:text-gray-300 mb-3 flex items-center">
                        <IoShieldCheckmarkOutline className="mr-2" size={18} />
                        Account Status
                    </h3>
                    <div className="space-y-3">
                        <div>
                            <p className="text-xs text-gray-500 dark:text-gray-400">Role</p>
                            <p className="text-sm text-gray-800 dark:text-white">{member.role}</p>
                        </div>
                        <div>
                            <p className="text-xs text-gray-500 dark:text-gray-400 mb-1">Status</p>
                            <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${
                                member.status === 'Active'
                                    ? 'bg-green-100 dark:bg-green-900/50 text-green-800 dark:text-green-300'
                                    : 'bg-red-100 dark:bg-red-900/50 text-red-800 dark:text-red-300'
                            }`}>
                                <IoBriefcaseOutline className={`mr-1 ${member.status === 'Active' ? 'text-green-500' : 'text-red-500'}`} size={12} />
                                {member.status}
                            </span>
                        </div>
                        <div>
                            <p className="text-xs text-gray-500 dark:text-gray-400">Joined Date</p>
                            <p className="text-sm text-gray-800 dark:text-white">{formatDate(member.joined)}</p>
                        </div>
                        <div>
                            <p className="text-xs text-gray-500 dark:text-gray-400">Last Active</p>
                            <p className="text-sm text-gray-800 dark:text-white">{formatRelativeTime(member.lastActive)}</p>
                        </div>
                    </div>
                </div>
            </div>

            {/* Activity Stats */}
            <div className="bg-gray-700/50 rounded-lg p-4 border border-gray-600">
                <h3 className="text-sm font-medium text-gray-300 mb-3 flex items-center">
                    <FiActivity className="mr-2" size={18} />
                    Activity &amp; GPTs
                </h3>
                
                <div className="grid grid-cols-2 md:grid-cols-3 gap-4">
                    <div className="bg-gray-800 rounded p-3">
                        <p className="text-xs text-gray-400">Last Active</p>
                        <p className="text-sm font-medium text-white">{member.lastActive}</p>
                    </div>
                    <div className="bg-gray-800 rounded p-3">
                        <p className="text-xs text-gray-400">Assigned GPTs</p>
                        <p className="text-sm font-medium text-white">{member.assignedGPTs}</p>
                    </div>
                    <div className="bg-gray-800 rounded p-3">
                        <p className="text-xs text-gray-400">Member Since</p>
                        <p className="text-sm font-medium text-white">{member.joined}</p>
                    </div>
                </div>
            </div>
        </div>
    );

    const renderAssignedGptsTab = () => {
        return (
            <div className="py-4">
                <div className="flex justify-between items-center mb-4">
                    <h3 className="text-lg font-medium text-white">Assigned GPTs ({memberGpts.length})</h3>
                    <button 
                        className="bg-blue-600 hover:bg-blue-700 text-white text-sm rounded-md px-3 py-1.5 flex items-center"
                        onClick={handleAssignGpts}
                    >
                        <FiPlus className="mr-1.5" size={14} />
                        Assign GPTs
                    </button>
                </div>

                {loading.gpts ? (
                    <div className="flex justify-center py-10">
                        <div className="animate-spin rounded-full h-8 w-8 border-t-2 border-b-2 border-blue-500"></div>
                    </div>
                ) : memberGpts.length > 0 ? (
                    <div className="space-y-3">
                        {memberGpts.map((gpt) => (
                            <div key={gpt._id} className="flex items-center justify-between p-3 rounded-lg bg-gray-700/50 border border-gray-600">
                                <div className="flex items-center">
                                    <div className="w-10 h-10 rounded-full overflow-hidden bg-gradient-to-br from-blue-600 to-purple-600 flex items-center justify-center mr-3">
                                        {gpt.imageUrl ? (
                                            <img src={gpt.imageUrl} alt={gpt.name} className="w-full h-full object-cover" />
                                        ) : (
                                            <span className={`text-lg text-white ${isDarkMode ? 'text-white' : 'text-gray-600'}`}>{gpt.name.charAt(0)}</span>
                                        )}
                                    </div>
                                    <div>
                                        <h4 className="font-medium text-white">{gpt.name}</h4>
                                        <p className="text-xs text-gray-400">{gpt.description}</p>
                                    </div>
                                </div>
                                <div className="flex items-center">
                                    <div className="text-xs text-gray-400 mr-4">
                                        Assigned: {formatRelativeTime(gpt.assignedAt)}
                                    </div>
                                    <button 
                                        onClick={() => handleRemoveGpt(gpt._id)}
                                        className="text-red-400 hover:text-red-300 p-1.5 hover:bg-gray-600 rounded-full transition-colors"
                                        title="Remove GPT"
                                    >
                                        <FiTrash2 size={18} />
                                    </button>
                                </div>
                            </div>
                        ))}
                    </div>
                ) : (
                    <div className="text-center py-10 bg-gray-800 rounded-lg border border-gray-700">
                        <FiBox className="mx-auto text-gray-500" size={32} />
                        <p className="mt-2 text-gray-400">No GPTs assigned yet</p>
                        <button 
                            className="mt-4 bg-blue-600 hover:bg-blue-700 text-white text-sm rounded-md px-4 py-2"
                            onClick={handleAssignGpts}
                        >
                            Assign First GPT
                        </button>
                    </div>
                )}
            </div>
        );
    };

    const renderActivityTab = () => (
        <div className="py-4">
            <h3 className="text-lg font-medium text-white mb-4">Recent Activity</h3>
            
            {loading.activity ? (
                <div className="flex justify-center py-10">
                    <div className="animate-spin rounded-full h-8 w-8 border-t-2 border-b-2 border-blue-500"></div>
                </div>
            ) : userActivity.length > 0 ? (
                <div className="space-y-4">
                    <div className="relative">
                        <div className="absolute top-0 bottom-0 left-2.5 w-0.5 bg-gray-700" />
                        
                        {userActivity.map((activity, index) => (
                            <div key={index} className="flex items-start mb-4 relative">
                                <div className="absolute left-0 mt-1.5">
                                    <div className="h-5 w-5 rounded-full bg-blue-600 flex items-center justify-center ring-4 ring-gray-800 z-10">
                                        <FiMessageSquare size={12} className="text-white" />
                                    </div>
                                </div>
                                
                                <div className="ml-10">
                                    <div className="bg-gray-700/50 rounded-lg p-3 border border-gray-600">
                                        {activity.type === 'gpt_usage' ? (
                                            <>
                                                <p className="text-sm text-white">Used <span className="font-medium">{activity.gptName}</span> GPT</p>
                                                <p className="text-xs text-gray-400 mt-1">Created {activity.messages} messages in conversation</p>
                                            </>
                                        ) : activity.type === 'login' ? (
                                            <p className="text-sm text-white">Logged into the platform</p>
                                        ) : (
                                            <p className="text-sm text-white">{activity.description || 'Unknown activity'}</p>
                                        )}
                                    </div>
                                    <div className="text-xs text-gray-500 mt-1">
                                        {formatRelativeTime(activity.date)}
                                    </div>
                                </div>
                            </div>
                        ))}
                    </div>
                </div>
            ) : (
                <div className="text-center py-10 bg-gray-800 rounded-lg border border-gray-700">
                    <FiActivity className="mx-auto text-gray-500" size={32} />
                    <p className="mt-2 text-gray-400">No activity recorded yet</p>
                </div>
            )}
        </div>
    );

    const renderNotesTab = () => (
        <div className="py-4">
            <div className="flex justify-between items-center mb-4">
                <h3 className="text-lg font-medium text-white">Notes</h3>
            </div>
            
            <div className="bg-gray-700/50 rounded-lg p-4 border border-gray-600 mb-4">
                <textarea 
                    className="w-full bg-gray-800 border border-gray-600 rounded-md p-3 text-white text-sm resize-none focus:outline-none focus:ring-2 focus:ring-blue-500 h-24"
                    placeholder="Add notes about this team member..."
                    value={noteText}
                    onChange={(e) => setNoteText(e.target.value)}
                ></textarea>
                <div className="flex justify-end mt-2">
                    <button 
                        onClick={handleAddNote}
                        disabled={!noteText.trim()}
                        className="bg-blue-600 hover:bg-blue-700 text-white text-sm rounded-md px-4 py-2 disabled:opacity-50 disabled:cursor-not-allowed"
                    >
                        Save Note
                    </button>
                </div>
            </div>
            
            {loading.notes ? (
                <div className="flex justify-center py-10">
                    <div className="animate-spin rounded-full h-8 w-8 border-t-2 border-b-2 border-blue-500"></div>
                </div>
            ) : userNotes.length > 0 ? (
                <div className="space-y-4">
                    {userNotes.map((note) => (
                        <div key={note.id} className="bg-gray-700/50 rounded-lg p-4 border border-gray-600">
                            <div className="flex justify-between items-start">
                                <div className="flex-1">
                                    <p className="text-sm text-white">{note.text}</p>
                                    <p className="text-xs text-gray-400 mt-2">Added by {note.createdBy} • {formatDate(note.createdAt)}</p>
                                </div>
                                <button 
                                    className="text-gray-500 hover:text-gray-400"
                                    onClick={() => handleRemoveNote(note.id)}
                                >
                                    <IoTrashOutline size={18} />
                                </button>
                            </div>
                        </div>
                    ))}
                </div>
            ) : (
                <div className="text-center py-10 bg-gray-800 rounded-lg border border-gray-700">
                    <FiMessageSquare className="mx-auto text-gray-500" size={32} />
                    <p className="mt-2 text-gray-400">No notes added yet</p>
                </div>
            )}
        </div>
    );

    return (
        <>
            <div className={`fixed inset-0 z-50 flex items-center justify-center p-4 ${isOpen ? 'opacity-100' : 'opacity-0 pointer-events-none'} transition-opacity duration-300`}>
                <div className="absolute inset-0 bg-black/60 dark:bg-black/80" onClick={onClose}></div>
                
                <div className={`relative bg-white dark:bg-gray-800 w-full max-w-3xl max-h-[90vh] rounded-xl shadow-xl border border-gray-200 dark:border-gray-700 overflow-hidden flex flex-col transform ${isOpen ? 'scale-100' : 'scale-95'} transition-transform duration-300`}>
                    <div className="px-6 py-4 border-b border-gray-200 dark:border-gray-700 flex justify-between items-center bg-gray-50 dark:bg-gray-900 flex-shrink-0">
                        <h3 className="text-lg font-semibold text-gray-900 dark:text-white truncate pr-4">
                            Member Details: {member?.name}
                        </h3>
                        <button 
                            onClick={onClose}
                            className="text-gray-400 hover:text-gray-600 dark:text-gray-500 dark:hover:text-white transition-colors rounded-full p-1 hover:bg-gray-200 dark:hover:bg-gray-700 flex-shrink-0"
                        >
                            <IoClose size={22} />
                        </button>
                    </div>

                    <div className="px-6 pt-4 border-b border-gray-200 dark:border-gray-700 flex-shrink-0 bg-white dark:bg-gray-800">
                        <div className="flex gap-1 -mb-px">
                            {[
                                { id: 'profile', label: 'Profile', icon: IoPersonCircleOutline },
                                { id: 'gpts', label: 'Assigned GPTs', icon: IoAppsOutline },
                                { id: 'activity', label: 'Activity', icon: FiActivity },
                                { id: 'notes', label: 'Notes', icon: IoBriefcaseOutline },
                            ].map(tab => (
                                <button
                                    key={tab.id}
                                    onClick={() => setActiveTab(tab.id)}
                                    className={`px-4 py-2.5 border-b-2 text-sm font-medium transition-colors duration-200 flex items-center gap-2 whitespace-nowrap ${
                                        activeTab === tab.id
                                            ? 'border-blue-500 text-blue-600 dark:text-blue-400'
                                            : 'border-transparent text-gray-500 dark:text-gray-400 hover:text-gray-800 dark:hover:text-white hover:border-gray-300 dark:hover:border-gray-600'
                                    }`}
                                >
                                    <tab.icon size={16} /> {tab.label}
                                </button>
                            ))}
                        </div>
                    </div>
                    
                    <div className="flex-1 overflow-y-auto p-6 bg-gray-50 dark:bg-gray-800/50 custom-scrollbar-dark dark:custom-scrollbar">
                        {activeTab === 'profile' && renderProfileTab()}
                        {activeTab === 'gpts' && renderAssignedGptsTab()}
                        {activeTab === 'activity' && renderActivityTab()}
                        {activeTab === 'notes' && renderNotesTab()}
                    </div>
                </div>
            </div>
            
            {showAssignGptsModal && member && (
                <div className="fixed inset-0 z-[60]">
                    <AssignGptsModal 
                        isOpen={showAssignGptsModal}
                        onClose={() => {
                            console.log("Closing AssignGptsModal");
                            setShowAssignGptsModal(false);
                            // Refresh the GPTs list after assignment
                            if (member) {
                                const fetchAssignedGpts = async () => {
                                    setLoading(prev => ({ ...prev, gpts: true }));
                                    try {
                                        const response = await axiosInstance.get(`/api/custom-gpts/team/members/${member.id}/gpts`, {
                                            withCredentials: true
                                        });
                                        
                                        if (response.data && response.data.gpts) {
                                            setMemberGpts(response.data.gpts);
                                        }
                                    } catch (error) {
                                        console.error("Error fetching assigned GPTs:", error);
                                        toast.error("Could not load assigned GPTs");
                                    } finally {
                                        setLoading(prev => ({ ...prev, gpts: false }));
                                    }
                                };
                                
                                fetchAssignedGpts();
                            }
                        }}
                        teamMember={member}
                        onAssignmentChange={handleGptAssignmentChange}
                    />
                </div>
            )}
        </>
    );
};

export default TeamMemberDetailsModal; 