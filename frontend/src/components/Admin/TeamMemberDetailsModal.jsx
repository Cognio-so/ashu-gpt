import React, { useState, useCallback, useMemo, useEffect, lazy, Suspense, memo } from 'react';
import { IoClose, IoPersonCircleOutline, IoAppsOutline } from 'react-icons/io5';
import { FiBox, FiPlus, FiTrash2 } from 'react-icons/fi';
import { axiosInstance } from '../../api/axiosInstance';
import { toast } from 'react-toastify';
import { useTheme } from '../../context/ThemeContext';
import { useAuth } from '../../context/AuthContext';
const AssignGptsModal = lazy(() => import('./AssignGptsModal'));

const TeamMemberDetailsModal = memo(({ isOpen, onClose, member }) => {
  const { user } = useAuth();
  const { isDarkMode } = useTheme();
  const [tabState, setTabState] = useState({
    activeTab: 'profile',
    data: { gpts: null },
    loading: { gpts: false },
  });
  const [showAssignGptsModal, setShowAssignGptsModal] = useState(false);

  const formatDate = useCallback((dateString) => {
    if (!dateString) return 'N/A';
    return new Date(dateString).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' });
  }, []);

  const formatRelativeTime = useCallback(
    (dateString) => {
      if (!dateString) return 'N/A';
      const date = new Date(dateString);
      const diffInSeconds = Math.floor((Date.now() - date) / 1000);
      if (diffInSeconds < 60) return 'Just now';
      if (diffInSeconds < 3600) return `${Math.floor(diffInSeconds / 60)} minutes ago`;
      if (diffInSeconds < 86400) return `${Math.floor(diffInSeconds / 3600)} hours ago`;
      if (diffInSeconds < 172800) return 'Yesterday';
      return formatDate(dateString);
    },
    [formatDate]
  );

  const handleApiError = (error, message) => {
    console.error(message, error);
    toast.error(message);
  };

  const fetchTabData = async (tabName) => {
    if (tabState.data[tabName]) return;
    setTabState((prev) => ({ ...prev, loading: { ...prev.loading, [tabName]: true } }));
    try {
      const response = await axiosInstance.get(`/api/custom-gpts/team/members/${member.id}/gpts`, {
        withCredentials: true,
      });
      setTabState((prev) => ({
        ...prev,
        data: { ...prev.data, gpts: response.data.gpts },
        loading: { ...prev.loading, gpts: false },
      }));
    } catch (error) {
      handleApiError(error, `Failed to fetch ${tabName}`);
    }
  };

  const refreshGpts = async () => {
    setTabState((prev) => ({ ...prev, loading: { ...prev.loading, gpts: true } }));
    try {
      const response = await axiosInstance.get(`/api/custom-gpts/team/members/${member.id}/gpts`, {
        withCredentials: true,
      });
      setTabState((prev) => ({
        ...prev,
        data: { ...prev.data, gpts: response.data.gpts },
        loading: { ...prev.loading, gpts: false },
      }));
    } catch (error) {
      handleApiError(error, 'Failed to refresh GPTs');
    }
  };

  const handleRemoveGpt = async (gptId) => {
    try {
      await axiosInstance.delete(`/api/custom-gpts/team/members/${member.id}/gpts/${gptId}`, {
        withCredentials: true,
      });
      setTabState((prev) => ({
        ...prev,
        data: { ...prev.data, gpts: prev.data.gpts.filter((gpt) => gpt._id !== gptId) },
      }));
      toast.success('GPT unassigned successfully');
    } catch (error) {
      handleApiError(error, 'Failed to unassign GPT');
    }
  };

  useEffect(() => {
    if (!isOpen || !member) return;
    fetchTabData(tabState.activeTab);
  }, [isOpen, member, tabState.activeTab]);

  useEffect(() => {
    if (!isOpen) {
      setTabState((prev) => ({ ...prev, data: { gpts: null } }));
    }
  }, [isOpen]);

  if (!isOpen || !member || user?._id === member.id) return null;

  const GptCard = ({ gpt, onRemove }) => (
    <div className="flex items-center justify-between p-3 rounded-lg bg-gray-700/50 border border-gray-600">
      <div className="flex items-center">
        <div className="w-10 h-10 rounded-full overflow-hidden bg-gradient-to-br from-blue-600 to-purple-600 flex items-center justify-center mr-3">
          {gpt.imageUrl ? (
            <img src={gpt.imageUrl} alt={gpt.name} className="w-full h-full object-cover" />
          ) : (
            <span className={`text-lg ${isDarkMode ? 'text-white' : 'text-gray-600'}`}>{gpt.name.charAt(0)}</span>
          )}
        </div>
        <div>
          <h4 className="font-medium text-white">{gpt.name}</h4>
          <p className="text-xs text-gray-400">{gpt.description}</p>
        </div>
      </div>
      <div className="flex items-center">
        <div className="text-xs text-gray-400 mr-4">Assigned: {formatRelativeTime(gpt.assignedAt)}</div>
        <button
          onClick={() => onRemove(gpt._id)}
          className="text-red-400 hover:text-red-300 p-1.5 hover:bg-gray-600 rounded-full transition-colors"
          title="Remove GPT"
        >
          <FiTrash2 size={18} />
        </button>
      </div>
    </div>
  );

  const renderProfileTab = () => (
    <div className="space-y-6 py-6 px-1">
      <div className="flex items-center space-x-4">
        <div className="h-16 w-16 rounded-full bg-gradient-to-br from-blue-500 to-purple-600 flex items-center justify-center text-white text-2xl font-medium flex-shrink-0">
          {member.name.charAt(0)}
        </div>

      </div>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div className="bg-gray-50 dark:bg-gray-700/50 rounded-lg p-4 border border-gray-200 dark:border-gray-600/50">
          <h3 className="text-sm font-medium text-gray-600 dark:text-gray-300 mb-3">Personal Information</h3>
          <div className="space-y-3">
            <div>
              <p className="text-xs text-gray-500 dark:text-gray-400">Email</p>
              <p className="text-sm text-gray-800 dark:text-white truncate" title={member.email}>
                {member.email}
              </p>
            </div>
            <div>
              <p className="text-xs text-gray-500 dark:text-gray-400">Department</p>
              <p className="text-sm text-gray-800 dark:text-white">{member.department}</p>
            </div>

          </div>
        </div>
        <div className="bg-gray-50 dark:bg-gray-700/50 rounded-lg p-4 border border-gray-200 dark:border-gray-600/50">
          <h3 className="text-sm font-medium text-gray-600 dark:text-gray-300 mb-3">Account Status</h3>
          <div className="space-y-3">
            <div>
              <p className="text-xs text-gray-500 dark:text-gray-400">Role</p>
              <p className="text-sm text-gray-800 dark:text-white">{member.role}</p>
            </div>
            <div>
              <p className="text-xs text-gray-500 dark:text-gray-400 mb-1">Status</p>
              <span
                className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${member.status === 'Active'
                    ? 'bg-green-100 dark:bg-green-900/50 text-green-800 dark:text-green-300'
                    : 'bg-red-100 dark:bg-red-900/50 text-red-800 dark:text-red-300'
                  }`}
              >
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
    </div>
  );

  const renderAssignedGptsTab = () => (
    <div className="py-4">
      <div className="flex justify-between items-center mb-4">
        <h3 className="text-lg font-medium text-white">Assigned GPTs ({tabState.data.gpts?.length || 0})</h3>
        <button
          className="bg-black dark:bg-white hover:bg-black/70 dark:hover:bg-white/70 text-white dark:text-black text-sm rounded-md px-3 py-1.5 flex items-center"
          onClick={() => setShowAssignGptsModal(true)}
        >
          <FiPlus className="mr-1.5" size={14} />
          Assign GPTs
        </button>
      </div>
      {tabState.loading.gpts ? (
        <div className="flex justify-center py-10">
          <div className="animate-spin rounded-full h-8 w-8 border-t-2 border-b-2 border-blue-500"></div>
        </div>
      ) : tabState.data.gpts?.length > 0 ? (
        <div className="space-y-3">
          {tabState.data.gpts.map((gpt) => (
            <GptCard key={gpt._id} gpt={gpt} onRemove={handleRemoveGpt} />
          ))}
        </div>
      ) : (
        <div className="text-center py-10 bg-gray-800 rounded-lg border border-gray-700">
          <FiBox className="mx-auto text-gray-500" size={32} />
          <p className="mt-2 text-gray-400">No GPTs assigned yet</p>
          <button
            className="mt-4 bg-blue-600 hover:bg-blue-700 text-white text-sm rounded-md px-4 py-2"
            onClick={() => setShowAssignGptsModal(true)}
          >
            Assign First GPT
          </button>
        </div>
      )}
    </div>
  );

  const tabs = [
    { id: 'profile', label: 'Profile', icon: IoPersonCircleOutline, render: renderProfileTab },
    { id: 'gpts', label: 'Assigned GPTs', icon: IoAppsOutline, render: renderAssignedGptsTab },
  ];

  const TabContent = useMemo(() => tabs.find((tab) => tab.id === tabState.activeTab)?.render() || null, [
    tabState.activeTab,
    member,
    tabState.data.gpts,
    tabState.loading.gpts,
    isDarkMode,
  ]);

  return (
    <>
      <div
        className={`fixed inset-0 z-50 flex items-center justify-center p-4 ${isOpen ? 'opacity-100' : 'opacity-0 pointer-events-none'
          } transition-opacity duration-300`}
      >
        <div className="absolute inset-0 bg-black/60 dark:bg-black/80" onClick={onClose}></div>
        <div
          className={`relative bg-white dark:bg-gray-800 w-full max-w-3xl max-h-[90vh] rounded-xl shadow-xl border border-gray-200 dark:border-gray-700 overflow-hidden flex flex-col transform ${isOpen ? 'scale-100' : 'scale-95'
            } transition-transform duration-300`}
        >
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
              {tabs.map((tab) => (
                <button
                  key={tab.id}
                  onClick={() => setTabState((prev) => ({ ...prev, activeTab: tab.id }))}
                  className={`px-4 py-2.5 border-b-2 text-sm font-medium transition-colors duration-200 flex items-center gap-2 whitespace-nowrap ${tabState.activeTab === tab.id
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
            {TabContent}
          </div>
        </div>
      </div>
      {showAssignGptsModal && member && (
        <Suspense fallback={<div>Loading...</div>}>
          <AssignGptsModal
            isOpen={showAssignGptsModal}
            onClose={() => {
              setShowAssignGptsModal(false);
              refreshGpts();
            }}
            teamMember={member}
            onAssignmentChange={refreshGpts}
          />
        </Suspense>
      )}
    </>
  );
});

export default TeamMemberDetailsModal;