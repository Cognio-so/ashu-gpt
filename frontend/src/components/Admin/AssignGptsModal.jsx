import React, { useState, useEffect } from 'react';
import { IoClose } from 'react-icons/io5';
import { FiSearch, FiCheck } from 'react-icons/fi';
import { axiosInstance } from '../../api/axiosInstance';
import { toast } from 'react-toastify';
import { useTheme } from '../../context/ThemeContext'; // Import useTheme

const AssignGptsModal = ({ isOpen, onClose, teamMember, onAssignmentChange }) => { // Added onAssignmentChange
    const [allGpts, setAllGpts] = useState([]);
    // selectedGpts state removed, using assignedGptIds and temporary selection
    const [searchTerm, setSearchTerm] = useState('');
    const [loading, setLoading] = useState(true);
    const [assignedGptIds, setAssignedGptIds] = useState(new Set());
    const [saving, setSaving] = useState(false); // State for save operation
    const [locallySelectedIds, setLocallySelectedIds] = useState(new Set()); // Track selections made in this modal session

    const { isDarkMode } = useTheme(); // Use theme context

    // Fetch all GPTs and user's assigned GPTs
    useEffect(() => {
        if (!isOpen || !teamMember) return;

        const fetchData = async () => {
            setLoading(true);
            setLocallySelectedIds(new Set()); // Reset local selections on open
            try {
                const [allGptsResponse, userGptsResponse] = await Promise.all([
                    axiosInstance.get('/api/custom-gpts', { withCredentials: true }),
                    axiosInstance.get(`/api/custom-gpts/team/members/${teamMember.id}/gpts`, { withCredentials: true })
                ]);

                if (allGptsResponse.data?.customGpts) {
                    setAllGpts(allGptsResponse.data.customGpts);
                }

                if (userGptsResponse.data?.gpts) {
                    const assignedIds = new Set(userGptsResponse.data.gpts.map(gpt => gpt._id));
                    setAssignedGptIds(assignedIds);
                    setLocallySelectedIds(assignedIds); // Initialize local selection with current assignments
                } else {
                    setAssignedGptIds(new Set()); // Ensure it's a set even if fetch fails
                    setLocallySelectedIds(new Set());
                }

            } catch (error) {
                console.error("Error fetching GPTs:", error);
                toast.error(`Failed to load GPT data: ${error.response?.data?.message || error.message}`);
                setAssignedGptIds(new Set()); // Reset on error
                setLocallySelectedIds(new Set());
            } finally {
                setLoading(false);
            }
        };

        fetchData();
    }, [isOpen, teamMember]);

    // Toggle local selection of a GPT ID
    const toggleGptSelection = (gptId) => {
        setLocallySelectedIds(prev => {
            const newSet = new Set(prev);
            if (newSet.has(gptId)) {
                newSet.delete(gptId); // Unselect
            } else {
                newSet.add(gptId); // Select
            }
            return newSet;
        });
    };


    // Assign/Unassign GPTs based on the difference between initial and final selections
    const handleSaveChanges = async () => {
        setSaving(true);
        let errors = [];

        try {
            const initialAssignedIds = assignedGptIds;
            const finalSelectedIds = locallySelectedIds;

            const idsToAssign = [...finalSelectedIds].filter(id => !initialAssignedIds.has(id));
            const idsToUnassign = [...initialAssignedIds].filter(id => !finalSelectedIds.has(id));


            // Process assignments one by one instead of using Promise.all
            for (const gptId of idsToAssign) {
                try {
                    // Ensure we're using the correct content type and body format
                    await axiosInstance.post(
                        `/api/custom-gpts/team/members/${teamMember.id}/gpts`,
                        { gptId }, // Make sure this matches exactly what the backend expects
                        {
                            withCredentials: true,
                            headers: {
                                'Content-Type': 'application/json'
                            }
                        }
                    );
                } catch (err) {
                    console.error(`Failed to assign GPT ${gptId}:`, err.response?.data || err.message);
                    errors.push({ type: 'assign', gptId, error: err.response?.data?.message || err.message });
                }
            }

            // Process unassignments one by one
            for (const gptId of idsToUnassign) {
                try {
                    await axiosInstance.delete(
                        `/api/custom-gpts/team/members/${teamMember.id}/gpts/${gptId}`,
                        { withCredentials: true }
                    );
                } catch (err) {
                    console.error(`Failed to unassign GPT ${gptId}:`, err.response?.data || err.message);
                    errors.push({ type: 'unassign', gptId, error: err.response?.data?.message || err.message });
                }
            }

            // Determine message based on results
            if (errors.length === 0) {
                let successMessage = "Assignments updated successfully.";
                if (idsToAssign.length > 0 && idsToUnassign.length === 0) {
                    successMessage = `Assigned ${idsToAssign.length} GPT(s).`;
                } else if (idsToUnassign.length > 0 && idsToAssign.length === 0) {
                    successMessage = `Unassigned ${idsToUnassign.length} GPT(s).`;
                } else if (idsToAssign.length > 0 && idsToUnassign.length > 0) {
                    successMessage = `Assigned ${idsToAssign.length}, Unassigned ${idsToUnassign.length} GPT(s).`;
                }
                toast.success(successMessage);
            } else {
                // Some operations failed
                if (errors.length < (idsToAssign.length + idsToUnassign.length)) {
                    // Partial success
                    toast.warning(`Some operations failed. ${errors.length} error(s) occurred.`);
                } else {
                    // All operations failed
                    toast.error("Failed to update assignments. Please try again.");
                }
            }

            // Always call the callback, even if there were some errors
            if (onAssignmentChange) {
                onAssignmentChange(teamMember.id);
            }

            onClose();
        } catch (error) {
            console.error("Error in handleSaveChanges:", error);
            toast.error(`Failed to update assignments: ${error.message}`);
        } finally {
            setSaving(false);
        }
    };


    // Filter GPTs based on search term
    const filteredGpts = allGpts.filter(gpt =>
        gpt.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
        (gpt.description && gpt.description.toLowerCase().includes(searchTerm.toLowerCase()))
    );

    if (!isOpen) return null;

    const changesMade = (() => {
        if (assignedGptIds.size !== locallySelectedIds.size) return true;
        for (const id of assignedGptIds) {
            if (!locallySelectedIds.has(id)) return true;
        }
        return false;
    })();


    return (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
            {/* Apply theme overlay */}
            <div className="absolute inset-0 bg-black/60 dark:bg-black/80" onClick={onClose}></div>

            <div className="relative bg-white dark:bg-gray-800 w-full max-w-2xl max-h-[90vh] rounded-xl shadow-xl border border-gray-200 dark:border-gray-700 overflow-hidden flex flex-col">
                <div className="px-6 py-4 border-b border-gray-200 dark:border-gray-700 flex justify-between items-center bg-gray-50 dark:bg-gray-900 flex-shrink-0">
                    <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
                        Assign GPTs to {teamMember?.name}
                    </h3>
                    <button
                        onClick={onClose}
                        className="text-gray-400 hover:text-gray-600 dark:text-gray-500 dark:hover:text-white transition-colors rounded-full p-1 hover:bg-gray-200 dark:hover:bg-gray-700"
                    >
                        <IoClose size={22} />
                    </button>
                </div>

                <div className="p-4 border-b border-gray-200 dark:border-gray-700 flex-shrink-0">
                    <div className="relative">
                        <FiSearch className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400 dark:text-gray-500" />
                        <input
                            type="text"
                            placeholder="Search GPTs..."
                            value={searchTerm}
                            onChange={(e) => setSearchTerm(e.target.value)}
                            className="w-full pl-10 pr-4 py-2 rounded-lg bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-600 focus:ring-2 focus:ring-blue-500 focus:border-transparent outline-none text-sm text-black dark:text-white placeholder-gray-500 dark:placeholder-gray-400"
                        />
                    </div>
                </div>

                <div className="flex-1 overflow-y-auto custom-scrollbar-dark dark:custom-scrollbar">
                    {loading ? (
                        <div className="flex justify-center items-center h-40 text-gray-500 dark:text-gray-400">
                            <div className="animate-spin rounded-full h-8 w-8 border-t-2 border-b-2 border-blue-500"></div>
                        </div>
                    ) : filteredGpts.length === 0 ? (
                        <div className="p-6 text-center text-gray-500 dark:text-gray-400">
                            No GPTs found{searchTerm && ` matching "${searchTerm}"`}.
                        </div>
                    ) : (
                        <div className="space-y-2 p-4">
                            {filteredGpts.map(gpt => {
                                const isSelected = locallySelectedIds.has(gpt._id);

                                return (
                                    <div
                                        key={gpt._id}
                                        className={`
                                            p-3 rounded-lg border transition-colors duration-150 flex items-center cursor-pointer
                                            ${isSelected
                                                ? 'bg-blue-50 dark:bg-blue-900/30 border-blue-300 dark:border-blue-700 ring-1 ring-blue-400 dark:ring-blue-600'
                                                : 'bg-white dark:bg-gray-700/50 border-gray-200 dark:border-gray-600 hover:bg-gray-50 dark:hover:bg-gray-700'
                                            }
                                        `}
                                        onClick={() => toggleGptSelection(gpt._id)}
                                    >

                                        <div className="flex-shrink-0 w-10 h-10 rounded-full overflow-hidden bg-gradient-to-br from-gray-200 to-gray-300 dark:from-blue-600 dark:to-purple-600 flex items-center justify-center mr-3">
                                            {gpt.imageUrl ? (
                                                <img src={gpt.imageUrl} alt={gpt.name} className="w-full h-full object-cover" />
                                            ) : (
                                                <span className={`text-lg ${isDarkMode ? 'text-white' : 'text-gray-600'}`}>{gpt.name.charAt(0)}</span>
                                            )}
                                        </div>

                                        <div className="flex-1 mr-3 overflow-hidden">
                                            <h3 className="font-medium truncate text-gray-900 dark:text-white" title={gpt.name}>{gpt.name}</h3>
                                            <p className="text-xs text-gray-500 dark:text-gray-400 line-clamp-1" title={gpt.description}>{gpt.description}</p>
                                        </div>

                                        <div className="flex-shrink-0">
                                            <div className={`w-5 h-5 rounded border-2 flex items-center justify-center transition-all duration-150 ${isSelected
                                                    ? 'bg-blue-600 border-blue-600'
                                                    : 'bg-white dark:bg-gray-600 border-gray-300 dark:border-gray-500 group-hover:border-gray-400 dark:group-hover:border-gray-400'
                                                }`}>
                                                {isSelected && <FiCheck className="text-white" size={14} strokeWidth={3} />}
                                            </div>
                                        </div>
                                    </div>
                                );
                            })}
                        </div>
                    )}
                </div>


                <div className="px-6 py-4 border-t border-gray-200 dark:border-gray-700 flex justify-between items-center bg-gray-50 dark:bg-gray-900 flex-shrink-0">

                    <div className="text-sm text-gray-600 dark:text-gray-400">
                        {locallySelectedIds.size} GPT(s) selected
                    </div>
                    <div className="flex space-x-3">

                        <button
                            onClick={onClose}
                            className="px-4 py-2 bg-white dark:bg-gray-700 border border-gray-300 dark:border-gray-600 text-gray-800 dark:text-white rounded-lg font-medium hover:bg-gray-50 dark:hover:bg-gray-600 transition-colors text-sm"
                        >
                            Cancel
                        </button>
                        <button
                            onClick={handleSaveChanges}
                            disabled={!changesMade || saving}
                            className="px-4 py-2 bg-black dark:bg-white text-white dark:text-black rounded-lg font-medium hover:bg-black/70 dark:hover:bg-white/70 transition-colors disabled:opacity-60 disabled:cursor-not-allowed text-sm flex items-center"
                        >
                            {saving && <div className="animate-spin rounded-full h-4 w-4 border-t-2 border-b-2 border-white mr-2"></div>}
                            {saving ? 'Saving...' : 'Save Changes'}
                        </button>
                    </div>
                </div>
            </div>
        </div>
    );
};

export default AssignGptsModal;