import React, { useState, useEffect } from 'react';
import { IoClose, IoBriefcaseOutline, IoRibbonOutline, IoPersonOutline } from 'react-icons/io5';
import { axiosInstance } from '../../api/axiosInstance';
import { toast } from 'react-toastify';
import { useTheme } from '../../context/ThemeContext';

const EditPermissionsModal = ({ isOpen, onClose, member, onPermissionsUpdated }) => {
  const [role, setRole] = useState('Employee');
  const [department, setDepartment] = useState('Not Assigned');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const { isDarkMode } = useTheme();

  useEffect(() => {
    if (member) {
      setRole(member.role || 'Employee');
      setDepartment(member.department || 'Not Assigned');
    }
  }, [member]);

  if (!isOpen || !member) return null;

  const handleSubmit = async (e) => {
    e.preventDefault();
    setIsSubmitting(true);

    try {
      const response = await axiosInstance.put(`/api/auth/users/${member.id}/permissions`, {
        role,
        department,
      }, { withCredentials: true });

      if (response.data.success) {
        toast.success('Permissions updated successfully');

        const updatedRole = response.data.user.role.charAt(0).toUpperCase() + response.data.user.role.slice(1);

        onPermissionsUpdated({
          ...member,
          role: updatedRole,
          department: response.data.user.department,
        });
        onClose();
      } else {
        const errorMessage = response.data.message || 'Failed to update permissions';
        toast.error(errorMessage);
      }
    } catch (error) {
      const errorMessage = error.response?.data?.message || 'Failed to update permissions';
      toast.error(errorMessage);
      console.error("Permission update error:", error);
    } finally {
      setIsSubmitting(false);
    }
  };

  const SelectInput = ({ id, label, value, onChange, children, icon: Icon }) => (
    <div>
      <label htmlFor={id} className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
        {label}
      </label>
      <div className="relative">
        {Icon && <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
          <Icon className="text-gray-400 dark:text-gray-500" size={16} />
        </div>}
        <select
          id={id}
          value={value}
          onChange={onChange}
          className={`appearance-none w-full ${Icon ? 'pl-10' : 'pl-3'} pr-8 py-2 rounded-lg bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-600 focus:ring-2 focus:ring-blue-500 focus:border-transparent outline-none text-sm text-black dark:text-white`}
        >
          {children}
        </select>
        <div className="absolute inset-y-0 right-0 pr-3 flex items-center pointer-events-none">
          <svg className="h-5 w-5 text-gray-400" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
            <path fillRule="evenodd" d="M5.293 7.293a1 1 0 011.414 0L10 10.586l3.293-3.293a1 1 0 111.414 1.414l-4 4a1 1 0 01-1.414 0l-4-4a1 1 0 010-1.414z" clipRule="evenodd" />
          </svg>
        </div>
      </div>
    </div>
  );

  const TextInput = ({ id, label, value, onChange, placeholder, icon: Icon }) => (
    <div>
      <label htmlFor={id} className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
        {label}
      </label>
      <div className="relative">
        {Icon && <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
          <Icon className="text-gray-400 dark:text-gray-500" size={16} />
        </div>}
        <input
          id={id}
          type="text"
          value={value}
          onChange={onChange}
          placeholder={placeholder}
          className={`w-full ${Icon ? 'pl-10' : 'pl-3'} pr-3 py-2 rounded-lg bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-600 focus:ring-2 focus:ring-blue-500 focus:border-transparent outline-none text-sm text-black dark:text-white placeholder-gray-500 dark:placeholder-gray-400`}
        />
      </div>
    </div>
  );

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 dark:bg-black/80 transition-opacity duration-300">
      <div className="relative bg-white dark:bg-gray-800 w-full max-w-md rounded-xl shadow-xl border border-gray-200 dark:border-gray-700 overflow-hidden transform transition-transform duration-300 scale-100">
        <div className="px-6 py-4 border-b border-gray-200 dark:border-gray-700 flex justify-between items-center bg-gray-50 dark:bg-gray-900">
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white">Edit Member Permissions</h3>
          <button
            onClick={onClose}
            className="text-gray-400 hover:text-gray-600 dark:text-gray-500 dark:hover:text-white transition-colors rounded-full p-1 hover:bg-gray-200 dark:hover:bg-gray-700"
          >
            <IoClose size={22} />
          </button>
        </div>

        <form onSubmit={handleSubmit} className="px-6 py-6 space-y-5">
          <div className="mb-2">
            <label className="block text-xs font-medium text-gray-500 dark:text-gray-400 mb-1">
              Member
            </label>
            <div className="flex items-center p-3 bg-gray-100 dark:bg-gray-700/60 rounded-lg border border-gray-200 dark:border-gray-600/50">
              <div className="h-10 w-10 rounded-full bg-gradient-to-br from-blue-500 to-purple-600 flex items-center justify-center text-white text-lg font-medium mr-3 flex-shrink-0">
                {member.name.charAt(0)}
              </div>
              <div>
                <div className="text-gray-900 dark:text-white font-medium">{member.name}</div>
                <div className="text-gray-500 dark:text-gray-400 text-sm">{member.email}</div>
              </div>
            </div>
          </div>

          <SelectInput
            id="edit-role"
            label="Role"
            value={role}
            onChange={(e) => setRole(e.target.value)}
            icon={IoRibbonOutline}
          >
            <option value="Admin">Admin</option>
            <option value="Employee">Employee</option>
          </SelectInput>

          <SelectInput
            id="edit-department"
            label="Department"
            value={department}
            onChange={(e) => setDepartment(e.target.value)}
            icon={IoBriefcaseOutline}
          >
            <option value="Not Assigned">Not Assigned</option>
            <option value="Product">Product</option>
            <option value="Engineering">Engineering</option>
            <option value="Design">Design</option>
            <option value="Marketing">Marketing</option>
            <option value="Sales">Sales</option>
            <option value="Customer Support">Customer Support</option>
          </SelectInput>



          <div className="pt-5 border-t border-gray-200 dark:border-gray-700 flex justify-end gap-3">
            <button
              type="button"
              onClick={onClose}
              className="px-4 py-2 bg-white dark:bg-gray-700 border border-gray-300 dark:border-gray-600 text-gray-800 dark:text-white rounded-lg font-medium hover:bg-gray-50 dark:hover:bg-gray-600 transition-colors text-sm"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={isSubmitting}
              className="px-4 py-2 bg-black dark:bg-white text-white dark:text-black rounded-lg font-medium hover:bg-blue-700 transition-colors disabled:opacity-60 disabled:cursor-not-allowed text-sm min-w-[150px] flex justify-center items-center"
            >
              {isSubmitting ? (
                <>
                  <svg className="animate-spin -ml-1 mr-2 h-4 w-4 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                  </svg>
                  Updating...
                </>
              ) : 'Update Permissions'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};

export default EditPermissionsModal;