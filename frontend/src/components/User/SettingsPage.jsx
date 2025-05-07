import React, { useState, useEffect, useCallback, memo, useRef } from 'react';
import { useAuth } from '../../context/AuthContext';
import { useTheme } from '../../context/ThemeContext';
import {
  FiUser, FiBell, FiMonitor, FiChevronRight,
  FiEdit2, FiCamera, FiCheck, FiInfo, FiXCircle, FiCheckCircle, FiLoader
} from 'react-icons/fi';
import { axiosInstance } from '../../api/axiosInstance';

// Account settings section component
const AccountSettings = memo(({
  formData,
  handleInputChange,
  handleAccountUpdate,
  handlePasswordChange,
  handleImageUpload,
  isDarkMode,
  toggleTheme,
  message,
  setMessage,
  isUpdatingAccount,
  isUpdatingPassword
}) => {
  const profileImageInputRef = useRef(null);

  const triggerImageUpload = () => {
    profileImageInputRef.current?.click();
  };

  return (
    <div className="animate-fadeIn">
      <div className="mb-8">
        <h2 className={`text-xl font-semibold mb-1 ${isDarkMode ? 'text-white' : 'text-gray-900'}`}>Account Information</h2>
        <p className={`text-sm ${isDarkMode ? 'text-gray-400' : 'text-gray-600'}`}>Manage your personal information and profile picture</p>
      </div>

      <div className="mb-8">
        <div className="flex items-center justify-center md:justify-start mb-6">
          <div className="relative">
            <div className={`w-24 h-24 rounded-full overflow-hidden border-2 ${isDarkMode
                ? 'bg-gradient-to-br from-blue-800 to-purple-800 border-white/10'
                : 'bg-gradient-to-br from-blue-100 to-purple-100 border-gray-300'
              }`}>
              {formData.profileImage ? (
                <img
                  src={formData.profileImage instanceof File ? URL.createObjectURL(formData.profileImage) : formData.profileImage}
                  alt="Profile"
                  className="w-full h-full object-cover"
                />
              ) : (
                <div className="w-full h-full flex items-center justify-center">
                  <span className={`text-3xl font-semibold ${isDarkMode ? 'text-white/70' : 'text-gray-500'}`}>
                    {formData.name ? formData.name.charAt(0).toUpperCase() : 'U'}
                  </span>
                </div>
              )}
            </div>
            <button
              type="button"
              onClick={triggerImageUpload}
              className={`absolute bottom-0 right-0 p-1.5 rounded-full cursor-pointer border-2 hover:bg-blue-700 transition-colors ${isDarkMode
                  ? 'bg-blue-600 border-gray-800 text-white'
                  : 'bg-blue-500 border-white text-white'
                }`}
              title="Change profile picture"
            >
              <FiCamera size={16} />
            </button>
            <input
              ref={profileImageInputRef}
              type="file"
              accept="image/*"
              onChange={handleImageUpload}
              className="hidden"
              name="profileImageInput"
            />
          </div>
        </div>

        <form onSubmit={handleAccountUpdate} className="space-y-5">
          <div>
            <label className={`block text-sm font-medium mb-1.5 ${isDarkMode ? 'text-gray-300' : 'text-gray-700'}`}>Full Name</label>
            <input
              type="text"
              name="name"
              value={formData.name}
              onChange={handleInputChange}
              className={`w-full border rounded-lg py-2.5 px-3 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition duration-200 ${isDarkMode
                  ? 'bg-gray-800 border-gray-700 text-white placeholder-gray-500'
                  : 'bg-white border-gray-300 text-gray-900 placeholder-gray-400'
                }`}
              placeholder="Your full name"
              disabled={isUpdatingAccount}
            />
          </div>

          <div>
            <label className={`block text-sm font-medium mb-1.5 ${isDarkMode ? 'text-gray-300' : 'text-gray-700'}`}>Email Address</label>
            <input
              type="email"
              name="email"
              value={formData.email}
              onChange={handleInputChange}
              className={`w-full border rounded-lg py-2.5 px-3 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition duration-200 ${isDarkMode
                  ? 'bg-gray-800 border-gray-700 text-white placeholder-gray-500'
                  : 'bg-white border-gray-300 text-gray-900 placeholder-gray-400'
                }`}
              placeholder="your.email@example.com"
              disabled={isUpdatingAccount}
            />
            <p className={`mt-1 text-xs ${isDarkMode ? 'text-gray-500' : 'text-gray-500'}`}>Your email address is used for notifications and account recovery</p>
          </div>

          <div className="pt-2">
            <button
              type="submit"
              disabled={isUpdatingAccount || isUpdatingPassword}
              className={`text-white py-2.5 px-5 rounded-lg transition duration-200 font-medium flex items-center justify-center min-w-[130px] ${isDarkMode
                  ? 'bg-blue-600 hover:bg-blue-700'
                  : 'bg-blue-500 hover:bg-blue-600'
                } ${isUpdatingAccount ? 'opacity-70 cursor-not-allowed' : ''}`}
            >
              {isUpdatingAccount ? (
                <>
                  <FiLoader className="animate-spin mr-2" size={18} /> Saving...
                </>
              ) : (
                'Save Changes'
              )}
            </button>
          </div>
        </form>
      </div>

      <div className={`border-t pt-8 mb-8 ${isDarkMode ? 'border-gray-700' : 'border-gray-200'}`}>
        <h2 className={`text-xl font-semibold mb-1 ${isDarkMode ? 'text-white' : 'text-gray-900'}`}>Appearance</h2>
        <p className={`text-sm mb-5 ${isDarkMode ? 'text-gray-400' : 'text-gray-600'}`}>Customize how the application looks</p>
        <div className="space-y-5">
          <div className="flex justify-between items-center">
            <div>
              <h3 className={`text-base font-medium ${isDarkMode ? 'text-gray-100' : 'text-gray-800'}`}>Dark Mode</h3>
              <p className={`text-sm ${isDarkMode ? 'text-gray-400' : 'text-gray-600'}`}>Use dark theme throughout the application</p>
            </div>
            <label className="relative inline-flex items-center cursor-pointer">
              <input
                type="checkbox"
                name="darkMode"
                checked={isDarkMode}
                onChange={() => toggleTheme()}
                className="sr-only peer"
              />
              <div className={`w-11 h-6 rounded-full peer peer-focus:outline-none peer-focus:ring-2 peer-focus:ring-blue-500 after:content-[''] after:absolute after:top-[2px] after:start-[2px] after:border after:rounded-full after:h-5 after:w-5 after:transition-all ${isDarkMode
                  ? 'bg-blue-600 after:translate-x-full after:border-white after:bg-white'
                  : 'bg-gray-300 after:border-gray-400 after:bg-white'
                }`}></div>
            </label>
          </div>
        </div>
      </div>

      <div className={`border-t pt-8 ${isDarkMode ? 'border-gray-700' : 'border-gray-200'}`}>
        <h2 className={`text-xl font-semibold mb-1 ${isDarkMode ? 'text-white' : 'text-gray-900'}`}>Change Password</h2>
        <p className={`text-sm mb-5 ${isDarkMode ? 'text-gray-400' : 'text-gray-600'}`}>Update your password to maintain account security</p>

        <form onSubmit={handlePasswordChange} className="space-y-5">
          <div>
            <label className={`block text-sm font-medium mb-1.5 ${isDarkMode ? 'text-gray-300' : 'text-gray-700'}`}>Current Password</label>
            <input
              type="password"
              name="currentPassword"
              value={formData.currentPassword}
              onChange={handleInputChange}
              className={`w-full border rounded-lg py-2.5 px-3 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition duration-200 ${isDarkMode
                  ? 'bg-gray-800 border-gray-700 text-white placeholder-gray-500'
                  : 'bg-white border-gray-300 text-gray-900 placeholder-gray-400'
                }`}
              placeholder="••••••••••••"
              disabled={isUpdatingPassword}
            />
          </div>

          <div>
            <label className={`block text-sm font-medium mb-1.5 ${isDarkMode ? 'text-gray-300' : 'text-gray-700'}`}>New Password</label>
            <input
              type="password"
              name="newPassword"
              value={formData.newPassword}
              onChange={handleInputChange}
              className={`w-full border rounded-lg py-2.5 px-3 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition duration-200 ${isDarkMode
                  ? 'bg-gray-800 border-gray-700 text-white placeholder-gray-500'
                  : 'bg-white border-gray-300 text-gray-900 placeholder-gray-400'
                }`}
              placeholder="Minimum 6 characters"
              disabled={isUpdatingPassword}
            />
          </div>

          <div>
            <label className={`block text-sm font-medium mb-1.5 ${isDarkMode ? 'text-gray-300' : 'text-gray-700'}`}>Confirm New Password</label>
            <input
              type="password"
              name="confirmPassword"
              value={formData.confirmPassword}
              onChange={handleInputChange}
              className={`w-full border rounded-lg py-2.5 px-3 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition duration-200 ${isDarkMode
                  ? 'bg-gray-800 border-gray-700 text-white placeholder-gray-500'
                  : 'bg-white border-gray-300 text-gray-900 placeholder-gray-400'
                }`}
              placeholder="••••••••••••"
              disabled={isUpdatingPassword}
            />
          </div>

          <div className="pt-2">
            <button
              type="submit"
              disabled={isUpdatingPassword || isUpdatingAccount}
              className={`text-white py-2.5 px-5 rounded-lg transition duration-200 font-medium flex items-center justify-center min-w-[170px] ${isDarkMode
                  ? 'bg-blue-600 hover:bg-blue-700'
                  : 'bg-blue-500 hover:bg-blue-600'
                } ${isUpdatingPassword ? 'opacity-70 cursor-not-allowed' : ''}`}
            >
              {isUpdatingPassword ? (
                <>
                  <FiLoader className="animate-spin mr-2" size={18} /> Updating...
                </>
              ) : (
                'Update Password'
              )}
            </button>
          </div>
        </form>
      </div>

      {message.text && (
        <div className={`mt-6 p-3 rounded-lg flex items-center gap-3 text-sm ${message.type === 'success'
            ? (isDarkMode ? 'bg-green-900/40 text-green-200 border border-green-700/50' : 'bg-green-100 text-green-700 border border-green-200')
            : (isDarkMode ? 'bg-red-900/40 text-red-200 border border-red-700/50' : 'bg-red-100 text-red-700 border border-red-200')
          }`}>
          {message.type === 'success' ? <FiCheckCircle size={18} /> : <FiXCircle size={18} />}
          <span>{message.text}</span>
          <button onClick={() => setMessage({ text: '', type: '' })} className="ml-auto p-1 rounded-full hover:bg-white/10">
            <FiXCircle size={16} />
          </button>
        </div>
      )}
    </div>
  );
});

const SettingsPage = () => {
  const { user, loading: authLoading, fetchUser } = useAuth();
  const { isDarkMode, toggleTheme } = useTheme();
  const [isLoading, setIsLoading] = useState(true);
  const [isUpdatingAccount, setIsUpdatingAccount] = useState(false);
  const [isUpdatingPassword, setIsUpdatingPassword] = useState(false);
  const [message, setMessage] = useState({ text: '', type: '' });
  const [formData, setFormData] = useState({
    name: '',
    email: '',
    profileImage: null,
    currentPassword: '',
    newPassword: '',
    confirmPassword: '',
  });

  useEffect(() => {
    if (message.text) {
      const timer = setTimeout(() => {
        setMessage({ text: '', type: '' });
      }, 5000);
      return () => clearTimeout(timer);
    }
  }, [message]);

  useEffect(() => {
    if (user) {
      setFormData(prev => ({
        ...prev,
        name: user.name || '',
        email: user.email || '',
        profileImage: user.profilePic || null,
      }));
      setIsLoading(false);
    } else if (!authLoading) {
      setIsLoading(false);
    }
  }, [user, authLoading]);

  const handleInputChange = useCallback((e) => {
    const { name, value, type, checked } = e.target;
    setFormData(prev => ({
      ...prev,
      [name]: type === 'checkbox' ? checked : value
    }));
  }, []);

  const handleImageUpload = useCallback((e) => {
    if (e.target.files && e.target.files[0]) {
      const file = e.target.files[0];
      if (!file.type.startsWith('image/')) {
        setMessage({ text: 'Please select a valid image file.', type: 'error' });
        return;
      }
      if (file.size > 5 * 1024 * 1024) {
        setMessage({ text: 'Image file size should not exceed 5MB.', type: 'error' });
        return;
      }
      setFormData(prev => ({
        ...prev,
        profileImage: file
      }));
      setMessage({ text: '', type: '' });
    }
  }, []);

  const handleAccountUpdate = useCallback(async (e) => {
    e.preventDefault();
    setMessage({ text: '', type: '' });
    setIsUpdatingAccount(true);

    try {
      let profilePicUrl = formData.profileImage instanceof File ? null : formData.profileImage;

      if (formData.profileImage instanceof File) {
        const imageFormData = new FormData();
        imageFormData.append('profileImage', formData.profileImage);

        const uploadResponse = await axiosInstance.post('/api/auth/user/profile-picture', imageFormData, {
          headers: { 'Content-Type': 'multipart/form-data' }
        });

        if (uploadResponse.data.success) {
          profilePicUrl = uploadResponse.data.user.profilePic;
          setFormData(prev => ({ ...prev, profileImage: profilePicUrl }));
        } else {
          throw new Error(uploadResponse.data.message || 'Failed to upload profile picture.');
        }
      }

      const nameChanged = user ? formData.name !== user.name : true;
      const emailChanged = user ? formData.email !== user.email : true;

      if (nameChanged || emailChanged) {
        const profileData = {
          name: formData.name,
          email: formData.email,
        };
        const updateResponse = await axiosInstance.patch('/api/auth/user/profile', profileData);

        if (!updateResponse.data.success) {
          throw new Error(updateResponse.data.message || 'Failed to update profile information.');
        }
      }

      setMessage({ text: 'Account updated successfully!', type: 'success' });
      await fetchUser();

    } catch (error) {
      console.error("Account update failed:", error);
      const errorMsg = error.response?.data?.message || error.message || 'Failed to update account.';
      setMessage({ text: errorMsg, type: 'error' });
    } finally {
      setIsUpdatingAccount(false);
    }
  }, [formData.name, formData.email, formData.profileImage, fetchUser, user]);

  const handlePasswordChange = useCallback(async (e) => {
    e.preventDefault();
    setMessage({ text: '', type: '' });
    if (formData.newPassword !== formData.confirmPassword) {
      setMessage({ text: 'New passwords do not match.', type: 'error' });
      return;
    }
    if (!formData.currentPassword || formData.newPassword.length < 6) {
      setMessage({ text: 'Please fill current password and ensure new password is at least 6 characters.', type: 'error' });
      return;
    }

    setIsUpdatingPassword(true);
    try {
      const response = await axiosInstance.post('/api/auth/user/change-password', {
        currentPassword: formData.currentPassword,
        newPassword: formData.newPassword,
      });

      if (response.data.success) {
        setMessage({ text: 'Password updated successfully!', type: 'success' });
        setFormData(prev => ({
          ...prev,
          currentPassword: '',
          newPassword: '',
          confirmPassword: '',
        }));
      } else {
        throw new Error(response.data.message || 'Failed to update password.');
      }

    } catch (error) {
      console.error("Password change failed:", error);
      const errorMsg = error.response?.data?.message || 'Failed to update password.';
      setMessage({ text: errorMsg, type: 'error' });
    } finally {
      setIsUpdatingPassword(false);
    }
  }, [formData.currentPassword, formData.newPassword, formData.confirmPassword]);

  if (isLoading || authLoading) {
    return (
      <div className={`flex items-center justify-center h-screen ${isDarkMode ? 'bg-black text-white' : 'bg-gray-50 text-gray-700'}`}>
        <div className={`animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 ${isDarkMode ? 'border-blue-500' : 'border-blue-600'}`}></div>
      </div>
    );
  }

  return (
    <div className={`flex flex-col h-full min-h-screen transition-colors duration-300 ${isDarkMode ? 'bg-black text-white' : 'bg-gray-50 text-gray-900'
      }`}>
      <div className="p-4 sm:p-6 md:p-8 lg:p-10 border-b border-gray-200 dark:border-gray-700">
        <h1 className="text-xl sm:text-2xl font-bold">Settings</h1>
      </div>

      <div className="flex-1 p-4 sm:p-6 md:p-8 lg:p-10 overflow-y-auto scrollbar-hide">
        <AccountSettings
          formData={formData}
          handleInputChange={handleInputChange}
          handleAccountUpdate={handleAccountUpdate}
          handlePasswordChange={handlePasswordChange}
          handleImageUpload={handleImageUpload}
          isDarkMode={isDarkMode}
          toggleTheme={toggleTheme}
          message={message}
          setMessage={setMessage}
          isUpdatingAccount={isUpdatingAccount}
          isUpdatingPassword={isUpdatingPassword}
        />
      </div>
    </div>
  );
};

export default SettingsPage; 