import React, { useState, useEffect, useCallback, memo } from 'react';
import { useAuth } from '../../context/AuthContext';
import { useTheme } from '../../context/ThemeContext';
import { 
  FiUser, FiBell, FiMonitor, FiLock, FiChevronRight, 
  FiEdit2, FiCamera, FiCheck, FiInfo, FiXCircle, FiCheckCircle
} from 'react-icons/fi';
import axios from 'axios';

const API_URL = import.meta.env.VITE_BACKEND_URL || 'http://localhost:5000';

// Account settings section component
const AccountSettings = memo(({ 
  formData, 
  handleInputChange, 
  handleAccountUpdate, 
  handlePasswordChange, 
  handleImageUpload,
  isDarkMode,
  message,
  setMessage 
}) => (
    <div className="animate-fadeIn">
      <div className="mb-8">
        <h2 className={`text-xl font-semibold mb-1 ${isDarkMode ? 'text-white' : 'text-gray-900'}`}>Account Information</h2>
        <p className={`text-sm ${isDarkMode ? 'text-gray-400' : 'text-gray-600'}`}>Manage your personal information and email address</p>
      </div>
      
      <div className="mb-8">
        <div className="flex items-center justify-center md:justify-start mb-6">
          <div className="relative">
            <div className={`w-24 h-24 rounded-full overflow-hidden border-2 ${
              isDarkMode 
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
            <label className={`absolute bottom-0 right-0 p-1.5 rounded-full cursor-pointer border-2 hover:bg-blue-700 transition-colors ${
              isDarkMode 
                ? 'bg-blue-600 border-gray-800 text-white' 
                : 'bg-blue-500 border-white text-white'
            }`}>
              <input type="file" accept="image/*" onChange={handleImageUpload} className="hidden" />
              <FiCamera size={16} />
            </label>
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
              className={`w-full border rounded-lg py-2.5 px-3 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition duration-200 ${
                isDarkMode 
                  ? 'bg-gray-800 border-gray-700 text-white placeholder-gray-500' 
                  : 'bg-white border-gray-300 text-gray-900 placeholder-gray-400'
              }`}
              placeholder="Your full name"
            />
          </div>
          
          <div>
            <label className={`block text-sm font-medium mb-1.5 ${isDarkMode ? 'text-gray-300' : 'text-gray-700'}`}>Email Address</label>
            <input 
              type="email" 
              name="email" 
              value={formData.email} 
              onChange={handleInputChange}
              className={`w-full border rounded-lg py-2.5 px-3 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition duration-200 ${
                isDarkMode 
                  ? 'bg-gray-800 border-gray-700 text-white placeholder-gray-500' 
                  : 'bg-white border-gray-300 text-gray-900 placeholder-gray-400'
              }`}
              placeholder="your.email@example.com"
            />
            <p className={`mt-1 text-xs ${isDarkMode ? 'text-gray-500' : 'text-gray-500'}`}>Your email address is used for notifications and account recovery</p>
          </div>
          
          <div className="pt-2">
            <button 
              type="submit" 
              className={`text-white py-2.5 px-5 rounded-lg transition duration-200 font-medium ${
                isDarkMode 
                  ? 'bg-blue-600 hover:bg-blue-700' 
                  : 'bg-blue-500 hover:bg-blue-600'
              }`}
            >
              Save Changes
            </button>
          </div>
        </form>
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
              className={`w-full border rounded-lg py-2.5 px-3 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition duration-200 ${
                isDarkMode 
                  ? 'bg-gray-800 border-gray-700 text-white placeholder-gray-500' 
                  : 'bg-white border-gray-300 text-gray-900 placeholder-gray-400'
              }`}
              placeholder="••••••••••••"
            />
          </div>
          
          <div>
            <label className={`block text-sm font-medium mb-1.5 ${isDarkMode ? 'text-gray-300' : 'text-gray-700'}`}>New Password</label>
            <input 
              type="password" 
              name="newPassword" 
              value={formData.newPassword} 
              onChange={handleInputChange}
              className={`w-full border rounded-lg py-2.5 px-3 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition duration-200 ${
                isDarkMode 
                  ? 'bg-gray-800 border-gray-700 text-white placeholder-gray-500' 
                  : 'bg-white border-gray-300 text-gray-900 placeholder-gray-400'
              }`}
              placeholder="••••••••••••"
            />
          </div>
          
          <div>
            <label className={`block text-sm font-medium mb-1.5 ${isDarkMode ? 'text-gray-300' : 'text-gray-700'}`}>Confirm New Password</label>
            <input 
              type="password" 
              name="confirmPassword" 
              value={formData.confirmPassword} 
              onChange={handleInputChange}
              className={`w-full border rounded-lg py-2.5 px-3 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition duration-200 ${
                isDarkMode 
                  ? 'bg-gray-800 border-gray-700 text-white placeholder-gray-500' 
                  : 'bg-white border-gray-300 text-gray-900 placeholder-gray-400'
              }`}
              placeholder="••••••••••••"
            />
          </div>
          
          <div className="pt-2">
            <button 
              type="submit" 
              className={`text-white py-2.5 px-5 rounded-lg transition duration-200 font-medium ${
                isDarkMode 
                  ? 'bg-blue-600 hover:bg-blue-700' 
                  : 'bg-blue-500 hover:bg-blue-600'
              }`}
            >
              Update Password
            </button>
          </div>
        </form>
      </div>

      {message.text && (
          <div className={`mt-6 p-3 rounded-lg flex items-center gap-3 text-sm ${
              message.type === 'success' 
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
));

// Preferences section component
const PreferencesSettings = memo(({ 
  formData, 
  handleInputChange, 
  handlePreferencesUpdate, 
  isDarkMode, 
  toggleTheme,
  message,
  setMessage 
}) => (
    <div className="animate-fadeIn">
      <div className="mb-8">
        <h2 className={`text-xl font-semibold mb-1 ${isDarkMode ? 'text-white' : 'text-gray-900'}`}>Appearance</h2>
        <p className={`text-sm ${isDarkMode ? 'text-gray-400' : 'text-gray-600'}`}>Customize how the application looks and feels</p>
      </div>
      
      <form onSubmit={handlePreferencesUpdate}>
        <div className="space-y-5 mb-8">
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
              <div className={`w-11 h-6 rounded-full peer peer-focus:outline-none peer-focus:ring-2 peer-focus:ring-blue-500 after:content-[''] after:absolute after:top-[2px] after:start-[2px] after:border after:rounded-full after:h-5 after:w-5 after:transition-all ${
                isDarkMode 
                  ? 'bg-blue-600 after:translate-x-full after:border-white after:bg-white' 
                  : 'bg-gray-300 after:border-gray-400 after:bg-white'
              }`}></div>
            </label>
          </div>

          <div className="flex justify-between items-center">
            <div>
              <h3 className={`text-base font-medium ${isDarkMode ? 'text-gray-100' : 'text-gray-800'}`}>Compact View</h3>
              <p className={`text-sm ${isDarkMode ? 'text-gray-400' : 'text-gray-600'}`}>Reduce spacing in the interface</p>
            </div>
            <label className="relative inline-flex items-center cursor-pointer">
              <input 
                type="checkbox" 
                name="compactView" 
                checked={formData.compactView} 
                onChange={handleInputChange}
                className="sr-only peer" 
              />
              <div className={`w-11 h-6 rounded-full peer peer-focus:outline-none peer-focus:ring-2 peer-focus:ring-blue-500 after:content-[''] after:absolute after:top-[2px] after:start-[2px] after:border after:rounded-full after:h-5 after:w-5 after:transition-all ${
                formData.compactView 
                  ? (isDarkMode ? 'bg-blue-600 after:translate-x-full after:border-white after:bg-white' : 'bg-blue-500 after:translate-x-full after:border-white after:bg-white') 
                  : (isDarkMode ? 'bg-gray-700 after:border-gray-600 after:bg-gray-400' : 'bg-gray-300 after:border-gray-400 after:bg-white')
              }`}></div>
            </label>
          </div>

          <div className="pt-3">
            <h3 className={`text-base font-medium mb-2 ${isDarkMode ? 'text-gray-100' : 'text-gray-800'}`}>Font Size</h3>
            <div className="flex flex-wrap gap-3 sm:gap-4">
              {['small', 'medium', 'large'].map(size => (
                <label key={size} className="flex items-center">
                  <input 
                    type="radio" 
                    name="fontSize" 
                    value={size} 
                    checked={formData.fontSize === size} 
                    onChange={handleInputChange}
                    className="sr-only peer" 
                  />
                  <div className={`relative border-2 rounded-lg px-4 py-2 cursor-pointer transition-colors ${
                    formData.fontSize === size 
                      ? 'border-blue-500 text-blue-500' 
                      : (isDarkMode ? 'border-gray-700 hover:border-gray-600 text-gray-300' : 'border-gray-300 hover:border-gray-400 text-gray-700')
                  }`}>
                    <span className="text-sm capitalize">{size}</span>
                    <FiCheck className={`absolute top-1.5 right-1.5 text-blue-500 transition-opacity ${formData.fontSize === size ? 'opacity-100' : 'opacity-0'}`} size={14} />
                  </div>
                </label>
              ))}
            </div>
          </div>
        </div>
        
        <div className={`border-t pt-8 mb-8 ${isDarkMode ? 'border-gray-700' : 'border-gray-200'}`}>
          <h2 className={`text-xl font-semibold mb-1 ${isDarkMode ? 'text-white' : 'text-gray-900'}`}>Notifications</h2>
          <p className={`text-sm mb-5 ${isDarkMode ? 'text-gray-400' : 'text-gray-600'}`}>Manage how you receive notifications</p>
          
          <div className="space-y-5">
            <div className="flex justify-between items-center">
              <div>
                <h3 className={`text-base font-medium ${isDarkMode ? 'text-gray-100' : 'text-gray-800'}`}>Email Notifications</h3>
                <p className={`text-sm ${isDarkMode ? 'text-gray-400' : 'text-gray-600'}`}>Receive important updates via email</p>
              </div>
              <label className="relative inline-flex items-center cursor-pointer">
                <input 
                  type="checkbox" 
                  name="emailNotifications" 
                  checked={formData.emailNotifications} 
                  onChange={handleInputChange}
                  className="sr-only peer" 
                />
                <div className={`w-11 h-6 rounded-full peer peer-focus:outline-none peer-focus:ring-2 peer-focus:ring-blue-500 after:content-[''] after:absolute after:top-[2px] after:start-[2px] after:border after:rounded-full after:h-5 after:w-5 after:transition-all ${
                  formData.emailNotifications 
                    ? (isDarkMode ? 'bg-blue-600 after:translate-x-full after:border-white after:bg-white' : 'bg-blue-500 after:translate-x-full after:border-white after:bg-white') 
                    : (isDarkMode ? 'bg-gray-700 after:border-gray-600 after:bg-gray-400' : 'bg-gray-300 after:border-gray-400 after:bg-white')
                }`}></div>
              </label>
            </div>
            
            <div className="flex justify-between items-center">
              <div>
                <h3 className={`text-base font-medium ${isDarkMode ? 'text-gray-100' : 'text-gray-800'}`}>In-App Notifications</h3>
                <p className={`text-sm ${isDarkMode ? 'text-gray-400' : 'text-gray-600'}`}>Show notifications within the application</p>
              </div>
              <label className="relative inline-flex items-center cursor-pointer">
                <input 
                  type="checkbox" 
                  name="inAppNotifications" 
                  checked={formData.inAppNotifications} 
                  onChange={handleInputChange}
                  className="sr-only peer" 
                />
                <div className={`w-11 h-6 rounded-full peer peer-focus:outline-none peer-focus:ring-2 peer-focus:ring-blue-500 after:content-[''] after:absolute after:top-[2px] after:start-[2px] after:border after:rounded-full after:h-5 after:w-5 after:transition-all ${
                  formData.inAppNotifications 
                    ? (isDarkMode ? 'bg-blue-600 after:translate-x-full after:border-white after:bg-white' : 'bg-blue-500 after:translate-x-full after:border-white after:bg-white') 
                    : (isDarkMode ? 'bg-gray-700 after:border-gray-600 after:bg-gray-400' : 'bg-gray-300 after:border-gray-400 after:bg-white')
                }`}></div>
              </label>
            </div>
          </div>
        </div>
        
        <div className="pt-2">
          <button 
            type="submit" 
            className={`text-white py-2.5 px-5 rounded-lg transition duration-200 font-medium ${
              isDarkMode 
                ? 'bg-blue-600 hover:bg-blue-700' 
                : 'bg-blue-500 hover:bg-blue-600'
            }`}
          >
            Save Preferences
          </button>
        </div>
      </form>

      {message.text && (
          <div className={`mt-6 p-3 rounded-lg flex items-center gap-3 text-sm ${
              message.type === 'success' 
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
));

// Notification component
const Notification = memo(({ type, message }) => {
  if (!message) return null;
  
  return (
    <div className={`fixed top-5 right-5 z-50 px-5 py-3 rounded-lg shadow-lg transition-all transform animate-slideIn ${
      type === 'success' ? 'bg-green-900/70 text-green-200 border border-green-700' : 
      'bg-red-900/70 text-red-200 border border-red-700'
    }`}>
      {type === 'success' ? 
        <FiCheck className="inline-block mr-2" /> : 
        <FiInfo className="inline-block mr-2" />
      }
      {message}
    </div>
  );
});

const SettingsPage = () => {
  const { user, loading: authLoading, updateUser } = useAuth();
  const { isDarkMode, toggleTheme } = useTheme();
  const [activeTab, setActiveTab] = useState('account');
  const [isLoading, setIsLoading] = useState(true);
  const [message, setMessage] = useState({ text: '', type: '' });
  const [formData, setFormData] = useState({
    name: '',
    email: '',
    profileImage: null,
    currentPassword: '',
    newPassword: '',
    confirmPassword: '',
    compactView: false,
    fontSize: 'medium',
    emailNotifications: true,
    inAppNotifications: true,
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
      setFormData(prev => ({
        ...prev,
        profileImage: file
      }));
      console.log("Selected image file:", file);
    }
  }, []);

  const handleAccountUpdate = useCallback(async (e) => {
    e.preventDefault();
    setMessage({ text: '', type: '' });
    console.log('Updating account info:', { name: formData.name, email: formData.email, profileImage: formData.profileImage });
    try {
      await new Promise(resolve => setTimeout(resolve, 1000));
      const updatedUserData = { name: formData.name, email: formData.email };
      if (formData.profileImage instanceof File) {
        updatedUserData.profilePic = URL.createObjectURL(formData.profileImage);
      } else if (formData.profileImage === null) {
        updatedUserData.profilePic = null;
      }
      console.log('Updated user data:', updatedUserData);
      // updateUser(updatedUserData);
      setMessage({ text: 'Account information updated successfully!', type: 'success' });
    } catch (error) {
      console.error("Account update failed:", error);
      setMessage({ text: 'Failed to update account information.', type: 'error' });
    }
  }, [formData.name, formData.email, formData.profileImage]);

  const handlePasswordChange = useCallback(async (e) => {
    e.preventDefault();
    setMessage({ text: '', type: '' });
    if (formData.newPassword !== formData.confirmPassword) {
      setMessage({ text: 'New passwords do not match.', type: 'error' });
      return;
    }
    if (!formData.currentPassword || !formData.newPassword) {
      setMessage({ text: 'Please fill in all password fields.', type: 'error' });
      return;
    }
    console.log('Changing password...');
    try {
      await new Promise((resolve, reject) => setTimeout(() => {
        if (formData.currentPassword === "password123") {
          resolve();
        } else {
          reject(new Error("Incorrect current password"));
        }
      }, 1000));
      setMessage({ text: 'Password updated successfully!', type: 'success' });
      setFormData(prev => ({
        ...prev,
        currentPassword: '',
        newPassword: '',
        confirmPassword: '',
      }));
    } catch (error) {
      console.error("Password change failed:", error);
      setMessage({ text: error.message || 'Failed to update password.', type: 'error' });
    }
  }, [formData.currentPassword, formData.newPassword, formData.confirmPassword]);

  const handlePreferencesUpdate = useCallback(async (e) => {
    e.preventDefault();
    setMessage({ text: '', type: '' });
    const prefsToSave = {
      compactView: formData.compactView,
      fontSize: formData.fontSize,
      emailNotifications: formData.emailNotifications,
      inAppNotifications: formData.inAppNotifications,
    };
    console.log('Saving preferences:', prefsToSave);
    try {
      await new Promise(resolve => setTimeout(resolve, 1000));
      setMessage({ text: 'Preferences saved successfully!', type: 'success' });
    } catch (error) {
      console.error("Preferences update failed:", error);
      setMessage({ text: 'Failed to save preferences.', type: 'error' });
    }
  }, [formData.compactView, formData.fontSize, formData.emailNotifications, formData.inAppNotifications]);

  const tabs = [
    { id: 'account', label: 'Account', icon: <FiUser size={18}/>, component: AccountSettings },
    { id: 'preferences', label: 'Preferences', icon: <FiMonitor size={18}/>, component: PreferencesSettings },
  ];

  const ActiveComponent = tabs.find(tab => tab.id === activeTab)?.component;

  if (isLoading || authLoading) {
    return (
      <div className={`flex items-center justify-center h-screen ${isDarkMode ? 'bg-black text-white' : 'bg-gray-50 text-gray-700'}`}>
        <div className={`animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 ${isDarkMode ? 'border-blue-500' : 'border-blue-600'}`}></div>
      </div>
    );
  }
  
  return (
    <div className={`flex flex-col md:flex-row h-full min-h-screen transition-colors duration-300 ${
      isDarkMode ? 'bg-black text-white' : 'bg-gray-50 text-gray-900'
    }`}>
      <div className={`w-full md:w-64 lg:w-72 flex-shrink-0 p-4 md:p-6 border-b md:border-b-0 md:border-r ${
        isDarkMode ? 'bg-gray-900/30 border-gray-700' : 'bg-white border-gray-200'
      }`}>
        <h1 className="text-lg font-semibold mb-6 hidden md:block">Settings</h1>
        <nav className="flex flex-row md:flex-col gap-1 md:gap-2 overflow-x-auto md:overflow-x-visible no-scrollbar pb-2 md:pb-0">
          {tabs.map(tab => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`flex items-center gap-3 px-3 py-2.5 rounded-lg text-left text-sm font-medium transition-colors w-full whitespace-nowrap ${
                activeTab === tab.id 
                  ? (isDarkMode ? 'bg-blue-600/80 text-white' : 'bg-blue-100 text-blue-700') 
                  : (isDarkMode 
                      ? 'text-gray-300 hover:bg-gray-700/50 hover:text-white' 
                      : 'text-gray-600 hover:bg-gray-100 hover:text-gray-900')
              }`}
            >
              {tab.icon}
              <span className="flex-1">{tab.label}</span>
              <FiChevronRight size={16} className="opacity-50 hidden md:block" />
            </button>
          ))}
        </nav>
      </div>

      <div className="flex-1 p-4 sm:p-6 md:p-8 lg:p-10 overflow-y-auto">
        {ActiveComponent && (
          <ActiveComponent 
            formData={formData}
            handleInputChange={handleInputChange}
            handleAccountUpdate={handleAccountUpdate}
            handlePasswordChange={handlePasswordChange}
            handleImageUpload={handleImageUpload}
            handlePreferencesUpdate={handlePreferencesUpdate}
            isDarkMode={isDarkMode}
            toggleTheme={toggleTheme}
            message={message}
            setMessage={setMessage}
          />
        )}
      </div>
    </div>
  );
};

export default SettingsPage; 