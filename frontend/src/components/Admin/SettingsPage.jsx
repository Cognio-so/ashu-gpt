import React, { useState, useEffect, useRef } from 'react';
import { IoSave, IoMoon, IoSunny, IoPersonOutline, IoKey, IoEyeOutline, IoEyeOffOutline, IoCheckmarkCircle } from 'react-icons/io5';
import { toast } from 'react-toastify';
import { useAuth } from '../../context/AuthContext';
import { useTheme } from '../../context/ThemeContext';
import { useNavigate } from 'react-router-dom';
import { axiosInstance } from '../../api/axiosInstance';

const SettingsPage = () => {
    const { user, loading: authLoading } = useAuth();
    const { isDarkMode, toggleTheme } = useTheme();
    const navigate = useNavigate();

    const [activeTab, setActiveTab] = useState('general');
    const [isLoading, setIsLoading] = useState(false);
    const [apiKeysLoading, setApiKeysLoading] = useState(false);
    const [passwordLoading, setPasswordLoading] = useState(false);

    // State to manage visibility of API keys
    const [showKeys, setShowKeys] = useState({
        openai: false,
        claude: false,
        gemini: false,
        llama: false,
    });

    // API keys state
    const [apiKeys, setApiKeys] = useState({
        openai: '',
        claude: '',
        gemini: '',
        llama: '',
    });

    // Password change state
    const [passwordData, setPasswordData] = useState({
        currentPassword: '',
        newPassword: '',
        confirmPassword: ''
    });

    // Load API keys from the backend on mount
    useEffect(() => {
        const fetchApiKeys = async () => {
            if (!user) return;

            try {
                setApiKeysLoading(true);
                const response = await axiosInstance.get('/api/auth/user/api-keys', {
                    withCredentials: true
                });

                if (response.data && response.data.success) {
                    // Convert the server response to our format
                    const keys = response.data.apiKeys || {};
                    setApiKeys({
                        openai: keys.openai || '',
                        claude: keys.claude || '',
                        gemini: keys.gemini || '',
                        llama: keys.llama || ''
                    });
                } else {
                    // If the server doesn't have API keys stored yet, try to load from localStorage for backward compatibility
                    const savedKeys = JSON.parse(localStorage.getItem('apiKeys') || '{}');
                    setApiKeys(prev => ({ ...prev, ...savedKeys }));
                }
            } catch (error) {
                // Fallback to localStorage if server fetch fails
                const savedKeys = JSON.parse(localStorage.getItem('apiKeys') || '{}');
                setApiKeys(prev => ({ ...prev, ...savedKeys }));
            } finally {
                setApiKeysLoading(false);
            }
        };

        fetchApiKeys();
    }, [user]);

    const toggleKeyVisibility = (keyName) => {
        setShowKeys(prev => ({ ...prev, [keyName]: !prev[keyName] }));
    };

    const handleApiKeyChange = (e) => {
        const { name, value } = e.target;
        setApiKeys({ ...apiKeys, [name]: value });
    };

    const saveApiKeys = async () => {
        try {
            setApiKeysLoading(true);

            // First, try to refresh the token before making the API call
            try {
                await axiosInstance.post('/api/auth/refresh');
            } catch (refreshError) {
                // Token refresh failed, continuing anyway
            }

            // Now make the API call with the refreshed token
            const response = await axiosInstance.post('/api/auth/user/api-keys', { apiKeys }, { withCredentials: true });

            if (response.data && response.data.success) {
                localStorage.setItem('apiKeys', JSON.stringify(apiKeys));
                toast.success("API keys updated successfully");
            } else {
                throw new Error(response.data?.message || "Failed to save API keys");
            }
        } catch (error) {
            toast.error(error.response?.data?.message || "Failed to save API keys");

            // Still try to save to localStorage as fallback
            try {
                localStorage.setItem('apiKeys', JSON.stringify(apiKeys));
                toast.info("API keys saved locally (offline mode)");
            } catch (localError) {
                // Error saving to localStorage
            }
        } finally {
            setApiKeysLoading(false);
        }
    };

    const handlePasswordChange = (e) => {
        const { name, value } = e.target;
        setPasswordData(prev => ({
            ...prev,
            [name]: value
        }));
    };

    const updatePassword = async () => {
        // Password validation
        if (!passwordData.currentPassword) {
            toast.error("Current password is required");
            return;
        }

        if (!passwordData.newPassword) {
            toast.error("New password is required");
            return;
        }

        if (passwordData.newPassword !== passwordData.confirmPassword) {
            toast.error("New passwords don't match");
            return;
        }

        try {
            setPasswordLoading(true);

            // Make API call to update the password
            const response = await axiosInstance.post('/api/auth/update-password', {
                currentPassword: passwordData.currentPassword,
                newPassword: passwordData.newPassword
            }, { withCredentials: true });

            if (response.data && response.data.success) {
                toast.success("Password updated successfully");
                setPasswordData({
                    currentPassword: '',
                    newPassword: '',
                    confirmPassword: ''
                });
            } else {
                throw new Error(response.data?.message || "Failed to update password");
            }
        } catch (error) {
            toast.error(error.response?.data?.message || "Failed to update password");
        } finally {
            setPasswordLoading(false);
        }
    };

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

    // Helper function to render API key input field
    const renderApiKeyInput = (modelName, placeholder) => (
        <div className="relative overflow-hidden transition-all duration-300 rounded-lg bg-gray-100 dark:bg-gray-800 border border-gray-300 dark:border-gray-700 p-4 hover:border-blue-500/30">
            <div className="flex items-center justify-between mb-2">
                <label className="block text-sm font-medium capitalize text-gray-800 dark:text-white">{modelName} API Key</label>
            </div>
            <div className="relative">
                <input
                    type={showKeys[modelName] ? 'text' : 'password'}
                    name={modelName}
                    value={apiKeys[modelName]}
                    onChange={handleApiKeyChange}
                    className="w-full bg-white dark:bg-gray-700 border border-gray-300 dark:border-gray-600 rounded-lg px-3 py-2.5 pr-10 text-sm focus:outline-none focus:border-blue-500/50 focus:ring-1 focus:ring-blue-500/50 text-black dark:text-white placeholder-gray-400 dark:placeholder-gray-500"
                    placeholder={placeholder}
                />
                <button
                    type="button"
                    onClick={() => toggleKeyVisibility(modelName)}
                    className="absolute inset-y-0 right-0 px-3 flex items-center text-gray-500 dark:text-gray-400 hover:text-black dark:hover:text-white"
                    aria-label={showKeys[modelName] ? `Hide ${modelName} key` : `Show ${modelName} key`}
                >
                    {showKeys[modelName] ? <IoEyeOffOutline size={18} /> : <IoEyeOutline size={18} />}
                </button>
            </div>
            <p className="text-xs text-gray-500 dark:text-gray-400 mt-1.5">Used for {modelName.charAt(0).toUpperCase() + modelName.slice(1)} models</p>
        </div>
    );

    return (
        <div className="flex flex-col h-full bg-white dark:bg-black text-black dark:text-white overflow-hidden">
            {/* Add the scrollbar-hiding styles */}
            <style>{scrollbarHideStyles}</style>

            {/* Top panel */}
            <div className="px-6 pt-6 pb-4 border-b border-gray-200 dark:border-gray-800 flex-shrink-0 text-center sm:text-left">
                <h1 className="text-xl font-bold text-gray-900 dark:text-white">Settings</h1>
                <p className="text-sm text-gray-500 dark:text-gray-400 mt-1">Customize your experience and manage your account</p>
            </div>

            {/* Tab Navigation */}
            <div className="px-6 pt-4 flex-shrink-0">
                <div className="flex gap-1 overflow-x-auto border-b border-gray-200 dark:border-gray-800 pb-px hide-scrollbar">
                    {[
                        { id: 'general', label: 'General', icon: IoPersonOutline },
                        { id: 'api-keys', label: 'API Keys', icon: IoKey },
                    ].map(tab => (
                        <button
                            key={tab.id}
                            onClick={() => setActiveTab(tab.id)}
                            className={`px-4 py-2.5 rounded-t-lg text-sm font-medium transition-all duration-200 flex items-center gap-2 whitespace-nowrap border-b-2
                                ${activeTab === tab.id
                                    ? 'text-blue-600 dark:text-blue-400 border-blue-500 dark:border-blue-500 bg-blue-50 dark:bg-gray-800/50'
                                    : 'text-gray-500 dark:text-gray-400 border-transparent hover:text-gray-800 dark:hover:text-white hover:bg-gray-100 dark:hover:bg-gray-800/30'
                                }`}
                        >
                            <tab.icon size={16} />
                            <span>{tab.label}</span>
                        </button>
                    ))}
                </div>
            </div>

            {/* Content Area - Added hide-scrollbar class */}
            <div className="flex-1 overflow-y-auto p-6 hide-scrollbar bg-white dark:bg-black">
                {activeTab === 'general' && (
                    <div className="space-y-8 max-w-3xl mx-auto">
                        {/* Account Details Card */}
                        <div className="bg-white dark:bg-gray-800 rounded-lg overflow-hidden border border-gray-200 dark:border-gray-700 shadow-sm">
                            <div className="p-6">
                                <h3 className="text-xl font-semibold text-gray-900 dark:text-white mb-6">Account Details</h3>
                                {authLoading ? (
                                    <div className="animate-pulse flex items-center space-x-4">
                                        <div className="w-16 h-16 rounded-full bg-gray-200 dark:bg-gray-700"></div>
                                        <div className="space-y-3 flex-1">
                                            <div className="h-4 bg-gray-200 dark:bg-gray-700 rounded w-3/4"></div>
                                            <div className="h-3 bg-gray-200 dark:bg-gray-700 rounded w-1/2"></div>
                                        </div>
                                    </div>
                                ) : user ? (
                                    <div className="flex items-center space-x-6">
                                        <div className="w-20 h-20 rounded-full bg-gradient-to-br from-blue-500 to-purple-600 flex items-center justify-center text-white text-2xl font-bold shadow-lg">
                                            {user.name ? user.name.charAt(0).toUpperCase() : '?'}
                                        </div>
                                        <div>
                                            <p className="text-xl font-medium text-gray-900 dark:text-white">{user.name || 'N/A'}</p>
                                            <p className="text-gray-500 dark:text-gray-400 mt-1">{user.email || 'N/A'}</p>
                                            <div className="flex items-center gap-1.5 mt-2 text-green-500 dark:text-green-400 text-sm">
                                                <IoCheckmarkCircle size={16} />
                                                <span>Verified account</span>
                                            </div>
                                        </div>
                                    </div>
                                ) : (
                                    <p className="text-gray-500 dark:text-gray-400">Could not load user information.</p>
                                )}
                            </div>
                        </div>

                        {/* Appearance Card */}
                        <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6 shadow-sm">
                            <div className="flex items-center justify-between mb-6">
                                <div>
                                    <h3 className="text-xl font-semibold text-gray-900 dark:text-white">Appearance</h3>
                                    <p className="text-gray-500 dark:text-gray-400 mt-1">Choose your preferred theme</p>
                                </div>
                            </div>
                            <div className="grid grid-cols-2 gap-4">
                                <button
                                    onClick={() => toggleTheme(true)}
                                    className={`relative overflow-hidden p-4 rounded-lg transition-all duration-300 ${isDarkMode
                                        ? 'border-2 border-blue-500 bg-gray-100 dark:bg-gray-900'
                                        : 'border border-gray-300 dark:border-gray-700 bg-gray-50 dark:bg-gray-700 hover:bg-gray-100 dark:hover:bg-gray-600'
                                        }`}
                                >
                                    <div className="relative">
                                        <div className="flex items-center justify-center">
                                            <div className={`p-2 rounded-lg mb-3 ${isDarkMode ? 'bg-blue-100 dark:bg-gray-800' : 'bg-gray-200 dark:bg-gray-600'}`}>
                                                <IoMoon size={20} className="text-blue-500 dark:text-blue-400" />
                                            </div>
                                        </div>
                                        <p className="text-center font-medium text-gray-900 dark:text-white">Dark Mode</p>
                                        <p className="text-xs text-center text-gray-500 dark:text-gray-400 mt-1">Reduced light emission</p>
                                    </div>
                                </button>

                                <button
                                    onClick={() => toggleTheme(false)}
                                    className={`relative overflow-hidden p-4 rounded-lg transition-all duration-300 ${!isDarkMode
                                        ? 'border-2 border-blue-500 bg-gray-100 dark:bg-gray-900'
                                        : 'border border-gray-300 dark:border-gray-700 bg-gray-50 dark:bg-gray-700 hover:bg-gray-100 dark:hover:bg-gray-600'
                                        }`}
                                >
                                    <div className="relative">
                                        <div className="flex items-center justify-center">
                                            <div className={`p-2 rounded-lg mb-3 ${!isDarkMode ? 'bg-amber-100 dark:bg-gray-800' : 'bg-gray-200 dark:bg-gray-600'}`}>
                                                <IoSunny size={20} className="text-amber-500 dark:text-amber-300" />
                                            </div>
                                        </div>
                                        <p className="text-center font-medium text-gray-900 dark:text-white">Light Mode</p>
                                        <p className="text-xs text-center text-gray-500 dark:text-gray-400 mt-1">Enhanced visibility</p>
                                    </div>
                                </button>
                            </div>
                        </div>

                        {/* Password Change Section */}
                        <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6 shadow-sm">
                            <h3 className="text-xl font-semibold text-gray-900 dark:text-white mb-6">Change Password</h3>
                            <div className="space-y-4">
                                <input
                                    type="password"
                                    name="currentPassword"
                                    value={passwordData.currentPassword}
                                    onChange={handlePasswordChange}
                                    className="w-full bg-gray-100 dark:bg-gray-700 border border-gray-300 dark:border-gray-600 rounded-lg px-4 py-3 text-black dark:text-white focus:outline-none focus:border-blue-500/50 focus:ring-1 focus:ring-blue-500/50 placeholder-gray-400 dark:placeholder-gray-500"
                                    placeholder="Current password"
                                    autoComplete="current-password"
                                />
                                <input
                                    type="password"
                                    name="newPassword"
                                    value={passwordData.newPassword}
                                    onChange={handlePasswordChange}
                                    className="w-full bg-gray-100 dark:bg-gray-700 border border-gray-300 dark:border-gray-600 rounded-lg px-4 py-3 text-black dark:text-white focus:outline-none focus:border-blue-500/50 focus:ring-1 focus:ring-blue-500/50 placeholder-gray-400 dark:placeholder-gray-500"
                                    placeholder="New password"
                                    autoComplete="new-password"
                                />
                                <input
                                    type="password"
                                    name="confirmPassword"
                                    value={passwordData.confirmPassword}
                                    onChange={handlePasswordChange}
                                    className="w-full bg-gray-100 dark:bg-gray-700 border border-gray-300 dark:border-gray-600 rounded-lg px-4 py-3 text-black dark:text-white focus:outline-none focus:border-blue-500/50 focus:ring-1 focus:ring-blue-500/50 placeholder-gray-400 dark:placeholder-gray-500"
                                    placeholder="Confirm new password"
                                    autoComplete="new-password"
                                />
                                <div className="pt-2 flex justify-end">
                                    <button
                                        onClick={updatePassword}
                                        disabled={passwordLoading}
                                        className="flex items-center gap-2 px-5 py-2.5 bg-black dark:bg-white hover:bg-black/80 dark:hover:bg-white/80 rounded-lg text-white dark:text-black font-medium transition-all disabled:opacity-70 disabled:cursor-not-allowed"
                                    >
                                        {passwordLoading ? (
                                            <div className="w-5 h-5 border-2 border-white border-t-transparent rounded-full animate-spin"></div>
                                        ) : (
                                            <IoSave size={18} />
                                        )}
                                        <span>{passwordLoading ? 'Updating...' : 'Update Password'}</span>
                                    </button>
                                </div>
                            </div>
                        </div>
                    </div>
                )}

                {activeTab === 'api-keys' && (
                    <div className="space-y-8 max-w-3xl mx-auto">
                        <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6 shadow-sm">
                            <div className="mb-6">
                                <h3 className="text-xl font-semibold text-gray-900 dark:text-white">Model API Keys</h3>
                                <p className="text-gray-500 dark:text-gray-400 mt-1">Connect your AI models with API keys</p>
                            </div>

                            {apiKeysLoading && apiKeys.openai === '' && apiKeys.claude === '' && apiKeys.gemini === '' && apiKeys.llama === '' ? (
                                <div className="py-8 flex justify-center">
                                    <div className="w-8 h-8 border-2 border-blue-500 border-t-transparent rounded-full animate-spin"></div>
                                </div>
                            ) : (
                                <div className="grid gap-4 md:grid-cols-2">
                                    {renderApiKeyInput('openai', 'sk-...')}
                                    {renderApiKeyInput('claude', 'sk-ant-...')}
                                    {renderApiKeyInput('gemini', 'AIza...')}
                                    {renderApiKeyInput('llama', 'meta-llama-...')}
                                </div>
                            )}

                            <div className="bg-blue-50 dark:bg-blue-900/20 border border-blue-300 dark:border-blue-500/30 rounded-lg p-4 flex items-start gap-3 mt-6">
                                <IoCheckmarkCircle className="text-blue-500 dark:text-blue-400 flex-shrink-0 mt-0.5" size={20} />
                                <p className="text-sm text-blue-700 dark:text-blue-200/80">
                                    Your API keys are securely stored and encrypted in the database. They are never shared with third parties.
                                </p>
                            </div>

                            <div className="mt-6 flex justify-end">
                                <button
                                    onClick={saveApiKeys}
                                    disabled={apiKeysLoading}
                                    className={`flex items-center gap-2 px-5 py-2.5 bg-black dark:bg-white hover:bg-black/80 dark:hover:bg-white/80 rounded-lg text-white dark:text-black font-medium transition-all disabled:opacity-70 disabled:cursor-not-allowed`}
                                >
                                    {apiKeysLoading ? (
                                        <div className="w-5 h-5 border-2 border-white border-t-transparent rounded-full animate-spin"></div>
                                    ) : (
                                        <IoSave size={18} />
                                    )}
                                    <span>{apiKeysLoading ? 'Saving...' : 'Save API Keys'}</span>
                                </button>
                            </div>
                        </div>
                    </div>
                )}
            </div>
        </div>
    );
};

export default SettingsPage; 