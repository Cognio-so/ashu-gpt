import React, { useState, useEffect } from 'react';
import {
  IoGridOutline,
  IoFolderOpenOutline,
  IoHeartOutline,
  IoTimeOutline,
  IoExitOutline,
  IoChevronBackOutline,
  IoChevronForwardOutline,
  IoMenuOutline,
  IoSettingsOutline
} from 'react-icons/io5';
import { useAuth } from '../../context/AuthContext';
import { useTheme } from '../../context/ThemeContext';
import { axiosInstance } from '../../api/axiosInstance';


const Sidebar = ({ activePage = 'dashboard', onNavigate }) => {
  const [isCollapsed, setIsCollapsed] = useState(false);
  const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false);
  const [activeItem, setActiveItem] = useState(activePage);
  const [assignedGptsCount, setAssignedGptsCount] = useState(0);
  const { logout } = useAuth();
  const { isDarkMode } = useTheme();

  // Fetch assigned GPTs count
  useEffect(() => {
    const fetchAssignedGpts = async () => {
      try {
        const response = await axiosInstance.get(`/api/custom-gpts/user/assigned`, {
          withCredentials: true
        });

        if (response.data.success && response.data.assignedGpts) {
          setAssignedGptsCount(response.data.assignedGpts.length);
        }
      } catch (error) {
        console.error("Error fetching assigned GPTs:", error);
      }
    };

    fetchAssignedGpts();
  }, []);

  // Auto-collapse on small screens
  useEffect(() => {
    const handleResize = () => {
      if (window.innerWidth < 768) {
        setIsCollapsed(true);
      }
    };

    window.addEventListener('resize', handleResize);
    handleResize(); // Check on initial render

    return () => window.removeEventListener('resize', handleResize);
  }, []);

  const toggleSidebar = () => {
    setIsCollapsed(!isCollapsed);
  };

  const toggleMobileMenu = () => {
    setIsMobileMenuOpen(!isMobileMenuOpen);
  };

  const handleNavigation = (itemId) => {
    setActiveItem(itemId);
    if (onNavigate) {
      onNavigate(itemId);
    }

    // Close mobile menu after navigation on small screens
    if (window.innerWidth < 768) {
      setIsMobileMenuOpen(false);
    }
  };

  const handleLogout = async () => {
    try {
      await logout();
    } catch (error) {
      console.error("Logout failed:", error);
    }
  };

  const navItems = [
    { id: 'dashboard', label: 'Dashboard', icon: <IoGridOutline size={20} /> },
    // { 
    //   id: 'collections', 
    //   label: 'Collections', 
    //   icon: <IoFolderOpenOutline size={20} />
    // },
    { id: 'favourites', label: 'Favourites', icon: <IoHeartOutline size={20} /> },
    { id: 'history', label: 'History', icon: <IoTimeOutline size={20} /> },
    { id: 'settings', label: 'Settings', icon: <IoSettingsOutline size={20} /> },
  ];

  return (
    <>
      {/* Mobile Menu Button - Only visible on small screens */}
      <div className="md:hidden fixed top-4 left-4 z-50">
        <button
          onClick={toggleMobileMenu}
          className={`rounded-full p-2 shadow-lg transition-colors ${isDarkMode
              ? 'bg-gray-800 text-white hover:bg-gray-700'
              : 'bg-white text-gray-700 hover:bg-gray-100'
            }`}
        >
          <IoMenuOutline size={24} />
        </button>
      </div>

      {/* Mobile Menu Overlay */}
      {isMobileMenuOpen && (
        <div
          className="md:hidden fixed inset-0 bg-black/80 z-40"
          onClick={() => setIsMobileMenuOpen(false)}
        />
      )}

      {/* Sidebar */}
      <div
        className={`fixed md:relative h-screen flex flex-col justify-between transition-all duration-300 ease-in-out z-40
          ${isDarkMode ? 'bg-[#121212] text-white' : 'bg-gray-50 text-gray-800 border-r border-gray-200'}
          ${isCollapsed ? 'w-[70px]' : 'w-[240px]'}
          ${isMobileMenuOpen ? 'translate-x-0' : '-translate-x-full md:translate-x-0'}
        `}
      >
        {/* Top content */}
        <div>
          {/* Logo and Toggle Button */}
          <div className={`px-4 py-6 mb-4 flex ${isCollapsed ? 'justify-center' : 'justify-between'} items-center`}>
            {!isCollapsed && <h1 className="text-xl font-bold">AI Agent</h1>}
            <button
              onClick={toggleSidebar}
              className={`rounded-full p-1.5 transition-colors hidden md:flex items-center justify-center ${isDarkMode
                  ? 'bg-white/10 hover:bg-white/20 text-white'
                  : 'bg-gray-200 hover:bg-gray-300 text-gray-600'
                }`}
            >
              {isCollapsed ? <IoChevronForwardOutline size={16} /> : <IoChevronBackOutline size={16} />}
            </button>
          </div>

          {/* Navigation */}
          <div className="flex flex-col space-y-1 px-2">
            {navItems.map((item) => (
              <button
                key={item.id}
                onClick={() => handleNavigation(item.id)}
                className={`flex items-center ${isCollapsed ? 'justify-center' : 'justify-start'} px-4 py-3 rounded-lg text-left transition-colors ${activeItem === item.id
                    ? (isDarkMode ? 'bg-white/10 text-white' : 'bg-blue-100 text-blue-700 font-medium')
                    : (isDarkMode
                      ? 'text-gray-400 hover:bg-white/5 hover:text-white'
                      : 'text-gray-600 hover:bg-gray-100 hover:text-gray-900')
                  }`}
                title={isCollapsed ? item.label : ''}
              >
                <span className="flex items-center justify-center">{item.icon}</span>
                {!isCollapsed && (
                  <div className="flex items-center justify-between w-full">
                    <span className="ml-3">{item.label}</span>
                  </div>
                )}
              </button>
            ))}
          </div>
        </div>

        {/* Bottom logout button */}
        <div className="px-2 pb-6">
          <button
            onClick={handleLogout}
            className={`flex items-center ${isCollapsed ? 'justify-center' : 'justify-start'} w-full px-4 py-3 rounded-lg text-left transition-colors ${isDarkMode
                ? 'text-gray-400 hover:bg-white/5 hover:text-white'
                : 'text-gray-600 hover:bg-gray-100 hover:text-gray-900'
              }`}
            title={isCollapsed ? 'Logout' : ''}
          >
            <span className="flex items-center justify-center"><IoExitOutline size={20} /></span>
            {!isCollapsed && <span className="ml-3">Logout</span>}
          </button>
        </div>
      </div>
    </>
  );
};

export default Sidebar;
