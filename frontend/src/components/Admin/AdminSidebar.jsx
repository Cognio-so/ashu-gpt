import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../../context/AuthContext';
import { useTheme } from '../../context/ThemeContext';
import {
    IoGridOutline,
    IoFolderOpenOutline,
    IoPeopleOutline,
    IoSettingsOutline,
    IoTimeOutline,
    IoExitOutline,
    IoChevronBackOutline,
    IoChevronForwardOutline,
    IoMenuOutline
} from 'react-icons/io5';

const AdminSidebar = ({ activePage = 'dashboard', onNavigate }) => {
    const [isCollapsed, setIsCollapsed] = useState(false);
    const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false);
    const [activeItem, setActiveItem] = useState(activePage);
    const navigate = useNavigate();
    const { logout } = useAuth();
    const { isDarkMode } = useTheme();

    useEffect(() => {
        setActiveItem(activePage);
    }, [activePage]);

    const handleLogout = async () => {
        if (window.confirm("Are you sure you want to logout?")) {
            await logout();
        }
    };

    useEffect(() => {
        const handleResize = () => {
            if (window.innerWidth < 768) {
                setIsCollapsed(true);
            }
        };

        window.addEventListener('resize', handleResize);
        handleResize();

        return () => window.removeEventListener('resize', handleResize);
    }, []);

    const toggleSidebar = () => {
        setIsCollapsed(!isCollapsed);
    };

    const toggleMobileMenu = () => {
        setIsMobileMenuOpen(!isMobileMenuOpen);
    };

    const handleNavigation = (itemId) => {
        if (onNavigate) {
            onNavigate(itemId);
        }

        if (window.innerWidth < 768 && isMobileMenuOpen) {
            toggleMobileMenu();
        }
    };

    const navItems = [
        { id: 'dashboard', label: 'Dashboard', icon: <IoGridOutline size={20} /> },
        { id: 'collections', label: 'Collections', icon: <IoFolderOpenOutline size={20} /> },
        { id: 'team', label: 'Team', icon: <IoPeopleOutline size={20} /> },
        { id: 'settings', label: 'Settings', icon: <IoSettingsOutline size={20} /> },
        { id: 'history', label: 'History', icon: <IoTimeOutline size={20} /> },
    ];

    return (
        <>
            <div className="md:hidden fixed top-4 left-4 z-50">
                <button
                    onClick={toggleMobileMenu}
                    className="rounded-full p-2 bg-gray-100 dark:bg-gray-800 text-gray-800 dark:text-white shadow-lg hover:bg-gray-200 dark:hover:bg-gray-700"
                >
                    <IoMenuOutline size={24} />
                </button>
            </div>

            {isMobileMenuOpen && (
                <div
                    className="md:hidden fixed inset-0 bg-black/60 dark:bg-black/80 z-40"
                    onClick={() => setIsMobileMenuOpen(false)}
                />
            )}

            <div
                className={`fixed md:relative h-screen bg-white dark:bg-[#121212] text-black dark:text-white flex flex-col justify-between transition-all duration-300 ease-in-out z-50 border-r border-gray-200 dark:border-gray-800
                    ${isCollapsed ? 'w-[70px]' : 'w-[240px]'}
                    ${isMobileMenuOpen ? 'translate-x-0' : '-translate-x-full md:translate-x-0'}
                `}
            >
                <div>
                    <div className={`px-4 py-6 mb-4 flex ${isCollapsed ? 'justify-center' : 'justify-between'} items-center`}>
                        {!isCollapsed && <h1 className="text-xl font-bold text-gray-900 dark:text-white">Admin Panel</h1>}
                        <button
                            onClick={toggleSidebar}
                            className="rounded-full p-1.5 bg-gray-100 dark:bg-white/10 text-gray-700 dark:text-white hover:bg-gray-200 dark:hover:bg-white/20 transition-colors hidden md:flex items-center justify-center"
                        >
                            {isCollapsed ? <IoChevronForwardOutline size={16} /> : <IoChevronBackOutline size={16} />}
                        </button>
                    </div>

                    <div className="flex flex-col space-y-1 px-2">
                        {navItems.map((item) => (
                            <button
                                key={item.id}
                                onClick={() => handleNavigation(item.id)}
                                className={`flex items-center ${isCollapsed ? 'justify-center' : 'justify-start'} w-full px-4 py-3 rounded-lg text-left transition-colors ${activePage === item.id || (activePage === 'collections' && (item.id === 'create-gpt' || item.id.startsWith('edit-gpt')))
                                        ? 'bg-white dark:bg-white/10 text-black dark:text-white'
                                        : 'text-gray-600 dark:text-gray-400 hover:bg-gray-100 dark:hover:bg-black hover:text-gray-900 dark:hover:text-white'
                                    }`}
                                title={isCollapsed ? item.label : ''}
                            >
                                <span className="flex items-center justify-center">{item.icon}</span>
                                {!isCollapsed && <span className="ml-3">{item.label}</span>}
                            </button>
                        ))}
                    </div>
                </div>

                <div className="px-2 pb-6 mt-auto">
                    <button
                        onClick={handleLogout}
                        className={`flex items-center ${isCollapsed ? 'justify-center' : 'justify-start'} w-full px-4 py-3 text-gray-600 dark:text-gray-400 hover:bg-red-100 dark:hover:bg-red-900/20 hover:text-red-600 dark:hover:text-red-300 rounded-lg text-left transition-colors`}
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

export default AdminSidebar; 