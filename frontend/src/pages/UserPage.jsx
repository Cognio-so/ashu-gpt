import React, { useState, useEffect } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import Sidebar from '../components/User/Sidebar';
import UserDashboard from '../components/User/UserDashboard';
import FavoritesPage from '../components/User/FavoritesPage';
import HistoryPage from '../components/User/HistoryPage';
import SettingsPage from '../components/User/SettingsPage';
import UserChat from '../components/User/UserChat';

// Placeholder components for other pages
const Favourites = () => <div className="p-4 sm:p-8 text-white mt-16 md:mt-0"><h1 className="text-2xl">Favourites Page</h1></div>;
const History = () => <div className="p-4 sm:p-8 text-white mt-16 md:mt-0"><h1 className="text-2xl">History Page</h1></div>;

const Layout = () => {
  const [currentPage, setCurrentPage] = useState('dashboard');
  const [isMobile, setIsMobile] = useState(false);
  const location = useLocation();
  const navigate = useNavigate();
  const queryParams = new URLSearchParams(location.search);
  const gptId = queryParams.get('gptId');

  // Check for mobile view
  useEffect(() => {
    const handleResize = () => {
      setIsMobile(window.innerWidth < 768);
    };

    window.addEventListener('resize', handleResize);
    handleResize(); // Check on initial render

    return () => window.removeEventListener('resize', handleResize);
  }, []);

  // Update currentPage based on location path
  useEffect(() => {
    const path = location.pathname.split('/user/')[1] || 'dashboard';
    setCurrentPage(path);
  }, [location.pathname]);

  // Handle sidebar navigation - renamed to match what UserChat.jsx expects
  const handleSidebarNavigation = (pageId) => {
    navigate(`/user/${pageId}`);
  };

  // Determine what content to render in the main area
  const renderMainContent = () => {
    if (gptId) {
      return <UserChat />; // Render chat if gptId is present
    }

    // Otherwise, render the selected page
    switch (currentPage) {
      case 'dashboard':
        return <UserDashboard />;
      case 'favourites':
      case 'favorites':
        return <FavoritesPage />;
      case 'history':
        return <HistoryPage />;
      case 'settings':
        return <SettingsPage />;
      default:
        return <UserDashboard />;
    }
  };

  return (
    <div className="flex h-screen overflow-hidden bg-black">
      {/* Sidebar is always rendered */}
      <Sidebar activePage={currentPage} onNavigate={handleSidebarNavigation} />

      {/* Main content area renders conditionally */}
      <div className={`flex-1 overflow-auto ${isMobile ? 'w-full' : ''}`}>
        {renderMainContent()}
      </div>
    </div>
  );
};

export default Layout;
