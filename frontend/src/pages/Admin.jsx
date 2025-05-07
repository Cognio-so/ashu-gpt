import React, { useState, useEffect } from 'react';
import { Routes, Route, useLocation, useParams, useNavigate } from 'react-router-dom';
import AdminSidebar from '../components/Admin/AdminSidebar';
import AdminDashboard from '../components/Admin/AdminDashboard';
import TeamManagement from '../components/Admin/TeamManagement';
import CollectionsPage from '../components/Admin/CollectionsPage';
import CreateCustomGpt from '../components/Admin/CreateCustomGpt';
import SettingsPage from '../components/Admin/SettingsPage';
import HistoryPage from '../components/Admin/HistoryPage';
import UserHistoryPage from '../components/Admin/UserHistoryPage';
import AdminChat from '../components/Admin/AdminChat';

// Placeholder components for other sections
const CollectionsComponent = () => <div className="flex-1 p-6"><h1 className="text-2xl font-bold">Collections Page</h1></div>;
const HistoryComponent = () => <div className="flex-1 p-6"><h1 className="text-2xl font-bold">History Page</h1></div>;

const AdminLayout = () => {
    const location = useLocation();
    const navigate = useNavigate();
    const [activeSection, setActiveSection] = useState('dashboard');

    useEffect(() => {
        const path = location.pathname.split('/admin/')[1] || 'dashboard';
        if (path.startsWith('edit-gpt/')) {
            setActiveSection('collections');
        } else if (path.startsWith('create-gpt')) {
            setActiveSection('collections');
        } else {
            setActiveSection(path);
        }
    }, [location.pathname]);

    const handleSidebarNavigate = (sectionId) => {
        navigate(`/admin/${sectionId}`);
    };

    return (
        <div className="flex h-screen overflow-hidden bg-black">
            <AdminSidebar activePage={activeSection} onNavigate={handleSidebarNavigate} />

            <div className="flex-1 overflow-hidden">
                <Routes>
                    <Route index element={<AdminDashboard />} />
                    <Route path="dashboard" element={<AdminDashboard />} />
                    <Route path="collections" element={<CollectionsPage />} />
                    <Route path="create-gpt" element={<CreateCustomGpt onGoBack={() => navigate('/admin/collections')} />} />
                    <Route path="edit-gpt/:gptId" element={<EditGptWrapper />} />
                    <Route path="team" element={<TeamManagement />} />
                    <Route path="settings" element={<SettingsPage />} />
                    <Route path="history" element={<HistoryPage />} />
                    <Route path="history/user/:userId" element={<UserHistoryPage />} />
                    <Route path="chat/:gptId" element={<AdminChat />} />
                    <Route path="*" element={<AdminDashboard />} />
                </Routes>
            </div>
        </div>
    );
};

const EditGptWrapper = () => {
    const { gptId } = useParams();
    const navigate = useNavigate();
    return <CreateCustomGpt editGptId={gptId} onGoBack={() => navigate('/admin/collections')} />;
};

export default AdminLayout;