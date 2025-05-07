import React, { useState, useEffect } from 'react';
import { FiMail, FiX, FiUser, FiSend, FiCheckCircle } from 'react-icons/fi';
import { axiosInstance } from '../../api/axiosInstance';
import { useTheme } from '../../context/ThemeContext';
import { toast } from 'react-toastify';

const InviteTeamMemberModal = ({ isOpen, onClose, onInviteSent }) => {
  const [email, setEmail] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState(false);
  const { isDarkMode } = useTheme();

  useEffect(() => {
    if (isOpen) {
      setEmail('');
      setError('');
      setSuccess(false);
      setLoading(false);
    }
  }, [isOpen]);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');

    try {
      const response = await axiosInstance.post(
        `/api/auth/invite`,
        { email },
        { withCredentials: true }
      );

      if (response.data.success) {
        setSuccess(true);
        toast.success(`Invitation sent successfully to ${email}!`);
        if (onInviteSent) {
          onInviteSent({ email });
        }
      } else {
        const message = response.data.message || 'Failed to send invitation';
        setError(message);
        toast.error(message);
      }
    } catch (err) {
      const message = err.response?.data?.message || 'An error occurred sending the invitation';
      setError(message);
      toast.error(message);
      console.error('Invitation error:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleClose = () => {
    setSuccess(false);
    onClose();
  };

  const handleSendAnother = () => {
    setSuccess(false);
    setEmail('');
    setError('');
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 bg-black/60 dark:bg-black/80 flex items-center justify-center z-50 p-4 transition-opacity duration-300">
      <div className="bg-white dark:bg-gray-800 rounded-lg w-full max-w-md border border-gray-200 dark:border-gray-700 shadow-xl transform transition-transform duration-300 scale-100">
        <div className="flex justify-between items-center border-b border-gray-200 dark:border-gray-700 p-4">
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white flex items-center">
            <FiMail className="mr-2" /> Invite Team Member
          </h3>
          <button
            onClick={handleClose}
            className="text-gray-400 hover:text-gray-600 dark:text-gray-500 dark:hover:text-white focus:outline-none p-1 rounded-full hover:bg-gray-100 dark:hover:bg-gray-700"
          >
            <FiX size={20} />
          </button>
        </div>

        {success ? (
          <div className="p-6 text-center">
            <FiCheckCircle className="mx-auto h-16 w-16 text-green-500 mb-4" />
            <h4 className="text-xl font-semibold mb-2 text-gray-900 dark:text-white">Invitation Sent!</h4>
            <p className="text-gray-600 dark:text-gray-300 mb-6">
              An invitation has been sent to <strong className="text-gray-800 dark:text-gray-100">{email}</strong>.
            </p>
            <div className="flex justify-center gap-3">
              <button
                onClick={handleClose}
                className="px-4 py-2 bg-white dark:bg-gray-700 border border-gray-300 dark:border-gray-600 text-gray-800 dark:text-white rounded-lg font-medium hover:bg-gray-50 dark:hover:bg-gray-600 transition-colors text-sm"
              >
                Close
              </button>
              <button
                onClick={handleSendAnother}
                className="px-4 py-2 bg-blue-600 text-white rounded-lg font-medium hover:bg-blue-700 transition-colors text-sm flex items-center"
              >
                <FiSend className="mr-1.5" size={14} /> Send Another
              </button>
            </div>
          </div>
        ) : (
          <form onSubmit={handleSubmit} className="p-6">
            <div className="space-y-5">
              <div>
                <label htmlFor="invite-email" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                  Email Address
                </label>
                <div className="relative">
                  <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                    <FiMail className="text-gray-400 dark:text-gray-500" />
                  </div>
                  <input
                    id="invite-email"
                    type="email"
                    required
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    className="w-full pl-10 pr-4 py-2 rounded-lg bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-600 focus:ring-2 focus:ring-blue-500 focus:border-transparent outline-none text-sm text-black dark:text-white placeholder-gray-500 dark:placeholder-gray-400"
                    placeholder="colleague@company.com"
                  />
                </div>
              </div>

              <div className="flex justify-end gap-3 pt-2">
                <button
                  type="button"
                  onClick={handleClose}
                  className="px-4 py-2 bg-white dark:bg-gray-700 border border-gray-300 dark:border-gray-600 text-gray-800 dark:text-white rounded-lg font-medium hover:bg-gray-50 dark:hover:bg-gray-600 transition-colors text-sm"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={loading || !email}
                  className="px-4 py-2 bg-blue-600 text-white rounded-lg font-medium hover:bg-blue-700 transition-colors disabled:opacity-60 disabled:cursor-not-allowed text-sm flex items-center justify-center min-w-[130px]"
                >
                  {loading ? (
                    <>
                      <svg className="animate-spin -ml-1 mr-2 h-4 w-4 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                        <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                        <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                      </svg>
                      Sending...
                    </>
                  ) : (
                    <>
                      <FiSend className="mr-1.5" size={14} /> Send Invitation
                    </>
                  )}
                </button>
              </div>
            </div>
          </form>
        )}
      </div>
    </div>
  );
};

export default InviteTeamMemberModal; 