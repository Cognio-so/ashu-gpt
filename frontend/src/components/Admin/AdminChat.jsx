import React, { useState, useEffect, useRef } from 'react';
import { motion } from 'framer-motion';
import { useParams, useNavigate } from 'react-router-dom';
import AdminMessageInput from './AdminMessageInput';
import { useAuth } from '../../context/AuthContext';
import { useTheme } from '../../context/ThemeContext';
import { IoPersonCircleOutline, IoSettingsOutline, IoPersonOutline, IoArrowBack, IoClose } from 'react-icons/io5';
import { axiosInstance } from '../../api/axiosInstance';
import axios from 'axios';
import ReactMarkdown from 'react-markdown';
import rehypeRaw from 'rehype-raw';
import remarkGfm from 'remark-gfm';
import { Prism as SyntaxHighlighter } from 'react-syntax-highlighter';
import { atomDark } from 'react-syntax-highlighter/dist/esm/styles/prism';
import { FaFilePdf, FaFileWord, FaFileAlt, FaFile } from 'react-icons/fa';

const PYTHON_URL = import.meta.env.VITE_PYTHON_API_URL || 'http://localhost:8000';

const MarkdownStyles = () => (
    <style dangerouslySetInnerHTML={{__html: `
        .markdown-content {
            line-height: 1.6;
            width: 100%;
        }
        
        .markdown-content h1,
        .markdown-content h2,
        .markdown-content h3 {
            margin-top: 1.5em;
            margin-bottom: 0.5em;
        }
        
        .markdown-content h1:first-child,
        .markdown-content h2:first-child,
        .markdown-content h3:first-child {
            margin-top: 0;
        }
        
        .markdown-content code {
            font-family: 'SFMono-Regular', Consolas, 'Liberation Mono', Menlo, monospace;
        }
        
        .markdown-content pre {
            overflow-x: auto;
            border-radius: 0.375rem;
        }
        
        .markdown-content blockquote {
            font-style: italic;
            color: #6b7280;
        }
        
        .markdown-content a {
            text-decoration: none;
        }
        
        .markdown-content a:hover {
            text-decoration: underline;
        }
        
        .markdown-content table {
            border-collapse: collapse;
        }
        
        .markdown-content img {
            max-width: 100%;
            height: auto;
        }
        
        .markdown-content hr {
            border-top: 1px solid;
            margin: 1em 0;
        }
        
        /* Hide scrollbar but maintain functionality */
        .hide-scrollbar {
            -ms-overflow-style: none;  /* IE and Edge */
            scrollbar-width: none;     /* Firefox */
        }
        
        .hide-scrollbar::-webkit-scrollbar {
            display: none;  /* Chrome, Safari, Opera */
        }
    `}} />
);

const AdminChat = () => {
    const { gptId } = useParams();
    const navigate = useNavigate();
    const { user, loading: authLoading } = useAuth();
    const { isDarkMode } = useTheme();
    const [isProfileOpen, setIsProfileOpen] = useState(false);
    const [userData, setUserData] = useState(null);
    const [isLoading, setIsLoading] = useState(false);
    const [isFetchingGpt, setIsFetchingGpt] = useState(false);
    const [gptData, setGptData] = useState(null);
    const [messages, setMessages] = useState([]);
    const [collectionName, setCollectionName] = useState(null);
    const messagesEndRef = useRef(null);
    const [userDocuments, setUserDocuments] = useState([]);
    const [isUploading, setIsUploading] = useState(false);
    const [uploadProgress, setUploadProgress] = useState(0);
    const [streamingMessage, setStreamingMessage] = useState(null);
    const [uploadedFiles, setUploadedFiles] = useState([]);
    const [backendAvailable, setBackendAvailable] = useState(null);
    const [hasInteracted, setHasInteracted] = useState(false);
    const [conversationMemory, setConversationMemory] = useState([]);
    const [hasNotifiedGptOpened, setHasNotifiedGptOpened] = useState(false);
    const [conversationId, setConversationId] = useState(null);
    
    // Use effect to handle user data changes
    useEffect(() => {
        if (user) {
            setUserData(user);
        }
    }, [user]);
    
    // Notify backend when GPT opens to trigger indexing
    const notifyGptOpened = async (gptData, userData) => {
        try {
            // Add additional check for gptData._id being defined
            if (!gptData || !userData || !gptData._id || hasNotifiedGptOpened) {
                console.log("Skipping GPT opened notification due to missing data");
                return;
            }
            
            // Only use remote file URLs, ensure no local file paths
            const fileUrls = gptData.knowledgeFiles?.map(file => file.fileUrl).filter(url => 
                url && (url.startsWith('http://') || url.startsWith('https://'))
            ) || [];
            
            console.log("Notifying GPT opened:", gptData._id);
            
            // Get hybridSearch setting from capabilities
            const useHybridSearch = gptData.capabilities?.hybridSearch || false;
            
            const response = await axios.post(
                `${PYTHON_URL}/gpt-opened`,
                {
                    user_email: userData.email,
                    gpt_name: gptData.name,
                    gpt_id: gptData._id,
                    file_urls: fileUrls,
                    // Use the actual hybridSearch setting
                    use_hybrid_search: useHybridSearch,
                    schema: {
                        model: gptData.model,
                        instructions: gptData.instructions,
                        capabilities: gptData.capabilities,
                        // Use the actual hybridSearch setting
                        use_hybrid_search: useHybridSearch
                    }
                },
                {
                    headers: {
                        'Content-Type': 'application/json',
                    }
                }
            );
            
            if (response.data.success) {
                console.log("GPT opened notification successful");
                setCollectionName(response.data.collection_name);
                setHasNotifiedGptOpened(true);
            }
        } catch (error) {
            console.error("Error notifying GPT opened:", error);
            // Don't set hasNotifiedGptOpened to true on error, allowing retry
        }
    };
    
    // Fetch GPT data if gptId is provided
    useEffect(() => {
        // Add check for userData to ensure user is authenticated before fetching
        if (gptId && userData) { 
            const fetchGptData = async () => {
                try {
                    setIsFetchingGpt(true);
                    const token = localStorage.getItem('authToken'); // or however you store your token
                    
                    const response = await axiosInstance.get(`/api/custom-gpts/${gptId}`, {
                        headers: {
                            'Authorization': `Bearer ${token}`,
                            'Content-Type': 'application/json'
                        },
                        withCredentials: true
                    });
                    
                    if (response.data.success) {
                        const fetchedGptData = response.data.customGpt;
                        setGptData(fetchedGptData);
                        setMessages([]);
                        
                        // Notify backend when GPT is opened
                        notifyGptOpened(fetchedGptData, userData);
                    } else {
                        console.error("Failed to load GPT data, success false");
                        navigate(-1);
                    }
                } catch (err) {
                    console.error("Error fetching GPT data:", err);
                    if (err.response?.status === 401) {
                        // Handle unauthorized error - maybe redirect to login
                        navigate('/login');
                    } else {
                        navigate(-1);
                    }
                } finally {
                    setIsFetchingGpt(false);
                }
            };
            
            fetchGptData();
        } else if (!gptId) { // Handle case where gptId is removed or absent
            setGptData(null);
            setMessages([]);
        }
        // Ensure userData is in the dependency array so the effect reruns when user logs in/out
    }, [gptId, navigate, userData]);
    
    // Update the useEffect that calls notifyGptOpened
    useEffect(() => {
        if (gptData && userData && !hasNotifiedGptOpened) {
            notifyGptOpened(gptData, userData);
        }
    }, [gptData, userData, hasNotifiedGptOpened]);
    
    const predefinedPrompts = [
        {
            id: 1,
            title: 'Create an Agent',
            prompt: 'I want to create a new AI agent for customer service tasks. What capabilities should I include?'
        },
        {
            id: 2,
            title: 'Configure Agent Settings',
            prompt: 'Help me configure the response patterns and permissions for my marketing assistant agent.'
        },
        {
            id: 3,
            title: 'Agent Performance',
            prompt: 'Can you show me analytics on how my support agents have been performing this month?'
        },
    ];

    const handlePromptClick = (item) => {
        handleChatSubmit(item.prompt);
    };

    // Function to save messages to history
    const saveMessageToHistory = async (message, role) => {
        try {
            if (!user?._id || !gptData || !message || !message.trim()) {
                console.warn('Cannot save message - missing data:', { 
                    userId: user?._id, 
                    gptId: gptData?._id,
                    hasMessage: !!message,
                    role
                });
                return null;
            }

            console.log(`Saving ${role} message to history:`, message.substring(0, 30) + '...');
            
            const payload = {
                userId: user._id,
                gptId: gptData._id,
                gptName: gptData.name || 'AI Assistant',
                message: message.trim(),
                role: role,
                model: gptData.model || 'gpt-4o-mini'
            };
            
            // Include conversation ID if it exists for threading messages
            if (conversationId) {
                payload.conversationId = conversationId;
            }
            
            const response = await axiosInstance.post('/api/chat-history/save', payload, {
                withCredentials: true
            });

            // Save the conversation ID for subsequent messages
            if (response.data && response.data.conversation && response.data.conversation._id) {
                setConversationId(response.data.conversation._id);
            }

            console.log(`${role} message saved successfully:`, response.data);
            return response.data;
        } catch (error) {
            console.error(`Error saving ${role} message to history:`, error.response?.data || error.message);
            return null;
        }
    };

    // Update handleChatSubmit to save messages
    const handleChatSubmit = async (message) => {
        if (!message.trim()) return;

        try {
            const userMessage = {
                id: Date.now(),
                role: 'user',
                content: message,
                timestamp: new Date()
            };
            
            // Save user message to history first
            await saveMessageToHistory(message, 'user');
            
            // Add to UI messages
            setMessages(prev => [...prev, userMessage]);
            
            // Update conversation memory with relevant context
            const updatedMemory = [...conversationMemory];
            if (updatedMemory.length >= 10) {
                // Keep only the most recent messages if memory gets too large
                updatedMemory.splice(0, updatedMemory.length - 9);
            }
            updatedMemory.push({
                role: 'user',
                content: message,
                timestamp: new Date().toISOString()
            });
            setConversationMemory(updatedMemory);
            
            setIsLoading(true);
            setHasInteracted(true);
            
            // Create request payload with enhanced memory
            // FIX: No longer need chatCollectionName here for the main payload
            // const chatCollectionName = collectionName || gptData?._id || "default_collection"; 
            
            // Get hybridSearch setting from capabilities
            const useHybridSearch = gptData?.capabilities?.hybridSearch || false;
            
            const payload = {
                message,
                // FIX: Send gptId instead of constructed collectionName
                gpt_id: gptId, 
                // FIX: Add user_email (using admin user's email)
                user_email: user?.email || 'unknown_admin', 
                // FIX: Add gpt_name
                gpt_name: gptData?.name || 'unknown_gpt', 
                user_documents: userDocuments,
                // model: gptData?.model, // Model is determined backend-side based on collection/gpt_id now
                memory: updatedMemory,
                history: messages.slice(-6).map(msg => ({
                    role: msg.role,
                    content: msg.content
                })),
                // Use the actual hybridSearch setting
                use_hybrid_search: useHybridSearch
            };

            // Add check for gptId before making the call
            if (!payload.gpt_id) {
                throw new Error("GPT ID is missing, cannot send message.");
            }
            
            // Try streaming first
            try {
                console.log("Attempting streaming response with payload:", payload); // Log the payload
                const response = await fetch(`${PYTHON_URL}/chat-stream`, {
                    method: "POST",
                    headers: {
                        'Content-Type': 'application/json',
                         // Add credentials if your backend CORS requires it for fetch
                        // credentials: 'include' 
                    },
                    body: JSON.stringify(payload)
                });
                
                if (response.ok) {
                    console.log("Stream response OK, handling stream...");
                    await handleStreamingResponse(response);
                } else {
                    console.error("Stream response not OK:", response.status, response.statusText);
                    const errorText = await response.text(); // Try to get error text
                    console.error("Stream error response body:", errorText);
                    throw new Error(`HTTP error! status: ${response.status} - ${errorText || response.statusText}`);
                }
            } catch (streamingError) {
                console.warn("Streaming failed, falling back to regular chat API:", streamingError);
                
                // Fallback to regular chat API
                 // Remove model from payload as it's handled backend-side
                // delete payload.model; 
                console.log("Attempting fallback response with payload:", payload); // Log the fallback payload

                const fallbackResponse = await axios.post(
                    `${PYTHON_URL}/chat`, 
                    payload,
                    {
                        headers: {
                            'Content-Type': 'application/json',
                            // credentials: 'include' // If using axios withCredentials in instance, maybe not needed here
                        },
                        // withCredentials: true // If using axios directly and need cookies
                    }
                );
                
                console.log("Fallback response:", fallbackResponse.data);
                
                if (fallbackResponse.data && fallbackResponse.data.success && fallbackResponse.data.response) {
                    const aiResponse = {
                        id: Date.now() + 1,
                        role: 'assistant',
                        content: fallbackResponse.data.response,
                        timestamp: new Date()
                    };
                    
                    setMessages(prev => [...prev, aiResponse]);
                     // Save fallback response to history
                    await saveMessageToHistory(aiResponse.content, 'assistant');

                } else {
                     // Handle fallback failure
                    const errorContent = fallbackResponse.data?.response || "Failed to get response from fallback API.";
                    const errorResponse = {
                        id: Date.now() + 1,
                        role: 'assistant',
                        content: errorContent,
                        timestamp: new Date()
                    };
                    setMessages(prev => [...prev, errorResponse]);
                    await saveMessageToHistory(errorContent, 'assistant'); // Save error
                }
            }
        } catch (err) {
            console.error("Error in handleChatSubmit:", err);
            // Set error in message list
            const errorContent = `I'm sorry, I couldn't process your request: ${err.message}`;
            const errorResponse = {
                id: Date.now() + 1,
                role: 'assistant',
                content: errorContent,
                timestamp: new Date()
            };
            setMessages(prev => [...prev, errorResponse]);
            
            // Save error message to history
            await saveMessageToHistory(errorContent, 'assistant');
            
            setStreamingMessage(null); // Clear any partial streaming message
        } finally {
            setIsLoading(false);
        }
    };
    
    const toggleProfile = () => {
        setIsProfileOpen(!isProfileOpen);
    };

    const handleGoBack = () => {
        navigate(-1);
    };

    const mockUser = {
        name: "Admin User",
        email: "admin@example.com",
        profilePic: null
    };

    // Scroll to bottom when messages change
    useEffect(() => {
        messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
    }, [messages]);

    const handleFileUpload = async (files) => {
        if (!files.length || !gptData) return;
        
        try {
            // Set uploading state to true
            setIsUploading(true);
            setUploadProgress(0);
            // Store file information for display
            setUploadedFiles(Array.from(files).map(file => ({
                name: file.name,
                size: file.size,
                type: file.type
            })));
            
            // Create FormData for file upload
            const formData = new FormData();
            for (let i = 0; i < files.length; i++) {
                formData.append('files', files[i]);
            }
            formData.append('user_email', userData?.email || 'user@example.com');
            formData.append('gpt_id', gptData._id);
            formData.append('gpt_name', gptData.name);
            formData.append('collection_name', collectionName || gptData._id);
            formData.append('is_user_document', 'true');
            
            // Use a faster progress simulation for better perceived performance
            const startTime = Date.now();
            const uploadDuration = 1500; // 1.5 seconds for initial upload phase
            const progressInterval = setInterval(() => {
                const elapsed = Date.now() - startTime;
                if (elapsed < uploadDuration) {
                    // Fast progress to 60% during "upload" phase
                    const progress = Math.min(60, (elapsed / uploadDuration) * 60);
                    setUploadProgress(progress);
                } else {
                    // Then slower progress to 90% during "processing" phase
                    setUploadProgress(prev => {
                        if (prev < 90) {
                            return prev + (90 - prev) * 0.08;
                        }
                        return prev;
                    });
                }
            }, 100); // Update progress more frequently
            
            // Upload files to backend
            const response = await axios.post(
                `${PYTHON_URL}/upload-chat-files`,
                formData,
                {
                    headers: {
                        'Content-Type': 'multipart/form-data',
                    },
                    onUploadProgress: (progressEvent) => {
                        // Only use real progress for the first 60%
                        const percentCompleted = Math.round(
                            (progressEvent.loaded * 60) / (progressEvent.total || 100)
                        );
                        // Cap at 60% since processing happens after upload
                        setUploadProgress(Math.min(percentCompleted, 60));
                    }
                }
            );
            
            // Clear the progress interval
            clearInterval(progressInterval);
            
            // Complete the progress bar
            setUploadProgress(100);
            
            // Small delay before removing the progress indicator
            setTimeout(() => {
                setIsUploading(false);
            }, 500);
            
            if (response.data.success) {
                // Track the user documents - use remote URLs only
                setUserDocuments(response.data.file_urls || []);
            } else {
                throw new Error(response.data.message || "Failed to process files");
            }
        } catch (error) {
            console.error("Error uploading files:", error);
            
            // Stop the animation
            setIsUploading(false);
        }
    };

    // Add a helper function to determine file icon
    const getFileIcon = (filename) => {
        if (!filename) return <FaFile className="text-white" />;
        
        const extension = filename.split('.').pop().toLowerCase();
        
        switch (extension) {
            case 'pdf':
                return <FaFilePdf className="text-white" />;
            case 'doc':
            case 'docx':
                return <FaFileWord className="text-white" />;
            case 'txt':
                return <FaFileAlt className="text-white" />;
            default:
                return <FaFile className="text-white" />;
        }
    };

    // Add function to handle removing uploaded file
    const handleRemoveUploadedFile = (indexToRemove) => {
        setUploadedFiles(prevFiles => prevFiles.filter((_, index) => index !== indexToRemove));
    };

    // Add this useEffect to check backend availability
    useEffect(() => {
        const checkBackendAvailability = async () => {
            try {
                // Change from HEAD request to / to a known endpoint that exists
                await axios.get(`${PYTHON_URL}/gpt-collection-info/test/test`);
                setBackendAvailable(true);
            } catch (error) {
                // Even if the endpoint returns 404/400, the server is still running
                // Only mark as offline for network errors
                if (error.code === "ERR_NETWORK") {
                    console.error("Backend server appears to be offline:", error);
                    setBackendAvailable(false);
                } else {
                    // If we get any response (even error), server is running
                    console.log("Backend server available but request failed:", error);
                    setBackendAvailable(true);
                }
            }
        };
        
        checkBackendAvailability();
    }, []);

    // Add this useEffect to log streaming message updates
    useEffect(() => {
        if (streamingMessage) {
            console.log("Streaming message updated:", streamingMessage);
        }
    }, [streamingMessage]);

    // Update handleStreamingResponse to save completed assistant messages
    const handleStreamingResponse = async (response) => {
        const reader = response.body.getReader();
        const decoder = new TextDecoder();
        
        try {
            while (true) {
                const { done, value } = await reader.read();
                
                if (done) {
                    // Save the complete message to history when streaming is done
                    if (streamingMessage) {
                        await saveMessageToHistory(streamingMessage.content, 'assistant');
                    }
                    
                    setStreamingMessage(prev => prev ? { ...prev, isStreaming: false } : null);
                    break;
                }
                
                const text = decoder.decode(value, {stream: true});
                console.log("Raw streaming data:", text);
                
                const trimmedText = text.trim();
                if (trimmedText) {
                    try {
                        // Try to parse it as full JSON for better debugging
                        const parsed = JSON.parse(trimmedText);
                        console.log("Full parsed stream chunk:", parsed);
                    } catch {
                        // If not valid JSON, just log the raw text
                        console.log("Raw stream chunk text:", trimmedText.substring(0, 100) + (trimmedText.length > 100 ? "..." : ""));
                    }
                }
                
                const lines = text.split('\n').filter(line => line.trim());
                
                for (const line of lines) {
                    if (line.startsWith('data: ')) {
                        try {
                            const jsonStr = line.substring(6);
                            const parsed = JSON.parse(jsonStr);
                            
                            if (parsed.error) {
                                console.error("Streaming Error:", parsed.error);
                                setStreamingMessage({
                                    id: Date.now(),
                                    role: 'assistant',
                                    content: `Error: ${parsed.error}`,
                                    isStreaming: false,
                                    timestamp: new Date()
                                });
                                return;
                            }
                            
                            if (parsed.done === true) {
                                setStreamingMessage(prev => prev ? { ...prev, isStreaming: false } : null);
                                return;
                            }
                            
                            if (parsed.content) {
                                setStreamingMessage((prev) => ({
                                    id: prev?.id || Date.now(),
                                    role: 'assistant',
                                    content: prev ? prev.content + parsed.content : parsed.content,
                                    isStreaming: true,
                                    timestamp: prev?.timestamp || new Date()
                                }));
                            }
                        } catch (e) {
                            console.error("Error parsing streaming line:", e, "Line:", line);
                        }
                    }
                }
            }
        } catch (err) {
            console.error("Error reading stream:", err);
            const errorContent = "Error reading response stream.";
            setStreamingMessage({
                id: Date.now(),
                role: 'assistant',
                content: errorContent,
                isStreaming: false,
                timestamp: new Date()
            });
            
            // Save error message to history
            await saveMessageToHistory(errorContent, 'assistant');
        }
    };

    // Add this useEffect above the return statement in your component
    useEffect(() => {
        // When a streaming message completes, add it to the messages array
        if (streamingMessage && !streamingMessage.isStreaming) {
            console.log("Adding completed streaming message to messages:", streamingMessage);
            
            // First add to main message list
            setMessages(prev => {
                // Check if message with same ID already exists to prevent duplicates
                const exists = prev.some(m => m.id === streamingMessage.id);
                if (exists) return prev;
                return [...prev, { ...streamingMessage }];
            });
            
            // Then update conversation memory
            setConversationMemory(prev => [...prev, {
                role: 'assistant',
                content: streamingMessage.content,
                timestamp: new Date().toISOString()
            }]);
            
            // Finally clear the streaming message
            setTimeout(() => setStreamingMessage(null), 100);
        }
    }, [streamingMessage]);

    return (
        <>
            <MarkdownStyles />
        <div className='flex flex-col h-screen bg-white dark:bg-black text-black dark:text-white overflow-hidden'>
            <div className="flex-shrink-0 bg-white dark:bg-black px-4 py-3 flex items-center justify-between">
                <div className="w-10 h-10">
                    {gptId && (
                        <button 
                            onClick={handleGoBack}
                            className="text-gray-500 dark:text-gray-400 hover:text-black dark:hover:text-white p-2 rounded-full hover:bg-gray-100 dark:hover:bg-gray-800 transition-colors flex items-center justify-center w-full h-full"
                            aria-label="Go back"
                        >
                            <IoArrowBack size={20} />
                        </button>
                    )}
                </div>
                <div className="relative">
                    <button 
                        onClick={toggleProfile}
                        className="w-10 h-10 rounded-full overflow-hidden border-2 border-gray-300 dark:border-white/20 hover:border-blue-500 dark:hover:border-white/40 transition-colors"
                    >
                        {(userData || mockUser)?.profilePic ? (
                            <img 
                                src={(userData || mockUser).profilePic} 
                                alt="Profile" 
                                className="w-full h-full object-cover"
                            />
                        ) : (
                            <div className="w-full h-full bg-gray-200 dark:bg-gray-700 flex items-center justify-center">
                                <IoPersonCircleOutline size={24} className="text-gray-500 dark:text-white" />
                            </div>
                        )}
                    </button>
                    
                    {isProfileOpen && (
                        <div className="absolute top-12 right-0 w-64 bg-white dark:bg-[#1e1e1e] rounded-xl shadow-lg border border-gray-200 dark:border-white/10 overflow-hidden z-30">
                            <div className="p-4 border-b border-gray-200 dark:border-white/10">
                                <p className="font-medium text-gray-900 dark:text-white">
                                    {userData?.name || mockUser.name}
                                </p>
                                <p className="text-sm text-gray-500 dark:text-gray-400 truncate">
                                    {userData?.email || mockUser.email}
                                </p>
                            </div>
                            <div className="py-1">
                                <button className="w-full px-4 py-2.5 text-left flex items-center space-x-3 hover:bg-gray-100 dark:hover:bg-white/5 text-gray-700 dark:text-gray-300">
                                    <IoPersonOutline size={18} />
                                    <span>Profile</span>
                                </button>
                                <button className="w-full px-4 py-2.5 text-left flex items-center space-x-3 hover:bg-gray-100 dark:hover:bg-white/5 text-gray-700 dark:text-gray-300" onClick={() => navigate('/admin/settings')}>
                                    <IoSettingsOutline size={18} />
                                    <span>Settings</span>
                                </button>
                            </div>
                        </div>
                    )}
                </div>
            </div>
            
                <div className="flex-1 overflow-y-auto p-4 flex flex-col bg-white dark:bg-black hide-scrollbar">
                <div className="w-full max-w-3xl mx-auto flex-1 flex flex-col space-y-4 pb-4">
                    {isFetchingGpt ? (
                        <div className="flex-1 flex items-center justify-center">
                            <div className="animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-blue-500 dark:border-blue-400"></div>
                        </div>
                    ) : messages.length === 0 ? (
                        <div className="flex-1 flex flex-col items-center justify-center text-center px-2">
                            {gptId && gptData ? (
                                <>
                                    <div className="w-16 h-16 rounded-full bg-gradient-to-br from-blue-600 to-purple-600 flex items-center justify-center mb-4">
                                        {gptData.imageUrl ? (
                                            <img src={gptData.imageUrl} alt={gptData.name} className="w-full h-full object-cover rounded-full" />
                                        ) : (
                                            <span className="text-2xl text-white">{gptData.name?.charAt(0) || '?'}</span>
                                        )}
                                    </div>
                                    <h2 className="text-xl font-semibold mb-2 text-gray-900 dark:text-white">{gptData.name}</h2>
                                    <p className="text-gray-500 dark:text-gray-400 max-w-md">{gptData.description || 'Start a conversation...'}</p>
                                    
                                    {/* Truncated conversation starter */}
                                    {gptData.conversationStarter && (
                                        <div 
                                            onClick={() => handleChatSubmit(gptData.conversationStarter)}
                                            className="mt-5 max-w-xs p-3 bg-gray-100 dark:bg-gray-800/70 border border-gray-300 dark:border-gray-700/70 rounded-lg text-left cursor-pointer hover:bg-gray-200 dark:hover:bg-gray-800 hover:border-gray-400 dark:hover:border-gray-600/70 transition-colors"
                                        >
                                            <p className="text-gray-800 dark:text-white text-sm">
                                                {gptData.conversationStarter.length > 40 
                                                    ? gptData.conversationStarter.substring(0, 40) + '...' 
                                                    : gptData.conversationStarter
                                                }
                                            </p>
                                        </div>
                                    )}
                                </>
                            ) : (
                                <>
                                    <h1 className='text-2xl sm:text-3xl md:text-4xl font-bold mb-2 text-gray-900 dark:text-white'>Welcome to AI Agent</h1>
                                    <span className='text-base sm:text-lg md:text-xl font-medium text-gray-500 dark:text-gray-400 mb-8 block'>How can I assist you today?</span>
                                    
                                    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3 sm:gap-4 md:gap-6 w-full">
                                        {predefinedPrompts.map((item) => (
                                            <motion.div
                                                key={item.id}
                                                className={`group relative bg-white dark:bg-white/[0.05] backdrop-blur-xl border border-gray-200 dark:border-white/20 hover:bg-gray-50 dark:hover:bg-white/[0.08] shadow-md hover:shadow-lg rounded-xl p-3 cursor-pointer transition-all duration-150 text-left`}
                                                whileHover={{ scale: 1.03, y: -2, transition: { duration: 0.15 } }}
                                                whileTap={{ scale: 0.98 }}
                                                onClick={() => handlePromptClick(item)}
                                            >
                                                <div className="relative z-10">
                                                    <h3 className="font-medium text-sm sm:text-base mb-1 text-gray-800 dark:text-gray-100">{item.title}</h3>
                                                    <p className="text-gray-600 dark:text-gray-400 text-xs sm:text-sm line-clamp-2">{item.prompt}</p>
                                                </div>
                                            </motion.div>
                                        ))}
                                    </div>
                                </>
                            )}
                        </div>
                    ) : (
                        <>
                            {messages.map(message => (
                                <div 
                                    key={message.id} 
                                    className={`flex ${message.role === 'user' ? 'justify-end' : 'justify-start'}`}
                                >
                                    <div 
                                        className={`w-full max-w-[95%] rounded-2xl px-5 py-4 ${
                                            message.role === 'user' 
                                                ? 'user-message-glossy text-white rounded-br-none' 
                                                : 'assistant-message text-black dark:text-white rounded-bl-none'
                                        }`}
                                    >
                                        {message.role === 'user' ? (
                                        <p className="whitespace-pre-wrap">{message.content}</p> 
                                        ) : (
                                            <div className="markdown-content">
                                                <ReactMarkdown
                                                    remarkPlugins={[remarkGfm]}
                                                    rehypePlugins={[rehypeRaw]}
                                                    components={{
                                                        h1: ({node, ...props}) => <h1 className="text-xl font-bold my-3" {...props} />,
                                                        h2: ({node, ...props}) => <h2 className="text-lg font-bold my-2" {...props} />,
                                                        h3: ({node, ...props}) => <h3 className="text-md font-bold my-2" {...props} />,
                                                        h4: ({node, ...props}) => <h4 className="font-bold my-2" {...props} />,
                                                        p: ({node, ...props}) => <p className="my-2" {...props} />,
                                                        ul: ({node, ...props}) => <ul className="list-disc pl-5 my-2" {...props} />,
                                                        ol: ({node, ...props}) => <ol className="list-decimal pl-5 my-2" {...props} />,
                                                        li: ({node, index, ...props}) => <li key={index} className="my-1" {...props} />,
                                                        a: ({node, ...props}) => <a className="text-blue-400 hover:underline" {...props} />,
                                                        blockquote: ({node, ...props}) => <blockquote className="border-l-4 border-gray-500 dark:border-gray-400 pl-4 my-3 italic" {...props} />,
                                                        code({node, inline, className, children, ...props}) {
                                                            const match = /language-(\w+)/.exec(className || '');
                                                            return !inline && match ? (
                                                                <SyntaxHighlighter
                                                                    style={atomDark}
                                                                    language={match[1]}
                                                                    PreTag="div"
                                                                    className="rounded-md my-3"
                                                                    {...props}
                                                                >
                                                                    {String(children).replace(/\n$/, '')}
                                                                </SyntaxHighlighter>
                                                            ) : (
                                                                <code className={`${inline ? 'bg-gray-300 dark:bg-gray-600 px-1 py-0.5 rounded text-sm' : ''} ${className}`} {...props}>
                                                                    {children}
                                                                </code>
                                                            );
                                                        },
                                                        table: ({node, ...props}) => (
                                                            <div className="overflow-x-auto my-3">
                                                                <table className="min-w-full border border-gray-400 dark:border-gray-500" {...props} />
                                                            </div>
                                                        ),
                                                        thead: ({node, ...props}) => <thead className="bg-gray-300 dark:bg-gray-600" {...props} />,
                                                        tbody: ({node, ...props}) => <tbody className="divide-y divide-gray-400 dark:divide-gray-500" {...props} />,
                                                        tr: ({node, ...props}) => <tr className="hover:bg-gray-300 dark:hover:bg-gray-600" {...props} />,
                                                        th: ({node, ...props}) => <th className="px-4 py-2 text-left font-medium" {...props} />,
                                                        td: ({node, ...props}) => <td className="px-4 py-2" {...props} />,
                                                    }}
                                                >
                                                    {message.content}
                                                </ReactMarkdown>
                                            </div>
                                        )}
                                        <div 
                                            className={`text-xs mt-2 text-right ${
                                                message.role === 'user' ? 'text-blue-50/80' : 'text-gray-400/80'
                                            }`}
                                        >
                                            {new Date(message.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                                        </div>
                                    </div>
                                </div>
                            ))}
                            
                            {/* Display streaming message */}
                            {streamingMessage && (
                                <div className="flex justify-start">
                                    <div className="w-full max-w-[95%] rounded-2xl px-5 py-4 assistant-message text-black dark:text-white rounded-bl-none">
                                        <div className="markdown-content">
                                            <ReactMarkdown
                                                remarkPlugins={[remarkGfm]}
                                                rehypePlugins={[rehypeRaw]}
                                                components={{
                                                    h1: ({node, ...props}) => <h1 className="text-xl font-bold my-3" {...props} />,
                                                    h2: ({node, ...props}) => <h2 className="text-lg font-bold my-2" {...props} />,
                                                    h3: ({node, ...props}) => <h3 className="text-md font-bold my-2" {...props} />,
                                                    h4: ({node, ...props}) => <h4 className="font-bold my-2" {...props} />,
                                                    p: ({node, ...props}) => <p className="my-2" {...props} />,
                                                    ul: ({node, ...props}) => <ul className="list-disc pl-5 my-2" {...props} />,
                                                    ol: ({node, ...props}) => <ol className="list-decimal pl-5 my-2" {...props} />,
                                                    li: ({node, index, ...props}) => <li key={index} className="my-1" {...props} />,
                                                    a: ({node, ...props}) => <a className="text-blue-400 hover:underline" {...props} />,
                                                    blockquote: ({node, ...props}) => <blockquote className="border-l-4 border-gray-500 dark:border-gray-400 pl-4 my-3 italic" {...props} />,
                                                    code({node, inline, className, children, ...props}) {
                                                        const match = /language-(\w+)/.exec(className || '');
                                                        return !inline && match ? (
                                                            <SyntaxHighlighter
                                                                style={atomDark}
                                                                language={match[1]}
                                                                PreTag="div"
                                                                className="rounded-md my-3"
                                                                {...props}
                                                            >
                                                                {String(children).replace(/\n$/, '')}
                                                            </SyntaxHighlighter>
                                                        ) : (
                                                            <code className={`${inline ? 'bg-gray-300 dark:bg-gray-600 px-1 py-0.5 rounded text-sm' : ''} ${className}`} {...props}>
                                                                {children}
                                                            </code>
                                                        );
                                                    },
                                                    table: ({node, ...props}) => (
                                                        <div className="overflow-x-auto my-3">
                                                            <table className="min-w-full border border-gray-400 dark:border-gray-500" {...props} />
                                                        </div>
                                                    ),
                                                    thead: ({node, ...props}) => <thead className="bg-gray-300 dark:bg-gray-600" {...props} />,
                                                    tbody: ({node, ...props}) => <tbody className="divide-y divide-gray-400 dark:divide-gray-500" {...props} />,
                                                    tr: ({node, ...props}) => <tr className="hover:bg-gray-300 dark:hover:bg-gray-600" {...props} />,
                                                    th: ({node, ...props}) => <th className="px-4 py-2 text-left font-medium" {...props} />,
                                                    td: ({node, ...props}) => <td className="px-4 py-2" {...props} />,
                                                }}
                                            >
                                                {streamingMessage.content}
                                            </ReactMarkdown>
                                            
                                            {streamingMessage.isStreaming && (
                                                <div className="typing-animation mt-2 inline-flex items-center text-gray-400">
                                                    <span></span>
                                                    <span></span>
                                                    <span></span>
                                                </div>
                                            )}
                                        </div>
                                        <div className="text-xs mt-2 text-right text-gray-400/80">
                                            {new Date(streamingMessage.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                                        </div>
                                    </div>
                                </div>
                            )}
                            
                            {/* Better loading animation - modified condition */}
                            {isLoading && !streamingMessage && messages.length > 0 && (
                                <div className="flex justify-start">
                                    <div className="max-w-[95%] w-full rounded-2xl px-5 py-4 assistant-message text-black dark:text-white rounded-bl-none flex items-center">
                                        <div className="typing-animation flex">
                                            <span></span>
                                            <span></span>
                                            <span></span>
                                        </div>
                                        <span className="ml-3 text-sm text-gray-500 dark:text-gray-400">Searching knowledge base...</span>
                                    </div>
                                </div>
                            )}
                            <div ref={messagesEndRef} />
                        </>
                    )}
                </div>
            </div>
            
                <div className="flex-shrink-0 w-[95%] max-w-3xl mx-auto">
                    {/* File Upload Animation - more compact with reduced width */}
                    {isUploading && (
                        <div className="mb-1 file-upload-card max-w-md bg-white dark:bg-gray-800/90 rounded-lg shadow-sm border border-gray-200 dark:border-gray-700/30 overflow-hidden">
                            <div className="p-1.5 flex items-center">
                                <div className="w-6 h-6 flex items-center justify-center relative mr-2">
                                    <svg className="w-6 h-6 animate-spin text-blue-500" viewBox="0 0 24 24">
                                        <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none"></circle>
                                        <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                                    </svg>
                                    <span className="absolute inset-0 flex items-center justify-center text-xs font-semibold text-blue-600 dark:text-blue-400">{Math.round(uploadProgress)}%</span>
                                </div>
                                <div className="flex-1 truncate">
                                    <div className="text-xs font-medium text-gray-900 dark:text-white flex items-center">
                                        Processing
                                        <span className="ml-1 text-[10px] text-gray-500">{uploadedFiles[0]?.name.substring(0, 12)}...</span>
                                        {uploadedFiles.length > 1 && <span className="text-[10px] text-gray-400 ml-1">+{uploadedFiles.length - 1}</span>}
                                    </div>
                                </div>
                            </div>
                        </div>
                    )}

                    {/* Show uploaded files with more compact styling */}
                    {uploadedFiles.length > 0 && !isUploading && !hasInteracted && (
                        <div className="mb-0.5">
                            {uploadedFiles.map((file, index) => (
                                <div key={`${file.name}-${index}`} className="flex items-center py-1 px-2 bg-gray-100 dark:bg-gray-800/70 rounded-lg mb-0.5 max-w-[25%]">
                                    <div className="w-5 h-5 flex items-center justify-center mr-1.5">
                                        {file.type.includes('pdf') ? 
                                            <FaFilePdf size={12} className="text-red-500" /> : 
                                            file.type.includes('word') || file.name.endsWith('.docx') || file.name.endsWith('.doc') ? 
                                            <FaFileWord size={12} className="text-blue-500" /> : 
                                            <FaFileAlt size={12} className="text-gray-500" />
                                        }
                                    </div>
                                    <div className="flex-1 truncate">
                                        <div className="text-xs font-medium text-gray-900 dark:text-white truncate">
                                            {file.name}
                                        </div>
                                    </div>
                                    <div className="text-[10px] text-gray-500 ml-1 whitespace-nowrap">
                                        {file.size ? `${Math.round(file.size / 1024)} KB` : ''}
                                    </div>
                                    <button
                                        onClick={() => handleRemoveUploadedFile(index)}
                                        className="ml-2 text-gray-500 hover:text-red-500 dark:text-gray-400 dark:hover:text-red-400"
                                        aria-label="Remove file"
                                    >
                                        <IoClose size={14} />
                                    </button>
                                </div>
                            ))}
                        </div>
                    )}

                <AdminMessageInput
                    onSubmit={handleChatSubmit}
                        onFileUpload={handleFileUpload}
                    isLoading={isLoading}
                        currentGptName={gptData?.name}
                />
            </div>
            
            {isProfileOpen && (
                <div 
                    className="fixed inset-0 z-20"
                    onClick={() => setIsProfileOpen(false)}
                />
            )}
        </div>
        </>
    );
};

export default AdminChat;


