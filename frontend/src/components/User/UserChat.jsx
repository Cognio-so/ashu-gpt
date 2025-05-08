import React, { useState, useEffect, useRef } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import ChatInput from './ChatInput';
import { useAuth } from '../../context/AuthContext';
import { useTheme } from '../../context/ThemeContext';
import { IoPersonCircleOutline, IoSettingsOutline, IoPersonOutline, IoArrowBack, IoSparkles, IoAddCircleOutline } from 'react-icons/io5';
import { axiosInstance } from '../../api/axiosInstance';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import axios from 'axios';
import { IoClose } from 'react-icons/io5';
import { FaFilePdf, FaFileWord, FaFileAlt, FaFile } from 'react-icons/fa';
import rehypeRaw from 'rehype-raw';
import { Prism as SyntaxHighlighter } from 'react-syntax-highlighter';
import { atomDark } from 'react-syntax-highlighter/dist/esm/styles/prism';
import { SiOpenai, SiGooglegemini } from 'react-icons/si';
import { FaRobot } from 'react-icons/fa6';
import { BiLogoMeta } from 'react-icons/bi';
import { RiOpenaiFill } from 'react-icons/ri';

const pythonApiUrl = import.meta.env.VITE_PYTHON_API_URL || 'http://localhost:8000';

const modelIcons = {
    'gpt-4': <RiOpenaiFill className="text-green-500" size={18} />,
    'gpt-4o-mini': <SiOpenai className="text-green-400" size={16} />,
    'claude': <FaRobot className="text-purple-400" size={16} />,
    'gemini': <SiGooglegemini className="text-blue-400" size={16} />,
    'llama': <BiLogoMeta className="text-blue-500" size={18} />
};

const MarkdownStyles = () => (
    <style dangerouslySetInnerHTML={{
        __html: `
        .markdown-content {
            line-height: 1.8;
            width: 100%;
        }
        
        .markdown-content h1,
        .markdown-content h2,
        .markdown-content h3 {
            margin-top: 2em;
            margin-bottom: 0.8em;
            line-height: 1.4;
        }
        
        .markdown-content h1:first-child,
        .markdown-content h2:first-child,
        .markdown-content h3:first-child {
            margin-top: 0.5em;
        }
        
        .markdown-content h1 {
            font-size: 1.75rem;
            margin-bottom: 1em;
        }
        
        .markdown-content h2 {
            font-size: 1.5rem;
            margin-bottom: 0.9em;
        }
        
        .markdown-content h3 {
            font-size: 1.25rem;
            margin-bottom: 0.8em;
        }
        
        .markdown-content p {
            margin-bottom: 1.2em;
            margin-top: 1.2em;
        }
        
        .markdown-content ul,
        .markdown-content ol {
            margin-top: 1.2em;
            margin-bottom: 1.2em;
            padding-left: 1.5em;
        }
        
        .markdown-content li {
            margin-bottom: 0.6em;
        }
        
        .markdown-content li:last-child {
            margin-bottom: 0;
        }
        
        .markdown-content code {
            font-family: 'SFMono-Regular', Consolas, 'Liberation Mono', Menlo, monospace;
            padding: 0.2em 0.4em;
        }
        
        .markdown-content pre {
            overflow-x: auto;
            border-radius: 0.375rem;
            margin: 1.5em 0;
            padding: 1em;
        }
        
        .markdown-content blockquote {
            font-style: italic;
            color: #6b7280;
            border-left: 4px solid;
            padding-left: 1em;
            margin: 1.5em 0;
        }
        
        .markdown-content a {
            text-decoration: none;
        }
        
        .markdown-content a:hover {
            text-decoration: underline;
        }
        
        .markdown-content table {
            border-collapse: collapse;
            margin: 1.5em 0;
            width: 100%;
        }
        
        .markdown-content th,
        .markdown-content td {
            padding: 0.75em 1em;
        }
        
        .markdown-content img {
            max-width: 100%;
            height: auto;
            margin: 1.5em 0;
        }
        
        .markdown-content hr {
            border-top: 1px solid;
            margin: 2em 0;
        }
        
        .hide-scrollbar {
            -ms-overflow-style: none;
            scrollbar-width: none;
        }
        
        .hide-scrollbar::-webkit-scrollbar {
            display: none;
        }
        
        .assistant-message {
            background-color: #f9fafb;
            padding: 1em 1.25em;
        }
        
        .dark .assistant-message {
            background-color: #1e1e1e;
        }

        .typing-animation {
            display: inline-flex;
            align-items: center;
            margin-top: 0.5em;
        }

        .typing-animation span {
            display: block;
            width: 5px;
            height: 5px;
            background-color: currentColor;
            border-radius: 50%;
            margin: 0 1px;
            animation: typing 1.5s infinite ease-in-out;
        }

        .typing-animation span:nth-child(1) {
            animation-delay: 0s;
        }

        .typing-animation span:nth-child(2) {
            animation-delay: 0.2s;
        }

        .typing-animation span:nth-child(3) {
            animation-delay: 0.4s;
        }

        @keyframes typing {
            0%, 60%, 100% {
                transform: translateY(0);
                opacity: 0.6;
            }
            30% {
                transform: translateY(-4px);
                opacity: 1;
            }
        }
    `}} />
);

const UserChat = () => {
    const location = useLocation();
    const navigate = useNavigate();
    const queryParams = new URLSearchParams(location.search);
    const gptId = queryParams.get('gptId');
    const { user, loading: authLoading } = useAuth();
    const { isDarkMode } = useTheme();
    const [isProfileOpen, setIsProfileOpen] = useState(false);
    const [userData, setUserData] = useState(null);
    const [loading, setLoading] = useState({
        gpt: false,
        history: false,
        message: false
    });
    const [gptData, setGptData] = useState(null);
    const [messages, setMessages] = useState([]);
    const [collectionName, setCollectionName] = useState('');
    const [uploadedFiles, setUploadedFiles] = useState([]);
    const [isUploading, setIsUploading] = useState(false);
    const [uploadProgress, setUploadProgress] = useState(0);
    const [userDocuments, setUserDocuments] = useState([]);
    const [hasInteracted, setHasInteracted] = useState(false);
    const [conversationMemory, setConversationMemory] = useState([]);
    const [isInitialLoading, setIsInitialLoading] = useState(false);
    const [streamingMessage, setStreamingMessage] = useState(null);
    const messagesEndRef = useRef(null);
    const [webSearchEnabled, setWebSearchEnabled] = useState(false);

    useEffect(() => {
        messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
    }, [messages]);

    useEffect(() => {
        if (user) {
            setUserData(user);
        }
    }, [user]);

    useEffect(() => {
        // --- Step 1: Basic Guard Clauses ---
        if (!gptId) {
            // If there's no GPT ID, clear everything and stop.
            setGptData(null);
            setMessages([]);
            setConversationMemory([]);
            setIsInitialLoading(false);
            return;
        }

        // --- Step 2: Wait for Authentication to Settle ---
        // If authentication is still loading, do nothing yet. Show loading indicator.
        if (authLoading) {
            setIsInitialLoading(true); // Keep showing loading while waiting
            return;
        }

        // --- Step 3: Handle Post-Auth State (User Loaded or Not) ---
        // If auth is finished, but there's no user, stop loading and show appropriate message.
        if (!authLoading && !user) {
            console.warn("Auth finished, but no user. Aborting fetch.");
            setIsInitialLoading(false); // Stop loading
            setGptData({ _id: gptId, name: "GPT Assistant", description: "Login required to load chat.", model: "gpt-4o-mini" });
            setMessages([]);
            setConversationMemory([]);
            return;
        }

        // --- Step 4: Conditions Met - Proceed with Fetch ---
        // If we reach here: gptId exists, authLoading is false, and user exists.
        setIsInitialLoading(true); // Ensure loading is true before fetch starts

        const fromHistory = location.state?.fromHistory || location.search.includes('loadHistory=true');

        const fetchInitialData = async () => {
            let fetchedGptData = null;
            let gptDataIdToLoad = gptId;
            let historyMessages = [];
            let historyMemory = [];

            try {
                // Fetch GPT Data
                const gptResponse = await axiosInstance.get(`/api/custom-gpts/user/assigned/${gptId}`, { withCredentials: true });

                if (gptResponse.data?.success && gptResponse.data.customGpt) {
                    fetchedGptData = gptResponse.data.customGpt;
                    gptDataIdToLoad = fetchedGptData._id;
                } else {
                    console.warn("[fetchInitialData] Failed GPT fetch:", gptResponse.data);
                    fetchedGptData = { _id: gptId, name: "GPT Assistant", description: "Assistant details unavailable.", model: "gpt-4o-mini" };
                }

                // Set GPT Data *before* history load
                setGptData(fetchedGptData);
                const sanitizedEmail = (user.email || 'user').replace(/[^a-zA-Z0-9]/g, '_');
                const sanitizedGptName = (fetchedGptData.name || 'gpt').replace(/[^a-zA-Z0-9]/g, '_');
                setCollectionName(`kb_${sanitizedEmail}_${sanitizedGptName}_${gptId}`);
                notifyGptOpened(fetchedGptData, user).catch(err => console.warn("[fetchInitialData] Notify error:", err));

                // Load History if needed
                if (fromHistory) {
                    const historyResponse = await axiosInstance.get(`/api/chat-history/conversation/${user._id}/${gptDataIdToLoad}`, { withCredentials: true });

                    if (historyResponse.data?.success && historyResponse.data.conversation?.messages?.length > 0) {
                        const { conversation } = historyResponse.data;
                        // Use a more robust unique key if possible, combining conv id and timestamp/index
                        historyMessages = conversation.messages.map((msg, index) => ({
                            id: `${conversation._id}-${index}-${msg.timestamp || Date.now()}`,
                            role: msg.role,
                            content: msg.content,
                            timestamp: new Date(msg.timestamp || conversation.createdAt)
                        }));
                        historyMemory = conversation.messages.slice(-10).map(msg => ({
                            role: msg.role,
                            content: msg.content,
                            timestamp: msg.timestamp || conversation.createdAt
                        }));
                    } else {
                        historyMessages = [];
                        historyMemory = [];
                    }
                } else {
                    historyMessages = [];
                    historyMemory = [];
                }

                // Set Messages & Memory *after* all fetches are done
                setMessages(historyMessages);
                setConversationMemory(historyMemory);

            } catch (err) {
                console.error("[fetchInitialData] Error during fetch:", err);
                setGptData({ _id: gptId, name: "GPT Assistant", description: "Error loading assistant.", model: "gpt-4o-mini" });
                setCollectionName(`kb_user_${gptId}`);
                setMessages([]);
                setConversationMemory([]);
            } finally {
                // Mark initial loading complete *only* after try/catch finishes
                setIsInitialLoading(false);
            }
        };

        fetchInitialData(); // Execute the fetch logic

        // Cleanup function: Reset loading states if dependencies change mid-fetch
        return () => {
            setIsInitialLoading(false);
            setLoading(prev => ({ ...prev, gpt: false, history: false })); // Clear old flags too
        };

        // Dependencies: Only re-run if these core identifiers change.
    }, [gptId, user, authLoading, location.state, location.search]); // Keep authLoading & user to trigger run *after* auth resolves

    const predefinedPrompts = [
        {
            id: 1,
            title: 'About this GPT',
            prompt: 'What can you tell me about yourself and your capabilities?'
        },
        {
            id: 2,
            title: 'Help me with',
            prompt: 'I need help with a specific task. Can you guide me through it?'
        },
        {
            id: 3,
            title: 'Examples',
            prompt: 'Can you show me some examples of how to use you effectively?'
        },
    ];

    const handlePromptClick = (item) => {
        handleChatSubmit(item.prompt);
    };

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



            const payload = {
                userId: user._id,
                gptId: gptData._id,
                gptName: gptData.name || 'AI Assistant',
                message: message.trim(),
                role: role,
                model: gptData.model || 'gpt-4o-mini'
            };


            const response = await axiosInstance.post('/api/chat-history/save', payload, {
                withCredentials: true
            });

            return response.data;
        } catch (error) {
            console.error(`Error saving ${role} message to history:`, error.response?.data || error.message);
            // Return null instead of throwing to prevent breaking the chat flow
            return null;
        }
    };

    const handleChatSubmit = async (message) => {
        if (!message.trim()) return;

        // Set interaction flag to hide files
        setHasInteracted(true);

        try {
            const userMessage = {
                id: Date.now(),
                role: 'user',
                content: message,
                timestamp: new Date()
            };

            setMessages(prev => [...prev, userMessage]);

            // Save user message immediately
            saveMessageToHistory(message, 'user');

            // Keep only the last 10 messages for context
            const recentHistory = [...conversationMemory, { role: 'user', content: message }]
                .slice(-10) // Take the last 10
                .map(msg => ({ role: msg.role, content: msg.content })); // Format for backend

            setConversationMemory(prev => [...prev, { role: 'user', content: message, timestamp: new Date() }].slice(-10));

            // Clear any existing streaming message
            setStreamingMessage(null);
            // Set loading state
            setLoading(prev => ({ ...prev, message: true }));

            // Backend API Call
            try {
                const payload = {
                    message: message,
                    gpt_id: gptId,
                    user_email: user?.email || 'unknown_user',
                    gpt_name: gptData?.name || 'unknown_gpt',
                    history: recentHistory,
                    memory: conversationMemory,
                    user_documents: userDocuments,
                    use_hybrid_search: gptData?.capabilities?.hybridSearch || false,
                    system_prompt: gptData?.instructions || null,
                    web_search_enabled: webSearchEnabled && gptData?.capabilities?.webBrowsing || false
                };

                const response = await fetch(`${pythonApiUrl}/chat-stream`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Accept': 'text/event-stream',
                    },
                    body: JSON.stringify(payload),
                    credentials: 'include'
                });

                if (!response.ok) {
                    throw new Error(`Server responded with ${response.status}: ${response.statusText}`);
                }

                if (response.body) {
                    await handleStreamingResponse(response);
                } else {
                    throw new Error("Received empty response body");
                }

            } catch (error) {
                console.error("Error calling chat stream API:", error);
                setStreamingMessage({
                    id: Date.now() + 1,
                    role: 'assistant',
                    content: `Error: ${error.message}`,
                    isStreaming: false,
                    isLoading: false,
                    isError: true,
                    timestamp: new Date()
                });
                saveMessageToHistory(`Error processing request: ${error.message}`, 'assistant');
            }
        } catch (error) {
            console.error("Error in handleChatSubmit:", error);
        }
    };

    const handleStreamingResponse = async (response) => {
        const reader = response.body.getReader();
        const decoder = new TextDecoder();
        let buffer = "";
        let doneStreaming = false;
        let sourcesInfo = null;
        let streamError = null;

        const messageId = Date.now() + 1;
        console.log(`[Stream ${messageId}] Starting to read stream...`);

        try {
            // Initialize streaming message state
            setStreamingMessage({
                id: messageId,
                role: 'assistant',
                content: '',
                isStreaming: true,
                isError: false,
                timestamp: new Date()
            });

            while (!doneStreaming) {
                const { done, value } = await reader.read();

                if (done) {
                    console.log(`[Stream ${messageId}] Stream reader done.`);
                    doneStreaming = true;
                    break;
                }

                const chunk = decoder.decode(value, { stream: true });
                const lines = chunk.split('\n\n').filter(line => line.trim().startsWith('data: '));

                for (const line of lines) {
                    try {
                        const jsonStr = line.substring(6);
                        const parsed = JSON.parse(jsonStr);
                        console.log(`[Stream ${messageId}] Parsed event:`, parsed);

                        if (parsed.type === 'error' || parsed.error) {
                            streamError = parsed.error || parsed.detail || 'Unknown streaming error';
                            console.error(`[Stream ${messageId}] Streaming Error:`, streamError);
                            buffer = `Error: ${streamError}`;
                            doneStreaming = true;
                            setStreamingMessage(prev => ({
                                ...prev,
                                content: buffer,
                                isStreaming: false,
                                isError: true
                            }));
                            break;
                        }

                        if (parsed.type === 'done') {
                            console.log(`[Stream ${messageId}] Done event received.`);
                            doneStreaming = true;
                            break;
                        }

                        if (parsed.type === 'content') {
                            buffer += parsed.data;
                            setStreamingMessage(prev => ({
                                ...prev,
                                content: buffer,
                                isStreaming: true,
                                isError: false
                            }));
                        }

                        if (parsed.type === 'sources_info') {
                            sourcesInfo = parsed.data;
                            console.log(`[Stream ${messageId}] Sources info:`, sourcesInfo);
                            buffer += `\n\n[Sources Retrieved: ${sourcesInfo.documents_retrieved_count} documents, ${sourcesInfo.retrieval_time_ms}ms]`;
                        }
                    } catch (e) {
                        console.error(`[Stream ${messageId}] Error parsing line:`, e, "Line:", line);
                    }
                }
            }

            if (!buffer && !streamError) {
                console.warn(`[Stream ${messageId}] Stream ended with no content.`);
                buffer = "No response generated. Please try rephrasing your query or check the uploaded documents.";
                streamError = true;
            }

            setStreamingMessage(prev => ({
                ...prev,
                content: buffer,
                isStreaming: false,
                isLoading: false,
                isError: !!streamError
            }));

            await saveMessageToHistory(buffer, 'assistant');
            console.log(`[Stream ${messageId}] Saved final content:`, buffer);
        } catch (err) {
            console.error(`[Stream ${messageId}] Error reading stream:`, err);
            buffer = `Error reading response stream: ${err.message}`;
            setStreamingMessage({
                id: messageId,
                role: 'assistant',
                content: buffer,
                isStreaming: false,
                isLoading: false,
                isError: true,
                timestamp: new Date()
            });
            await saveMessageToHistory(buffer, 'assistant');
        } finally {
            setLoading(prev => ({ ...prev, message: false }));
            console.log(`[Stream ${messageId}] Stream processing complete.`);
        }
    };

    useEffect(() => {
        if (streamingMessage && !streamingMessage.isStreaming) {
            setMessages(prev => {
                const exists = prev.some(m => 
                    m.id === streamingMessage.id || 
                    (m.content === streamingMessage.content && 
                     m.timestamp.getTime() === streamingMessage.timestamp.getTime())
                );
                if (exists) return prev;
                return [...prev, { ...streamingMessage }];
            });

            // Add to conversation memory
            setConversationMemory(prev => [...prev, {
                role: 'assistant',
                content: streamingMessage.content,
                timestamp: new Date().toISOString()
            }]);

            // Clear streaming message with a short delay
            setTimeout(() => {
                setStreamingMessage(null);
                setLoading(prev => ({ ...prev, message: false }));
            }, 100);
        }
    }, [streamingMessage]);

    const toggleProfile = () => {
        setIsProfileOpen(!isProfileOpen);
    };

    const handleGoBack = () => {
        navigate(-1);
    };

    const goToSettings = () => {
        navigate('/user/settings');
        setIsProfileOpen(false);
    };

    const mockUser = {
        name: "Test User",
        email: "test@example.com",
        profilePic: null
    };

    const showWebSearch = gptData?.capabilities?.webBrowsing === true;

    const notifyGptOpened = async (customGpt, userData) => {
        try {
            // Use actual hybridSearch setting
            const useHybridSearch = customGpt.capabilities?.hybridSearch || false;

            const fileUrls = customGpt.knowledgeFiles?.map(file => file.fileUrl).filter(url =>
                url && (url.startsWith('http://') || url.startsWith('https://'))
            ) || [];

            const backendUrl = import.meta.env.VITE_PYTHON_API_URL || 'http://localhost:8000';

            const payload = {
                user_email: userData?.email || 'user@example.com',
                gpt_name: customGpt.name || 'Unnamed GPT',
                gpt_id: customGpt._id,
                file_urls: fileUrls,
                use_hybrid_search: useHybridSearch,
                schema: {
                    model: customGpt.model || "gpt-4o-mini",
                    instructions: customGpt.instructions || "",
                    capabilities: customGpt.capabilities || {},
                    use_hybrid_search: useHybridSearch
                }
            };


            const response = await fetch(`${backendUrl}/gpt-opened`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(payload)
            });

            if (response.ok) {
                const data = await response.json();

                // Store the collection name if provided
                if (data && data.collection_name) {
                    setCollectionName(data.collection_name);
                }

                return true;
            } else {
                console.error("Failed to notify GPT opened:", await response.text());
                return false;
            }
        } catch (err) {
            console.error("Error notifying GPT opened:", err);
            return false;
        }
    };

    // Replace the existing handleFileUpload function with this
    const handleFileUpload = async (files) => {
        if (!files.length || !gptData) return;

        try {
            setIsUploading(true);
            setUploadProgress(0);
            setUploadedFiles(Array.from(files).map(file => ({
                name: file.name,
                size: file.size,
                type: file.type
            })));

            const formData = new FormData();
            for (let i = 0; i < files.length; i++) {
                formData.append('files', files[i]);
            }
            
            // Add required metadata - match AdminChat.jsx
            formData.append('user_email', userData?.email || 'anonymous');
            formData.append('gpt_id', gptData?._id || gptId);
            formData.append('gpt_name', gptData?.name || 'Assistant');
            formData.append('collection_name', collectionName || gptData._id);
            formData.append('is_user_document', 'true');
            formData.append('system_prompt', gptData?.instructions || '');

            // Get hybridSearch setting from capabilities
            const useHybridSearch = gptData?.capabilities?.hybridSearch || false;
            formData.append('use_hybrid_search', useHybridSearch.toString());

            // Optimized upload with simple progress tracking
            const response = await axios.post(
                `${pythonApiUrl}/upload-chat-files`,
                formData,
                {
                    headers: {
                        'Content-Type': 'multipart/form-data',
                    },
                    withCredentials: true,
                    onUploadProgress: (progressEvent) => {
                        const percentCompleted = Math.round(
                            (progressEvent.loaded * 100) / (progressEvent.total || 100)
                        );
                        setUploadProgress(percentCompleted);
                    }
                }
            );

            setUploadProgress(100);
            setTimeout(() => setIsUploading(false), 500);

            if (response.data.success) {
                setUserDocuments(response.data.file_urls || []);
            } else {
                throw new Error(response.data.message || "Failed to process files");
            }
        } catch (error) {
            console.error("Error uploading files:", error);
            setIsUploading(false);
            setMessages(prev => [...prev, {
                id: Date.now(),
                role: 'system',
                content: `Error uploading files: ${error.message || 'Unknown error'}`,
                timestamp: new Date()
            }]);
        }
    };

    // Add this helper function for file icons
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

    // Add this function to handle removing uploaded files
    const handleRemoveUploadedFile = (indexToRemove) => {
        setUploadedFiles(prevFiles => prevFiles.filter((_, index) => index !== indexToRemove));
    };

    // Add a function to handle starting a new chat
    const handleNewChat = () => {
        setMessages([]);
        setConversationMemory([]);
        setHasInteracted(false);
        setUserDocuments([]);
        setUploadedFiles([]);
    };

    return (
        <>
            <MarkdownStyles />
            <div className={`flex flex-col h-screen overflow-hidden transition-colors duration-300 ${isDarkMode ? 'bg-black text-white' : 'bg-gray-100 text-gray-900'}`}>
                <div className={`flex-shrink-0 px-4 py-3 flex items-center justify-between ${isDarkMode ? 'bg-black border-gray-800' : 'bg-gray-100 border-gray-200'}`}>
                    <div className="flex items-center space-x-2">
                        {gptId && (
                            <button
                                onClick={handleGoBack}
                                className={`p-2 rounded-full transition-colors flex items-center justify-center w-10 h-10 ${isDarkMode ? 'text-gray-400 hover:text-white hover:bg-gray-800' : 'text-gray-500 hover:text-gray-700 hover:bg-gray-200'
                                    }`}
                                aria-label="Go back"
                            >
                                <IoArrowBack size={20} />
                            </button>
                        )}

                        {/* New Chat Button */}
                        <button
                            onClick={handleNewChat}
                            className={`p-2 rounded-full transition-colors flex items-center justify-center w-10 h-10 ${isDarkMode ? 'text-gray-400 hover:text-white hover:bg-gray-800' : 'text-gray-500 hover:text-gray-700 hover:bg-gray-200'
                                }`}
                            aria-label="New Chat"
                        >
                            <IoAddCircleOutline size={24} />
                        </button>

                        {/* Show the GPT name when it's available */}
                        {gptData && (
                            <div className="ml-2 text-sm md:text-base font-medium flex items-center">
                                <span className="mr-1">New Chat</span>
                                {gptData.model && (
                                    <div className={`flex items-center ml-2 text-xs md:text-sm px-2 py-0.5 rounded-full ${isDarkMode ? 'bg-gray-800' : 'bg-gray-100'}`}>
                                        {modelIcons[gptData.model] || null}
                                        <span>{gptData.model === 'gpt-4o-mini' ? 'GPT-4o Mini' : gptData.model}</span>
                                    </div>
                                )}
                            </div>
                        )}
                    </div>

                    <div className="relative">
                        <button
                            onClick={toggleProfile}
                            className={`w-10 h-10 rounded-full overflow-hidden border-2 transition-colors ${isDarkMode ? 'border-white/20 hover:border-white/40' : 'border-gray-300 hover:border-gray-500'
                                }`}
                        >
                            {(userData || mockUser)?.profilePic ? (
                                <img
                                    src={(userData || mockUser).profilePic}
                                    alt="Profile"
                                    className="w-full h-full object-cover"
                                />
                            ) : (
                                <div className={`w-full h-full flex items-center justify-center ${isDarkMode ? 'bg-gray-700' : 'bg-gray-300'}`}>
                                    <IoPersonCircleOutline size={24} className={isDarkMode ? 'text-white' : 'text-gray-600'} />
                                </div>
                            )}
                        </button>

                        {isProfileOpen && (
                            <div className={`absolute top-12 right-0 w-64 rounded-xl shadow-lg border overflow-hidden z-30 ${isDarkMode ? 'bg-[#1e1e1e] border-white/10' : 'bg-white border-gray-200'
                                }`}>
                                <div className={`p-4 border-b ${isDarkMode ? 'border-white/10' : 'border-gray-200'}`}>
                                    <p className={`font-medium ${isDarkMode ? 'text-white' : 'text-gray-900'}`}>
                                        {userData?.name || mockUser.name}
                                    </p>
                                    <p className={`text-sm truncate ${isDarkMode ? 'text-gray-400' : 'text-gray-500'}`}>
                                        {userData?.email || mockUser.email}
                                    </p>
                                </div>
                                <div className="py-1">
                                    <button className={`w-full px-4 py-2.5 text-left flex items-center space-x-3 transition-colors ${isDarkMode ? 'text-gray-300 hover:bg-white/5' : 'text-gray-700 hover:bg-gray-100'
                                        }`}>
                                        <IoPersonOutline size={18} />
                                        <span>Profile</span>
                                    </button>
                                    <button
                                        onClick={goToSettings}
                                        className={`w-full px-4 py-2.5 text-left flex items-center space-x-3 transition-colors ${isDarkMode ? 'text-gray-300 hover:bg-white/5' : 'text-gray-700 hover:bg-gray-100'
                                            }`}
                                    >
                                        <IoSettingsOutline size={18} />
                                        <span>Settings</span>
                                    </button>
                                </div>
                            </div>
                        )}
                    </div>
                </div>

                <div className="flex-1 overflow-y-auto p-4 no-scrollbar">
                    <div className="w-full max-w-3xl mx-auto flex flex-col space-y-4">
                        {/* --- Consolidated Initial Loading Indicator --- */}
                        {isInitialLoading ? (
                            <div className="flex-1 flex flex-col items-center justify-center p-20">
                                <div className={`animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 ${isDarkMode ? 'border-blue-500' : 'border-blue-600'}`}></div>
                                <span className="mt-4 text-sm">
                                    Loading assistant...
                                </span>
                            </div>
                        ) : messages.length === 0 ? (
                            // Welcome Screen (Rendered only after initial load is complete and if no messages)
                            <div className="welcome-screen py-10">
                                {gptId && gptData ? (
                                    // GPT-specific welcome
                                    <div className="text-center">
                                        <div className={`w-16 h-16 rounded-full mx-auto flex items-center justify-center mb-4 ${isDarkMode ? 'bg-gray-700' : 'bg-gray-200'}`}>
                                            {gptData.imageUrl ? (
                                                <img src={gptData.imageUrl} alt={gptData.name} className="w-full h-full object-cover rounded-full" />
                                            ) : (
                                                <span className={`text-2xl ${isDarkMode ? 'text-white' : 'text-gray-600'}`}>{gptData.name?.charAt(0) || '?'}</span>
                                            )}
                                        </div>
                                        <h2 className={`text-xl font-semibold mb-2 ${isDarkMode ? 'text-white' : 'text-gray-900'}`}>{gptData.name}</h2>
                                        <p className={`max-w-md mx-auto ${isDarkMode ? 'text-gray-400' : 'text-gray-600'}`}>{gptData.description || 'Start a conversation...'}</p>

                                        {/* Conversation starter */}
                                        {gptData.conversationStarter && (
                                            <div
                                                onClick={() => handleChatSubmit(gptData.conversationStarter)}
                                                className={`mt-5 max-w-xs mx-auto p-3 border rounded-lg text-left cursor-pointer transition-colors ${isDarkMode
                                                        ? 'bg-gray-800/70 border-gray-700/70 hover:bg-gray-800 hover:border-gray-600/70 text-white'
                                                        : 'bg-gray-200 border-gray-300 hover:bg-gray-300 hover:border-gray-400 text-gray-800'
                                                    }`}
                                            >
                                                <p className="text-sm line-clamp-3">{gptData.conversationStarter}</p>
                                            </div>
                                        )}
                                    </div>
                                ) : (
                                    // Generic welcome
                                    <div className="text-center">
                                        <h1 className={`text-2xl sm:text-3xl md:text-4xl font-bold mb-2 ${isDarkMode ? 'text-white' : 'text-gray-900'}`}>AI Assistant</h1>
                                        <p className={`text-base sm:text-lg md:text-xl font-medium mb-8 ${isDarkMode ? 'text-gray-400' : 'text-gray-600'}`}>How can I assist you today?</p>

                                        {/* Simplified prompts display */}
                                        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 max-w-2xl mx-auto">
                                            {predefinedPrompts.map((item) => (
                                                <div
                                                    key={item.id}
                                                    onClick={() => handlePromptClick(item)}
                                                    className={`p-3 border rounded-lg cursor-pointer text-left ${isDarkMode
                                                            ? 'bg-gray-800 border-gray-700 hover:bg-gray-700'
                                                            : 'bg-white border-gray-200 hover:bg-gray-50'
                                                        }`}
                                                >
                                                    <h3 className={`font-medium mb-1 ${isDarkMode ? 'text-white' : 'text-gray-800'}`}>{item.title}</h3>
                                                    <p className={`text-xs line-clamp-2 ${isDarkMode ? 'text-gray-400' : 'text-gray-500'}`}>{item.prompt}</p>
                                                </div>
                                            ))}
                                        </div>
                                    </div>
                                )}
                            </div>
                        ) : (
                            // Message list (Rendered only after initial load and when messages exist)
                            <>
                                {messages.length > 0 && (
                                    messages
                                        .filter(msg => msg.role !== 'system')
                                        .map((msg) => (
                                            <div
                                                key={msg.id}
                                                className={`flex ${msg.role === 'user' ? 'justify-end' : 'justify-start'}`}
                                            >
                                                {/* Assistant Icon - Render if it's an assistant message */}
                                                {msg.role === 'assistant' && (
                                                    <div className={`flex-shrink-0 w-8 h-8 rounded-full flex items-center justify-center ${isDarkMode ? 'bg-gray-700' : 'bg-gray-300'}`}>
                                                        {gptData?.imageUrl ? (
                                                            <img src={gptData.imageUrl} alt="GPT" className="w-full h-full rounded-full object-cover" />
                                                        ) : (
                                                            <IoSparkles size={16} className={isDarkMode ? 'text-blue-400' : 'text-blue-600'} />
                                                        )}
                                                    </div>
                                                )}

                                                {/* Message content */}
                                                <div
                                                    className={`${msg.role === 'user'
                                                        ? `${isDarkMode ? 'bg-black/10 dark:bg-white/80 text-black dark:text-black rounded-br-none' : 'bg-blue-600 text-white rounded-br-none'} max-w-max`
                                                        : `${msg.isError
                                                            ? (isDarkMode ? 'bg-red-800/70 text-red-100' : 'bg-red-100 text-red-700')
                                                            : 'assistant-message text-black dark:text-white rounded-bl-none'} 
                                                        w-full max-w-3xl`
                                                    } rounded-2xl px-5 py-3`}
                                                >
                                                    {msg.role === 'user' ? (
                                                        <p className="whitespace-pre-wrap">{msg.content}</p>
                                                    ) : (
                                                        <div className="markdown-content">
                                                            <ReactMarkdown
                                                                remarkPlugins={[remarkGfm]}
                                                                rehypePlugins={[rehypeRaw]}
                                                                components={{
                                                                    h1: ({ node, ...props }) => <h1 className="text-xl font-bold my-4" {...props} />,
                                                                    h2: ({ node, ...props }) => <h2 className="text-lg font-bold my-3" {...props} />,
                                                                    h3: ({ node, ...props }) => <h3 className="text-md font-bold my-3" {...props} />,
                                                                    h4: ({ node, ...props }) => <h4 className="font-bold my-2" {...props} />,
                                                                    p: ({ node, ...props }) => <p className="my-3" {...props} />,
                                                                    ul: ({ node, ...props }) => <ul className="list-disc pl-6 my-3" {...props} />,
                                                                    ol: ({ node, ...props }) => <ol className="list-decimal pl-6 my-3" {...props} />,
                                                                    li: ({ node, index, ...props }) => <li className="my-2" key={index} {...props} />,
                                                                    a: ({ node, ...props }) => <a className="text-blue-400 hover:underline" {...props} />,
                                                                    blockquote: ({ node, ...props }) => <blockquote className="border-l-4 border-gray-500 dark:border-gray-400 pl-4 my-4 italic" {...props} />,
                                                                    code({ node, inline, className, children, ...props }) {
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
                                                                    table: ({ node, ...props }) => (
                                                                        <div className="overflow-x-auto my-4">
                                                                            <table className="min-w-full border border-gray-400 dark:border-gray-500" {...props} />
                                                                        </div>
                                                                    ),
                                                                    thead: ({ node, ...props }) => <thead className="bg-gray-300 dark:bg-gray-600" {...props} />,
                                                                    tbody: ({ node, ...props }) => <tbody className="divide-y divide-gray-400 dark:divide-gray-500" {...props} />,
                                                                    tr: ({ node, ...props }) => <tr className="hover:bg-gray-300 dark:hover:bg-gray-600" {...props} />,
                                                                    th: ({ node, ...props }) => <th className="px-4 py-3 text-left font-medium" {...props} />,
                                                                    td: ({ node, ...props }) => <td className="px-4 py-3" {...props} />,
                                                                }}
                                                            >
                                                                {msg.content}
                                                            </ReactMarkdown>
                                                        </div>
                                                    )}
                                                    <div className={`text-xs mt-2 text-right ${msg.role === 'user' ? 'text-blue-50/80' : 'text-gray-400/80'}`}>
                                                    </div>
                                                </div>

                                                {/* User Icon - Render if it's a user message */}
                                                {msg.role === 'user' && (
                                                    <div className={`flex-shrink-0 w-8 h-8 rounded-full overflow-hidden border ${isDarkMode ? 'border-white/20 bg-gray-700' : 'border-gray-300 bg-gray-300'}`}>
                                                        {userData?.profilePic ? (
                                                            <img src={userData.profilePic} alt="You" className="w-full h-full object-cover" />
                                                        ) : (
                                                            <div className={`w-full h-full flex items-center justify-center`}>
                                                                <IoPersonOutline size={16} className={isDarkMode ? 'text-gray-300' : 'text-gray-600'} />
                                                            </div>
                                                        )}
                                                    </div>
                                                )}
                                            </div>
                                        ))
                                )}
                            </>
                        )}

                        {/* Streaming message - displayed when streaming is active */}
                        {streamingMessage && (
                            <div className="flex justify-start items-end space-x-2">
                                <div className={`flex-shrink-0 w-8 h-8 rounded-full flex items-center justify-center ${isDarkMode ? 'bg-gray-700' : 'bg-gray-300'}`}>
                                    {gptData?.imageUrl ? (
                                        <img src={gptData.imageUrl} alt="GPT" className="w-full h-full rounded-full object-cover" />
                                    ) : (
                                        <IoSparkles size={16} className={isDarkMode ? 'text-blue-400' : 'text-blue-600'} />
                                    )}
                                </div>
                                <div
                                    className={`rounded-2xl px-4 py-2 assistant-message text-black dark:text-white rounded-bl-none w-full max-w-3xl ${
                                        streamingMessage.isError ? (isDarkMode ? 'bg-red-800/70 text-red-100' : 'bg-red-100 text-red-700') : ''
                                    }`}
                                >
                                    <div className="markdown-content">
                                        <ReactMarkdown
                                            remarkPlugins={[remarkGfm]}
                                            rehypePlugins={[rehypeRaw]}
                                            components={{
                                                h1: ({ node, ...props }) => <h1 className="text-xl font-bold my-4" {...props} />,
                                                h2: ({ node, ...props }) => <h2 className="text-lg font-bold my-3" {...props} />,
                                                h3: ({ node, ...props }) => <h3 className="text-md font-bold my-3" {...props} />,
                                                h4: ({ node, ...props }) => <h4 className="font-bold my-2" {...props} />,
                                                p: ({ node, ...props }) => <p className="my-3" {...props} />,
                                                ul: ({ node, ...props }) => <ul className="list-disc pl-6 my-3" {...props} />,
                                                ol: ({ node, ...props }) => <ol className="list-decimal pl-6 my-3" {...props} />,
                                                li: ({ node, index, ...props }) => <li className="my-2" key={index} {...props} />,
                                                a: ({ node, ...props }) => <a className="text-blue-400 hover:underline" {...props} />,
                                                blockquote: ({ node, ...props }) => <blockquote className="border-l-4 border-gray-500 dark:border-gray-400 pl-4 my-4 italic" {...props} />,
                                                code({ node, inline, className, children, ...props }) {
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
                                                table: ({ node, ...props }) => (
                                                    <div className="overflow-x-auto my-4">
                                                        <table className="min-w-full border border-gray-400 dark:border-gray-500" {...props} />
                                                    </div>
                                                ),
                                                thead: ({ node, ...props }) => <thead className="bg-gray-300 dark:bg-gray-600" {...props} />,
                                                tbody: ({ node, ...props }) => <tbody className="divide-y divide-gray-400 dark:divide-gray-500" {...props} />,
                                                tr: ({ node, ...props }) => <tr className="hover:bg-gray-300 dark:hover:bg-gray-600" {...props} />,
                                                th: ({ node, ...props }) => <th className="px-4 py-3 text-left font-medium" {...props} />,
                                                td: ({ node, ...props }) => <td className="px-4 py-3" {...props} />,
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

                        {/* Replace loading indicator with better styling */}
                        {!isInitialLoading && loading.message && !streamingMessage && (
                            <div className="flex justify-start">
                                <div className={`flex-shrink-0 w-8 h-8 rounded-full flex items-center justify-center ${isDarkMode ? 'bg-gray-700' : 'bg-gray-300'}`}>
                                    <IoSparkles size={16} className={isDarkMode ? 'text-blue-400' : 'text-blue-600'} />
                                </div>
                                <div className="rounded-2xl px-4 py-2 assistant-message text-black dark:text-white rounded-bl-none ml-2">
                                    <div className="typing-animation inline-flex items-center text-gray-400">
                                        <span></span>
                                        <span></span>
                                        <span></span>
                                    </div>
                                </div>
                            </div>
                        )}

                        <div ref={messagesEndRef} />
                    </div>
                </div>

                <div className={`flex-shrink-0 p-3  ${isDarkMode ? 'bg-black border-gray-800' : 'bg-gray-100 border-gray-200'}`}>
                    <div className="w-full max-w-3xl mx-auto">
                        {/* File Upload Animation */}
                        {isUploading && (
                            <div className="mb-2 px-2">
                                <div className="flex items-center p-2 bg-blue-50 dark:bg-blue-900/20 rounded-lg border border-blue-100 dark:border-blue-800/30">
                                    <div className="flex-shrink-0 mr-3">
                                        <div className="w-8 h-8 flex items-center justify-center">
                                            <svg className="animate-spin w-5 h-5 text-blue-500 dark:text-blue-400" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                                                <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                                                <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                                            </svg>
                                        </div>
                                    </div>
                                    <div className="flex-1 min-w-0">
                                        <div className="text-xs font-medium text-blue-700 dark:text-blue-300">
                                            {uploadedFiles.length === 1
                                                ? `Uploading ${uploadedFiles[0]?.name}`
                                                : `Uploading ${uploadedFiles.length} files`}
                                        </div>
                                        <div className="mt-1 relative h-1.5 w-full bg-blue-100 dark:bg-blue-800/40 rounded-full overflow-hidden">
                                            <div
                                                className="absolute left-0 top-0 h-full bg-blue-500 dark:bg-blue-400 transition-all duration-300"
                                                style={{ width: `${uploadProgress}%` }}
                                            ></div>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        )}

                        {/* Replace the existing uploaded files display with this improved version */}
                        {uploadedFiles.length > 0 && !isUploading && !hasInteracted && (
                            <div className="mb-2 flex flex-wrap gap-2">
                                {uploadedFiles.map((file, index) => (
                                    <div
                                        key={`${file.name}-${index}`}
                                        className="flex items-center py-1 px-2 bg-gray-50 dark:bg-gray-800/50 rounded-md border border-gray-200 dark:border-gray-700/50 max-w-fit"
                                    >
                                        <div className="mr-1.5 text-gray-500 dark:text-gray-400">
                                            {getFileIcon(file.name)}
                                        </div>
                                        <span className="text-xs font-medium text-gray-700 dark:text-gray-300 truncate max-w-[140px]">
                                            {file.name}
                                        </span>
                                        <div className="text-[10px] text-gray-500 ml-1 whitespace-nowrap">
                                            {file.size ? `${Math.round(file.size / 1024)} KB` : ''}
                                        </div>
                                        <button
                                            onClick={() => handleRemoveUploadedFile(index)}
                                            className="ml-1.5 text-gray-400 hover:text-gray-600 dark:text-gray-500 dark:hover:text-gray-300 p-0.5 rounded-full hover:bg-gray-200 dark:hover:bg-gray-700/50 transition-colors"
                                            aria-label="Remove file"
                                        >
                                            <IoClose size={14} />
                                        </button>
                                    </div>
                                ))}
                            </div>
                        )}

                        <ChatInput
                            onSubmit={handleChatSubmit}
                            onFileUpload={handleFileUpload}
                            isLoading={loading.message}
                            isDarkMode={isDarkMode}
                            showWebSearch={showWebSearch}
                            webSearchEnabled={webSearchEnabled}
                            setWebSearchEnabled={setWebSearchEnabled}
                        />
                    </div>
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

export default UserChat;