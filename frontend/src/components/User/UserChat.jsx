import React, { useState, useEffect, useRef } from 'react';
import { motion } from 'framer-motion';
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

const pythonApiUrl = import.meta.env.VITE_PYTHON_API_URL || 'http://localhost:8000';


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
    const [shouldLoadHistory, setShouldLoadHistory] = useState(false);
    const [isInitialLoading, setIsInitialLoading] = useState(false);
    const messagesEndRef = useRef(null);

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
            console.log("Auth loading, waiting...");
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
        console.log("Conditions met (gptId, user loaded). Starting fetchInitialData.");
        setIsInitialLoading(true); // Ensure loading is true before fetch starts

        const fromHistory = location.state?.fromHistory || location.search.includes('loadHistory=true');

        const fetchInitialData = async () => {
            let fetchedGptData = null;
            let gptDataIdToLoad = gptId;
            let historyMessages = [];
            let historyMemory = [];

            try {
                // Fetch GPT Data
                console.log("[fetchInitialData] Fetching GPT data for:", gptId);
                const gptResponse = await axiosInstance.get(`/api/custom-gpts/user/assigned/${gptId}`, { withCredentials: true });

                if (gptResponse.data?.success && gptResponse.data.customGpt) {
                    fetchedGptData = gptResponse.data.customGpt;
                    gptDataIdToLoad = fetchedGptData._id;
                    console.log("[fetchInitialData] GPT data fetched:", fetchedGptData.name);
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
                    console.log("[fetchInitialData] Loading history for GPT ID:", gptDataIdToLoad);
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
                        console.log(`[fetchInitialData] Loaded ${historyMessages.length} messages from history.`);
                    } else {
                        console.log("[fetchInitialData] No history found or history load failed.");
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
                console.log("[fetchInitialData] Messages and memory state updated.");

            } catch (err) {
                console.error("[fetchInitialData] Error during fetch:", err);
                setGptData({ _id: gptId, name: "GPT Assistant", description: "Error loading assistant.", model: "gpt-4o-mini" });
                setCollectionName(`kb_user_${gptId}`);
                setMessages([]);
                setConversationMemory([]);
            } finally {
                // Mark initial loading complete *only* after try/catch finishes
                console.log("[fetchInitialData] Process complete. Setting isInitialLoading to false.");
                setIsInitialLoading(false);
            }
        };

        fetchInitialData(); // Execute the fetch logic

        // Cleanup function: Reset loading states if dependencies change mid-fetch
        return () => {
            console.log("useEffect cleanup: Resetting loading states.");
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

            console.log(`Attempting to save ${role} message to history:`, message.substring(0, 30) + '...');
            
            const payload = {
                userId: user._id,
                gptId: gptData._id,
                gptName: gptData.name || 'AI Assistant',
                message: message.trim(),
                role: role,
                model: gptData.model || 'gpt-4o-mini'
            };
            
            console.log('Save message payload:', payload);

            const response = await axiosInstance.post('/api/chat-history/save', payload, {
                withCredentials: true
            });

            console.log(`${role.toUpperCase()} message saved successfully:`, response.data);
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

        setLoading(prev => ({ ...prev, message: true }));

        // Add a definitive placeholder for the streaming response
        const assistantMessageId = Date.now() + 1; // Unique ID for this response
        setMessages(prev => [
            ...prev, 
            {
                id: assistantMessageId,
            role: 'assistant',
                content: '', // Start empty
                isLoading: false, // We'll use isStreaming to show activity
                isStreaming: true, // Mark as actively streaming
            timestamp: new Date()
            }
        ]);

        // Backend API Call
        try {
            const payload = {
                message: message,
                // FIX: Send gptId instead of constructed collectionName
                gpt_id: gptId, 
                // FIX: Add user_email
                user_email: user?.email || 'unknown_user', 
                // FIX: Add gpt_name
                gpt_name: gptData?.name || 'unknown_gpt', 
                history: recentHistory, // Send formatted recent history
                memory: conversationMemory, // Send current memory state
                user_documents: userDocuments,
                use_hybrid_search: gptData?.capabilities?.hybridSearch || false // Default to false if not set
            };
            
            console.log("Sending to /chat-stream:", payload);

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
                // Handle fetch error: Update the placeholder message with the error
                setMessages(prev => prev.map(msg => 
                    msg.id === assistantMessageId 
                    ? { ...msg, content: `Error: ${response.status} ${response.statusText}`, isStreaming: false, isLoading: false, isError: true } 
                    : msg
                ));
                setLoading(prev => ({ ...prev, message: false })); // Stop loading
                saveMessageToHistory(`Error: ${response.status} ${response.statusText}`, 'assistant'); // Save error
                return; // Stop further processing
            }
            
            if (response.body) {
                // Pass the specific message ID to the handler
                await handleStreamingResponse(response, saveMessageToHistory, assistantMessageId);
            } else {
                // Handle null body error: Update placeholder
                setMessages(prev => prev.map(msg => 
                    msg.id === assistantMessageId 
                    ? { ...msg, content: "Error: Received empty response body", isStreaming: false, isLoading: false, isError: true } 
                    : msg
                ));
                setLoading(prev => ({ ...prev, message: false })); // Stop loading
                saveMessageToHistory("Error: Received empty response body", 'assistant'); // Save error
                return; // Stop further processing
            }

        } catch (error) {
            // Handle general catch error: Update placeholder
            console.error("Error calling chat stream API:", error);
            setMessages(prev => prev.map(msg => 
                msg.id === assistantMessageId 
                ? { ...msg, content: `Error: ${error.message}`, isStreaming: false, isLoading: false, isError: true } 
                : msg
            ));
            setLoading(prev => ({ ...prev, message: false })); // Stop loading
            saveMessageToHistory(`Error processing request: ${error.message}`, 'assistant'); // Save error
        }
    };

    const handleStreamingResponse = async (response, saveMessageToHistory, messageId) => {
        const reader = response.body.getReader();
        const decoder = new TextDecoder();
        let buffer = ""; // Accumulates the full response content
        let doneStreaming = false;

        console.log(`[Stream ${messageId}] Starting to read stream.`);

        try {
            while (!doneStreaming) {
                const { done, value } = await reader.read();
                
                if (done) {
                    console.log(`[Stream ${messageId}] Stream finished.`);
                    doneStreaming = true;
                    break; // Exit the loop
                }

                const chunk = decoder.decode(value, { stream: true });
                const lines = chunk.split('\n').filter(line => line.trim().startsWith('data: '));
                
                for (const line of lines) {
                        try {
                            const jsonStr = line.substring(6);
                            const parsed = JSON.parse(jsonStr);
                            
                            if (parsed.error) {
                            console.error(`[Stream ${messageId}] Streaming Error:`, parsed.error);
                            buffer = `Error: ${parsed.error}`; // Update buffer with error
                            doneStreaming = true; // Treat error as end of stream
                                setMessages(prev => prev.map(msg => 
                                msg.id === messageId ? { ...msg, content: buffer, isStreaming: false, isError: true } : msg
                                ));
                            break; // Stop processing lines for this chunk on error
                            }
                            
                            if (parsed.done === true) {
                            console.log(`[Stream ${messageId}] Done signal received.`);
                            doneStreaming = true; // Mark as done
                            break; // Stop processing lines for this chunk
                            }
                            
                            if (parsed.content) {
                            buffer += parsed.content; // Append content to the buffer
                            // Update the specific message content progressively
                                setMessages(prev => prev.map(msg => 
                                msg.id === messageId ? { ...msg, content: buffer, isStreaming: true, isError: false } : msg 
                                ));
                            }
                        } catch (e) {
                        console.error(`[Stream ${messageId}] Error parsing line:`, e, "Line:", line);
                        // Continue to next line if parsing fails
                    }
                } // end for loop over lines
            } // end while loop reading stream

            // --- Final Update After Stream Ends ---
            console.log(`[Stream ${messageId}] Finalizing state. Full content length: ${buffer.length}`);
            setMessages(prev => prev.map(msg => 
                msg.id === messageId 
                ? { 
                    ...msg, 
                    content: buffer || (msg.isError ? msg.content : "Empty response"), // Keep error content if it occurred
                    isStreaming: false, // Mark as finished streaming
                    isLoading: false,
                    isError: msg.isError || !buffer.trim() // Mark error if buffer is empty or error previously set
                  } 
                : msg
            ));

            // Save the final content (or error) to history
            if (buffer || messages.find(m => m.id === messageId)?.isError) {
                 await saveMessageToHistory(buffer || messages.find(m => m.id === messageId)?.content, 'assistant');
                 console.log(`[Stream ${messageId}] Final message saved to history.`);
            } else {
                 console.warn(`[Stream ${messageId}] No final content buffer to save.`);
            }

        } catch (err) {
            console.error(`[Stream ${messageId}] Error reading stream:`, err);
            // Update the placeholder with stream reading error
            setMessages(prev => prev.map(msg => 
                msg.id === messageId 
                ? { ...msg, content: "Error reading response stream.", isStreaming: false, isLoading: false, isError: true } 
                : msg
            ));
             await saveMessageToHistory("Error reading response stream.", 'assistant'); // Save error
        } finally {
            console.log(`[Stream ${messageId}] Cleaning up. Setting loading to false.`);
            setLoading(prev => ({ ...prev, message: false })); // Ensure loading always stops
        }
    };

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
            
            console.log("Sending GPT opened notification with system prompt:", payload.schema.instructions?.substring(0, 50) + "...");
            
            const response = await fetch(`${backendUrl}/gpt-opened`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(payload)
            });
            
            if (response.ok) {
                const data = await response.json();
                console.log("GPT opened notification successful");
                
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

    // Optimize file upload for maximum speed
    const handleFileUpload = async (files) => {
        if (!files || files.length === 0) return;
        
        setIsUploading(true);
        setUploadProgress(0);
        
        try {
            // 1. Client-side file preprocessing for faster uploads
            const preprocessedFiles = await Promise.all(
                Array.from(files).map(async (file) => {
                    // Size validation - fail fast for oversized files
                    const MAX_FILE_SIZE = 20 * 1024 * 1024; // 20MB limit
                    if (file.size > MAX_FILE_SIZE) return { file, oversized: true };
                    
                    // File type validation - only process supported formats
                    const validTypes = ['application/pdf', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document', 'text/plain'];
                    const fileExt = file.name.split('.').pop().toLowerCase();
                    if (!validTypes.includes(file.type) && !['pdf', 'docx', 'txt'].includes(fileExt)) {
                        return { file, unsupported: true };
                    }
                    
                    return { file, valid: true };
                })
            );
            
            // Handle invalid files separately to avoid slowing down the upload
            const validFiles = preprocessedFiles.filter(f => f.valid).map(f => f.file);
            const invalidFiles = preprocessedFiles.filter(f => !f.valid);
            
            if (invalidFiles.length > 0) {
                const oversizedMsg = invalidFiles.filter(f => f.oversized).map(f => f.file.name).join(', ');
                const unsupportedMsg = invalidFiles.filter(f => f.unsupported).map(f => f.file.name).join(', ');
                
                let errorMsg = '';
                if (oversizedMsg) errorMsg += `Files exceeding size limit: ${oversizedMsg}. `;
                if (unsupportedMsg) errorMsg += `Unsupported file types: ${unsupportedMsg}`;
                
                setMessages(prev => [...prev, {
                    id: Date.now(),
                    role: 'system',
                    content: errorMsg,
                    timestamp: new Date()
                }]);
            }
            
            // Exit early if no valid files
            if (validFiles.length === 0) {
                setIsUploading(false);
                return;
            }
            
            // 2. Parallel file uploads with chunking for large files
            const formData = new FormData();
            validFiles.forEach(file => {
                formData.append('files', file);
            });
            
            // Add required metadata
            formData.append('user_email', userData?.email || 'anonymous');
            formData.append('gpt_id', gptData?._id || gptId);
            formData.append('gpt_name', gptData?.name || 'Assistant');
            formData.append('collection_name', collectionName);
            formData.append('is_user_document', 'true');
            
            // Get hybridSearch setting from capabilities
            const useHybridSearch = gptData?.capabilities?.hybridSearch || false;
            formData.append('use_hybrid_search', useHybridSearch.toString());
            
            // 3. Optimized upload with compress-only option for PDFs
            formData.append('optimize_pdfs', 'true');
            
            // 4. Use faster transfer with appropriate headers
            const response = await axios.post(`${pythonApiUrl}/upload-chat-files`, formData, {
                withCredentials: true,
                headers: {
                    'Content-Type': 'multipart/form-data',
                    'X-Request-Priority': 'high',
                    'X-Fast-Processing': 'true',
                },
                onUploadProgress: (progressEvent) => {
                    const percentCompleted = Math.round((progressEvent.loaded * 100) / progressEvent.total);
                    setUploadProgress(percentCompleted);
                },
                // Increase timeout for larger files but not too much
                timeout: 60000, // 60 seconds
            });
            
            // 5. Optimistic UI updates - don't wait for processing to complete
            if (response.data) {
                // Add file paths to userDocuments state immediately
                if (response.data.file_urls) {
                    setUserDocuments(prev => [...prev, ...response.data.file_urls]);
                }
                
                // Don't add system message for file uploads - silently process in the background
                console.log(`✅ ${validFiles.length} file(s) uploaded${response.data.processing ? ' and processing...' : ' successfully!'}`);
                
                // Show uploaded files in the UI
                setUploadedFiles(prev => [
                    ...prev,
                    ...validFiles.map(file => ({
                        name: file.name,
                        type: file.type,
                        size: file.size,
                        status: response.data.processing ? 'processing' : 'ready'
                    }))
                ]);
                
                // Handle background processing status if needed
                if (response.data.processing && response.data.task_id) {
                    checkProcessingStatus(response.data.task_id);
                }
            }
        } catch (error) {
            console.error("Error uploading files:", error);
            setMessages(prev => [...prev, {
                id: Date.now(),
                role: 'system',
                content: `❌ Error uploading files: ${error.message || 'Unknown error'}. Please try again.`,
                timestamp: new Date()
            }]);
        } finally {
            setIsUploading(false);
        }
    };

    // Optional: Add a status checker for background processing
    const checkProcessingStatus = async (taskId) => {
        try {
            const statusCheck = setInterval(async () => {
                const response = await axiosInstance.get(`/api/processing-status/${taskId}`);
                
                if (response.data.status === 'completed') {
                    // Update UI to show processing complete
                    setUploadedFiles(prev => 
                        prev.map(file => 
                            file.status === 'processing' ? {...file, status: 'ready'} : file
                        )
                    );
                    
                    // Silently complete processing without adding system message
                    console.log('✅ File processing completed. All files ready for queries.');
                    
                    clearInterval(statusCheck);
                } else if (response.data.status === 'failed') {
                    // Show error message
                    setMessages(prev => [...prev, {
                        id: Date.now(),
                        role: 'system',
                        content: `⚠️ Some files couldn't be processed properly: ${response.data.error || 'Unknown error'}`,
                        timestamp: new Date()
                    }]);
                    
                    clearInterval(statusCheck);
                }
            }, 3000); // Check every 3 seconds
            
            // Clear interval after 2 minutes max
            setTimeout(() => clearInterval(statusCheck), 120000);
        } catch (error) {
            console.error("Error checking processing status:", error);
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
        <div className={`flex flex-col h-screen overflow-hidden transition-colors duration-300 ${
            isDarkMode ? 'bg-black text-white' : 'bg-gray-100 text-gray-900'
        }`}>
            <div className={`flex-shrink-0 px-4 py-3 flex items-center justify-between ${
                isDarkMode ? 'bg-black border-gray-800' : 'bg-gray-100 border-gray-200'
            }`}>
                <div className="flex items-center space-x-2">
                    {gptId && (
                        <button 
                            onClick={handleGoBack}
                            className={`p-2 rounded-full transition-colors flex items-center justify-center w-10 h-10 ${
                                isDarkMode ? 'text-gray-400 hover:text-white hover:bg-gray-800' : 'text-gray-500 hover:text-gray-700 hover:bg-gray-200'
                            }`}
                            aria-label="Go back"
                        >
                            <IoArrowBack size={20} />
                        </button>
                    )}
                    
                    {/* New Chat Button */}
                    <button 
                        onClick={handleNewChat}
                        className={`p-2 rounded-full transition-colors flex items-center justify-center w-10 h-10 ${
                            isDarkMode ? 'text-gray-400 hover:text-white hover:bg-gray-800' : 'text-gray-500 hover:text-gray-700 hover:bg-gray-200'
                        }`}
                        aria-label="New Chat"
                    >
                        <IoAddCircleOutline size={24} />
                    </button>
                    
                    {/* Show the GPT name when it's available */}
                    {gptData && (
                        <div className="ml-2 text-sm md:text-base font-medium truncate max-w-[150px] md:max-w-xs">
                            {gptData.name}
                        </div>
                    )}
                </div>
                
                <div className="relative">
                    <button 
                        onClick={toggleProfile}
                        className={`w-10 h-10 rounded-full overflow-hidden border-2 transition-colors ${
                            isDarkMode ? 'border-white/20 hover:border-white/40' : 'border-gray-300 hover:border-gray-500'
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
                        <div className={`absolute top-12 right-0 w-64 rounded-xl shadow-lg border overflow-hidden z-30 ${
                             isDarkMode ? 'bg-[#1e1e1e] border-white/10' : 'bg-white border-gray-200'
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
                                <button className={`w-full px-4 py-2.5 text-left flex items-center space-x-3 transition-colors ${
                                    isDarkMode ? 'text-gray-300 hover:bg-white/5' : 'text-gray-700 hover:bg-gray-100'
                                }`}>
                                    <IoPersonOutline size={18} />
                                    <span>Profile</span>
                                </button>
                                <button 
                                    onClick={goToSettings} 
                                    className={`w-full px-4 py-2.5 text-left flex items-center space-x-3 transition-colors ${
                                        isDarkMode ? 'text-gray-300 hover:bg-white/5' : 'text-gray-700 hover:bg-gray-100'
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
                                            className={`mt-5 max-w-xs mx-auto p-3 border rounded-lg text-left cursor-pointer transition-colors ${
                                                isDarkMode 
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
                                                className={`p-3 border rounded-lg cursor-pointer text-left ${
                                                    isDarkMode 
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
                            <motion.div 
                                key={msg.id}
                                initial={{ opacity: 0, y: 10 }}
                                animate={{ opacity: 1, y: 0 }}
                                transition={{ duration: 0.3 }}
                                className={`flex ${msg.role === 'user' ? 'justify-end' : 'justify-start'} items-end space-x-2`}
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
                                            
                                            {/* Message Bubble */}
                                <div 
                                    className={`max-w-[95%] sm:max-w-[85%] md:max-w-[80%] p-3 rounded-lg ${
                                        msg.role === 'user' 
                                            ? (isDarkMode ? 'bg-blue-600 text-white' : 'bg-blue-500 text-white') 
                                            : (msg.isError 
                                                ? (isDarkMode ? 'bg-red-800/70 text-red-100' : 'bg-red-100 text-red-700') 
                                                : (isDarkMode ? 'bg-gray-700 text-gray-100' : 'bg-gray-200 text-gray-800'))
                                    }`}
                                >
                                                <ReactMarkdown remarkPlugins={[remarkGfm]}>
                                        {msg.content}
                                    </ReactMarkdown>
                                                
                                    {msg.isStreaming && (
                                        <div className="flex space-x-1 mt-1">
                                                        <motion.div animate={{ scale: [1, 1.2, 1], opacity: [0.5, 1, 0.5] }} transition={{ duration: 1, repeat: Infinity, repeatDelay: 0.5 }} className={`w-2 h-2 rounded-full ${isDarkMode ? 'bg-gray-400' : 'bg-gray-500'}`}></motion.div>
                                                        <motion.div animate={{ scale: [1, 1.2, 1], opacity: [0.5, 1, 0.5] }} transition={{ duration: 1, repeat: Infinity, delay: 0.2, repeatDelay: 0.5 }} className={`w-2 h-2 rounded-full ${isDarkMode ? 'bg-gray-400' : 'bg-gray-500'}`}></motion.div>
                                                        <motion.div animate={{ scale: [1, 1.2, 1], opacity: [0.5, 1, 0.5] }} transition={{ duration: 1, repeat: Infinity, delay: 0.4, repeatDelay: 0.5 }} className={`w-2 h-2 rounded-full ${isDarkMode ? 'bg-gray-400' : 'bg-gray-500'}`}></motion.div>
                                        </div>
                                    )}
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
                            </motion.div>
                        ))
                    )}
                        </>
                    )}
                    
                    {/* Loading indicator for NEW messages (when submitting) */}
                    {!isInitialLoading && loading.message && !messages.some(msg => msg.isStreaming) && (
                        <div className="flex justify-start items-end space-x-2">
                            <div className={`flex-shrink-0 w-8 h-8 rounded-full flex items-center justify-center ${isDarkMode ? 'bg-gray-700' : 'bg-gray-300'}`}>
                                    <IoSparkles size={16} className={isDarkMode ? 'text-blue-400' : 'text-blue-600'} />
                            </div>
                            <div className={`p-3 rounded-lg ${isDarkMode ? 'bg-gray-700' : 'bg-gray-200'}`}>
                                <div className="flex space-x-1">
                                    <motion.div animate={{ scale: [1, 1.2, 1], opacity: [0.5, 1, 0.5] }} transition={{ duration: 1, repeat: Infinity, repeatDelay: 0.5 }} className={`w-2 h-2 rounded-full ${isDarkMode ? 'bg-gray-400' : 'bg-gray-500'}`}></motion.div>
                                    <motion.div animate={{ scale: [1, 1.2, 1], opacity: [0.5, 1, 0.5] }} transition={{ duration: 1, repeat: Infinity, delay: 0.2, repeatDelay: 0.5 }} className={`w-2 h-2 rounded-full ${isDarkMode ? 'bg-gray-400' : 'bg-gray-500'}`}></motion.div>
                                    <motion.div animate={{ scale: [1, 1.2, 1], opacity: [0.5, 1, 0.5] }} transition={{ duration: 1, repeat: Infinity, delay: 0.4, repeatDelay: 0.5 }} className={`w-2 h-2 rounded-full ${isDarkMode ? 'bg-gray-400' : 'bg-gray-500'}`}></motion.div>
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

                    {/* Replace the existing uploaded files display with this one */}
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

                    <ChatInput 
                        onSubmit={handleChatSubmit} 
                        onFileUpload={handleFileUpload}
                        isLoading={loading.message} 
                        isDarkMode={isDarkMode} 
                        showWebSearch={showWebSearch}
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
    );
};

export default UserChat;