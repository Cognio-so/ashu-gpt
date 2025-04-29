import React, { useState, useEffect } from 'react';
import { IoAddOutline,  IoCloseOutline, IoPersonCircleOutline,  IoInformationCircleOutline, IoSearchOutline, IoSparklesOutline, IoArrowBackOutline } from 'react-icons/io5';
import { FaBox, FaUpload,  FaGlobe, FaChevronDown } from 'react-icons/fa';
import { LuBrain } from 'react-icons/lu';
import { SiOpenai, SiGooglegemini } from 'react-icons/si';
import { BiLogoMeta } from 'react-icons/bi';
import { FaRobot } from 'react-icons/fa6';
import { RiOpenaiFill } from 'react-icons/ri';
import { toast } from 'react-toastify';
import { useNavigate } from 'react-router-dom';
import { axiosInstance } from '../../api/axiosInstance';
import { useTheme } from '../../context/ThemeContext'; // Import useTheme
import axios from 'axios';
// Import Markdown components
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';

const PYTHON_URL = import.meta.env.VITE_PYTHON_API_URL;

const CreateCustomGpt = ({ onGoBack, editGptId = null, onGptCreated }) => {
    const navigate = useNavigate();
    const { isDarkMode } = useTheme(); // Get theme state

    // System prompt example with markdown hints
    const defaultInstructions = `You are a helpful, creative, clever, and very friendly AI assistant.

When providing code examples:
- Focus on readability and maintainability
- Include helpful comments
- Consider edge cases
- Explain the reasoning behind your implementation
- Avoid implementing solutions with known security vulnerabilities or performance issues.

**Key guidelines**: 
* Be concise and direct in your responses
* If you don't know something, admit it rather than making up information
* Provide step-by-step explanations when appropriate`;

    // State for GPT Configuration
    const [formData, setFormData] = useState({
        name: 'My Custom GPT',
        description: 'A helpful assistant that can answer questions about various topics.',
        instructions: defaultInstructions,
        conversationStarter: '',
    });
    
    // Simplified capabilities state
    const [capabilities, setCapabilities] = useState({
        webBrowsing: true,
        hybridSearch: false
    });
    
    const [imagePreview, setImagePreview] = useState(null);
    const [imageFile, setImageFile] = useState(null); // Store the actual file
    const [promptMode, setPromptMode] = useState('edit'); // 'edit' or 'preview'
    const [selectedModel, setSelectedModel] = useState('gpt-4');
    const [isTemplateDropdownOpen, setIsTemplateDropdownOpen] = useState(false); // State for dropdown
    const [knowledgeFiles, setKnowledgeFiles] = useState([]); // State for knowledge files
    const [isMobileView, setIsMobileView] = useState(false);
    const [isLoading, setIsLoading] = useState(false); // Keep for initial fetch in edit mode
    const [isSaving, setIsSaving] = useState(false); // New state for save button
    const [isEditMode, setIsEditMode] = useState(false);

    // Check if we're in edit mode
    useEffect(() => {
        if (editGptId) {
            setIsEditMode(true);
            setIsLoading(true); // Set loading true only for initial fetch
            fetchGptDetails(editGptId);
        }
    }, [editGptId]);

    // Fetch GPT details if in edit mode
    const fetchGptDetails = async (id) => {
        try {
            const response = await axiosInstance.get(
                `${axiosInstance.defaults.baseURL.endsWith('/api') ? axiosInstance.defaults.baseURL : `${axiosInstance.defaults.baseURL}/api`}/custom-gpts/${id}`, 
                { withCredentials: true }
            );
            
            const gpt = response.data.customGpt;
            
            // Set form data
            setFormData({
                name: gpt.name,
                description: gpt.description,
                instructions: gpt.instructions,
                conversationStarter: gpt.conversationStarter || '',
            });
            
            // Set other states
            setSelectedModel(gpt.model);
            setCapabilities({
                ...capabilities, // Keep default values
                ...gpt.capabilities, // Override with existing values
                // Ensure hybridSearch is defined even if not in original data
                hybridSearch: gpt.capabilities?.hybridSearch ?? false
            });
            
            // Set image preview if exists
            if (gpt.imageUrl) {
                setImagePreview(gpt.imageUrl);
            }
            
            // Set knowledge files
            if (gpt.knowledgeFiles && gpt.knowledgeFiles.length > 0) {
                setKnowledgeFiles(gpt.knowledgeFiles.map(file => ({
                    name: file.name,
                    url: file.fileUrl,
                    // Mark as already uploaded to distinguish from new files
                    isUploaded: true,
                    index: gpt.knowledgeFiles.indexOf(file) // Maintain original index if needed
                })));
            }
            
        } catch (error) {
            console.error("Error fetching GPT details:", error);
            toast.error("Failed to load GPT details");
        } finally {
            setIsLoading(false); // Stop loading after fetch completes/fails
        }
    };

    // Check screen size on mount and resize
    useEffect(() => {
        const handleResize = () => {
            setIsMobileView(window.innerWidth < 768);
        };
        
        window.addEventListener('resize', handleResize);
        handleResize(); // Initial check
        
        return () => window.removeEventListener('resize', handleResize);
    }, []);

    // Model icons mapping
    const modelIcons = {
        'gpt-4': <RiOpenaiFill className="text-green-500 mr-2" size={18} />,
        'gpt-3.5': <SiOpenai className="text-green-400 mr-2" size={16} />,
        'claude': <FaRobot className="text-purple-400 mr-2" size={16} />,
        'gemini': <SiGooglegemini className="text-blue-400 mr-2" size={16} />,
        'llama': <BiLogoMeta className="text-blue-500 mr-2" size={18} />
    };

    const handleInputChange = (e) => {
        const { name, value } = e.target;
        setFormData({
            ...formData,
            [name]: value
        });
    };
    
    const handleImageUpload = (e) => {
        const file = e.target.files[0];
        if (file) {
            setImageFile(file); // Store the file for later upload
            const reader = new FileReader();
            reader.onloadend = () => {
                setImagePreview(reader.result);
            };
            reader.readAsDataURL(file);
        }
    };
    
    // Updated handler for simplified capabilities
    const handleCapabilityChange = (capability) => {
        setCapabilities(prevCapabilities => ({
            ...prevCapabilities,
            [capability]: !prevCapabilities[capability]
        }));
    };

    const handleGeneratePrompt = () => {

        setFormData({ ...formData, instructions: 'Generated prompt: Be concise and helpful.' });
        setPromptMode('edit'); // Switch back to edit mode after generating
    };
    
    const handleSelectTemplate = (templateInstructions) => {
        setFormData({ ...formData, instructions: templateInstructions });
        setIsTemplateDropdownOpen(false);
        setPromptMode('edit');
    };
    
    // Handler for knowledge file upload
    const handleKnowledgeUpload = (e) => {
        const files = Array.from(e.target.files);
        
        // Create file objects with preview capabilities
        const newFiles = files.map(file => ({
            file, // Keep the file object for upload
            name: file.name,
            type: file.type,
            size: file.size,
            isUploaded: false // Mark as not yet uploaded to server
        }));
        
        setKnowledgeFiles([...knowledgeFiles, ...newFiles]);
    };

    // Handler to remove a knowledge file
    const removeKnowledgeFile = async (index) => {
        const fileToRemove = knowledgeFiles[index];
        
        // If the file is already uploaded to the server and we're in edit mode
        if (fileToRemove.isUploaded && isEditMode && editGptId) {
            try {
                await axiosInstance.delete(
                    `${axiosInstance.defaults.baseURL.endsWith('/api') ? axiosInstance.defaults.baseURL : `${axiosInstance.defaults.baseURL}/api`}/custom-gpts/${editGptId}/knowledge/${fileToRemove.index}`, // Using original index
                    { withCredentials: true }
                );
                toast.success("File deleted successfully");
                setKnowledgeFiles(prevFiles => prevFiles.filter((_, i) => i !== index));
            } catch (error) {
                console.error("Error deleting file:", error);
                toast.error("Failed to delete file");
                return; // Don't remove from UI if server deletion failed
            }
        } else {
            setKnowledgeFiles(prevFiles => prevFiles.filter((_, i) => i !== index));
        }
    };

    // Example prompt templates
    const promptTemplates = {
        "Coding Expert": "You are an expert programmer with deep knowledge of software development best practices. Help users with coding problems, architecture decisions, and debugging issues.\n\nWhen providing code examples:\n- Focus on readability and maintainability\n- Include helpful comments\n- Consider edge cases\n- Explain the reasoning behind your implementation\n- Avoid implementing solutions with known security vulnerabilities or performance issues.",
        "Creative Writer": "You are a creative writing assistant. Help users brainstorm ideas, develop characters, write dialogue, and overcome writer's block. Use vivid language and imaginative suggestions.",
        "Marketing Assistant": "You are a helpful marketing assistant. Generate ad copy, social media posts, email campaigns, and suggest marketing strategies based on user goals and target audience.",
    };

    // System Prompt Section - Updated with Markdown support
    const renderSystemPromptSection = () => (
        <div className="border border-gray-400 dark:border-gray-700 rounded-lg overflow-hidden">
            <div className="p-3 md:p-4 border-b border-gray-400 dark:border-gray-700">
                <div className="flex items-center mb-1 md:mb-2">
                    <LuBrain className="text-purple-500 dark:text-purple-400 mr-2" size={16} />
                    <h3 className="text-sm md:text-base font-medium text-gray-800 dark:text-gray-100">Model Instructions</h3>
                </div>
                <p className="text-xs text-gray-500 dark:text-gray-400">
                    Set instructions for how your GPT should behave and respond. 
                    <span className="ml-1 italic">Supports Markdown formatting.</span>
                </p>
            </div>
            
            <div className="p-3 md:p-4">
                <div className="flex justify-between items-center mb-2 md:mb-3">
                    <label className="text-xs md:text-sm font-medium text-gray-600 dark:text-gray-300">System Prompt</label>
                    <div className="flex space-x-2">
                        <button 
                            onClick={handleGeneratePrompt}
                            className="flex items-center text-xs text-white px-2 py-1 rounded-md bg-purple-600 hover:bg-purple-700"
                        >
                            <IoSparklesOutline className="mr-1" size={14} />
                            Generate
                        </button>
                        <button 
                            onClick={() => setIsTemplateDropdownOpen(!isTemplateDropdownOpen)}
                            className="flex items-center text-xs text-gray-700 dark:text-gray-300 px-2 py-1 rounded-md bg-gray-200 dark:bg-gray-700 hover:bg-gray-300 dark:hover:bg-gray-600"
                        >
                            <IoSearchOutline className="mr-1" size={14} />
                            Templates
                        </button>
                    </div>
                </div>
                
                {/* Template Selector Dropdown */}
                {isTemplateDropdownOpen && (
                    <div className="relative mb-2 md:mb-3">
                        <div className="absolute z-10 mt-1 w-full bg-white dark:bg-[#262626] border border-gray-400 dark:border-gray-700 rounded-md shadow-lg max-h-48 overflow-y-auto no-scrollbar">
                            <ul>
                                {Object.entries(promptTemplates).map(([name, instructions]) => (
                                    <li key={name}>
                                        <button 
                                            onClick={() => handleSelectTemplate(instructions)}
                                            className="w-full text-left px-3 py-2 text-xs md:text-sm text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700"
                                        >
                                            {name}
                                        </button>
                                    </li>
                                ))}
                            </ul>
                        </div>
                    </div>
                )}
                
                {/* Edit/Preview Toggle */}
                <div className="flex rounded-t-md overflow-hidden mb-0 bg-gray-300 dark:bg-gray-800">
                    <button
                        onClick={() => setPromptMode('edit')}
                        className={`flex-1 py-1.5 text-xs md:text-sm font-medium ${promptMode === 'edit' ? 'bg-gray-400 dark:bg-gray-600 text-gray-900 dark:text-white' : 'bg-gray-300 dark:bg-gray-800 text-gray-600 dark:text-gray-400'}`}
                    >
                        Edit
                    </button>
                    <button
                        onClick={() => setPromptMode('preview')}
                        className={`flex-1 py-1.5 text-xs md:text-sm font-medium ${promptMode === 'preview' ? 'bg-purple-600 text-white' : 'bg-gray-300 dark:bg-gray-800 text-gray-600 dark:text-gray-400'}`}
                    >
                        Preview
                    </button>
                </div>
                
                {/* Conditional Rendering: Edit Textarea or Preview with Markdown */}
                {promptMode === 'edit' ? (
                    <div className="relative">
                        <textarea 
                            name="instructions" 
                            value={formData.instructions}
                            onChange={handleInputChange}
                            className="w-full bg-white dark:bg-[#262626] border border-gray-400 dark:border-gray-700 border-t-0 rounded-b-md px-3 py-2 text-xs md:text-sm text-gray-900 dark:text-white focus:outline-none focus:ring-1 focus:ring-blue-500 min-h-[120px] md:min-h-[200px] no-scrollbar placeholder-gray-500 dark:placeholder-gray-400 font-mono"
                            placeholder="Instructions for how the GPT should behave..."
                            style={{ lineHeight: '1.5' }}
                        />
                        <div className="absolute bottom-2 right-2 text-xs text-gray-500 dark:text-gray-400 italic">
                            Supports Markdown
                        </div>
                    </div>
                ) : (
                    <div className="w-full bg-white dark:bg-[#262626] border border-gray-400 dark:border-gray-700 border-t-0 rounded-b-md px-3 py-2 text-xs md:text-sm text-gray-900 dark:text-white min-h-[120px] md:min-h-[200px] overflow-y-auto no-scrollbar">
                        <ReactMarkdown 
                            remarkPlugins={[remarkGfm]}
                            components={{
                                // Apply styling to specific elements
                                p: ({node, ...props}) => <p className="mb-3 text-gray-900 dark:text-white" {...props} />,
                                h1: ({node, ...props}) => <h1 className="text-xl font-bold mb-2 mt-3 text-gray-900 dark:text-white" {...props} />,
                                h2: ({node, ...props}) => <h2 className="text-lg font-semibold mb-2 mt-3 text-gray-900 dark:text-white" {...props} />,
                                h3: ({node, ...props}) => <h3 className="text-base font-medium mb-2 mt-2 text-gray-900 dark:text-white" {...props} />,
                                ul: ({node, ...props}) => <ul className="list-disc pl-5 mb-3 text-gray-900 dark:text-white" {...props} />,
                                ol: ({node, ...props}) => <ol className="list-decimal pl-5 mb-3 text-gray-900 dark:text-white" {...props} />,
                                li: ({node, ...props}) => <li className="mb-1 text-gray-900 dark:text-white" {...props} />,
                                code: ({node, inline, ...props}) => 
                                    inline 
                                        ? <code className="bg-gray-100 dark:bg-gray-800 px-1 py-0.5 rounded text-gray-900 dark:text-white font-mono text-sm" {...props} />
                                        : <code className="block bg-gray-100 dark:bg-gray-800 p-2 rounded text-gray-900 dark:text-white font-mono text-sm overflow-x-auto" {...props} />,
                                pre: ({node, ...props}) => <pre className="bg-gray-100 dark:bg-gray-800 p-3 rounded-md mb-3 overflow-x-auto" {...props} />,
                                blockquote: ({node, ...props}) => <blockquote className="border-l-4 border-gray-300 dark:border-gray-700 pl-3 italic my-2" {...props} />,
                                a: ({node, ...props}) => <a className="text-blue-600 dark:text-blue-400 hover:underline" {...props} />
                            }}
                        >
                            {formData.instructions}
                        </ReactMarkdown>
                    </div>
                )}
                
                {/* Markdown helper */}
                {promptMode === 'edit' && (
                    <div className="mt-2 flex flex-wrap gap-1">
                        <button 
                            onClick={() => insertMarkdown('**bold**')}
                            className="px-2 py-1 text-xs bg-gray-200 dark:bg-gray-700 text-gray-700 dark:text-gray-300 rounded hover:bg-gray-300 dark:hover:bg-gray-600"
                            title="Bold"
                        >
                            <strong>B</strong>
                        </button>
                        <button 
                            onClick={() => insertMarkdown('*italic*')}
                            className="px-2 py-1 text-xs bg-gray-200 dark:bg-gray-700 text-gray-700 dark:text-gray-300 rounded hover:bg-gray-300 dark:hover:bg-gray-600"
                            title="Italic"
                        >
                            <em>I</em>
                        </button>
                        <button 
                            onClick={() => insertMarkdown('## Heading')}
                            className="px-2 py-1 text-xs bg-gray-200 dark:bg-gray-700 text-gray-700 dark:text-gray-300 rounded hover:bg-gray-300 dark:hover:bg-gray-600"
                            title="Heading"
                        >
                            H
                        </button>
                        <button 
                            onClick={() => insertMarkdown('- List item')}
                            className="px-2 py-1 text-xs bg-gray-200 dark:bg-gray-700 text-gray-700 dark:text-gray-300 rounded hover:bg-gray-300 dark:hover:bg-gray-600"
                            title="List"
                        >
                            • List
                        </button>
                        <button 
                            onClick={() => insertMarkdown('```\ncode block\n```')}
                            className="px-2 py-1 text-xs bg-gray-200 dark:bg-gray-700 text-gray-700 dark:text-gray-300 rounded hover:bg-gray-300 dark:hover:bg-gray-600"
                            title="Code Block"
                        >
                            {'</>'}
                        </button>
                    </div>
                )}
            </div>
        </div>
    );

    // Function to insert markdown at cursor position
    const insertMarkdown = (markdown) => {
        const textarea = document.querySelector('textarea[name="instructions"]');
        if (textarea) {
            const start = textarea.selectionStart;
            const end = textarea.selectionEnd;
            const newText = formData.instructions.substring(0, start) + markdown + formData.instructions.substring(end);
            
            setFormData({
                ...formData,
                instructions: newText
            });
            
            // Focus back on textarea and set cursor position after the inserted markdown
            setTimeout(() => {
                textarea.focus();
                textarea.setSelectionRange(start + markdown.length, start + markdown.length);
            }, 0);
        }
    };

    // Modify triggerKnowledgeIndexing to include system prompt
    const triggerKnowledgeIndexing = async (gptId, fileUrls, email) => {
        try {
            // Always trigger indexing even if there are no files to save system prompt
            const response = await axios.post(
                `${PYTHON_URL}/index-knowledge`,
                {
                    file_urls: fileUrls,
                    user_email: email || "user@example.com",
                    gpt_name: formData.name,
                    gpt_id: gptId,
                    force_recreate: false,
                    system_prompt: formData.instructions,
                    use_hybrid_search: capabilities.hybridSearch,
                    schema: {
                        model: selectedModel,
                        capabilities: capabilities,
                        name: formData.name,
                        description: formData.description,
                        instructions: formData.instructions,
                        conversationStarter: formData.conversationStarter,
                        use_hybrid_search: capabilities.hybridSearch
                    }
                }
            );
            
            if (response.data.success) {
                console.log(`KB indexing completed for collection: ${response.data.collection_name}`);
                toast.success("Knowledge files indexed successfully");
            } else {
                console.error("KB indexing failed");
                toast.warning("Knowledge file upload succeeded but indexing failed. Search functionality may be limited.");
            }
        } catch (error) {
            console.error("Error triggering KB indexing:", error);
            toast.warning("Knowledge files uploaded but indexing failed. Search functionality may be limited.");
        }
    };

    // Modify handleSaveGpt to call the indexing function
    const handleSaveGpt = async () => {
        setIsSaving(true);
        
        try {
            // Prepare form data for API
            const apiFormData = new FormData();
            apiFormData.append('name', formData.name);
            apiFormData.append('description', formData.description);
            apiFormData.append('instructions', formData.instructions);
            apiFormData.append('conversationStarter', formData.conversationStarter);
            apiFormData.append('model', selectedModel);
            apiFormData.append('capabilities', JSON.stringify(capabilities));
            
            // Add image if selected
            if (imageFile) {
                apiFormData.append('image', imageFile);
            }
            
            const newKnowledgeFiles = knowledgeFiles.filter(file => !file.isUploaded);
            newKnowledgeFiles.forEach(fileObj => {
                apiFormData.append('knowledgeFiles', fileObj.file);
            });
            
            let response;
            let successMessage = '';
            
            if (isEditMode) {
                response = await axiosInstance.put(
                    `${axiosInstance.defaults.baseURL.endsWith('/api') ? axiosInstance.defaults.baseURL : `${axiosInstance.defaults.baseURL}/api`}/custom-gpts/${editGptId}`, 
                    apiFormData, 
                    { 
                        withCredentials: true,
                        headers: { 'Content-Type': 'multipart/form-data' } 
                    }
                );
                successMessage = "Custom GPT updated successfully!";
            } else {
                response = await axiosInstance.post(
                    `${axiosInstance.defaults.baseURL.endsWith('/api') ? axiosInstance.defaults.baseURL : `${axiosInstance.defaults.baseURL}/api`}/custom-gpts`, 
                    apiFormData, 
                    { 
                        withCredentials: true,
                        headers: { 'Content-Type': 'multipart/form-data' } 
                    }
                );
                 successMessage = "Custom GPT created successfully!";
            }
            
            // Get gptId and extract file URLs from response
            const gptId = response.data.customGpt._id;
            const fileUrls = response.data.customGpt.knowledgeFiles.map(file => file.fileUrl);
            const userEmail = response.data.customGpt.createdBy.email || "user@example.com";
            
            // Always trigger indexing to pass system prompt, even if no files
            triggerKnowledgeIndexing(gptId, fileUrls, userEmail);
            
            if (response.status === 200 || response.status === 201) {
                toast.success(successMessage);
                
                // Call the callback to notify parent *before* navigating
                if (onGptCreated) {
                    onGptCreated(); 
                }

                // Navigate back after success and notification
                if (onGoBack) {
                   onGoBack();
                } else {
                    navigate('/admin'); // Fallback navigation
                }

            } else {
                 toast.error(response.data?.message || "Failed to save Custom GPT");
            }
            
        } catch (error) {
            console.error("Error saving GPT:", error);
            toast.error(error.response?.data?.message || "An error occurred while saving.");
        } finally {
            setIsSaving(false); 
        }
    };

    if (isLoading && isEditMode) {
        return (
            <div className="w-full h-full flex items-center justify-center bg-gray-100 dark:bg-[#1A1A1A]">
                <div className="animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-purple-500"></div>
            </div>
        );
    }

    return (
        <div className={`w-full h-full flex flex-col ${isDarkMode ? 'dark' : ''} bg-gray-100 dark:bg-[#1A1A1A] text-gray-900 dark:text-white`}>
            <div className={`flex ${isMobileView ? 'flex-col' : 'flex-row'} flex-1 overflow-hidden`}>
                
                {/* Right Side - Preview (Now appears first in JSX for flex-col ordering) */}
                <div className={`${isMobileView ? 'w-full h-1/2 border-b border-gray-300 dark:border-gray-800' : 'w-1/2 h-full'} bg-gray-200 dark:bg-[#2A2A2A] flex flex-col`}>
                    <div className="p-4 md:p-6 flex flex-col flex-1">
                        <div className="mb-3 md:mb-4 flex justify-between items-center">
                            <h2 className="text-base md:text-xl font-bold text-gray-900 dark:text-white">Preview</h2>
                            <button className="flex items-center text-xs md:text-sm text-gray-600 dark:text-gray-300 px-2 md:px-3 py-1 rounded-md bg-gray-300 dark:bg-gray-800 hover:bg-gray-400 dark:hover:bg-gray-700">
                                <IoInformationCircleOutline className="mr-1" size={14} />
                                View Details
                            </button>
                        </div>

                        {/* UserDashboard Preview */}
                        <div className="flex-1 flex flex-col bg-white dark:bg-black rounded-lg overflow-hidden relative">
                            {/* Mock Header with Profile Icon */}
                            <div className="absolute top-2 md:top-4 right-2 md:right-4">
                                <div className="w-8 h-8 md:w-10 md:h-10 rounded-full overflow-hidden border-2 border-white/20 dark:border-white/20">
                                    <div className="w-full h-full bg-gray-300 dark:bg-gray-700 flex items-center justify-center">
                                        <IoPersonCircleOutline size={20} className="text-gray-800 dark:text-white" />
                                    </div>
                                </div>
                            </div>

                            {/* Preview Content - Updated to center content */}
                            <div className="flex-1 flex flex-col p-4 md:p-6 items-center justify-center"> 
                                {/* Header */}
                                <div className="text-center mb-2 md:mb-4">
                                    <div className="flex justify-center mb-2 md:mb-4">
                                        {imagePreview ? (
                                            <div className="w-12 h-12 md:w-16 md:h-16 rounded-full overflow-hidden">
                                                <img src={imagePreview} alt="GPT" className="w-full h-full object-cover" />
                                            </div>
                                        ) : (
                                            <div className="w-12 h-12 md:w-16 md:h-16 rounded-full bg-gray-200 dark:bg-gray-800 flex items-center justify-center">
                                                <FaBox size={20} className="text-gray-500 dark:text-gray-600" />
                                            </div>
                                        )}
                                    </div>
                                    <h1 className="text-lg md:text-2xl font-bold text-gray-900 dark:text-white">
                                        {formData.name || "Welcome to AI Agent"}
                                    </h1>
                                    <span className="text-sm md:text-base font-medium mt-1 md:mt-2 block text-gray-600 dark:text-gray-300">
                                        {formData.description || "How can I assist you today?"}
                                    </span>
                                </div>

                                {/* Conversation Starter as Preset Card (if provided) */}
                                {formData.conversationStarter && (
                                    <div className="w-full max-w-xs md:max-w-md mx-auto mt-2 md:mt-4"> 
                                        <div className="bg-white/80 dark:bg-white/[0.05] backdrop-blur-xl border border-gray-300 dark:border-white/20 shadow-[0_0_15px_rgba(204,43,94,0.2)] rounded-xl p-2 md:p-3 text-left">
                                            <p className="text-xs md:text-sm text-gray-700 dark:text-gray-300">{formData.conversationStarter}</p>
                                        </div>
                                    </div>
                                )}
                            </div>

                            {/* Chat Input at Bottom */}
                            <div className="p-3 md:p-4 border-t border-gray-300 dark:border-gray-800">
                                <div className="relative">
                                    <input 
                                        type="text" 
                                        className="w-full bg-gray-100 dark:bg-[#1A1A1A] border border-gray-400 dark:border-gray-700 rounded-lg px-3 md:px-4 py-2 md:py-3 pr-8 md:pr-10 text-gray-900 dark:text-white focus:outline-none text-sm placeholder-gray-500 dark:placeholder-gray-500"
                                        placeholder="Ask anything"
                                        disabled
                                    />
                                    <button className="absolute right-3 top-1/2 transform -translate-y-1/2 text-gray-500 dark:text-gray-500">
                                        <IoAddOutline size={18} />
                                    </button>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                {/* Left Side - Configuration Panel (Now appears second in JSX for flex-col ordering) */}
                <div className={`${isMobileView ? 'w-full h-1/2' : 'w-1/2 h-full border-r border-gray-300 dark:border-gray-800'} overflow-y-auto p-4 md:p-6 no-scrollbar`}>
                    <div className="mb-4 md:mb-6 flex items-center">
                        {/* Back Button */}
                        <button 
                            onClick={onGoBack} 
                            className="mr-3 md:mr-4 p-1 rounded-full hover:bg-gray-200 dark:hover:bg-gray-700 transition-colors"
                            title="Back to Dashboard"
                        >
                            <IoArrowBackOutline size={20} className="text-gray-700 dark:text-gray-300"/>
                        </button>
                        <div>
                            <h1 className="text-lg md:text-2xl font-bold text-gray-900 dark:text-white">Custom GPT Builder</h1>
                            <p className="text-xs md:text-sm text-gray-500 dark:text-gray-400">Configure your GPT on the left, test it on the right</p>
                        </div>
                    </div>
                    
                    {/* Image Upload at top center */}
                    <div className="flex justify-center mb-5 md:mb-8">
                        <div 
                            onClick={() => document.getElementById('gptImage').click()}
                            className="w-16 h-16 md:w-24 md:h-24 rounded-full border-2 border-dashed border-gray-400 dark:border-gray-600 flex items-center justify-center cursor-pointer hover:border-blue-500"
                        >
                            {imagePreview ? (
                                <img src={imagePreview} alt="GPT Preview" className="w-full h-full object-cover rounded-full" />
                            ) : (
                                <IoAddOutline size={24} className="text-gray-500 dark:text-gray-500" />
                            )}
                            <input 
                                type="file" 
                                id="gptImage" 
                                className="hidden" 
                                accept="image/*" 
                                onChange={handleImageUpload}
                            />
                        </div>
                    </div>
                    
                    {/* Basic Configuration Section */}
                    <div className="space-y-4">
                        {/* Name Field */}
                        <div>
                            <label className="block text-xs md:text-sm font-medium text-gray-600 dark:text-gray-300 mb-1">Name</label>
                            <input 
                                type="text" 
                                name="name" 
                                value={formData.name}
                                onChange={handleInputChange}
                                className="w-full bg-white dark:bg-[#262626] border border-gray-400 dark:border-gray-700 rounded-md px-3 py-2 text-sm text-gray-900 dark:text-white focus:outline-none focus:ring-1 focus:ring-blue-500 placeholder-gray-500 dark:placeholder-gray-400"
                                placeholder="My Custom GPT"
                            />
                        </div>
                        
                        {/* Description Field */}
                        <div>
                            <label className="block text-xs md:text-sm font-medium text-gray-600 dark:text-gray-300 mb-1">Description</label>
                            <input 
                                type="text" 
                                name="description" 
                                value={formData.description}
                                onChange={handleInputChange}
                                className="w-full bg-white dark:bg-[#262626] border border-gray-400 dark:border-gray-700 rounded-md px-3 py-2 text-sm text-gray-900 dark:text-white focus:outline-none focus:ring-1 focus:ring-blue-500 placeholder-gray-500 dark:placeholder-gray-400"
                                placeholder="A helpful assistant that can answer questions about various topics."
                            />
                        </div>
                        
                        {/* Model Selection with Icons */}
                        <div>
                            <label className="block text-xs md:text-sm font-medium text-gray-600 dark:text-gray-300 mb-1">Model</label>
                            <div className="relative">
                                <select
                                    value={selectedModel}
                                    onChange={(e) => setSelectedModel(e.target.value)}
                                    className="w-full bg-white dark:bg-[#262626] border border-gray-400 dark:border-gray-700 rounded-md pl-10 pr-4 py-2 text-sm text-gray-900 dark:text-white focus:outline-none focus:ring-1 focus:ring-blue-500 appearance-none"
                                >
                                    <option value="gpt-4">GPT-4</option>
                                    <option value="gpt-3.5">GPT-3.5</option>
                                    <option value="claude">Claude</option>
                                    <option value="gemini">Gemini</option>
                                    <option value="llama">Llama</option>
                                </select>
                                <div className="absolute inset-y-0 left-0 flex items-center pl-3 pointer-events-none">
                                    {modelIcons[selectedModel]}
                                </div>
                                <div className="absolute inset-y-0 right-0 flex items-center pr-3 pointer-events-none">
                                    <FaChevronDown className="text-gray-400 dark:text-gray-400" size={12} />
                                </div>
                            </div>
                        </div>
                        
                        {/* System Prompt Section */}
                        {renderSystemPromptSection()}
                        
                        {/* Web Browsing Capability */}
                        <div className="flex items-center justify-between pt-2">
                            <div>
                                <div className="flex items-center">
                                    <FaGlobe className="text-gray-500 dark:text-gray-400 mr-2" size={14} />
                                    <label htmlFor="webBrowsingToggle" className="text-xs md:text-sm font-medium text-gray-600 dark:text-gray-300 cursor-pointer">Web Browsing</label>
                                </div>
                                <p className="text-xs text-gray-500 dark:text-gray-500 mt-1">Allow your GPT to search and browse the web</p>
                            </div>
                            <label htmlFor="webBrowsingToggle" className="relative inline-flex items-center cursor-pointer">
                                <input
                                    id="webBrowsingToggle"
                                    type="checkbox"
                                    className="sr-only peer"
                                    checked={capabilities.webBrowsing}
                                    onChange={() => handleCapabilityChange('webBrowsing')}
                                />
                                <div className="w-9 h-5 md:w-11 md:h-6 bg-gray-300 dark:bg-gray-700 rounded-full peer peer-checked:after:translate-x-full peer-checked:bg-purple-600 after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white dark:after:bg-white after:border-gray-300 dark:after:border-gray-600 after:border after:rounded-full after:h-4 after:w-4 md:after:h-5 md:after:w-5 after:transition-all"></div>
                            </label>
                        </div>

                        {/* Hybrid Search Capability */}
                        <div className="flex items-center justify-between pt-2">
                            <div>
                                <div className="flex items-center">
                                    <LuBrain className="text-gray-500 dark:text-gray-400 mr-2" size={14} />
                                    <label htmlFor="hybridSearchToggle" className="text-xs md:text-sm font-medium text-gray-600 dark:text-gray-300 cursor-pointer">Hybrid Search</label>
                                </div>
                                <p className="text-xs text-gray-500 dark:text-gray-500 mt-1">Enable more accurate knowledge retrieval with hybrid search</p>
                            </div>
                            <label htmlFor="hybridSearchToggle" className="relative inline-flex items-center cursor-pointer">
                                <input
                                    id="hybridSearchToggle"
                                    type="checkbox"
                                    className="sr-only peer"
                                    checked={capabilities.hybridSearch}
                                    onChange={() => handleCapabilityChange('hybridSearch')}
                                />
                                <div className="w-9 h-5 md:w-11 md:h-6 bg-gray-300 dark:bg-gray-700 rounded-full peer peer-checked:after:translate-x-full peer-checked:bg-purple-600 after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white dark:after:bg-white after:border-gray-300 dark:after:border-gray-600 after:border after:rounded-full after:h-4 after:w-4 md:after:h-5 md:after:w-5 after:transition-all"></div>
                            </label>
                        </div>

                        {/* Conversation Starter */}
                        <div>
                            <label className="block text-xs md:text-sm font-medium text-gray-600 dark:text-gray-300 mb-1">Conversation Starter</label>
                            <input 
                                type="text" 
                                name="conversationStarter" 
                                value={formData.conversationStarter}
                                onChange={handleInputChange}
                                className="w-full bg-white dark:bg-[#262626] border border-gray-400 dark:border-gray-700 rounded-md px-3 py-2 text-xs md:text-sm text-gray-900 dark:text-white focus:outline-none focus:ring-1 focus:ring-blue-500 placeholder-gray-500 dark:placeholder-gray-400"
                                placeholder="Add a conversation starter..."
                            />
                        </div>
                        
                        {/* Knowledge Section */}
                        <div className="space-y-2 md:space-y-3">
                            <label className="block text-xs md:text-sm font-medium text-gray-600 dark:text-gray-300">Knowledge</label>
                            <div className="border-2 border-dashed border-gray-400 dark:border-gray-700 rounded-lg p-3 md:p-4 text-center">
                                <FaUpload className="h-4 w-4 md:h-6 md:w-6 mx-auto mb-1 md:mb-2 text-gray-500 dark:text-gray-500" />
                                <h3 className="font-medium text-xs md:text-sm text-gray-800 dark:text-white mb-1">Upload Files</h3>
                                <p className="text-xs text-gray-500 dark:text-gray-400 mb-2 md:mb-3">Upload PDFs, docs, or text files to give your GPT specific knowledge</p>
                                <button 
                                    type="button" 
                                    onClick={() => document.getElementById('knowledgeFiles').click()}
                                    className="px-3 md:px-4 py-1 md:py-1.5 text-xs md:text-sm bg-gray-200 dark:bg-[#262626] text-gray-700 dark:text-gray-300 rounded-md hover:bg-gray-300 dark:hover:bg-gray-700 transition-colors"
                                >
                                    Select Files
                                </button>
                                <input 
                                    type="file" 
                                    id="knowledgeFiles" 
                                    className="hidden" 
                                    multiple 
                                    onChange={handleKnowledgeUpload} 
                                />
                            </div>
                            
                            {/* Display uploaded files */}
                            {knowledgeFiles.length > 0 && (
                                <div className="mt-2">
                                    <ul className="space-y-1">
                                        {knowledgeFiles.map((file, index) => (
                                            <li key={index} className="flex justify-between items-center bg-white dark:bg-[#262626] px-3 py-1.5 rounded text-xs md:text-sm border border-gray-400 dark:border-gray-700">
                                                <span className="text-gray-700 dark:text-gray-300 truncate mr-2">{file.name}</span>
                                                <button 
                                                    type="button" 
                                                    onClick={() => removeKnowledgeFile(index)}
                                                    className="text-gray-500 dark:text-gray-500 hover:text-red-500 dark:hover:text-red-400"
                                                >
                                                    <IoCloseOutline size={16} />
                                                </button>
                                            </li>
                                        ))}
                                    </ul>
                                </div>
                            )}
                            {knowledgeFiles.length === 0 && (
                                 <div className="text-xs md:text-sm text-gray-500 dark:text-gray-500 mt-2">No files uploaded yet</div>
                            )}
                        </div>
                    </div>
                    
                    {/* Save Button - Updated */}
                    <div className="mt-4 md:mt-6 pt-3 md:pt-4 border-t border-gray-400 dark:border-gray-700">
                        <button 
                            onClick={handleSaveGpt}
                            disabled={isSaving} // Disable button when saving
                            className={`w-full px-4 py-2 md:py-3 rounded-md text-white text-sm md:text-base font-medium transition-colors shadow-lg ${
                                isSaving 
                                ? 'bg-gray-400 dark:bg-gray-500 cursor-not-allowed' 
                                : 'bg-gradient-to-r from-purple-600 to-blue-600 hover:from-purple-700 hover:to-blue-700'
                            }`}
                        >
                            {isSaving 
                                ? 'Saving...' 
                                : isEditMode 
                                    ? "Update Configuration" 
                                    : "Save Configuration"}
                        </button>
                    </div>
                </div>

            </div>
        </div>
    );
};

export default CreateCustomGpt;