import React, { useState, useEffect } from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import axios from 'axios';
import './App.css';

// Import Shadcn components
import { Button } from './components/ui/button';
import { Input } from './components/ui/input';
import { Textarea } from './components/ui/textarea';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from './components/ui/card';
import { Badge } from './components/ui/badge';
import { Separator } from './components/ui/separator';
import { Tabs, TabsContent, TabsList, TabsTrigger } from './components/ui/tabs';
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle, DialogTrigger } from './components/ui/dialog';
import { Label } from './components/ui/label';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from './components/ui/select';
import { toast } from 'sonner';
import { Toaster } from './components/ui/sonner';

// Icons
import { Search, FileText, Upload, User, BarChart3, Brain, Sparkles, FileUp, MessageSquare, TrendingUp, Clock, DollarSign } from 'lucide-react';

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;
const API = `${BACKEND_URL}/api`;

// Auth Context
const AuthContext = React.createContext();

const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [token, setToken] = useState(localStorage.getItem('token'));
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (token) {
      axios.defaults.headers.common['Authorization'] = `Bearer ${token}`;
      // Verify token validity by making a test request
      fetchUsageSummary().catch(() => {
        logout();
      });
    }
    setLoading(false);
  }, [token]);

  const login = async (email, password) => {
    try {
      const response = await axios.post(`${API}/auth/login`, { email, password });
      const { access_token, user: userData } = response.data;
      
      setToken(access_token);
      setUser(userData);
      localStorage.setItem('token', access_token);
      axios.defaults.headers.common['Authorization'] = `Bearer ${access_token}`;
      
      toast.success('Login successful!');
      return true;
    } catch (error) {
      toast.error(error.response?.data?.detail || 'Login failed');
      return false;
    }
  };

  const signup = async (name, email, password) => {
    try {
      const response = await axios.post(`${API}/auth/signup`, { name, email, password });
      const { access_token, user: userData } = response.data;
      
      setToken(access_token);
      setUser(userData);
      localStorage.setItem('token', access_token);
      axios.defaults.headers.common['Authorization'] = `Bearer ${access_token}`;
      
      toast.success('Account created successfully!');
      return true;
    } catch (error) {
      toast.error(error.response?.data?.detail || 'Signup failed');
      return false;
    }
  };

  const logout = () => {
    setToken(null);
    setUser(null);
    localStorage.removeItem('token');
    delete axios.defaults.headers.common['Authorization'];
    toast.success('Logged out successfully');
  };

  const fetchUsageSummary = async () => {
    try {
      const response = await axios.get(`${API}/dashboard/usage`);
      return response.data;
    } catch (error) {
      throw error;
    }
  };

  return (
    <AuthContext.Provider value={{
      user,
      token,
      login,
      signup,
      logout,
      loading,
      fetchUsageSummary
    }}>
      {children}
    </AuthContext.Provider>
  );
};

const useAuth = () => {
  const context = React.useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within AuthProvider');
  }
  return context;
};

// Landing Page Component
const LandingPage = () => {
  const [isLoginMode, setIsLoginMode] = useState(true);
  const [formData, setFormData] = useState({ name: '', email: '', password: '' });
  const [isLoading, setIsLoading] = useState(false);
  const { login, signup } = useAuth();

  const handleSubmit = async (e) => {
    e.preventDefault();
    setIsLoading(true);

    try {
      if (isLoginMode) {
        await login(formData.email, formData.password);
      } else {
        await signup(formData.name, formData.email, formData.password);
      }
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 via-blue-50 to-indigo-100">
      {/* Hero Section */}
      <div className="container mx-auto px-4 py-12">
        <div className="text-center mb-16">
          <div className="flex justify-center mb-6">
            <div className="p-4 bg-gradient-to-r from-blue-600 to-indigo-600 rounded-2xl shadow-lg">
              <Brain className="h-12 w-12 text-white" />
            </div>
          </div>
          <h1 className="text-5xl font-bold text-gray-900 mb-6 bg-gradient-to-r from-blue-600 to-indigo-600 bg-clip-text text-transparent">
            Smart Research Assistant
          </h1>
          <p className="text-xl text-gray-600 mb-8 max-w-3xl mx-auto leading-relaxed">
            Your AI-powered research companion that answers any question, analyzes documents, 
            and generates comprehensive reports with citations. Save hours of research time.
          </p>
          
          {/* Feature Cards */}
          <div className="grid md:grid-cols-3 gap-8 mb-12">
            <Card className="border-0 shadow-lg hover:shadow-xl transition-all duration-300 bg-white/70 backdrop-blur-sm">
              <CardHeader className="text-center">
                <div className="mx-auto mb-4 p-3 bg-gradient-to-r from-green-500 to-emerald-500 rounded-xl w-fit">
                  <MessageSquare className="h-6 w-6 text-white" />
                </div>
                <CardTitle className="text-gray-900">Ask Any Question</CardTitle>
              </CardHeader>
              <CardContent>
                <p className="text-gray-600">
                  Get comprehensive answers to any research question with AI-powered analysis and insights.
                </p>
              </CardContent>
            </Card>

            <Card className="border-0 shadow-lg hover:shadow-xl transition-all duration-300 bg-white/70 backdrop-blur-sm">
              <CardHeader className="text-center">
                <div className="mx-auto mb-4 p-3 bg-gradient-to-r from-purple-500 to-violet-500 rounded-xl w-fit">
                  <FileText className="h-6 w-6 text-white" />
                </div>
                <CardTitle className="text-gray-900">Document Analysis</CardTitle>
              </CardHeader>
              <CardContent>
                <p className="text-gray-600">
                  Upload PDFs, docs, and files for intelligent analysis and information extraction.
                </p>
              </CardContent>
            </Card>

            <Card className="border-0 shadow-lg hover:shadow-xl transition-all duration-300 bg-white/70 backdrop-blur-sm">
              <CardHeader className="text-center">
                <div className="mx-auto mb-4 p-3 bg-gradient-to-r from-orange-500 to-red-500 rounded-xl w-fit">
                  <BarChart3 className="h-6 w-6 text-white" />
                </div>
                <CardTitle className="text-gray-900">Generate Reports</CardTitle>
              </CardHeader>
              <CardContent>
                <p className="text-gray-600">
                  Create structured research reports with citations, analysis, and professional formatting.
                </p>
              </CardContent>
            </Card>
          </div>
        </div>

        {/* Auth Section */}
        <div className="max-w-md mx-auto">
          <Card className="shadow-xl border-0 bg-white/80 backdrop-blur-sm">
            <CardHeader className="text-center">
              <CardTitle className="text-2xl text-gray-900">
                {isLoginMode ? 'Sign In' : 'Create Account'}
              </CardTitle>
              <CardDescription>
                {isLoginMode ? 'Access your research assistant' : 'Start your research journey'}
              </CardDescription>
            </CardHeader>
            <CardContent>
              <form onSubmit={handleSubmit} className="space-y-4">
                {!isLoginMode && (
                  <div>
                    <Label htmlFor="name">Full Name</Label>
                    <Input
                      id="name"
                      type="text"
                      placeholder="Enter your name"
                      value={formData.name}
                      onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                      required={!isLoginMode}
                      className="mt-1"
                    />
                  </div>
                )}
                <div>
                  <Label htmlFor="email">Email</Label>
                  <Input
                    id="email"
                    type="email"
                    placeholder="Enter your email"
                    value={formData.email}
                    onChange={(e) => setFormData({ ...formData, email: e.target.value })}
                    required
                    className="mt-1"
                  />
                </div>
                <div>
                  <Label htmlFor="password">Password</Label>
                  <Input
                    id="password"
                    type="password"
                    placeholder="Enter your password"
                    value={formData.password}
                    onChange={(e) => setFormData({ ...formData, password: e.target.value })}
                    required
                    className="mt-1"
                  />
                </div>
                <Button
                  type="submit"
                  className="w-full bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-700 hover:to-indigo-700"
                  disabled={isLoading}
                >
                  {isLoading ? (
                    <div className="flex items-center gap-2">
                      <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin" />
                      {isLoginMode ? 'Signing In...' : 'Creating Account...'}
                    </div>
                  ) : (
                    isLoginMode ? 'Sign In' : 'Create Account'
                  )}
                </Button>
              </form>
              
              <div className="mt-6 text-center">
                <button
                  type="button"
                  onClick={() => setIsLoginMode(!isLoginMode)}
                  className="text-blue-600 hover:text-blue-700 font-medium"
                >
                  {isLoginMode ? "Don't have an account? Sign up" : 'Already have an account? Sign in'}
                </button>
              </div>
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
};

// Main Dashboard Component
const Dashboard = () => {
  const { user, logout, fetchUsageSummary } = useAuth();
  const [activeTab, setActiveTab] = useState('research');
  const [usageData, setUsageData] = useState(null);
  const [question, setQuestion] = useState('');
  const [answer, setAnswer] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [files, setFiles] = useState([]);
  const [history, setHistory] = useState([]);
  const [reportTitle, setReportTitle] = useState('');
  const [reportQuery, setReportQuery] = useState('');
  const [reportResult, setReportResult] = useState('');

  useEffect(() => {
    loadUsageData();
    loadFiles();
    loadHistory();
  }, []);

  const loadUsageData = async () => {
    try {
      const data = await fetchUsageSummary();
      setUsageData(data);
    } catch (error) {
      toast.error('Failed to load usage data');
    }
  };

  const loadFiles = async () => {
    try {
      const response = await axios.get(`${API}/files/list`);
      setFiles(response.data.files);
    } catch (error) {
      toast.error('Failed to load files');
    }
  };

  const loadHistory = async () => {
    try {
      const response = await axios.get(`${API}/dashboard/history`);
      setHistory(response.data.history);
    } catch (error) {
      toast.error('Failed to load history');
    }
  };

  const handleQuestionSubmit = async (e) => {
    e.preventDefault();
    if (!question.trim()) return;

    setIsLoading(true);
    try {
      const response = await axios.post(`${API}/research/ask`, {
        question: question,
        complexity: 'standard',
        use_files: true
      });
      
      setAnswer(response.data.answer);
      toast.success(`Question processed! Cost: $${response.data.cost}`);
      
      // Refresh data
      loadUsageData();
      loadHistory();
    } catch (error) {
      toast.error(error.response?.data?.detail || 'Failed to process question');
    } finally {
      setIsLoading(false);
    }
  };

  const handleFileUpload = async (e) => {
    const file = e.target.files[0];
    if (!file) return;

    const formData = new FormData();
    formData.append('file', file);

    try {
      await axios.post(`${API}/files/upload`, formData, {
        headers: { 'Content-Type': 'multipart/form-data' }
      });
      
      toast.success('File uploaded successfully!');
      loadFiles();
    } catch (error) {
      toast.error('Failed to upload file');
    }
  };

  const handleReportGeneration = async (e) => {
    e.preventDefault();
    if (!reportTitle.trim() || !reportQuery.trim()) return;

    setIsLoading(true);
    try {
      const response = await axios.post(`${API}/research/report`, {
        title: reportTitle,
        query: reportQuery,
        report_type: 'standard'
      });
      
      setReportResult(response.data.report);
      toast.success(`Report generated! Cost: $${response.data.cost}`);
      
      // Refresh data
      loadUsageData();
      loadHistory();
    } catch (error) {
      toast.error(error.response?.data?.detail || 'Failed to generate report');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 via-blue-50 to-indigo-100">
      {/* Header */}
      <header className="bg-white/80 backdrop-blur-sm border-b border-gray-200 shadow-sm">
        <div className="container mx-auto px-4 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="p-2 bg-gradient-to-r from-blue-600 to-indigo-600 rounded-xl">
                <Brain className="h-6 w-6 text-white" />
              </div>
              <h1 className="text-xl font-bold text-gray-900">Smart Research Assistant</h1>
            </div>
            
            <div className="flex items-center gap-4">
              <Badge variant="secondary" className="px-3 py-1">
                <User className="h-4 w-4 mr-1" />
                {user?.name}
              </Badge>
              <Button variant="outline" onClick={logout} size="sm">
                Logout
              </Button>
            </div>
          </div>
        </div>
      </header>

      <div className="container mx-auto px-4 py-6">
        {/* Usage Stats */}
        {usageData && (
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-8">
            <Card className="bg-white/70 backdrop-blur-sm border-0 shadow-lg">
              <CardContent className="p-4">
                <div className="flex items-center gap-3">
                  <div className="p-2 bg-gradient-to-r from-green-500 to-emerald-500 rounded-lg">
                    <MessageSquare className="h-5 w-5 text-white" />
                  </div>
                  <div>
                    <p className="text-sm text-gray-600">Questions Asked</p>
                    <p className="text-2xl font-bold text-gray-900">{usageData.questions_asked}</p>
                  </div>
                </div>
              </CardContent>
            </Card>

            <Card className="bg-white/70 backdrop-blur-sm border-0 shadow-lg">
              <CardContent className="p-4">
                <div className="flex items-center gap-3">
                  <div className="p-2 bg-gradient-to-r from-purple-500 to-violet-500 rounded-lg">
                    <FileText className="h-5 w-5 text-white" />
                  </div>
                  <div>
                    <p className="text-sm text-gray-600">Reports Generated</p>
                    <p className="text-2xl font-bold text-gray-900">{usageData.reports_generated}</p>
                  </div>
                </div>
              </CardContent>
            </Card>

            <Card className="bg-white/70 backdrop-blur-sm border-0 shadow-lg">
              <CardContent className="p-4">
                <div className="flex items-center gap-3">
                  <div className="p-2 bg-gradient-to-r from-blue-500 to-cyan-500 rounded-lg">
                    <FileUp className="h-5 w-5 text-white" />
                  </div>
                  <div>
                    <p className="text-sm text-gray-600">Files Uploaded</p>
                    <p className="text-2xl font-bold text-gray-900">{usageData.files_uploaded}</p>
                  </div>
                </div>
              </CardContent>
            </Card>

            <Card className="bg-white/70 backdrop-blur-sm border-0 shadow-lg">
              <CardContent className="p-4">
                <div className="flex items-center gap-3">
                  <div className="p-2 bg-gradient-to-r from-orange-500 to-red-500 rounded-lg">
                    <DollarSign className="h-5 w-5 text-white" />
                  </div>
                  <div>
                    <p className="text-sm text-gray-600">Total Cost</p>
                    <p className="text-2xl font-bold text-gray-900">${usageData.total_cost.toFixed(2)}</p>
                  </div>
                </div>
              </CardContent>
            </Card>
          </div>
        )}

        {/* Main Content */}
        <Tabs value={activeTab} onValueChange={setActiveTab} className="space-y-6">
          <TabsList className="grid grid-cols-4 w-fit bg-white/70 backdrop-blur-sm">
            <TabsTrigger value="research" className="flex items-center gap-2">
              <Search className="h-4 w-4" />
              Research
            </TabsTrigger>
            <TabsTrigger value="reports" className="flex items-center gap-2">
              <FileText className="h-4 w-4" />
              Reports
            </TabsTrigger>
            <TabsTrigger value="files" className="flex items-center gap-2">
              <Upload className="h-4 w-4" />
              Files
            </TabsTrigger>
            <TabsTrigger value="history" className="flex items-center gap-2">
              <Clock className="h-4 w-4" />
              History
            </TabsTrigger>
          </TabsList>

          {/* Research Tab */}
          <TabsContent value="research">
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
              <Card className="bg-white/70 backdrop-blur-sm border-0 shadow-lg">
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <Search className="h-5 w-5" />
                    Ask a Question
                  </CardTitle>
                  <CardDescription>
                    Get comprehensive answers to any research question
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <form onSubmit={handleQuestionSubmit} className="space-y-4">
                    <Textarea
                      placeholder="What would you like to research? Ask any question..."
                      value={question}
                      onChange={(e) => setQuestion(e.target.value)}
                      rows={4}
                      className="resize-none"
                    />
                    <Button
                      type="submit"
                      disabled={isLoading || !question.trim()}
                      className="w-full bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-700 hover:to-indigo-700"
                    >
                      {isLoading ? (
                        <div className="flex items-center gap-2">
                          <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin" />
                          Processing...
                        </div>
                      ) : (
                        <>
                          <Sparkles className="h-4 w-4 mr-2" />
                          Ask Question
                        </>
                      )}
                    </Button>
                  </form>
                </CardContent>
              </Card>

              {answer && (
                <Card className="bg-white/70 backdrop-blur-sm border-0 shadow-lg">
                  <CardHeader>
                    <CardTitle className="flex items-center gap-2">
                      <Brain className="h-5 w-5" />
                      Research Answer
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="prose prose-sm max-w-none">
                      <div className="whitespace-pre-wrap text-gray-700 leading-relaxed">
                        {answer}
                      </div>
                    </div>
                  </CardContent>
                </Card>
              )}
            </div>
          </TabsContent>

          {/* Reports Tab */}
          <TabsContent value="reports">
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
              <Card className="bg-white/70 backdrop-blur-sm border-0 shadow-lg">
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <FileText className="h-5 w-5" />
                    Generate Report
                  </CardTitle>
                  <CardDescription>
                    Create comprehensive research reports with citations
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <form onSubmit={handleReportGeneration} className="space-y-4">
                    <div>
                      <Label htmlFor="reportTitle">Report Title</Label>
                      <Input
                        id="reportTitle"
                        placeholder="Enter report title..."
                        value={reportTitle}
                        onChange={(e) => setReportTitle(e.target.value)}
                        className="mt-1"
                      />
                    </div>
                    <div>
                      <Label htmlFor="reportQuery">Research Query</Label>
                      <Textarea
                        id="reportQuery"
                        placeholder="What should this report cover? Describe your research needs..."
                        value={reportQuery}
                        onChange={(e) => setReportQuery(e.target.value)}
                        rows={4}
                        className="resize-none mt-1"
                      />
                    </div>
                    <Button
                      type="submit"
                      disabled={isLoading || !reportTitle.trim() || !reportQuery.trim()}
                      className="w-full bg-gradient-to-r from-purple-600 to-violet-600 hover:from-purple-700 hover:to-violet-700"
                    >
                      {isLoading ? (
                        <div className="flex items-center gap-2">
                          <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin" />
                          Generating...
                        </div>
                      ) : (
                        <>
                          <FileText className="h-4 w-4 mr-2" />
                          Generate Report
                        </>
                      )}
                    </Button>
                  </form>
                </CardContent>
              </Card>

              {reportResult && (
                <Card className="bg-white/70 backdrop-blur-sm border-0 shadow-lg">
                  <CardHeader>
                    <CardTitle className="flex items-center gap-2">
                      <FileText className="h-5 w-5" />
                      Generated Report
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="prose prose-sm max-w-none">
                      <div className="whitespace-pre-wrap text-gray-700 leading-relaxed">
                        {reportResult}
                      </div>
                    </div>
                  </CardContent>
                </Card>
              )}
            </div>
          </TabsContent>

          {/* Files Tab */}
          <TabsContent value="files">
            <Card className="bg-white/70 backdrop-blur-sm border-0 shadow-lg">
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Upload className="h-5 w-5" />
                  Document Library
                </CardTitle>
                <CardDescription>
                  Upload documents for enhanced research capabilities
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-6">
                  <div>
                    <Label htmlFor="file-upload" className="block mb-2">Upload New File</Label>
                    <Input
                      id="file-upload"
                      type="file"
                      onChange={handleFileUpload}
                      accept=".pdf,.txt,.doc,.docx,.csv"
                      className="cursor-pointer"
                    />
                    <p className="text-sm text-gray-600 mt-1">
                      Supported formats: PDF, TXT, DOC, DOCX, CSV
                    </p>
                  </div>

                  <Separator />

                  <div>
                    <h3 className="font-medium mb-4">Uploaded Files ({files.length})</h3>
                    <div className="space-y-2">
                      {files.length > 0 ? (
                        files.map((file) => (
                          <Card key={file.id} className="border border-gray-200">
                            <CardContent className="p-4">
                              <div className="flex items-center justify-between">
                                <div className="flex items-center gap-3">
                                  <FileText className="h-5 w-5 text-gray-500" />
                                  <div>
                                    <p className="font-medium text-gray-900">{file.filename}</p>
                                    <p className="text-sm text-gray-500">
                                      {(file.file_size / 1024).toFixed(1)} KB • {file.file_type}
                                    </p>
                                  </div>
                                </div>
                                <Badge variant="secondary">
                                  {new Date(file.uploaded_at).toLocaleDateString()}
                                </Badge>
                              </div>
                            </CardContent>
                          </Card>
                        ))
                      ) : (
                        <p className="text-gray-500 text-center py-8">
                          No files uploaded yet. Upload documents to enhance your research capabilities.
                        </p>
                      )}
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>
          </TabsContent>

          {/* History Tab */}
          <TabsContent value="history">
            <Card className="bg-white/70 backdrop-blur-sm border-0 shadow-lg">
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Clock className="h-5 w-5" />
                  Research History
                </CardTitle>
                <CardDescription>
                  View your recent questions and reports
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  {history.length > 0 ? (
                    history.map((item) => (
                      <Card key={item.id} className="border border-gray-200">
                        <CardContent className="p-4">
                          <div className="flex items-center justify-between">
                            <div className="flex items-center gap-3">
                              {item.type === 'question' ? (
                                <MessageSquare className="h-5 w-5 text-green-500" />
                              ) : (
                                <FileText className="h-5 w-5 text-purple-500" />
                              )}
                              <div>
                                <p className="font-medium text-gray-900">{item.title}</p>
                                <p className="text-sm text-gray-500">
                                  {new Date(item.created_at).toLocaleString()}
                                </p>
                              </div>
                            </div>
                            <div className="text-right">
                              <Badge variant={item.type === 'question' ? 'default' : 'secondary'}>
                                {item.type === 'question' ? 'Question' : 'Report'}
                              </Badge>
                              <p className="text-sm text-gray-600 mt-1">
                                ${item.cost.toFixed(2)}
                              </p>
                            </div>
                          </div>
                        </CardContent>
                      </Card>
                    ))
                  ) : (
                    <p className="text-gray-500 text-center py-8">
                      No history yet. Start by asking a question or generating a report.
                    </p>
                  )}
                </div>
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>
      </div>
    </div>
  );
};

// Main App Component
function App() {
  return (
    <AuthProvider>
      <BrowserRouter>
        <div className="App">
          <Routes>
            <Route path="/" element={<AppContent />} />
          </Routes>
          <Toaster />
        </div>
      </BrowserRouter>
    </AuthProvider>
  );
}

const AppContent = () => {
  const { token, loading } = useAuth();

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-slate-50 via-blue-50 to-indigo-100">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600 mx-auto mb-4"></div>
          <p className="text-gray-600">Loading...</p>
        </div>
      </div>
    );
  }

  return token ? <Dashboard /> : <LandingPage />;
};

export default App;