from fastapi import FastAPI, APIRouter, Depends, HTTPException, UploadFile, File, Form
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
import uuid
from datetime import datetime, timedelta
import bcrypt
import jwt
import asyncio
import json
import aiofiles
from emergentintegrations.llm.chat import LlmChat, UserMessage, FileContentWithMimeType

# Load environment variables
ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# MongoDB connection
mongo_url = os.environ.get('MONGO_URL', 'mongodb://localhost:27017')
db_name = os.environ.get('DB_NAME', 'research_assistant_db')
client = AsyncIOMotorClient(mongo_url)
db = client[db_name]

# LLM Configuration
EMERGENT_LLM_KEY = os.environ.get('EMERGENT_LLM_KEY')

# Create the main app
app = FastAPI(title="Smart Research Assistant", version="1.0.0")
api_router = APIRouter(prefix="/api")
security = HTTPBearer()

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Models
class User(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    email: str
    name: str
    hashed_password: str
    created_at: datetime = Field(default_factory=datetime.utcnow)
    is_active: bool = True

class UserCreate(BaseModel):
    email: str
    name: str
    password: str

class UserLogin(BaseModel):
    email: str
    password: str

class QuestionRequest(BaseModel):
    question: str
    complexity: Optional[str] = "standard"
    use_files: Optional[bool] = True

class ResearchQuery(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    user_id: str
    question: str
    complexity: str
    answer: str
    sources_used: List[str] = []
    cost: float = 0.0
    created_at: datetime = Field(default_factory=datetime.utcnow)

class ReportRequest(BaseModel):
    title: str
    query: str
    report_type: Optional[str] = "standard"
    include_citations: Optional[bool] = True

class ResearchReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    user_id: str
    title: str
    content: str
    sources: List[Dict[str, Any]] = []
    report_type: str
    cost: float = 0.0  
    created_at: datetime = Field(default_factory=datetime.utcnow)

class UserFile(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    user_id: str
    filename: str
    file_path: str
    file_type: str
    file_size: int
    uploaded_at: datetime = Field(default_factory=datetime.utcnow)

class UsageSummary(BaseModel):
    questions_asked: int = 0
    reports_generated: int = 0
    total_cost: float = 0.0
    files_uploaded: int = 0

# Auth functions
def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(hours=24)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, "your-secret-key", algorithm="HS256")

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        payload = jwt.decode(credentials.credentials, "your-secret-key", algorithms=["HS256"])
        user_id = payload.get("sub")
        if user_id is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        
        user = await db.users.find_one({"id": user_id})
        if user is None:
            raise HTTPException(status_code=401, detail="User not found")
        
        return User(**user)
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

# Research Assistant Service
class ResearchAssistantService:
    def __init__(self):
        self.llm_chat = None
        self.pricing = {
            "question": {"simple": 0.05, "standard": 0.10, "complex": 0.20, "expert": 0.50},
            "report": {"basic": 1.00, "standard": 2.50, "premium": 5.00, "enterprise": 10.00}
        }
    
    async def initialize_llm(self, session_id: str):
        """Initialize LLM chat with session"""
        if not EMERGENT_LLM_KEY:
            raise HTTPException(status_code=500, detail="LLM API key not configured")
        
        self.llm_chat = LlmChat(
            api_key=EMERGENT_LLM_KEY,
            session_id=session_id,
            system_message="You are a smart research assistant. Provide comprehensive, well-researched answers with citations when possible. Be thorough and accurate."
        ).with_model("openai", "gpt-4o")
        
        return self.llm_chat
    
    async def answer_question(self, user_id: str, question: str, complexity: str = "standard", 
                            file_paths: List[str] = None) -> Dict[str, Any]:
        """Answer a research question with optional file context"""
        try:
            # Initialize LLM chat
            session_id = f"user_{user_id}_{int(datetime.utcnow().timestamp())}"
            chat = await self.initialize_llm(session_id)
            
            # Prepare message with files if provided
            file_contents = []
            if file_paths:
                for file_path in file_paths:
                    if os.path.exists(file_path):
                        # Determine mime type based on extension
                        if file_path.endswith('.pdf'):
                            mime_type = "application/pdf"
                        elif file_path.endswith('.txt'):
                            mime_type = "text/plain"
                        elif file_path.endswith('.csv'):
                            mime_type = "text/csv"
                        else:
                            mime_type = "text/plain"
                        
                        file_content = FileContentWithMimeType(
                            file_path=file_path,
                            mime_type=mime_type
                        )
                        file_contents.append(file_content)
            
            # Create enhanced prompt for research
            enhanced_question = f"""
            Research Question: {question}
            
            Please provide a comprehensive answer that includes:
            1. A clear, detailed response to the question
            2. Key insights and analysis
            3. Relevant context and background information
            4. If using uploaded files, reference specific information from them
            5. Suggest related topics or follow-up questions
            
            Format your response with clear sections and cite sources when applicable.
            """
            
            # Send message to LLM
            if file_contents and len(file_contents) > 0:
                # Use Gemini for file processing
                chat = chat.with_model("gemini", "gemini-2.0-flash")
                user_message = UserMessage(
                    text=enhanced_question,
                    file_contents=file_contents
                )
            else:
                user_message = UserMessage(text=enhanced_question)
            
            response = await chat.send_message(user_message)
            
            # Calculate cost
            cost = self.pricing["question"].get(complexity, 0.10)
            
            # Store query in database
            query_record = ResearchQuery(
                user_id=user_id,
                question=question,
                complexity=complexity,
                answer=response,
                sources_used=file_paths or [],
                cost=cost
            )
            
            await db.queries.insert_one(query_record.dict())
            
            return {
                "answer": response,
                "cost": cost,
                "sources_used": file_paths or [],
                "query_id": query_record.id
            }
            
        except Exception as e:
            logger.error(f"Error answering question: {str(e)}")
            raise HTTPException(status_code=500, detail=f"Failed to process question: {str(e)}")
    
    async def generate_report(self, user_id: str, title: str, query: str, 
                           report_type: str = "standard", file_paths: List[str] = None) -> Dict[str, Any]:
        """Generate a comprehensive research report"""
        try:
            # Initialize LLM chat
            session_id = f"report_{user_id}_{int(datetime.utcnow().timestamp())}"
            chat = await self.initialize_llm(session_id)
            
            # Prepare files if provided
            file_contents = []
            if file_paths:
                for file_path in file_paths:
                    if os.path.exists(file_path):
                        if file_path.endswith('.pdf'):
                            mime_type = "application/pdf"
                        elif file_path.endswith('.txt'):
                            mime_type = "text/plain"
                        elif file_path.endswith('.csv'):
                            mime_type = "text/csv"
                        else:
                            mime_type = "text/plain"
                        
                        file_content = FileContentWithMimeType(
                            file_path=file_path,
                            mime_type=mime_type
                        )
                        file_contents.append(file_content)
            
            # Create comprehensive report prompt
            report_prompt = f"""
            Generate a comprehensive research report with the following specifications:
            
            Title: {title}
            Research Query: {query}
            Report Type: {report_type}
            
            Please structure the report as follows:
            
            # {title}
            
            ## Executive Summary
            [Provide a concise overview of key findings]
            
            ## Introduction
            [Context and background information]
            
            ## Methodology
            [Explain research approach and sources used]
            
            ## Key Findings
            [Detailed analysis and insights]
            
            ## Discussion
            [Interpretation of findings and implications]
            
            ## Conclusions
            [Summary of main conclusions and recommendations]
            
            ## Sources and Citations
            [List all sources and references used]
            
            ## Appendices
            [Additional supporting information if relevant]
            
            Make the report comprehensive, well-structured, and professional. Include specific data, statistics, and examples where relevant. If using uploaded files, extract and reference specific information from them.
            """
            
            # Send message to LLM
            if file_contents and len(file_contents) > 0:
                # Use Gemini for file processing
                chat = chat.with_model("gemini", "gemini-2.0-flash")
                user_message = UserMessage(
                    text=report_prompt,
                    file_contents=file_contents
                )
            else:
                user_message = UserMessage(text=report_prompt)
            
            response = await chat.send_message(user_message)
            
            # Calculate cost
            cost = self.pricing["report"].get(report_type, 2.50)
            
            # Store report in database
            report_record = ResearchReport(
                user_id=user_id,
                title=title,
                content=response,
                sources=[{"type": "file", "path": fp} for fp in (file_paths or [])],
                report_type=report_type,
                cost=cost
            )
            
            await db.reports.insert_one(report_record.dict())
            
            return {
                "report": response,
                "cost": cost,
                "sources": file_paths or [],
                "report_id": report_record.id
            }
            
        except Exception as e:
            logger.error(f"Error generating report: {str(e)}")
            raise HTTPException(status_code=500, detail=f"Failed to generate report: {str(e)}")

# Initialize service
research_service = ResearchAssistantService()

# Auth endpoints
@api_router.post("/auth/signup")
async def signup(user_data: UserCreate):
    try:
        # Check if user exists
        existing_user = await db.users.find_one({"email": user_data.email})
        if existing_user:
            raise HTTPException(status_code=400, detail="Email already registered")
        
        # Create user
        hashed_password = hash_password(user_data.password)
        user = User(
            email=user_data.email,
            name=user_data.name,
            hashed_password=hashed_password
        )
        
        await db.users.insert_one(user.dict())
        
        # Create access token
        access_token = create_access_token(data={"sub": user.id})
        
        return {
            "access_token": access_token,
            "token_type": "bearer",
            "user": {"id": user.id, "email": user.email, "name": user.name}
        }
    except Exception as e:
        logger.error(f"Signup error: {str(e)}")
        raise HTTPException(status_code=500, detail="Signup failed")

@api_router.post("/auth/login")
async def login(user_data: UserLogin):
    try:
        # Find user
        user = await db.users.find_one({"email": user_data.email})
        if not user or not verify_password(user_data.password, user["hashed_password"]):
            raise HTTPException(status_code=401, detail="Invalid credentials")
        
        # Create access token
        access_token = create_access_token(data={"sub": user["id"]})
        
        return {
            "access_token": access_token,
            "token_type": "bearer",
            "user": {"id": user["id"], "email": user["email"], "name": user["name"]}
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Login error: {str(e)}")
        raise HTTPException(status_code=500, detail="Login failed")

# File upload endpoint
@api_router.post("/files/upload")
async def upload_file(
    file: UploadFile = File(...),
    current_user: User = Depends(get_current_user)
):
    try:
        # Create uploads directory if it doesn't exist
        upload_dir = Path("/app/uploads")
        upload_dir.mkdir(exist_ok=True)
        
        # Generate unique filename
        file_extension = Path(file.filename).suffix
        unique_filename = f"{uuid.uuid4()}{file_extension}"
        file_path = upload_dir / unique_filename
        
        # Save file
        async with aiofiles.open(file_path, 'wb') as f:
            content = await file.read()
            await f.write(content)
        
        # Store file record
        file_record = UserFile(
            user_id=current_user.id,
            filename=file.filename,
            file_path=str(file_path),
            file_type=file.content_type or "application/octet-stream",
            file_size=len(content)
        )
        
        await db.files.insert_one(file_record.dict())
        
        return {
            "file_id": file_record.id,
            "filename": file.filename,
            "file_size": len(content),
            "message": "File uploaded successfully"
        }
        
    except Exception as e:
        logger.error(f"File upload error: {str(e)}")
        raise HTTPException(status_code=500, detail="File upload failed")

# Research endpoints
@api_router.post("/research/ask")
async def ask_question(
    request: QuestionRequest,
    current_user: User = Depends(get_current_user)
):
    try:
        # Get user's files if requested
        file_paths = []
        if request.use_files:
            user_files = await db.files.find({"user_id": current_user.id}).to_list(length=10)
            file_paths = [f["file_path"] for f in user_files if os.path.exists(f["file_path"])]
        
        result = await research_service.answer_question(
            user_id=current_user.id,
            question=request.question,
            complexity=request.complexity,
            file_paths=file_paths
        )
        
        return result
        
    except Exception as e:
        logger.error(f"Question processing error: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@api_router.post("/research/report")
async def generate_report(
    request: ReportRequest,
    current_user: User = Depends(get_current_user)
):
    try:
        # Get user's files
        user_files = await db.files.find({"user_id": current_user.id}).to_list(length=10)
        file_paths = [f["file_path"] for f in user_files if os.path.exists(f["file_path"])]
        
        result = await research_service.generate_report(
            user_id=current_user.id,
            title=request.title,
            query=request.query,
            report_type=request.report_type,
            file_paths=file_paths
        )
        
        return result
        
    except Exception as e:
        logger.error(f"Report generation error: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

# Dashboard endpoints
@api_router.get("/dashboard/usage")
async def get_usage_summary(current_user: User = Depends(get_current_user)):
    try:
        # Get usage statistics
        queries_count = await db.queries.count_documents({"user_id": current_user.id})
        reports_count = await db.reports.count_documents({"user_id": current_user.id})
        files_count = await db.files.count_documents({"user_id": current_user.id})
        
        # Calculate total cost
        queries = await db.queries.find({"user_id": current_user.id}).to_list(length=1000)
        reports = await db.reports.find({"user_id": current_user.id}).to_list(length=1000)
        
        total_cost = sum(q.get("cost", 0) for q in queries) + sum(r.get("cost", 0) for r in reports)
        
        return UsageSummary(
            questions_asked=queries_count,
            reports_generated=reports_count,
            total_cost=total_cost,
            files_uploaded=files_count
        )
        
    except Exception as e:
        logger.error(f"Usage summary error: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to get usage summary")

@api_router.get("/dashboard/history")
async def get_history(
    limit: int = 20,
    current_user: User = Depends(get_current_user)
):
    try:
        # Get recent queries and reports
        queries = await db.queries.find({"user_id": current_user.id})\
                                 .sort("created_at", -1)\
                                 .limit(limit//2)\
                                 .to_list(length=limit//2)
        
        reports = await db.reports.find({"user_id": current_user.id})\
                                 .sort("created_at", -1)\
                                 .limit(limit//2)\
                                 .to_list(length=limit//2)
        
        # Combine and sort by date
        all_items = []
        for q in queries:
            all_items.append({
                "id": q["id"],
                "type": "question",
                "title": q["question"][:100] + "..." if len(q["question"]) > 100 else q["question"],
                "cost": q.get("cost", 0),
                "created_at": q["created_at"]
            })
        
        for r in reports:
            all_items.append({
                "id": r["id"],
                "type": "report", 
                "title": r["title"],
                "cost": r.get("cost", 0),
                "created_at": r["created_at"]
            })
        
        # Sort by creation date
        all_items.sort(key=lambda x: x["created_at"], reverse=True)
        
        return {"history": all_items[:limit]}
        
    except Exception as e:
        logger.error(f"History retrieval error: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to get history")

@api_router.get("/files/list")
async def list_files(current_user: User = Depends(get_current_user)):
    try:
        files = await db.files.find({"user_id": current_user.id})\
                             .sort("uploaded_at", -1)\
                             .to_list(length=50)
        
        return {
            "files": [
                {
                    "id": f["id"],
                    "filename": f["filename"],
                    "file_type": f["file_type"],
                    "file_size": f["file_size"],
                    "uploaded_at": f["uploaded_at"]
                }
                for f in files
            ]
        }
    except Exception as e:
        logger.error(f"File list error: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to list files")

# Include router
app.include_router(api_router)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get('CORS_ORIGINS', '*').split(','),
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)