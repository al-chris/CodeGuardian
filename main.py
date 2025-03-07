import uvicorn
from fastapi import FastAPI, Depends, HTTPException, status, File, UploadFile, Form, BackgroundTasks
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Union
import os
import shutil
import tempfile
import json

from src.analyzer.code_analyzer import CodeAnalyzer
from src.analyzer.vulnerability_detector import VulnerabilityDetector
from src.ml.vulnerability_classifier import VulnerabilityClassifier
from src.ml.fix_generator import FixGenerator
from src.dashboard.stats_generator import StatsGenerator

app = FastAPI(
    title="CodeGuardian",
    description="ML-powered vulnerability scanner with intelligent remediation",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

class ScanRequest(BaseModel):
    repository_url: str
    branch: Optional[str] = "main"
    depth: Optional[int] = 3
    scan_type: Optional[str] = "full"  # Options: full, quick, deep

class ScanResult(BaseModel):
    scan_id: str
    timestamp: str
    vulnerabilities: List[Dict]
    stats: Dict
    risk_score: float
    
class User(BaseModel):
    username: str
    email: Optional[str] = None
    full_name: Optional[str] = None
    disabled: Optional[bool] = None

# In-memory storage for demo purposes
scan_results = {}
active_scans = {}
users_db = {}

@app.post("/token")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    # This is simplified for the example
    # In a real app, you would validate against a proper database
    user = users_db.get(form_data.username)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Create access token
    access_token_expires = timedelta(minutes=30)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

def create_access_token(data: dict, expires_delta: timedelta):
    # This is a simplified token generator
    # In production, use a proper JWT implementation
    import uuid
    import base64
    import json
    
    token_data = data.copy()
    token_data.update({"exp": datetime.utcnow() + expires_delta})
    token_data.update({"jti": str(uuid.uuid4())})
    encoded = base64.b64encode(json.dumps(token_data).encode())
    return encoded.decode()

def get_current_user(token: str = Depends(oauth2_scheme)):
    # This would validate the token and return the user
    # Simplified for demo
    return User(username="demo_user")

@app.post("/scan", response_model=dict)
async def start_scan(
    request: ScanRequest,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_user)
):
    """Start a new code scan based on repository URL"""
    import uuid
    scan_id = str(uuid.uuid4())
    
    # Store scan details
    active_scans[scan_id] = {
        "status": "in_progress",
        "repository_url": request.repository_url,
        "started_at": datetime.now().isoformat(),
        "requested_by": current_user.username,
    }
    
    # Execute scan in background
    background_tasks.add_task(
        execute_scan,
        scan_id,
        request.repository_url,
        request.branch,
        request.depth,
        request.scan_type
    )
    
    return {
        "scan_id": scan_id,
        "status": "scan_started",
        "message": "Scan initiated successfully"
    }

async def execute_scan(scan_id: str, repo_url: str, branch: str, depth: int, scan_type: str):
    """Execute the actual code scanning process"""
    try:
        # Create temporary directory
        temp_dir = tempfile.mkdtemp()
        
        # Clone repository
        import git
        git.Repo.clone_from(repo_url, temp_dir, branch=branch, depth=depth)
        
        # Initialize components
        code_analyzer = CodeAnalyzer()
        vuln_detector = VulnerabilityDetector()
        vuln_classifier = VulnerabilityClassifier()
        fix_generator = FixGenerator()
        stats_generator = StatsGenerator()
        
        # Analyze code
        file_list = code_analyzer.find_files(temp_dir)
        vulnerabilities = []
        
        for file_path in file_list:
            if code_analyzer.is_supported_file(file_path):
                file_vulns = vuln_detector.scan_file(file_path)
                if file_vulns:
                    # Classify and enhance vulnerability data
                    for vuln in file_vulns:
                        classification = vuln_classifier.classify(vuln)
                        suggested_fix = fix_generator.generate_fix(vuln)
                        
                        enhanced_vuln = {
                            **vuln,
                            "classification": classification,
                            "suggested_fix": suggested_fix
                        }
                        vulnerabilities.append(enhanced_vuln)
        
        # Generate statistics
        stats = stats_generator.generate(vulnerabilities)
        risk_score = stats_generator.calculate_risk_score(vulnerabilities)
        
        # Store results
        scan_results[scan_id] = {
            "scan_id": scan_id,
            "timestamp": datetime.now().isoformat(),
            "vulnerabilities": vulnerabilities,
            "stats": stats,
            "risk_score": risk_score,
        }
        
        # Update scan status
        active_scans[scan_id]["status"] = "completed"
        active_scans[scan_id]["completed_at"] = datetime.now().isoformat()
        
    except Exception as e:
        active_scans[scan_id]["status"] = "failed"
        active_scans[scan_id]["error"] = str(e)
    finally:
        # Clean up
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)

@app.get("/scan/{scan_id}")
async def get_scan_status(scan_id: str, current_user: User = Depends(get_current_user)):
    """Get the status and results of a scan"""
    if scan_id not in active_scans:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found"
        )
    
    scan_status = active_scans[scan_id]
    
    if scan_status["status"] == "completed" and scan_id in scan_results:
        return {
            "status": scan_status["status"],
            "results": scan_results[scan_id]
        }
    else:
        return {
            "status": scan_status["status"],
            "message": "Scan is still in progress or failed"
        }

@app.get("/scans")
async def list_scans(current_user: User = Depends(get_current_user)):
    """List all scans for the current user"""
    user_scans = {
        scan_id: scan_info
        for scan_id, scan_info in active_scans.items()
        if scan_info["requested_by"] == current_user.username
    }
    return user_scans

@app.get("/dashboard/stats")
async def get_dashboard_stats(current_user: User = Depends(get_current_user)):
    """Get aggregated statistics for the dashboard"""
    stats_generator = StatsGenerator()
    
    # Get completed scans for the user
    user_scan_ids = [
        scan_id for scan_id, info in active_scans.items()
        if info["status"] == "completed" and info["requested_by"] == current_user.username
    ]
    
    # Collect vulnerabilities from all completed scans
    all_vulnerabilities = []
    for scan_id in user_scan_ids:
        if scan_id in scan_results:
            all_vulnerabilities.extend(scan_results[scan_id]["vulnerabilities"])
    
    # Generate aggregated statistics
    stats = stats_generator.generate(all_vulnerabilities)
    trend_data = stats_generator.generate_trend_data(user_scan_ids, scan_results)
    
    return {
        "overall_stats": stats,
        "trends": trend_data,
        "scan_count": len(user_scan_ids),
    }

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)