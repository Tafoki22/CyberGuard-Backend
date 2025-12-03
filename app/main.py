# app/main.py
from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session
from pydantic import BaseModel
from datetime import datetime

from app.db.database import engine, get_db, Base
from app.models import models

# 1. Create Tables
models.Base.metadata.create_all(bind=engine)

app = FastAPI(title="CyberGuard Cloud API", version="2.2.0")

# 2. ENABLE CORS (Allows Browser to fetch data)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allows all origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 3. MOUNT STATIC FILES (For the Web Dashboard HTML)
# Ensure you have a folder named 'static' with 'dashboard.html' inside it
app.mount("/static", StaticFiles(directory="static"), name="static")

# --- MODELS ---
class ScanCreate(BaseModel):
    device_name: str
    ip_address: str
    threat_level: str
    details: str

class OrgCreate(BaseModel):
    name: str
    cac_number: str

# --- ENDPOINTS ---

@app.get("/")
def root():
    return {"system": "CyberGuard Cloud", "status": "ONLINE"}

@app.get("/dashboard")
async def serve_dashboard():
    return FileResponse('static/dashboard.html')

@app.post("/api/v1/register/org")
def register_organization(org: OrgCreate, db: Session = Depends(get_db)):
    import secrets
    # Check if exists
    existing = db.query(models.Organization).filter(models.Organization.cac_number == org.cac_number).first()
    if existing:
        # If it exists, just return the existing key so you can use it
        return {
            "status": "exists", 
            "api_key": existing.api_key, 
            "org_id": existing.id, 
            "message": "Organization already registered"
        }
    
    new_key = f"sk_live_{secrets.token_hex(16)}"
    db_org = models.Organization(name=org.name, cac_number=org.cac_number, api_key=new_key)
    db.add(db_org)
    db.commit()
    db.refresh(db_org)
    return {"status": "success", "api_key": new_key, "org_id": db_org.id}

@app.post("/api/v1/sync/scan")
def upload_scan(scan: ScanCreate, api_key: str, db: Session = Depends(get_db)):
    # Authenticate
    org = db.query(models.Organization).filter(models.Organization.api_key == api_key).first()
    if not org:
        raise HTTPException(status_code=401, detail="Invalid API Key")
        
    # Save Scan
    db_scan = models.ScanReport(
        organization_id=org.id,
        device_name=scan.device_name,
        ip_address=scan.ip_address,
        threat_level=scan.threat_level,
        details=scan.details
    )
    db.add(db_scan)
    db.commit()
    return {"status": "synced"}

@app.get("/api/v1/dashboard/{api_key}")
def get_dashboard_stats(api_key: str, db: Session = Depends(get_db)):
    # Authenticate
    org = db.query(models.Organization).filter(models.Organization.api_key == api_key).first()
    if not org:
        raise HTTPException(status_code=401, detail="Invalid API Key")

    # Get Scans
    scans = db.query(models.ScanReport).filter(models.ScanReport.organization_id == org.id).all()
    
    # --- CALCULATE STATS ---
    # This was the missing definition in the previous snippet
    critical_threats = sum(1 for s in scans if "CRITICAL" in s.threat_level)
    
    # Format Recent Activity for the Table
    activity = []
    for s in scans[-10:]: # Show last 10
        activity.append({
            "timestamp": s.timestamp.isoformat(),
            "device": s.device_name,
            "ip": s.ip_address,
            "threat": s.threat_level
        })
    
    # If no scans yet, send dummy data so the dashboard doesn't look empty
    if not activity:
        activity = [{"timestamp": datetime.now().isoformat(), "device": "System", "ip": "127.0.0.1", "threat": "System Ready - Waiting for Scans"}]

    return {
        "total_devices": len(scans) if len(scans) > 0 else 1,
        "active_threats": critical_threats,
        "compliance_score": 100 - (critical_threats * 5),
        "recent_activity": activity
    }