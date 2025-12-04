# app/main.py
from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from pydantic import BaseModel
from datetime import datetime
import secrets

from app.db.database import engine, get_db, Base
from app.models import models

# Auto-create tables (including the new 'devices' table)
models.Base.metadata.create_all(bind=engine)

app = FastAPI(title="CyberGuard Cloud API", version="2.5.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Pydantic Models ---
class OrgAuth(BaseModel):
    name: str
    api_key: str

class DeviceRegister(BaseModel):
    org_name: str
    api_key: str
    device_name: str
    hw_id: str # Hardware ID (MAC address or similar)

class ScanCreate(BaseModel):
    device_hw_id: str # NEW: We track by Hardware ID now
    ip_address: str
    threat_level: str
    details: str

# --- ENDPOINTS ---

@app.get("/")
def root():
    return {"system": "CyberGuard Zero-Trust Cloud", "status": "ACTIVE"}

# 1. ORGANIZATION ACTIVATION (Client Side Step 1)
@app.post("/api/v1/activate")
def activate_license(auth: OrgAuth, db: Session = Depends(get_db)):
    """
    Checks if Org Name + API Key match.
    """
    org = db.query(models.Organization).filter(
        models.Organization.name == auth.name,
        models.Organization.api_key == auth.api_key
    ).first()
    
    if not org:
        raise HTTPException(status_code=401, detail="Invalid License Credentials")
    
    return {"status": "valid", "message": f"License Verified for {org.name}"}

# 2. DEVICE REGISTRATION (Client Side Step 2)
@app.post("/api/v1/register/device")
def register_device(data: DeviceRegister, db: Session = Depends(get_db)):
    """
    Registers a new computer. Triggers an 'Alert' (Log).
    """
    # Verify Org
    org = db.query(models.Organization).filter(models.Organization.api_key == data.api_key).first()
    if not org:
        raise HTTPException(status_code=401, detail="Invalid API Key")
        
    # Check if device exists
    device = db.query(models.Device).filter(models.Device.hw_id == data.hw_id).first()
    
    if device:
        if device.is_blocked:
            raise HTTPException(status_code=403, detail="ACCESS DENIED: This device is blocked by Administrator.")
        return {"status": "exists", "message": "Device already registered"}

    # Register New Device
    new_device = models.Device(
        organization_id=org.id,
        device_name=data.device_name,
        hw_id=data.hw_id,
        status="Active"
    )
    db.add(new_device)
    db.commit()
    
    # 🚨 SIMULATED ALERT TO ADMIN 🚨
    print(f"⚠️ SECURITY ALERT: New Device '{data.device_name}' attempted access for {org.name}.")
    
    return {"status": "registered", "message": "Device Authorization Pending"}

# 3. SYNC SCAN (With Block Check)
@app.post("/api/v1/sync/scan")
def upload_scan(scan: ScanCreate, api_key: str, db: Session = Depends(get_db)):
    # 1. Verify Org
    org = db.query(models.Organization).filter(models.Organization.api_key == api_key).first()
    if not org:
        raise HTTPException(status_code=401, detail="Invalid API Key")

    # 2. Verify Device Block Status
    device = db.query(models.Device).filter(models.Device.hw_id == scan.device_hw_id).first()
    if device and device.is_blocked:
        print(f"🚫 BLOCKED ATTEMPT from {device.device_name}")
        raise HTTPException(status_code=403, detail="DEVICE BLOCKED")

    # 3. Save Scan
    db_scan = models.ScanReport(
        organization_id=org.id,
        device_name=device.device_name if device else "Unknown",
        ip_address=scan.ip_address,
        threat_level=scan.threat_level,
        details=scan.details
    )
    db.add(db_scan)
    db.commit()
    return {"status": "synced"}

# --- ADMIN DASHBOARD ---
@app.get("/api/v1/admin/devices/{api_key}")
def get_devices(api_key: str, db: Session = Depends(get_db)):
    org = db.query(models.Organization).filter(models.Organization.api_key == api_key).first()
    if not org: raise HTTPException(status_code=401)
    return org.devices

# NEW: Block a Device
@app.post("/api/v1/admin/block/{hw_id}")
def block_device(hw_id: str, api_key: str, db: Session = Depends(get_db)):
    org = db.query(models.Organization).filter(models.Organization.api_key == api_key).first()
    if not org: raise HTTPException(status_code=401)
    
    device = db.query(models.Device).filter(models.Device.hw_id == hw_id, models.Device.organization_id == org.id).first()
    if device:
        device.is_blocked = True
        device.status = "Blocked"
        db.commit()
        return {"status": "blocked", "device": device.device_name}
    raise HTTPException(status_code=404, detail="Device not found")