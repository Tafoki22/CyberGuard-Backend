# app/models/models.py
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Boolean
from sqlalchemy.orm import relationship
from datetime import datetime
from app.db.database import Base

class Organization(Base):
    __tablename__ = "organizations"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, index=True)
    cac_number = Column(String, unique=True) # RC123456
    api_key = Column(String, unique=True) # The secret key for the Desktop App
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationship: One Org has many Scan Reports
    scans = relationship("ScanReport", back_populates="organization")

class ScanReport(Base):
    __tablename__ = "scan_reports"
    
    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id"))
    
    device_name = Column(String)
    ip_address = Column(String)
    threat_level = Column(String) # Low, High, Critical
    details = Column(String)
    timestamp = Column(DateTime, default=datetime.utcnow)

    # Relationship
    organization = relationship("Organization", back_populates="scans")