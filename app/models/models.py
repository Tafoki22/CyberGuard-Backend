# app/models/models.py
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Boolean
from sqlalchemy.orm import relationship
from datetime import datetime
from app.db.database import Base

class Organization(Base):
    __tablename__ = "organizations"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, index=True)
    cac_number = Column(String, unique=True)
    api_key = Column(String, unique=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    scans = relationship("ScanReport", back_populates="organization")
    devices = relationship("Device", back_populates="organization")

class Device(Base):
    """
    Tracks individual computers installed with the software.
    Allows the Admin to BLOCK a specific laptop.
    """
    __tablename__ = "devices"
    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id"))
    
    device_name = Column(String) # e.g. "HR-LAPTOP-01"
    hw_id = Column(String, index=True) # Unique Hardware ID
    status = Column(String, default="Active") # Active, Blocked, Pending
    is_blocked = Column(Boolean, default=False) # The Kill Switch
    last_seen = Column(DateTime, default=datetime.utcnow)
    
    organization = relationship("Organization", back_populates="devices")

class ScanReport(Base):
    __tablename__ = "scan_reports"
    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id"))
    
    device_name = Column(String)
    ip_address = Column(String)
    threat_level = Column(String)
    details = Column(String)
    timestamp = Column(DateTime, default=datetime.utcnow)

    organization = relationship("Organization", back_populates="scans")