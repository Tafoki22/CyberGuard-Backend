# database/models.py
import datetime
from sqlalchemy import Column, Integer, String, DateTime, Boolean
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()

class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True)
    password_hash = Column(String)
    org_name = Column(String)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

class ScanResult(Base):
    __tablename__ = 'scan_results'
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)
    target_ip = Column(String, index=True)
    port_id = Column(Integer)
    protocol = Column(String)
    service_name = Column(String)
    version = Column(String)
    state = Column(String)
    risk_level = Column(String)
    is_common_router = Column(Boolean, default=False)
    
class BreachAlert(Base):
    __tablename__ = 'breach_alerts'
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)
    email_hash = Column(String, index=True)
    breach_name = Column(String)
    pwned_date = Column(DateTime)
    data_classes = Column(String)
    is_acknowledged = Column(Boolean, default=False)