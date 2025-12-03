# app/db/database.py
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

# ⚠️ REPLACE 'admin123' WITH THE PASSWORD YOU SET DURING INSTALLATION
# Format: postgresql://user:password@localhost/dbname
SQLALCHEMY_DATABASE_URL = "postgresql://postgres:admin123@localhost/cyberguard_cloud"

# Create the connection engine
engine = create_engine(SQLALCHEMY_DATABASE_URL)

# Create a SessionLocal class (each request gets its own database session)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Base class for our database models
Base = declarative_base()

# Dependency: This gives the API a database session when needed
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()