# database/db_session.py
import sqlalchemy as sa
from sqlalchemy.orm import sessionmaker
from .models import Base
import os
import sys

def get_database_path():
    """
    Intelligently finds the database file. 
    - If running as .exe (frozen), looks in the same folder as the .exe
    - If running in VS Code, looks in the project root
    """
    if getattr(sys, 'frozen', False):
        # We are running as an executable
        base_path = os.path.dirname(sys.executable)
    else:
        # We are running in a normal Python environment
        base_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
        
    return os.path.join(base_path, 'cyberguard.sqlite')

# Set the dynamic path
DATABASE_FILE = get_database_path()
DB_URL = f'sqlite:///{DATABASE_FILE}'

__engine = None

def global_init():
    global __engine
    if __engine: return
    
    # Create engine
    __engine = sa.create_engine(DB_URL, echo=False)
    Base.metadata.create_all(__engine)

def create_session():
    if not __engine: raise Exception("DB not initialized")
    Session = sessionmaker(bind=__engine)
    return Session()