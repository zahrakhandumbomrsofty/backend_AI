#!/usr/bin/env python3
"""
Test script to verify the Cloud SQL connector setup.
This script tests the database connection without starting the full Flask app.
"""

import os
from dotenv import load_dotenv
from database import getconn, db
import sqlalchemy

# Load environment variables
load_dotenv()

def test_connection():
    """Test the Cloud SQL connection setup."""
    print("Testing Cloud SQL connection...")
    
    # Check required environment variables
    required_vars = ['DB_USER', 'DB_PASS', 'DB_NAME', 'INSTANCE_CONNECTION_NAME']
    missing_vars = []
    
    for var in required_vars:
        if not os.getenv(var):
            missing_vars.append(var)
    
    if missing_vars:
        print(f"❌ Missing environment variables: {', '.join(missing_vars)}")
        print("Please set these environment variables:")
        print("- DB_USER: Database username")
        print("- DB_PASS: Database password") 
        print("- DB_NAME: Database name")
        print("- INSTANCE_CONNECTION_NAME: Project:Region:Instance (e.g., 'my-project:us-central1:my-instance')")
        return False
    
    print("✅ All required environment variables found")
    
    try:
        # Test direct connection
        print("Testing direct connection with getconn()...")
        conn = getconn()
        cursor = conn.cursor()
        cursor.execute("SELECT version();")
        version = cursor.fetchone()
        print(f"✅ Direct connection successful! PostgreSQL version: {version[0]}")
        cursor.close()
        conn.close()
        
        # Test SQLAlchemy engine
        print("Testing SQLAlchemy engine...")
        engine = sqlalchemy.create_engine(
            "postgresql+pg8000://",
            creator=getconn,
        )
        
        with engine.connect() as connection:
            result = connection.execute(sqlalchemy.text("SELECT current_database();"))
            db_name = result.fetchone()[0]
            print(f"✅ SQLAlchemy connection successful! Connected to database: {db_name}")
        
        print("🎉 All connection tests passed!")
        return True
        
    except Exception as e:
        print(f"❌ Connection test failed: {str(e)}")
        print("Please check your environment variables and Cloud SQL instance status.")
        return False

if __name__ == "__main__":
    test_connection()
