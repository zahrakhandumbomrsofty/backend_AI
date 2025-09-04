# Cloud SQL Connector Migration Summary

This document outlines the changes made to migrate from Unix socket connections to the Google Cloud SQL connector for connecting to Cloud SQL from Cloud Run.

## Changes Made

### 1. Dependencies Updated
- Added `cloud-sql-python-connector==1.11.0` to `requirements.txt`
- This library provides a secure way to connect to Cloud SQL instances using IAM authentication

### 2. Environment Variables Changed
**Old Environment Variables (removed):**
- `INSTANCE_UNIX_SOCKET` - Path to Unix socket

**New Environment Variables (required):**
- `INSTANCE_CONNECTION_NAME` - Format: `PROJECT:REGION:INSTANCE`
  - Example: `my-project:us-central1:my-database-instance`
- `DB_USER` - Database username (unchanged)
- `DB_PASS` - Database password (unchanged) 
- `DB_NAME` - Database name (unchanged)

### 3. Database Connection Code Updated

#### `database.py` Changes:
- **Added import:** `from google.cloud.sql.connector import Connector`
- **Replaced functions:**
  - `get_db_engine()` - Removed (no longer needed)
  - `get_database_uri()` - Simplified to return `"postgresql+pg8000://"`
  - **Added `getconn()`** - New function that creates connections using Cloud SQL connector

```python
def getconn():
    """Create a connection to Cloud SQL using the Cloud SQL connector."""
    db_user = os.environ.get("DB_USER")
    db_pass = os.environ.get("DB_PASS")
    db_name = os.environ.get("DB_NAME")
    instance_connection_name = os.environ.get("INSTANCE_CONNECTION_NAME")
    
    if not all([db_user, db_pass, db_name, instance_connection_name]):
        raise ValueError("Missing required Cloud SQL environment variables")
    
    connector = Connector()
    conn = connector.connect(
        instance_connection_name,
        "pg8000",
        user=db_user,
        password=db_pass,
        db=db_name
    )
    return conn
```

#### `task.py` Changes:
- **Added import:** `import sqlalchemy`
- **Updated database configuration:**
  - Added SQLAlchemy engine configuration with custom creator function
  - Added `SQLALCHEMY_ENGINE_OPTIONS` to Flask config

```python
# Database configuration - Create engine with Cloud SQL connector
engine = sqlalchemy.create_engine(
    "postgresql+pg8000://",
    creator=getconn,
)
app.config['SQLALCHEMY_DATABASE_URI'] = get_database_uri()
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'creator': getconn
}
```

## Benefits of Cloud SQL Connector

1. **Automatic IAM Authentication**: Uses Cloud IAM for secure authentication
2. **Automatic Connection Management**: Handles connection pooling and retry logic
3. **Better Security**: No need to manage database passwords in some cases (with Cloud SQL IAM users)
4. **Simplified Deployment**: No need to configure Unix sockets or VPC connectors
5. **Better Performance**: Optimized connection handling for Cloud Run environments

## Testing

A test script `test_connection.py` has been created to verify the connection setup:

```bash
python test_connection.py
```

This script will:
- Check that all required environment variables are set
- Test direct connection using the connector
- Test SQLAlchemy engine connection
- Provide clear error messages if something is wrong

## Deployment Checklist

Before deploying to Cloud Run, ensure:

1. ✅ Install dependencies: `pip install -r requirements.txt`
2. ✅ Set environment variables in Cloud Run:
   - `INSTANCE_CONNECTION_NAME=your-project:your-region:your-instance`
   - `DB_USER=your-username`
   - `DB_PASS=your-password`
   - `DB_NAME=your-database`
3. ✅ Remove old environment variables:
   - `INSTANCE_UNIX_SOCKET` (no longer needed)
4. ✅ Ensure Cloud Run service has proper IAM permissions:
   - `Cloud SQL Client` role for the service account
5. ✅ Test connection using the test script

## Rollback Plan

If you need to rollback to the Unix socket method:
1. Revert the changes in `database.py` and `task.py`
2. Remove `cloud-sql-python-connector` from `requirements.txt`
3. Restore `INSTANCE_UNIX_SOCKET` environment variable
4. Remove `INSTANCE_CONNECTION_NAME` environment variable

## Migration Benefits

- **Simplified Architecture**: No need for Cloud SQL Proxy or Unix sockets
- **Better Error Handling**: Cloud SQL connector provides better error messages
- **Automatic Retries**: Built-in retry logic for transient connection failures
- **IAM Integration**: Can use Cloud IAM database users for enhanced security
- **Cloud Run Optimized**: Designed specifically for serverless environments like Cloud Run
