# api/database.py
import os
from sqlalchemy import create_engine, MetaData, Table, Column, Integer, String, VARCHAR, TIMESTAMP, Boolean, Float
from sqlalchemy.sql import func # For default timestamp
from dotenv import load_dotenv # Optional: For loading env variables

# Optional: Load environment variables from a .env file if you create one
# Create a file named '.env' in your project root and add:
# POSTGRES_PASSWORD=your_actual_password
load_dotenv()

# --- Database Configuration ---
# Best practice: Use environment variables for sensitive info like passwords
DB_USER = "postgres"
DB_PASSWORD = os.getenv("POSTGRES_PASSWORD") # Replace default if not using .env
DB_HOST = "localhost"
DB_PORT = "5433" # *** CORRECT PORT ***
DB_NAME = "api_security_db"

DATABASE_URL = f"postgresql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}"

# !!! IMPORTANT: Replace YOUR_DEFAULT_PASSWORD if you don't use a .env file !!!
# if "YOUR_DEFAULT_PASSWORD" in DATABASE_URL and DB_PASSWORD == "YOUR_DEFAULT_PASSWORD":
#     print("WARNING: Using default password in DATABASE_URL. Consider using environment variables.")


# Create the SQLAlchemy engine
try:
    engine = create_engine(DATABASE_URL, echo=False) # Set echo=True for debugging SQL
    # Test connection
    with engine.connect() as connection:
        print("Database connection successful.")
except Exception as e:
    print(f"ERROR: Failed to connect to database at {DB_HOST}:{DB_PORT}")
    print(f"Make sure the PostgreSQL server is running on port {DB_PORT} and credentials are correct.")
    print(f"Database URL used: postgresql://{DB_USER}:***@{DB_HOST}:{DB_PORT}/{DB_NAME}")
    print(f"Error details: {e}")
    # Optionally raise the error or exit if connection is critical for module load
    # raise e
    engine = None # Set engine to None if connection fails

# Define metadata
metadata = MetaData()

# Define the api_logs table structure mirroring the SQL definition
# Ensure this matches the table you created in PGAdmin
api_logs_table = Table(
    'api_logs',
    metadata,
    Column('id', Integer, primary_key=True),
    # Corrected Column Type: Use TIMESTAMP(timezone=True)
    Column('timestamp', TIMESTAMP(timezone=True), server_default=func.now()),
    Column('endpoint', VARCHAR(255)),
    Column('method', VARCHAR(10)),
    Column('client_ip', VARCHAR(50)),
    Column('is_anomalous', Boolean, nullable=True),
    Column('anomaly_score', Float, nullable=True)
)

# Function to create tables (can be called from main.py on startup)
def create_db_and_tables():
    if engine is None:
        print("ERROR: Cannot create tables, database engine not initialized.")
        return
    try:
        print("Attempting to create database tables (if they don't exist)...")
        metadata.create_all(engine)
        print("Database tables check/creation complete.")
    except Exception as e:
        print(f"Error creating/checking database tables: {e}")

print("Database module loaded.")