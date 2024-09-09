import psycopg2
from psycopg2 import sql
from dotenv import load_dotenv
import os

load_dotenv()
# Database initialization
def init_db():
    # Connect to PostgreSQL database
    conn = psycopg2.connect(
        host=os.getenv('DB_HOST'),
        database=os.getenv('DB_NAME'),
        user=os.getenv('DB_USER'),
        password=os.getenv('DB_PASSWORD'),
        port=os.getenv('DB_PORT')
    )
    cursor = conn.cursor()

    # Create vendors table first (because it's referenced by advisories)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS vendors (
            id SERIAL PRIMARY KEY,
            name TEXT,
            source TEXT
        )
    ''')
    
    # Create advisories table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS advisories (
        id TEXT PRIMARY KEY,
        title TEXT,
        publication_date DATE,
        vendor_id INTEGER,
        url TEXT,
        FOREIGN KEY (vendor_id) REFERENCES vendors(id)
    )
    ''')
    
    # Create vulnerabilities table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS vulnerabilities (
            id SERIAL PRIMARY KEY,
            advisory_id TEXT,
            cve TEXT,
            base_score REAL,
            severity TEXT,
            vector_string TEXT,
            version TEXT,
            FOREIGN KEY (advisory_id) REFERENCES advisories(id)
        )
    ''')

    # Create products table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS products (
            id SERIAL PRIMARY KEY,
            product_name TEXT,
            vulnerability_id INTEGER,
            FOREIGN KEY (vulnerability_id) REFERENCES vulnerabilities(id)
        )
    ''')

    # Commit the changes and close the connection
    conn.commit()
    cursor.close()
    conn.close()

if __name__ == "__main__":
    init_db()
    print("Database initialized.")
