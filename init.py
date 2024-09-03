import sqlite3
# Database initialization
def init_db():
    conn = sqlite3.connect('advisories.db')
    cursor = conn.cursor()
    
    # Create advisories table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS advisories (
            id TEXT PRIMARY KEY,
            title TEXT,
            publication_date TEXT,
            vendor_id INTEGER,
            url TEXT,
            FOREIGN KEY (vendor_id) REFERENCES vendors(id)
        )
    ''')
    
    # Create vulnerabilities table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS vulnerabilities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
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
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            product_name TEXT,
            vulnerability_id INTEGER,
            FOREIGN KEY (vulnerability_id) REFERENCES vulnerabilities(id)
        )
    ''')

    # Create vendors table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS vendors (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            source TEXT
        )
    ''')
    
    conn.commit()
    conn.close()


if __name__ == "__main__":
    init_db()  
    print("Database initialized.")
