import sqlite3
import requests

# Function to fetch JSON data from URL
def get_json_from_url(url):
    try:
        response = requests.get(url)
        if response.status_code == 200:
            return response.json()
        else:
            print(f"Failed to retrieve data. HTTP Status Code: {response.status_code}")
            return None
    except Exception as e:
        print(f"An error occurred: {e}")
        return None

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

# Insert vendor into the database
def insert_vendor(vendor_name, source=None):
    conn = sqlite3.connect('advisories.db')
    cursor = conn.cursor()
    
    cursor.execute('SELECT id FROM vendors WHERE name = ?', (vendor_name,))
    vendor = cursor.fetchone()
    
    if not vendor:
        cursor.execute('''
            INSERT INTO vendors (name, source)
            VALUES (?, ?)
        ''', (vendor_name, source))
        vendor_id = cursor.lastrowid
        conn.commit()
    else:
        vendor_id = vendor[0]
    
    conn.close()
    return vendor_id

# Insert advisory into the database
def insert_advisory(advisory, vendor_id):
    """
    advisory = {
        identifier: str,
        title: str,
        firstPublished: str,
        url: str
    }
    """
    conn = sqlite3.connect('advisories.db')
    cursor = conn.cursor()
    
    try:
        cursor.execute('''
            INSERT INTO advisories (id, title, publication_date, vendor_id, url)
            VALUES (?, ?, ?, ?, ?)
        ''', (advisory['identifier'], advisory['title'], advisory['firstPublished'], vendor_id, advisory['url']))
        
        conn.commit()
    except sqlite3.IntegrityError:
        pass
    
    conn.close()

# Insert vulnerabilities into the database
def insert_vulnerability(vulnerability, advisory_id):
    conn = sqlite3.connect('advisories.db')
    cursor = conn.cursor()
    
    cve = vulnerability['cveMetadata']['cveId']

    if "metrics" in vulnerability["containers"]["cna"]:
        for metric in vulnerability["containers"]["cna"]["metrics"]:
            if "cvssV3_1" in metric:
                metrics = metric["cvssV3_1"]
                break
        
        version = metrics["version"]
        vectorString = metrics["vectorString"]
        baseScore = metrics["baseScore"]
        baseSeverity = metrics["baseSeverity"]
    else:
        version = None
        vectorString = None
        baseScore = None
        baseSeverity = None

    print("Inserting Vulnerability: ", cve)
    cursor.execute('''
        INSERT INTO vulnerabilities (advisory_id, cve, base_score, severity, vector_string, version)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (advisory_id, cve, baseScore, baseSeverity,
          vectorString, version))
    
    print("DONE Inserting Vulnerability: ", cve)
    vulnerability_id = cursor.lastrowid
    conn.commit()
    conn.close()
    
    return vulnerability_id

# Insert affected product into the database
def insert_product(product, vulnerability_id):
    conn = sqlite3.connect('advisories.db')
    cursor = conn.cursor()
    
    if "product" in product:
        print("Inserting Product: ", product["product"])
        cursor.execute('''
            INSERT INTO products (product_name, vulnerability_id)
            VALUES (?, ?)
        ''', (product['product'],  vulnerability_id))
        print("DONE Inserting Product: ", product["product"])
    elif "packageName" in product:
        print("Inserting Product: ", product["packageName"])
        cursor.execute('''
            INSERT INTO products (product_name, vulnerability_id)
            VALUES (?, ?)
        ''', (product["packageName"],  vulnerability_id))
        print("DONE Inserting Product: ", product["packageName"])
    else:
        print("Product not found in the data.")
    conn.commit()
    conn.close()

# Function to check for new advisories
def check_for_new_advisories(new_data, vendor_id):
    """
    advisory = {
        identifier: str,
        title: str,
        firstPublished: str,
        url: str
    }
    """
    conn = sqlite3.connect('advisories.db')
    cursor = conn.cursor()
    
    new_advisories = []
    
    for advisory in new_data:
        # Check if advisory is already in the database
        cursor.execute('SELECT 1 FROM advisories WHERE id = ?', (advisory['identifier'],))
        result = cursor.fetchone()
        
        if not result:
            # New advisory found
            new_advisories.append(advisory)
            print("Inseting Advisory: ", advisory["title"])
            insert_advisory(advisory, vendor_id)
            print("DONE Inserting Advisory: ", advisory["title"])
        
    conn.close()
    return new_advisories

def process_cve(cve_array, advisory_id):
    for cve in cve_array:
        print("Fetching CVE DATA for : ", cve)
        cve_data = requests.get(f"https://cveawg.mitre.org/api/cve/{cve}").json()
        if "cveMetadata" in cve_data:
                vulnerability_id = insert_vulnerability(cve_data, advisory_id)
                products = cve_data["containers"]["cna"]["affected"]
                for product in products:
                    insert_product(product, vulnerability_id)
        else:
            pass


# Example usage
def main():
    # Initialize the database
    init_db()
    print("Database initialized.")
    # URL for Cisco advisories
    url = "https://sec.cloudapps.cisco.com/security/center/publicationService.x?criteria=exact&cves=&keyword=&last_published_date=&limit=20&offset=0&publicationTypeIDs=1,3&securityImpactRatings=&sort=-day_sir&title="
    data = get_json_from_url(url)
    print("Data fetched.")
    # Example vendor
    vendor_name = "Cisco"
    source = "https://sec.cloudapps.cisco.com/security/center/publicationListing.x"
    vendor_id = insert_vendor(vendor_name, source)

    print("Vendor inserted.")
    


    if data:
        new_advisories = check_for_new_advisories(data, vendor_id)

        titles = [advisory['title'] for advisory in new_advisories]
        print("New advisories: ", titles)
        for advisory in new_advisories:
            print("ADVISORY : ", advisory['identifier'], " / ", advisory['title'])
            cves = advisory['cve']
            cve_array = cves.split(",")
            process_cve(cve_array, advisory['identifier'])

                    
                        

                        
           
    
if __name__ == "__main__":
    main()
