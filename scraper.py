import psycopg2
import requests
import os
from dateutil import parser
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Function to establish a connection to the PostgreSQL database
def connect_to_db():
    return psycopg2.connect(
        host=os.getenv('DB_HOST'),
        database=os.getenv('DB_NAME'),
        user=os.getenv('DB_USER'),
        password=os.getenv('DB_PASSWORD'),
        port=os.getenv('DB_PORT')
    )

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

# Insert vendor into the database
def insert_vendor(vendor_name, source=None):
    conn = connect_to_db()
    cursor = conn.cursor()

    cursor.execute('SELECT id FROM vendors WHERE name = %s', (vendor_name,))
    vendor = cursor.fetchone()

    if not vendor:
        cursor.execute('''
            INSERT INTO vendors (name, source)
            VALUES (%s, %s)
            RETURNING id
        ''', (vendor_name, source))
        vendor_id = cursor.fetchone()[0]
        conn.commit()
    else:
        vendor_id = vendor[0]

    cursor.close()
    conn.close()
    return vendor_id

# Insert advisory into the database
def insert_advisory(advisory, vendor_id):
    conn = connect_to_db()
    cursor = conn.cursor()

    publication_date = parser.parse(advisory['firstPublished']).date()
    try:
        cursor.execute('''
            INSERT INTO advisories (id, title, publication_date, vendor_id, url)
            VALUES (%s, %s, %s, %s, %s)
        ''', (advisory['identifier'], advisory['title'], publication_date, vendor_id, advisory['url']))
        
        conn.commit()
    except psycopg2.IntegrityError:
        conn.rollback()
    
    cursor.close()
    conn.close()

# Insert vulnerabilities into the database
def insert_vulnerability(vulnerability, advisory_id):
    conn = connect_to_db()
    cursor = conn.cursor()

    cve = vulnerability['cveMetadata']['cveId']
 # Initialize variables in case metrics aren't found
    version = None
    vectorString = None
    baseScore = None
    baseSeverity = None
    metrics = None
    # Check if "metrics" exists in the vulnerability data
    if "metrics" in vulnerability["containers"]["cna"]:
        # Iterate through the metrics
        for metric in vulnerability["containers"]["cna"]["metrics"]:
            # Dynamically check for keys that start with "cvssV"
            for key, value in metric.items():
                if key.startswith("cvssV"):
                    metrics = value
                    version = key  # Use the version key (e.g., "cvssV3_1", "cvssV4_0")
                    break
            # Break the outer loop if we found a match
            if version:
                break

        # If a matching metric was found, extract the data
        if metrics:
            vectorString = metrics.get("vectorString", None)
            baseScore = metrics.get("baseScore", None)
            baseSeverity = metrics.get("baseSeverity", None)


    print("Inserting Vulnerability: ", cve)
    cursor.execute('''
        INSERT INTO vulnerabilities (advisory_id, cve, base_score, severity, vector_string, version)
        VALUES (%s, %s, %s, %s, %s, %s)
        RETURNING id
    ''', (advisory_id, cve, baseScore, baseSeverity, vectorString, version))

    vulnerability_id = cursor.fetchone()[0]
    conn.commit()

    print("DONE Inserting Vulnerability: ", cve)
    
    cursor.close()
    conn.close()

    return vulnerability_id

# Insert affected product into the database
def insert_product(product, vulnerability_id):
    conn = connect_to_db()
    cursor = conn.cursor()

    if "product" in product:
        product_name = product["product"]
    elif "packageName" in product:
        product_name = product["packageName"]
    else:
        print("Product not found in the data.")
        return

    if(product_name.lower() == "n/a"):
        cursor.close()
        conn.close()
        return
    print("Inserting Product: ", product_name)
    cursor.execute('''
        INSERT INTO products (product_name, vulnerability_id)
        VALUES (%s, %s)
    ''', (product_name, vulnerability_id))
    
    conn.commit()
    print("DONE Inserting Product: ", product_name)

    cursor.close()
    conn.close()

# Function to check for new advisories
def check_for_new_advisories(new_data, vendor_id):
    """
    new_data:{
        "identifier",
        "title",
        "firstPublished",
        "url",
    }
    """
    conn = connect_to_db()
    cursor = conn.cursor()

    new_advisories = []

    for advisory in new_data:
        # Check if advisory is already in the database
        cursor.execute('SELECT 1 FROM advisories WHERE id = %s', (advisory['identifier'],))
        result = cursor.fetchone()
        
        if not result:
            # New advisory found
            new_advisories.append(advisory)
            print("Inserting Advisory: ", advisory["title"])
            insert_advisory(advisory, vendor_id)
            print("DONE Inserting Advisory: ", advisory["title"])
        else:
            print("Advisory already exists in the database.", advisory)

    cursor.close()
    conn.close()
    return new_advisories

# Process CVE information
def process_cve(cve_array, advisory_id):
    for cve in cve_array:
        print("Fetching CVE DATA for: ", cve)
        cve_data = requests.get(f"https://cveawg.mitre.org/api/cve/{cve}").json()
        if "cveMetadata" in cve_data:
            vulnerability_id = insert_vulnerability(cve_data, advisory_id)
            cna = cve_data["containers"]["cna"]
            if "affected" in cna:
                products = cna["affected"]
                for product in products:
                    insert_product(product, vulnerability_id)
