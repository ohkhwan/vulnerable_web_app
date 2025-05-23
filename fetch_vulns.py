import requests
import json
import sqlite3
import gzip
import io

# Configuration
NVD_JSON_FEED_URL = "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-modified.json.gz"
DB_NAME = "users.db"

def download_and_decompress_data(url):
    """Downloads and decompresses the gzipped JSON data from the given URL."""
    print("Downloading data...")
    try:
        response = requests.get(url, stream=True, timeout=60)
        response.raise_for_status()  # Raise an exception for bad status codes

        # Decompress the content
        compressed_file = io.BytesIO(response.content)
        decompressed_file = gzip.GzipFile(fileobj=compressed_file)
        
        print("Data downloaded and decompressed successfully.")
        return json.load(decompressed_file)
    except requests.exceptions.RequestException as e:
        print(f"Error downloading data: {e}")
        return None
    except gzip.BadGzipFile as e:
        print(f"Error decompressing data: {e}")
        return None
    except json.JSONDecodeError as e:
        print(f"Error decoding JSON from decompressed data: {e}")
        return None

def parse_json_data(nvd_data):
    """Parses the NVD JSON data to extract relevant vulnerability information."""
    if not nvd_data or 'vulnerabilities' not in nvd_data:
        print("No vulnerability data found or data is malformed.")
        return []

    print("Parsing data...")
    extracted_vulns = []
    for item in nvd_data.get('vulnerabilities', []):
        cve = item.get('cve', {})
        
        cve_id = cve.get('id')
        if not cve_id:
            continue # Skip if no CVE ID

        # Description (English)
        description = ""
        for desc_entry in cve.get('descriptions', []):
            if desc_entry.get('lang') == 'en':
                description = desc_entry.get('value')
                break
        
        published_date = cve.get('published')
        last_modified_date = cve.get('lastModified')
        source_identifier = cve.get('sourceIdentifier')

        severity = None
        cvss_v3_score = None
        
        metrics = cve.get('metrics', {})
        if 'cvssMetricV31' in metrics and metrics['cvssMetricV31']:
            cvss_data = metrics['cvssMetricV31'][0].get('cvssData', {})
            severity = cvss_data.get('baseSeverity')
            cvss_v3_score = cvss_data.get('baseScore')
        elif 'cvssMetricV30' in metrics and metrics['cvssMetricV30']:
            cvss_data = metrics['cvssMetricV30'][0].get('cvssData', {})
            severity = cvss_data.get('baseSeverity')
            cvss_v3_score = cvss_data.get('baseScore')
            
        extracted_vulns.append({
            'cve_id': cve_id,
            'description': description,
            'published_date': published_date,
            'last_modified_date': last_modified_date,
            'severity': severity,
            'cvss_v3_score': cvss_v3_score,
            'source_identifier': source_identifier
        })
    print(f"Parsed {len(extracted_vulns)} vulnerabilities.")
    return extracted_vulns

def store_vulnerabilities(db_name, vulnerabilities):
    """Stores the extracted vulnerability data into the SQLite database."""
    if not vulnerabilities:
        print("No vulnerabilities to store.")
        return

    print("Inserting data into database...")
    conn = None
    try:
        conn = sqlite3.connect(db_name)
        cursor = conn.cursor()

        # Create the table if it doesn't exist (though create_db.py should do this)
        # This is good for robustness if this script is run independently.
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                cve_id TEXT PRIMARY KEY,
                description TEXT NOT NULL,
                published_date TEXT,
                last_modified_date TEXT,
                severity TEXT,
                cvss_v3_score REAL,
                source_identifier TEXT
            )
        """)

        for vuln in vulnerabilities:
            cursor.execute("""
                INSERT OR REPLACE INTO vulnerabilities (
                    cve_id, description, published_date, last_modified_date, 
                    severity, cvss_v3_score, source_identifier
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                vuln['cve_id'], vuln['description'], vuln['published_date'],
                vuln['last_modified_date'], vuln['severity'], vuln['cvss_v3_score'],
                vuln['source_identifier']
            ))
        
        conn.commit()
        print(f"{len(vulnerabilities)} vulnerabilities processed and stored/updated in the database.")
    except sqlite3.Error as e:
        print(f"Database error: {e}")
    finally:
        if conn:
            conn.close()

def main():
    """Main function to orchestrate the fetching and storing of vulnerabilities."""
    # First, ensure the database and table are created by running create_db.py
    # This is not strictly necessary here if create_db.py is always run first,
    # but makes this script more robust.
    # For this exercise, we assume create_db.py has run or store_vulnerabilities will create the table.

    nvd_data = download_and_decompress_data(NVD_JSON_FEED_URL)
    if nvd_data:
        vulnerabilities = parse_json_data(nvd_data)
        if vulnerabilities:
            store_vulnerabilities(DB_NAME, vulnerabilities)
        else:
            print("No vulnerabilities were parsed. Nothing to store.")
    else:
        print("Failed to download or decompress data. Exiting.")

if __name__ == "__main__":
    main()
