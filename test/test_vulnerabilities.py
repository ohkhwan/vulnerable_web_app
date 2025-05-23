import unittest
import json
import sqlite3
import os

# Add project root to sys.path to allow importing app and create_db
import sys
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app import app # Flask app instance
import create_db # To create schema and potentially DB_NAME

class VulnerabilitiesTestCase(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        """
        Set up the Flask app for testing and create the database schema.
        This runs once before all tests in the class.
        """
        app.config['TESTING'] = True
        app.config['WTF_CSRF_ENABLED'] = False # Disable CSRF for testing forms if any
        app.config['DATABASE'] = os.path.join(os.path.dirname(__file__), 'test_users.db') # Use a separate test DB
        
        # Override DB_NAME in create_db if it's used directly by create_db functions
        # This ensures create_db operates on our test_users.db
        create_db.DB_NAME = app.config['DATABASE']
        
        # Ensure a clean database for each test run
        if os.path.exists(app.config['DATABASE']):
            os.remove(app.config['DATABASE'])
            
        create_db.create_database() # Create schema in test_users.db

        cls.test_vulns_data = [
            ('CVE-TEST-001', 'Test vulnerability for exact match', '2023-01-01T00:00:00Z', '2023-01-02T00:00:00Z', 'HIGH', 7.5, 'test1@example.com'),
            ('CVE-TEST-002', 'Another test case for description search unique_keyword_abc', '2023-01-03T00:00:00Z', '2023-01-04T00:00:00Z', 'MEDIUM', 5.0, 'test2@example.com'),
            ('CVE-TEST-003', 'Unique keyword XYZ for testing', '2023-01-05T00:00:00Z', '2023-01-06T00:00:00Z', 'LOW', 2.5, 'test3@example.com'),
            ('CVE-TEST-004', 'Paged result item 1', '2023-01-07T00:00:00Z', '2023-01-08T00:00:00Z', 'HIGH', 7.8, 'test4@example.com'),
            ('CVE-TEST-005', 'Paged result item 2', '2023-01-09T00:00:00Z', '2023-01-10T00:00:00Z', 'MEDIUM', 5.1, 'test5@example.com'),
            ('CVE-TEST-006', 'Paged result item 3 (should be on page 2)', '2023-01-11T00:00:00Z', '2023-01-12T00:00:00Z', 'CRITICAL', 9.0, 'test6@example.com'),
            ('CVE-TEST-007', 'Oldest entry for sorting test', '2022-12-31T00:00:00Z', '2022-12-31T01:00:00Z', 'INFO', 1.0, 'test7@example.com'),
        ]


    def setUp(self):
        """
        Set up the test client and populate the vulnerabilities table with test data.
        This runs before each individual test method.
        """
        self.client = app.test_client()
        
        # Populate with test data
        conn = sqlite3.connect(app.config['DATABASE'])
        cursor = conn.cursor()
        try:
            # Clear previous test data from vulnerabilities table specifically
            cursor.execute("DELETE FROM vulnerabilities")
            # Insert new test data
            cursor.executemany("""
                INSERT OR REPLACE INTO vulnerabilities 
                (cve_id, description, published_date, last_modified_date, severity, cvss_v3_score, source_identifier)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, self.test_vulns_data)
            conn.commit()
        finally:
            conn.close()

    @classmethod
    def tearDownClass(cls):
        """Clean up the test database file after all tests are done."""
        if os.path.exists(app.config['DATABASE']):
            os.remove(app.config['DATABASE'])

    # --- API Test Cases ---

    def test_01_get_vulnerabilities_api_success(self):
        """Test Case 1: Basic Success Response for /api/vulnerabilities."""
        response = self.client.get('/api/vulnerabilities')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertTrue(data['success'])
        self.assertIsInstance(data['vulnerabilities'], list)
        self.assertEqual(data['page'], 1)
        self.assertEqual(data['per_page'], 10) # Default per_page

    def test_02_get_vulnerabilities_api_pagination(self):
        """Test Case 2: Pagination for /api/vulnerabilities."""
        # With 7 items, page 1 per_page 5 should have 5 items
        response_page1 = self.client.get('/api/vulnerabilities?page=1&per_page=5')
        self.assertEqual(response_page1.status_code, 200)
        data_page1 = json.loads(response_page1.data)
        self.assertTrue(data_page1['success'])
        self.assertEqual(len(data_page1['vulnerabilities']), 5)
        self.assertEqual(data_page1['page'], 1)
        self.assertEqual(data_page1['per_page'], 5)
        self.assertEqual(data_page1['total_count'], len(self.test_vulns_data))
         # Check sorting (newest first by last_modified_date)
        self.assertEqual(data_page1['vulnerabilities'][0]['cve_id'], 'CVE-TEST-006') # newest

        # Page 2 should have the remaining 2 items
        response_page2 = self.client.get('/api/vulnerabilities?page=2&per_page=5')
        self.assertEqual(response_page2.status_code, 200)
        data_page2 = json.loads(response_page2.data)
        self.assertTrue(data_page2['success'])
        self.assertEqual(len(data_page2['vulnerabilities']), 2) # 7 total - 5 on page 1
        self.assertEqual(data_page2['page'], 2)
        self.assertEqual(data_page2['per_page'], 5)
        self.assertEqual(data_page2['total_count'], len(self.test_vulns_data))
        self.assertEqual(data_page2['vulnerabilities'][0]['cve_id'], 'CVE-TEST-001') # second to last group by date
        self.assertEqual(data_page2['vulnerabilities'][1]['cve_id'], 'CVE-TEST-007') # oldest


    def test_03_search_vulnerabilities_api_cve_id_exact(self):
        """Test Case 3a: Search by exact CVE ID."""
        response = self.client.get('/api/vulnerabilities?search=CVE-TEST-001')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertTrue(data['success'])
        self.assertEqual(len(data['vulnerabilities']), 1)
        self.assertEqual(data['vulnerabilities'][0]['cve_id'], 'CVE-TEST-001')
        self.assertEqual(data['total_count'], 1)

    def test_04_search_vulnerabilities_api_description(self):
        """Test Case 3b: Search by keyword in description."""
        response = self.client.get('/api/vulnerabilities?search=unique_keyword_abc')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertTrue(data['success'])
        self.assertEqual(len(data['vulnerabilities']), 1)
        self.assertEqual(data['vulnerabilities'][0]['cve_id'], 'CVE-TEST-002')
        self.assertIn('unique_keyword_abc', data['vulnerabilities'][0]['description'])
        self.assertEqual(data['total_count'], 1)

    def test_05_search_vulnerabilities_api_not_found(self):
        """Test Case 3c: Search with a term that yields no results."""
        response = self.client.get('/api/vulnerabilities?search=NON_EXISTENT_TERM_XYZ_123')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertTrue(data['success'])
        self.assertEqual(len(data['vulnerabilities']), 0)
        self.assertEqual(data['total_count'], 0)

    def test_06_search_vulnerabilities_api_combined_cve_id_and_description(self):
        """Test Case 3d: Search term that could match CVE_ID of one and description of another."""
        # 'CVE-TEST-001' is a CVE ID
        # 'Test vulnerability for exact match' is description for CVE-TEST-001
        # 'Another test case for description search unique_keyword_abc' is desc for CVE-TEST-002
        # A search for "Test" (which becomes %Test% for LIKE) will match:
        # CVE-TEST-001: "Test vulnerability for exact match"
        # CVE-TEST-002: "Another test case for description search unique_keyword_abc"
        # CVE-TEST-003: "Unique keyword XYZ for testing"
        # CVE-TEST-007: "Oldest entry for sorting test"
        # The API logic is (cve_id = ? OR description LIKE ?)
        response = self.client.get('/api/vulnerabilities?search=Test')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertTrue(data['success'])
        self.assertEqual(data['total_count'], 4, "Should find four entries with 'Test' in description or cve_id")
        cve_ids_found = {v['cve_id'] for v in data['vulnerabilities']}
        expected_cve_ids = {'CVE-TEST-001', 'CVE-TEST-002', 'CVE-TEST-003', 'CVE-TEST-007'}
        self.assertEqual(cve_ids_found, expected_cve_ids)

    # --- Page Load Test Case ---
    def test_07_vulnerabilities_page_loads(self):
        """Test Case: Vulnerability Page Loads for /vulnerabilities.html."""
        response = self.client.get('/vulnerabilities.html')
        self.assertEqual(response.status_code, 200)
        response_data_str = response.data.decode('utf-8')
        self.assertIn("<title>취약점 게시판 - Vulnerability Board</title>", response_data_str)
        self.assertIn("취약점 게시판", response_data_str) # Check for heading or prominent text

if __name__ == '__main__':
    unittest.main()
