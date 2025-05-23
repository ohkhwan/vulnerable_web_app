import sqlite3

# Define the database file name
DB_NAME = 'users.db'

# SQL statement to create the users table
# ssn field is included as per the HTML form, but storing SSN directly is highly sensitive and risky.
# For a real application, strong encryption, tokenization, or avoiding storing it is crucial.
CREATE_USERS_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    password TEXT NOT NULL,
    name TEXT NOT NULL,
    ssn TEXT NOT NULL UNIQUE,
    is_admin INTEGER DEFAULT 0
);
"""

CREATE_BOARD_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS board (
    post_id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    content TEXT NOT NULL,
    author_id TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (author_id) REFERENCES users(id)
);
"""

CREATE_VULNERABILITIES_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS vulnerabilities (
    cve_id TEXT PRIMARY KEY,
    description TEXT NOT NULL,
    published_date TEXT,
    last_modified_date TEXT,
    severity TEXT,
    cvss_v3_score REAL,
    source_identifier TEXT
);
"""

def create_database():
    """Creates the SQLite database and the users table if they don't exist."""
    conn = None
    try:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute(CREATE_USERS_TABLE_SQL)
        cursor.execute(CREATE_BOARD_TABLE_SQL)
        cursor.execute(CREATE_VULNERABILITIES_TABLE_SQL)
        conn.commit()
        print(f"Database '{DB_NAME}' and table 'users' created successfully (or already exist).")
        print(f"Table 'vulnerabilities' created successfully (or already exists).")

        # Optional: Add a default admin user if the table was just created and is empty
        cursor.execute("SELECT COUNT(*) FROM users")
        if cursor.fetchone()[0] == 0:
             # Note: Storing plain passwords is insecure. This is for demonstration.
             # In a real app, use proper password hashing (e.g., bcrypt).
            try:
                cursor.execute("INSERT INTO users (id, password, name, ssn, is_admin) VALUES (?, ?, ?, ?, ?)",
                               ('admin', 'admin', '관리자', '800101-1234567', 1))
                conn.commit()
                print("Default 'admin' user added.")
            except sqlite3.IntegrityError:
                # Should not happen if count was 0, but good practice
                print("Default 'admin' user already exists.")

    except sqlite3.Error as e:
        print(f"Database error: {e}")
    finally:
        if conn:
            conn.close()

if __name__ == '__main__':
    create_database()