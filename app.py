from flask import Flask, request, jsonify, render_template, redirect, url_for, send_from_directory, session, abort, g
import sqlite3
import os
import traceback
import requests
import urllib.request
import urllib.error
# import functools # login_required 데코레이터 사용 시 필요

app = Flask(__name__)

# --- Configuration ---
# IMPORTANT: Replace with a real secret key in production!
# This is used to encrypt session cookies.
app.secret_key = os.urandom(24)
DB_NAME = 'users.db'

# Ensure the database file exists by running the creation script
# (This is a simple way; in production, you'd ensure migration is handled)
if not os.path.exists(DB_NAME):
     print(f"Database file '{DB_NAME}' not found. Please run create_db.py first.")
     # In a real application, you might exit or handle this more robust하게


# --- Database Connection Helper ---
def get_db():
    """Opens a new database connection if there is none yet for the current application context."""
    if 'db' not in g:
        g.db = sqlite3.connect(DB_NAME)
        g.db.row_factory = sqlite3.Row # Allows accessing columns by name
    return g.db

@app.teardown_appcontext
def close_db(e=None):
    """Closes the database connection at the end of the request."""
    db = g.pop('db', None)
    if db is not None:
        db.close()

# --- Before Request: Load logged in user ---
@app.before_request
def load_logged_in_user():
    """Load the user from the session before each request."""
    user_id = session.get('user_id')
    if user_id is None:
        g.user = None # Store user object (or None) in Flask's global context 'g'
    else:
        db = get_db()
        g.user = db.execute(
            'SELECT * FROM users WHERE id = ?', (user_id,)
        ).fetchone()

# --- Routes for Serving HTML Pages ---

@app.route('/')
@app.route('/index.html')
def index():
    """Serves the index.html homepage."""
    return render_template('index.html') # Assumes index.html exists

@app.route('/register.html')
def register_page():
    """Serves the register.html page."""
    # Check if user is already logged in, maybe redirect
    if g.user:
         return redirect(url_for('myinfo_page'))
    return render_template('register.html') # Assumes register.html exists


@app.route('/login.html')
def login_page():
    """Serves the login.html page."""
    # Check if user is already logged in, maybe redirect
    if g.user:
         return redirect(url_for('myinfo_page'))
    return render_template('login.html') # Assumes login.html exists

@app.route('/myinfo.html')
def myinfo_page():
    """Serves the myinfo.html page (requires login)."""
    # Require login
    if g.user is None:
        return redirect(url_for('login_page')) # Redirect to login if not logged in
    # Pass user data to the template if myinfo.html needs it for display
    # You would typically fetch user data here based on g.user['id'] if needed in the template
    return render_template('myinfo.html') # Assumes myinfo.html exists

@app.route('/reset_password.html')
def reset_password_page():
    """Serves the reset_password.html page."""
    return render_template('reset_password.html') # Assumes reset_password.html exists

# Assuming xml_parser.html and redirect.html also exist as static pages
@app.route('/xml_parser.html')
def xml_parser_page():
    return render_template('xml_parser.html')

@app.route('/redirect.html')
def redirect_page():
    return render_template('redirect.html')

@app.route('/ssrf_test.html')
def ssrf_test_page():
    """Serves the ssrf_test.html page."""
    # 로그인 필요
    if g.user is None:
        return redirect(url_for('login_page'))
    return render_template('ssrf_test.html')

@app.route('/board.html')
def board_page():
    """Serves the board.html page with the list of posts."""
    return render_template('board.html')

@app.route('/write_post.html')
def write_post_page():
    """Serves the write_post.html page for creating new posts."""
    # 로그인 필요
    if g.user is None:
        return redirect(url_for('login_page'))
    return render_template('write_post.html')

@app.route('/post_detail.html')
def post_detail_page():
    """Serves the post_detail.html page for viewing a post."""
    return render_template('post_detail.html')


@app.route('/test', methods=['GET'])
def list_test_directory():
 
    test_dir = os.path.join(os.getcwd(), 'test')

    if not os.path.exists(test_dir):
        return render_template('error.html', message='test 디렉토리가 존재하지 않습니다.'), 404

    try:
        items = os.listdir(test_dir)
        directory_contents = []
        for item in items:
            item_path = os.path.join(test_dir, item)
            item_type = 'directory' if os.path.isdir(item_path) else 'file'
            size = os.path.getsize(item_path) if item_type == 'file' else None
            mtime = os.path.getmtime(item_path) if item_type == 'file' else None
            directory_contents.append({
                'name': item,
                'type': item_type,
                'size': size,
                'mtime': mtime
            })

        return render_template('test_directory.html', contents=directory_contents, directory='test')

    except Exception as e:
        print(f"Error listing test directory: {e}")
        traceback.print_exc()  # 전체 스택 트레이스 출력
        return render_template('error.html', message='디렉토리 목록을 가져오는 중 오류가 발생했습니다.'), 500
        
  

@app.route('/test/download/<path:filename>', methods=['GET'])
def download_file(filename):
    """test 디렉토리 내 파일 다운로드"""
    if g.user is None:
        return jsonify({'success': False, 'message': '로그인이 필요합니다.'}), 401

    test_dir = os.path.join(os.getcwd(), 'test')
    file_path = os.path.join(test_dir, filename)

    if not os.path.abspath(file_path).startswith(os.path.abspath(test_dir)):
        print(f"Path traversal attempt detected: {filename}")
        abort(403)

    if not os.path.exists(file_path) or os.path.isdir(file_path):
        print(f"File not found or is a directory: {filename}")
        return render_template('error.html', message='파일을 찾을 수 없습니다.'), 404

    try:
        return send_from_directory(test_dir, filename, as_attachment=True)
    except Exception as e:
        print(f"Error downloading file {filename}: {e}")
        return render_template('error.html', message='파일 다운로드 중 오류가 발생했습니다.'), 500

@app.route('/test', methods=['POST'])
def test_csrf():
    """CSRF 테스트용 POST 엔드포인트"""
    if g.user is None:
        return jsonify({'success': False, 'message': '로그인이 필요합니다.'}), 401

    data = request.json or request.form
    action = data.get('action', 'No action provided')
    return jsonify({
        'success': True,
        'message': f'CSRF 테스트: {action} 수행됨'
    }), 200
# --- API Endpoints ---

@app.route('/register', methods=['POST'])
def register_user():
    """Handles user registration requests."""
    data = request.json # Get data sent as JSON

    if not data:
        return jsonify({'success': False, 'message': 'No data provided'}), 400

    user_id = data.get('user_id')
    password = data.get('password') # WARNING: Plain password received
    name = data.get('name')
    ssn = data.get('ssn') # WARNING: Sensitive data received

    # Basic validation
    if not all([user_id, password, name, ssn]):
        return jsonify({'success': False, 'message': '모든 필드를 입력해주세요.'}), 400

    db = get_db()
    cursor = db.cursor()

    try:
        # Check if user_id already exists
        cursor.execute("SELECT id FROM users WHERE id = ?", (user_id,))
        if cursor.fetchone() is not None:
            print(f"Registration failed: User ID '{user_id}' already exists.")
            return jsonify({'success': False, 'message': '이미 사용 중인 아이디입니다.'}), 409 # Conflict

        # Check if SSN already exists (as it's marked UNIQUE in DB schema)
        cursor.execute("SELECT id FROM users WHERE ssn = ?", (ssn,))
        if cursor.fetchone() is not None:
             print(f"Registration failed: SSN '{ssn}' already exists.")
             return jsonify({'success': False, 'message': '이미 등록된 주민등록번호입니다.'}), 409 # Conflict

        # Insert new user (WARNING: Storing plain password and SSN!)
        # In production: Hash password, encrypt SSN, use prepared statements securely.
        cursor.execute("INSERT INTO users (id, password, name, ssn) VALUES (?, ?, ?, ?)",
                       (user_id, password, name, ssn))

        db.commit()

        # XSS Vulnerability Simulation (as in original HTML)
        # WARNING: This is intentionally insecure to match the original file's simulation.
        # Do NOT do this in a real application. Sanitize/escape output.
        welcome_message = f"회원가입이 완료되었습니다. 환영합니다, {name}님!"
        print(f"Registration successful for user ID '{user_id}'.")

        return jsonify({'success': True, 'message': welcome_message}), 201 # Created

    except sqlite3.Error as e:
        print(f"Database error during registration: {e}")
        db.rollback() # Roll back changes if insert failed
        return jsonify({'success': False, 'message': '데이터베이스 오류가 발생했습니다.'}), 500


@app.route('/login', methods=['POST'])
def login():
    """Handles user login requests and creates a session."""
    data = request.json

    if not data:
        return jsonify({'success': False, 'message': 'No data provided'}), 400

    user_id = data.get('user_id')
    password = data.get('password') # WARNING: Plain password received

    if not user_id or not password:
         return jsonify({'success': False, 'message': '아이디와 비밀번호를 입력해주세요.'}), 400

    db = get_db()
    user = db.execute(
        'SELECT * FROM users WHERE id = ?', (user_id,)
    ).fetchone()

    # WARNING: Comparing plain password! Use password hashing (bcrypt) in real apps.
    if user is None or user['password'] != password:
        print(f"Login failed: Invalid credentials for user ID '{user_id}'.")
        return jsonify({'success': False, 'message': '잘못된 아이디 또는 비밀번호입니다.'}), 401 # Unauthorized
    else:
        # Login successful, create session
        session.clear()
        session['user_id'] = user['id']
        print(f"Login successful for user ID '{user_id}'.")
        return jsonify({'success': True, 'message': f"로그인 성공! 환영합니다, {user['name']}님!"}), 200

@app.route('/logout')
def logout():
    """Logs out the current user by clearing the session."""
    session.clear()
    return redirect(url_for('index')) # Redirect to homepage after logout

@app.route('/user_info', methods=['GET'])
def user_info():
    """Provides the logged-in user's information."""
    # Require login (uses g.user populated by before_request)
    if g.user is None:
        print("Access to /user_info denied: User not logged in.")
        return jsonify({'success': False, 'message': '로그인이 필요합니다.'}), 401

    # Return user info (excluding sensitive password, but including SSN as per original structure)
    # WARNING: Returning SSN is highly sensitive! Do not do this in real apps without justification and security measures.
    user_data = {
        'id': g.user['id'],
        'name': g.user['name'],
        'ssn': g.user['ssn']
        # Password is NOT included
    }
    print(f"Serving user info for user ID '{g.user['id']}'.")
    return jsonify({'success': True, 'user': user_data}), 200

@app.route('/api/ssrf_test', methods=['POST'])
def ssrf_test():
    """SSRF 테스트 API - 입력된 URL에 요청을 보내고 응답을 반환"""
    # 로그인 확인
    if g.user is None:
        return jsonify({'success': False, 'message': '로그인이 필요합니다.'}), 401
    
    data = request.json
    if not data or 'url' not in data:
        return jsonify({'success': False, 'message': 'URL이 제공되지 않았습니다.'}), 400
    
    url = data.get('url')
    
    try:
        # SSRF 취약점 - 사용자 입력 URL에 직접 요청을 보냄
        # 안전하지 않은 방식: URL 검증 없이 요청을 보냄
        if url.startswith('file://'):
            # 파일 URL 처리
            file_path = url[7:]  # file:// 제거
            try:
                with urllib.request.urlopen(url) as response:
                    content = response.read().decode('utf-8', errors='replace')
                    return jsonify({'success': True, 'response': content}), 200
            except urllib.error.URLError as e:
                return jsonify({'success': False, 'message': f'파일 접근 오류: {str(e)}'}), 400
        else:
            # HTTP/HTTPS URL 처리
            response = requests.get(url, timeout=5)
            return jsonify({'success': True, 'response': response.text}), 200
            
    except requests.exceptions.RequestException as e:
        return jsonify({'success': False, 'message': f'요청 처리 중 오류가 발생했습니다: {str(e)}'}), 400
    except Exception as e:
        print(f"SSRF 테스트 중 오류 발생: {e}")
        return jsonify({'success': False, 'message': f'오류가 발생했습니다: {str(e)}'}), 500

# --- View Other User Info (Now with Admin Check) ---
@app.route('/user_info_other/<user_id>', methods=['GET'])
def user_info_other(user_id):
    """
    Provides information for a specified user ID.
    Only admin users can access other users' information.
    """
    # Check if user is logged in
    if g.user is None:
         print(f"Access to /user_info_other/{user_id} denied: User not logged in.")
         return jsonify({'success': False, 'message': '로그인이 필요합니다.'}), 401
    
    # Check if user is admin
    if g.user['is_admin'] != 1:
         print(f"Access to /user_info_other/{user_id} denied: User '{g.user['id']}' is not admin.")
         return jsonify({'success': False, 'message': '관리자만 다른 사용자의 정보를 조회할 수 있습니다.'}), 403 # Forbidden

    db = get_db()
    user = db.execute(
        'SELECT id, name, ssn FROM users WHERE id = ?', (user_id,) # Select only needed fields
    ).fetchone()

    if user is None:
        print(f"Access to /user_info_other/{user_id}: User not found.")
        return jsonify({'success': False, 'message': '해당 사용자를 찾을 수 없습니다.'}), 404 # Not Found

    # WARNING: Returning SSN is highly sensitive!
    user_data = {
        'id': user['id'],
        'name': user['name'], # WARNING: XSS Source if used unsafely on client
        'ssn': user['ssn']
    }
    print(f"Serving info for user ID '{user_id}' requested by admin '{g.user['id']}'.")
    return jsonify({'success': True, 'user': user_data}), 200


@app.route('/update_password', methods=['POST'])
def update_password():
    """Handles password update requests."""
    # Require login
    if g.user is None:
        print("Access to /update_password denied: User not logged in.")
        return jsonify({'success': False, 'message': '로그인이 필요합니다.'}), 401

    data = request.json
    # Need current password validation against the one in the DB
    # The client-side JS sends current_password and new_password
    if not data or 'current_password' not in data or 'new_password' not in data:
        return jsonify({'success': False, 'message': '현재 비밀번호와 새 비밀번호를 모두 입력해주세요.'}), 400

    current_password_input = data['current_password'] # WARNING: Plain password received
    new_password = data['new_password'] # WARNING: Plain password received

    db = get_db()
    # Fetch the user again to verify current password
    user = db.execute(
        'SELECT * FROM users WHERE id = ?', (g.user['id'],)
    ).fetchone()

    # Check if the provided current password matches the one in the DB
    # WARNING: Comparing plain passwords! Use password hashing (bcrypt) in real apps.
    if user is None or user['password'] != current_password_input:
         print(f"Password update failed for user '{g.user['id']}': Incorrect current password.")
         return jsonify({'success': False, 'message': '현재 비밀번호가 올바르지 않습니다.'}), 401 # Unauthorized

    try:
        # Update password for the logged-in user
        # WARNING: Storing plain password! Use password hashing (bcrypt) in real apps.
        cursor = db.cursor()
        cursor.execute("UPDATE users SET password = ? WHERE id = ?",
                       (new_password, g.user['id']))
        db.commit()
        print(f"Password updated successfully for user '{g.user['id']}'.")
        return jsonify({'success': True, 'message': '비밀번호가 성공적으로 업데이트되었습니다.'}), 200

    except sqlite3.Error as e:
        print(f"Database error during password update for user '{g.user['id']}': {e}")
        db.rollback()
        return jsonify({'success': False, 'message': '비밀번호 업데이트 중 오류가 발생했습니다.'}), 500


# --- 게시판 관련 API 엔드포인트 ---

@app.route('/api/posts', methods=['GET'])
def get_posts():
    """게시글 목록 조회 API"""
    search_keyword = request.args.get('search', '')
    
    db = get_db()
    cursor = db.cursor()
    
    try:
        # XSS 취약점 시뮬레이션 - 검색어를 직접 SQL 쿼리에 사용
        # 실제 프로덕션에서는 절대 이렇게 하면 안됩니다!
        if search_keyword:
            # SQL Injection 취약점 해결 - 매개변수화된 쿼리 사용
            # LIKE 쿼리에 대한 파라미터는 '%'를 포함해서 전달합니다
            search_param = f'%{search_keyword}%'
            cursor.execute("""
                SELECT p.post_id, p.title, p.author_id, p.created_at, u.name as author_name 
                FROM board p 
                JOIN users u ON p.author_id = u.id 
                WHERE p.title LIKE ? OR p.content LIKE ? 
                ORDER BY p.created_at DESC
            """, (search_param, search_param))
        else:
            cursor.execute("""
                SELECT p.post_id, p.title, p.author_id, p.created_at, u.name as author_name 
                FROM board p 
                JOIN users u ON p.author_id = u.id 
                ORDER BY p.created_at DESC
            """)
        
        posts = []
        for row in cursor.fetchall():
            posts.append({
                'post_id': row['post_id'],
                'title': row['title'],
                'author_id': row['author_id'],
                'author_name': row['author_name'],
                'created_at': row['created_at']
            })
        
        return jsonify({'success': True, 'posts': posts}), 200
    
    except sqlite3.Error as e:
        print(f"Database error during post retrieval: {e}")
        return jsonify({'success': False, 'message': '게시글을 불러오는 중 오류가 발생했습니다.'}), 500

@app.route('/api/posts/<int:post_id>', methods=['GET'])
def get_post(post_id):
    """특정 게시글 조회 API"""
    db = get_db()
    cursor = db.cursor()
    
    try:
        cursor.execute("""
            SELECT p.post_id, p.title, p.content, p.author_id, p.created_at, u.name as author_name 
            FROM board p 
            JOIN users u ON p.author_id = u.id 
            WHERE p.post_id = ?
        """, (post_id,))
        
        post = cursor.fetchone()
        if not post:
            return jsonify({'success': False, 'message': '게시글을 찾을 수 없습니다.'}), 404
        
        post_data = {
            'post_id': post['post_id'],
            'title': post['title'],
            'content': post['content'],
            'author_id': post['author_id'],
            'author_name': post['author_name'],
            'created_at': post['created_at']
        }
        
        return jsonify({'success': True, 'post': post_data}), 200
    
    except sqlite3.Error as e:
        print(f"Database error during post retrieval: {e}")
        return jsonify({'success': False, 'message': '게시글을 불러오는 중 오류가 발생했습니다.'}), 500

@app.route('/api/posts', methods=['POST'])
def create_post():
    """새 게시글 작성 API"""
    # 로그인 확인
    if g.user is None:
        return jsonify({'success': False, 'message': '로그인이 필요합니다.'}), 401
    
    data = request.json
    if not data:
        return jsonify({'success': False, 'message': '데이터가 제공되지 않았습니다.'}), 400
    
    title = data.get('title')
    content = data.get('content')
    
    if not title or not content:
        return jsonify({'success': False, 'message': '제목과 내용을 모두 입력해주세요.'}), 400
    
    db = get_db()
    cursor = db.cursor()
    
    try:
        cursor.execute(
            "INSERT INTO board (title, content, author_id) VALUES (?, ?, ?)",
            (title, content, g.user['id'])
        )
        db.commit()
        
        # 새로 생성된 게시글의 ID 가져오기
        post_id = cursor.lastrowid
        
        return jsonify({
            'success': True, 
            'message': '게시글이 성공적으로 작성되었습니다.',
            'post_id': post_id
        }), 201
    
    except sqlite3.Error as e:
        print(f"Database error during post creation: {e}")
        db.rollback()
        return jsonify({'success': False, 'message': '게시글 작성 중 오류가 발생했습니다.'}), 500

@app.route('/reset_password', methods=['POST'])
def reset_password():
    """Handles password reset requests using ID and SSN."""
    # ... (existing validation and DB logic remains the same) ...
    # ... (Includes the simulated SQL Injection and plain password reset to user_id) ...
    # ... (Ensure this logic correctly updates the DB using execute with parameters) ...
    # Note: The simulated SQL injection happens in the check `if "' OR '1'='1" in ssn:`
    # The subsequent UPDATE query *should* use parameterized execution `cursor.execute("UPDATE users SET password = ? WHERE id = ?", (new_password, user_id))`
    # which prevents *actual* injection in the UPDATE, but the logic flow is still vulnerable
    # because the SSN check is bypassed.
    # ... (Add logging for reset attempts) ...
    data = request.json
    # ... validation ...
    db = get_db()
    cursor = db.cursor()
    # ... user check by id ...
    # ... simulated SSN check / injection ...
    # ... password reset logic ...
    try:
         # Assuming user_id and new_password (which is user_id) are determined by logic above
         cursor.execute("UPDATE users SET password = ? WHERE id = ?",
                       (new_password, user_id))
         db.commit()
         print(f"Password reset successfully for user '{user_id}'.")
         message = "비밀번호가 초기화되었습니다. 새 비밀번호는 사용자 아이디와 동일합니다."
         # If injection was simulated, provide a different message as in the original HTML
         if data and data.get('ssn') and "' OR '1'='1" in data['ssn']: # Check against input ssn
              message = "SQL 인젝션 공격 성공 시뮬레이션! 비밀번호가 초기화되었습니다."
         return jsonify({'success': True, 'message': message}), 200
    except sqlite3.Error as e:
        print(f"Database error during password reset for user '{user_id}': {e}")
        db.rollback()
        return jsonify({'success': False, 'message': '비밀번호 초기화 중 오류가 발생했습니다.'}), 500


# --- Helper to require login for certain routes ---
# Not used as a decorator here, but checked explicitly in route functions
# Example:
# def login_required(view):
#     @functools.wraps(view)
#     def wrapped_view(**kwargs):
#         if g.user is None:
#             return redirect(url_for('login_page'))
#         return view(**kwargs)
#     return wrapped_view


if __name__ == '__main__':
    # Running with debug=True allows code changes to auto-reload
    # In production, use a production WSGI server (like Gunicorn or uWSGI)
    app.run(host='0.0.0.0', debug=True)