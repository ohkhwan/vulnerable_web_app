# 취약한 웹 애플리케이션 데모 (Vulnerable Web Application Demo)
이 프로젝트는 다양한 웹 취약점을 학습하고 테스트하기 위한 데모용 웹 애플리케이션입니다. (This project is a demo web application for learning and testing various web vulnerabilities.)

## 설치 방법
### 사전 준비 (Prerequisites)
- Python 3
- pip (Python package installer)

### 설치 단계 (Installation Steps)
1.  **저장소 복제 (Clone the repository):**
    ```bash
    git clone <repository_url>
    cd <repository_directory>
    ```
    *(Note: Replace `<repository_url>` and `<repository_directory>` with actual values.)*

2.  **가상 환경 생성 및 활성화 (Create and activate a virtual environment - recommended):**
    ```bash
    python -m venv venv
    # Windows
    venv\Scripts\activate
    # macOS/Linux
    source venv/bin/activate
    ```

3.  **필요한 패키지 설치 (Install required packages):**
    ```bash
    pip install Flask
    ```

4.  **데이터베이스 초기화 (Initialize the database):**
    ```bash
    python create_db.py
    ```
    *이 스크립트는 `users.db` 데이터베이스 파일과 필요한 테이블을 생성합니다. 기본 관리자 계정 (`admin`/`admin`)도 생성됩니다.*

5.  **애플리케이션 실행 (Run the application):**
    ```bash
    python app.py
    ```
    *애플리케이션은 기본적으로 `http://127.0.0.1:5000` 또는 `http://0.0.0.0:5000` 에서 실행됩니다.*

## 주요 기능
이 애플리케이션은 다음 주요 기능을 제공합니다:

### 1. 사용자 관리 (User Management)
*   **회원가입 (User Registration):** 새로운 사용자가 계정을 생성할 수 있습니다. (`/register.html`)
*   **로그인 및 로그아웃 (Login and Logout):** 사용자가 시스템에 로그인하고 로그아웃할 수 있습니다. (`/login.html`, `/logout`)
*   **내 정보 확인 (My Info):** 로그인한 사용자는 자신의 정보를 확인할 수 있습니다. (`/myinfo.html`)
*   **비밀번호 변경 (Password Update):** 로그인한 사용자는 자신의 비밀번호를 변경할 수 있습니다. (`/myinfo.html` 내 기능)
*   **비밀번호 초기화 (Password Reset):** 사용자 ID와 주민등록번호를 이용해 비밀번호를 초기화할 수 있습니다. (`/reset_password.html`)
    *   *주의: 이 기능에는 데모 목적으로 시뮬레이션된 SQL Injection 취약점이 포함되어 있으며, 비밀번호가 사용자 ID로 초기화됩니다.*
*   **관리자 기능 (Admin Features):** 관리자 계정(`admin`/`admin`)으로 로그인 시, 다른 사용자의 정보를 조회할 수 있습니다. (`/user_info_other/<user_id>`)

### 2. 게시판 시스템 (Board System)
*   **게시글 목록 조회 (View Posts):** 전체 게시글 목록을 확인하고 검색할 수 있습니다. (`/board.html`)
*   **게시글 작성 (Write Post):** 로그인한 사용자는 새로운 게시글을 작성할 수 있습니다. (`/write_post.html`)
*   **게시글 상세 조회 (View Post Detail):** 특정 게시글의 내용을 확인할 수 있습니다. (`/post_detail.html`)

### 3. 테스트 및 유틸리티 기능 (Testing and Utility Features)
*   **SSRF (Server-Side Request Forgery) 테스트 페이지 (SSRF Test Page):** SSRF 취약점을 테스트해볼 수 있는 기능을 제공합니다. (`/ssrf_test.html`) (로그인 필요)
*   **테스트 디렉토리 파일 목록 (Test Directory File Listing):** `/test` 디렉토리 내의 파일 및 하위 디렉토리 목록을 보여줍니다. (`/test`)
*   **테스트 파일 다운로드 (Test File Download):** `/test` 디렉토리 내의 파일을 다운로드할 수 있습니다. (`/test/download/<filename>`) (로그인 필요)
*   **CSRF 테스트 엔드포인트 (CSRF Test Endpoint):** CSRF 보호 메커니즘을 테스트하기 위한 POST 엔드포인트입니다. (`/test`) (로그인 필요)
*   **XML 파서 페이지 (XML Parser Page):** 정적 XML 파서 예제 페이지입니다. (`/xml_parser.html`)
*   **리다이렉트 페이지 (Redirect Page):** 정적 리다이렉트 예제 페이지입니다. (`/redirect.html`)
