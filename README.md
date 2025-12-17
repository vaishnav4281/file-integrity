
# Hash-Based File Integrity Verification System

A secure, privacy-preserving web application that verifies file integrity using cryptographic hashes without storing the actual files. Built with Django and Neon PostgreSQL.

## Features
- **Privacy-First**: Files are hashed in memory and never stored on disk.
- **Chunk-Level Analysis**: Detects partial modifications with 64KB granularity.
- **Visual Feedback**: Color-coded results for No Change, Partial Modification, and Complete Tampering.
- **Secure**: Uses SHA-256 caching and secure Postgres storage.

## Setup Instructions

### 1. Prerequisites
- Python 3.10+
- PostgreSQL (or Neon account)

### 2. Installation
Navigate to the project directory:
```bash
cd file_integrity
```

Install dependencies:
```bash
pip install -r requirements.txt
```

### 3. Configuration
1. Rename `.env.example` to `.env`.
2. Open `.env` and add your Neon PostgreSQL connection string:
   ```env
   DATABASE_URL=postgres://user:password@endpoint.neon.tech/dbname?sslmode=require
   ```
   If you don't have one, the system will default to SQLite (for local testing only).

### 4. Database Setup
Initialize the database tables:
```bash
python manage.py makemigrations core
python manage.py migrate
```

### 5. Run Server
Start the development server:
```bash
python manage.py runserver
```

Visit `http://127.0.0.1:8000` in your browser.

## Usage
1. **Register**: Upload a file (max 5MB). The system generates a cryptographic profile.
2. **Verify**: Re-upload the same file later.
   - **Green**: File is authentic.
   - **Yellow**: File has been partially modified.
   - **Red**: File is completely different or tampered with.

## Technology Stack
- **Backend**: Django 5.0, Python
- **Database**: Neon PostgreSQL
- **Frontend**: Tailwind CSS, HTML5
- **Cryptography**: hashlib (SHA-256)
