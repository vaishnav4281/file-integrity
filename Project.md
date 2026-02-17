# Project Overview: FORENSIC INTELLIGENCE (File Integrity System)

This project is a Django-based web application designed for advanced file integrity verification. Unlike simple checksum tools, it analyzes the *structure* of file changes using block-level hashing (SHA-256) and Shannon Entropy to distinguish between various types of data corruption (Bit-Rot, Ransomware, Trojan Injection).

**Key Philosophy:** Zero-Knowledge. Validates file integrity without permanently storing the user's files.

## 📂 Project Directory Structure

```text
.
├── build.sh                 # Script for building/deploying the project
├── manage.py                # Django's command-line utility for administrative tasks
├── requirements.txt         # Python dependencies list
├── vercel.json              # Configuration file for Vercel deployment
├── README.md                # Project documentation and start guide
├── file_integrity/          # Project-level configuration directory
│   ├── __init__.py          # Marks directory as a Python package
│   ├── asgi.py              # ASGI config for asynchronous web servers (Daphne, Uvicorn)
│   ├── settings.py          # Global settings (DB, Apps, Middleware, Security)
│   ├── urls.py              # Root URL routing configuration
│   └── wsgi.py              # WSGI config for synchronous web servers (Gunicorn)
└── core/                    # Main application containing business logic
    ├── __init__.py
    ├── admin.py             # Configuration for the Django Admin interface
    ├── apps.py              # Application configuration
    ├── models.py            # Database schema definition (IntegrityProfile)
    ├── urls.py              # App-specific URL routing
    ├── utils.py             # Core cryptographic and forensic logic
    ├── views.py             # Request handlers (Controllers)
    ├── migrations/          # Database schema evolution files
    └── templates/           # HTML templates for the UI
        ├── base.html        # Base layout template
        └── core/            # App-specific templates
            ├── landing.html # Home/Registration page
            └── result.html  # Verification results page (assumed based on views)
```

## 📄 Detailed File Explanations

### Root Directory

- **`manage.py`**: The entry point for interacting with the Django project. Used to run the server, apply migrations, and create superusers.
- **`requirements.txt`**: Lists all external Python libraries required to run the project (e.g., `Django`, `chart.js` headers if any, etc.).
- **`build.sh`**: A shell script likely used during the deployment process (e.g., on Vercel) to install dependencies and run migrations.
- **`vercel.json`**: specific configuration for deploying the Django app to the Vercel serverless platform.

### `file_integrity/` (Project Configuration)

- **`settings.py`**: The heart of the configuration. Contains database credentials, installed apps, middleware settings, security keys, and static file configurations.
- **`urls.py`**: The main entry point for URL routing. It delegates specific routes (like `/`) to the `core` application.
- **`wsgi.py` / `asgi.py`**: Interface files used by web servers to serve the project in production environments.

### `core/` (Application Logic)

This is where the actual functionality lives.

#### `models.py`
Defines the `IntegrityProfile` model, which acts as the digital fingerprint of a file. It verifies files *without* storing them by saving:
- `full_hash`: SHA-256 hash of the entire file.
- `chunk_hashes`: List of hashes for every 4KB block.
- `chunk_entropies`: List of Shannon Entropy values for every 4KB block.
- `file_header`: The first few bytes of the file (Magic Bytes) to detect file type tampering.

#### `utils.py` (The "Brain")
Contains the heavy computational logic:
- **`calculate_entropy(data)`**: Computes the randomness of a byte block. High entropy (> 7.5) indicates encryption/compression; low entropy indicates text/padding.
- **`generate_file_hashes(file_obj)`**: Reads a file in 4KB chunks, generating a hash and entropy score for each chunk.
- **`compare_hashes(...)`**: Compares a live file against a stored `IntegrityProfile`. It generates the "Heatmap" data and detects mismatches.
- **`classify_anomaly(...)`**: A heuristic decision matrix that looks at hash mismatches, entropy changes, and size differences to label threats (e.g., "Ransomware" vs. "Bit-Rot" vs. "Trojan").

#### `views.py`
Hanldes HTTP requests from the browser:
- **`index`**: Renders the landing page.
- **`register_integrity`**: Handles file uploads for *registration*. It calculates hashes using `utils.py` and saves a new `IntegrityProfile` to the database.
- **`verify_integrity`**: Handles file uploads for *verification*. It fetches the previously saved profile, calculates new hashes for the uploaded file, and compares them using `utils.compare_hashes`.

#### `urls.py`
Maps browser URL paths (e.g., `/register`, `/verify`) to the specific python functions in `views.py`.

#### `admin.py`
Registers the `IntegrityProfile` model with the Django Admin panel, allowing administrators to inspect stored file profiles directly.
