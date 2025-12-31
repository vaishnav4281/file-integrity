# 🛡️ Block-Level File Integrity Verification for Secure and Private Systems

**FORΞNSIC INTELLIGENCE** is a next-generation file integrity verification system designed for privacy, precision, and forensic depth. Unlike traditional checksum tools that only say "Match" or "Mismatch," Sentinel analyzes the *structure* of the change to determine if it was caused by **Bit-Rot**, **Cyberattacks (Ransomware/Trojans)**, or **Benign Modifications**.

> **Privacy First**: Files are processed in memory using stream-based hashing. We never store your files—only their cryptographic fingerprints.

---

## 🚀 Key Features

### 🧠 The Forensic Brain (Heuristic Decision Matrix)
When a file changes, Sentinel doesn't just alert you; it diagnoses the cause:
-   **Hardware Bit-Rot**: Detects single-bit flips and minor data degradation.
-   **Ransomware Detection**: Identifies high-entropy spikes indicative of encryption.
-   **Trojan/Injection**: Flags unauthorized data insertion while preserving the file header.

### 👁️ Advanced Visualization
-   **Forensic Heatmap**: A 4KB-block visual grid showing exactly where the file is damaged, modified, or appended.
-   **Temporal Entropy Mapping**: Compares the "Shadow Baseline" (original) vs. Current entropy profiles, highlighting "Conflict Zones" where data structure has fundamentally shifted.

### 🔒 Zero-Knowledge Architecture
-   **Granular Hashing**: Files are analyzed in 4KB chunks using SHA-256.
-   **Privacy-Preserving**: Only hashes and entropy metadata are stored. The original file content is discarded immediately after analysis.

### 📊 Professional Reporting
-   **PDF Export**: Generate detailed forensic audit reports for compliance and security reviews.
-   **Confidence Score**: A calculated percentage indicating how much of the file remains authentic.

---

## 🛠️ Tech Stack

-   **Backend**: Python 3, Django 5.0
-   **Frontend**: HTML5, Tailwind CSS, JavaScript
-   **Visualization**: Chart.js (Entropy Graph), CSS Grid (Heatmap)
-   **Cryptography**: SHA-256, Shannon Entropy Algorithms

---

## ⚡ Quick Start (Local Development)

Follow these steps to run Sentinel on your local machine.

### Prerequisites
-   Python 3.10+
-   pip (Python Package Manager)

### Installation

1.  **Clone the Repository**
    ```bash
    git clone https://github.com/yourusername/sentinel-integrity.git
    cd sentinel-integrity
    ```

2.  **Create a Virtual Environment**
    ```bash
    python -m venv venv
    source venv/bin/activate  # On Windows: venv\Scripts\activate
    ```

3.  **Install Dependencies**
    ```bash
    pip install -r requirements.txt
    ```

4.  **Apply Database Migrations**
    ```bash
    python manage.py migrate
    ```

5.  **Run the Development Server**
    ```bash
    python manage.py runserver
    ```

6.  **Access the Application**
    Open your browser and navigate to: `http://127.0.0.1:8000/`

---

## 📖 Usage Guide

1.  **Register a File**:
    -   Upload a critical document (e.g., firmware, contract, database backup).
    -   Sentinel generates a "Cryptographic Profile" (Hashes + Entropy) and stores it.
    -   *Note: The file itself is NOT stored.*

2.  **Verify Integrity**:
    -   Upload the file again (or a modified version) at a later date.
    -   Sentinel compares the live file against the stored profile.

3.  **Analyze Results**:
    -   View the **Verdict** (e.g., "Critical Alert: Cryptographic Anomaly").
    -   Inspect the **Heatmap** to see which specific blocks were altered.
    -   Check the **Entropy Graph** to visualize structural changes.

---

## 🔮 Future Roadmap: Zero-Knowledge Verification

We are drafting a protocol where the server never even receives the file stream. Instead, the server sends a "Challenge" (a list of random block indices), and the client's browser computes the hashes locally. This ensures absolute privacy for highly sensitive data.
*See `zero_knowledge_verification.md` for the technical draft.*

---

## 📄 License

This project is open-source and available under the MIT License.
