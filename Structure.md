# System Design & Architecture Documentation

This document outlines the architectural blueprints, data flows, and design diagrams for the **Forensic Intelligence (File Integrity System)**. It is designed to be used for project presentations, technical documentation, and system analysis.

## 1. System Design Architecture (High Level)

The system follows the **Django MVT (Model-View-Template)** architecture, which is a variation of the MVC pattern.

*   **Model**: Manages the data schema (`IntegrityProfile`) and database interactions.
*   **View**: Handles business logic, file processing, and cryptographic analysis (`views.py`, `utils.py`).
*   **Template**: Renders the user interface (`landing.html`, `result.html`).

### Component Diagram
```mermaid
graph TD
    User[User] -->|"HTTPS Request"| LoadBalancer["Web Server / Load Balancer"]
    LoadBalancer -->|"WSGI/ASGI"| Django["Django Application"]
    subgraph "Core Module"
        Django -->|Routing| Views["Views (Logic)"]
        Views -->|Forensics| Logic["Utils (Hashing/Entropy)"]
        Views -->|ORM| Models["Models (Data Layer)"]
    end
    Models -->|SQL| DB[("PostgreSQL/SQLite")]
    Views -->|Render| UI["Templates (HTML/CSS)"]
    UI -->|Response| User
```

---

## 2. Data Flow Diagram (DFD)

### Level 0 (Context Diagram)
```mermaid
graph LR
    User[User] -- "Uploads File" --> System("File Integrity System")
    System -- "Returns Integrity Report" --> User
    System -- "Stores Metadata" --> DB[("Database")]
```

### Level 1 (Process Decomposition)
```mermaid
graph TD
    User[User] -->|"1. Upload File"| Process1("Input Validation")
    Process1 -->|"2. Valid File Stick"| Process2("Cryptographic Engine")
    Process2 -->|"3. Streaming Read (4KB Chunks)"| Process3("Calculate SHA-256 & Entropy")
    
    Process3 -->|"4a. Registration"| DBStep("Save Integrity Profile")
    DBStep --> DB[("Database")]
    
    Process3 -->|"4b. Verification"| FetchStep("Fetch Existing Profile")
    DB --> FetchStep
    FetchStep --> Compare("Heuristic Comparison Engine")
    Compare --> Report("Generate Heatmap & Report")
    Report --> User
```

---

## 3. Entity Relationship (ER) Diagram

Since this is a privacy-focused system, we only store **metadata**, not the actual files.

```mermaid
erDiagram
    INTEGRITY_PROFILE {
        int id PK
        string file_name "Original filename"
        bigint file_size "Size in bytes"
        string full_hash "SHA-256 of entire file"
        json chunk_hashes "Array of 4KB block hashes"
        json chunk_entropies "Array of entropy floats"
        string file_header "Magic bytes (Hex)"
        datetime created_at "Timestamp"
    }
```

---

## 4. Project Schedule (Gantt Chart)

A typical timeline for the development of this Mini Project.

```mermaid
gantt
    title File Integrity System Development Timeline
    dateFormat  YYYY-MM-DD
    section Phase 1: Planning
    Requirement Analysis   :active, 2025-11-01, 7d
    System Design & UML    :2025-11-08, 5d
    section Phase 2: Core Dev
    Project Setup (Django) :2025-11-13, 2d
    Backend Logic (Hashing):2025-11-15, 5d
    Database Integration   :2025-11-20, 3d
    section Phase 3: Frontend
    UI Design (Landing)    :2025-11-23, 4d
    Result Visualization   :2025-11-27, 4d
    section Phase 4: Testing & Docs
    Integration Testing    :2025-12-01, 3d
    Documentation (Reports):2025-12-04, 3d
```

---

## 5. UML Diagrams

### A. Use Case Diagram
Describes the user's interaction with the system.

*(Note: Modeled using Graph syntax for compatibility)*

```mermaid
graph LR
    User((User))
    subgraph "File Integrity System"
        UC1("Register File (Create Profile)")
        UC2("Verify File Integrity")
        UC3("View Forensic Report")
        UC4("Analyze Entropy Heatmap")
    end
    User --> UC1
    User --> UC2
    UC2 -.->|include| UC3
    UC3 -.->|include| UC4
```

### B. Sequence Diagram (Verification Flow)
Detailed flow of messages during a file verification process.

```mermaid
sequenceDiagram
    participant User
    participant Browser
    participant View as View (Django)
    participant Utils as Utils (Logic)
    participant Database

    User->>Browser: Uploads File for Verification
    Browser->>View: POST /verify_integrity
    View->>Database: Query Profile (by filename)
    Database-->>View: Return IntegrityProfile object
    
    alt Profile Not Found
        View-->>Browser: Error: File not registered
    else Profile Found
        loop For each 4KB Chunk
            View->>Utils: Read Chunk
            Utils->>Utils: Calculate Hash & Entropy
        end
        View->>Utils: compare_hashes(stored, current)
        Utils-->>View: Comparison Result (Heatmap Data)
        View-->>Browser: Render Result.html
        Browser-->>User: Display Integrity Report
    end
```

### C. Class Diagram
Represents the code structure and relationships.

```mermaid
classDiagram
    class IntegrityProfile {
        +String file_name
        +BigInt file_size
        +String full_hash
        +JSON chunk_hashes
        +JSON chunk_entropies
        +String file_header
        +DateTime created_at
        +__str__()
    }

    class LogicUtils {
        +CHUNK_SIZE: 4096
        +calculate_entropy(data)
        +generate_file_hashes(file_obj)
        +classify_anomaly(original, current)
        +compare_hashes(profile, file_data)
    }

    class CoreViews {
        +index(request)
        +register_integrity(request)
        +verify_integrity(request)
    }

    CoreViews ..> IntegrityProfile : uses
    CoreViews ..> LogicUtils : calls
```

### D. Activity Diagram
The logic flow for deciding if a file is safe or corrupted.

```mermaid
flowchart TD
    Start([Start]) --> Upload[User Uploads File]
    Upload --> Check[Check DB for Profile]
    Check -- Not Found --> Error[Show Error]
    Check -- Found --> Hash[Stream & Hash File]
    Hash --> Compare{Compare Hashes}
    
    Compare -- Match --> Safe[Result: VALID]
    Compare -- Mismatch --> Analyze[Analyze Entropies]
    
    Analyze --> CheckEntropy{Entropy Diff?}
    CheckEntropy -- "High Spike" --> Ransom[Detect: Ransomware]
    CheckEntropy -- "No Change" --> BitRot[Detect: Bit-Rot]
    CheckEntropy -- "Stable Header" --> Trojan[Detect: Injection]
    
    Ransom --> Report[Generate Report]
    BitRot --> Report
    Trojan --> Report
    Safe --> Report
    Report --> End([End])
```
