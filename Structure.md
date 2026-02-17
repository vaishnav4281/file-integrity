# 🏗️ System Architecture & Design Portfolio

**Project:** Forensic Intelligence (File Integrity Verification System)  
**Document Status:** Final  
**Intended Audience:** Evaluators, Developers, and System Architects

---

## 📖 Executive Summary

This document visualizes the internal architecture of our **Privacy-Preserving File Integrity System**. Unlike traditional tools that just check *if* a file changed, our system understands *how* and *where* it changed using **Cryptographic Forensics** (SHA-256 + Shannon Entropy).

**Key Architectural Decisions:**
1.  **Zero-Knowledge Storage**: We only store mathematical fingerprints, never the actual files.
2.  **Granular Analysis**: Files are processed in 4KB chunks, allowing for "Heatmap" visualization.
3.  **Heuristic Logic**: A decision engine classifies anomalies as Bit-Rot, Ransomware, or Injection.

---

## 1. 🏛️ High-Level System Architecture
**"The 10,000-foot view of how the system works."**

We utilize a **Django MVT (Model-View-Template)** architecture. The system is layered to separate user interaction, business logic, and data storage.

### 🎨 Architecture Diagram
```mermaid
graph TD
    classDef client fill:#e1f5fe,stroke:#01579b,stroke-width:2px,color:black;
    classDef server fill:#fff9c4,stroke:#fbc02d,stroke-width:2px,color:black;
    classDef db fill:#f3e5f5,stroke:#7b1fa2,stroke-width:2px,color:black;

    User((👤 User)):::client -->|"HTTPS / Browser"| LoadBalancer["🌐 Web Server"]:::client
    LoadBalancer -->|Request| Django["🦁 Django Core"]:::server

    subgraph "Backend Logic (The Brain)"
        direction TB
        Django -->|"URL Routing"| Views["⚡ Views / Controllers"]:::server
        Views -->|"Forensic Analysis"| Logic["🧠 Utils.py (Hashing & Entropy)"]:::server
        Views -->|"Query Data"| Models["🗃️ Models.py"]:::server
    end

    Models <-->|"Read/Write"| DB[("🛢️ Database")]:::db
    
    Views -->|"Render HTML"| UI["🖥️ Templates (Dashboard & Reports)"]:::client
    UI -->|Response| User

```

**🗣️ Presentation Talking Points:**
*   "The user interacts with a clean web interface."
*   "The heart of the system is the **Utils.py** module, which acts as the 'Forensic Brain'."
*   "The database stores **IntegrityProfiles**—lightweight metadata fingerprints—keeping user data private."

---

## 2. 🔄 Data Flow Diagrams (DFD)
**"How data moves through the system."**

### Level 0: The Context (The Big Picture)
Simple Input/Output flow.
```mermaid
graph LR
    classDef default fill:#fff,stroke:#333,stroke-width:1px,color:black;
    User((👤 User)) -- "1. Upload File" --> System["🛡️ File Integrity System"]
    System -- "2. Calculation" --> Engine(("⚙️ Logic Engine"))
    Engine -- "3. Store Hashes" --> DB[("🛢️ DB")]
    Engine -- "4. Integrity Report" --> User
```

### Level 1: Detailed Process Flow
What happens inside the "Logic Engine"?
```mermaid
graph TD
    classDef default fill:#fff,stroke:#333,stroke-width:1px,color:black;
    input(("📂 Input File")) -->|"Stream Read"| Validator{"Is Valid?"}
    Validator -- No --> Error["❌ Reject"]
    Validator -- Yes --> Chunker["🔪 Split into 4KB Chunks"]
    
    subgraph "Cryptographic Processing"
        Chunker --> Hash["#️⃣ SHA-256 Hashing"]
        Chunker --> Entropy["🎲 Entropy Calculation"]
    end
    
    Hash & Entropy --> Profiler["📝 Build Integrity Profile"]
    
    Profiler -->|"Scenario A: Register"| Save["💾 Save to Database"]
    Profiler -->|"Scenario B: Verify"| Compare{"🔍 Compare w/ Stored"}
    
    Compare -->|Match| ResultOK["✅ Success Report"]
    Compare -->|Mismatch| ResultBad["⚠️ Forensic Heatmap"]
```

---

## 3. 🗂️ Database Design (ER Diagram)
**"How we structure the data."**

We use a flat, efficient schema optimized for fast lookups.

```mermaid
erDiagram
    INTEGRITY_PROFILE {
        int id PK "Unique ID"
        string file_name "e.g. firmware.bin"
        bigint file_size "Size in Bytes"
        string full_hash "Global SHA-256 Fingerprint"
        json chunk_hashes "List of 4KB Block Hashes"
        json chunk_entropies "List of Entropy Scores (0.0-8.0)"
        string file_header "File Magic Bytes (Hex)"
        datetime created_at "Registration Time"
    }
```
**🗣️ Presentation Taking Point:** "Notice the `chunk_entropies` JSON field. This is what allows us to later generate the 'Heatmap' and detect if a specific part of the file was encrypted by ransomware."

---

## 4. 📐 UML Diagrams
**"The formal blueprints of the software."**

### A. Sequence Diagram
**"The timeline of a verification request."**

```mermaid
sequenceDiagram
    autonumber
    participant User as 👤 User
    participant Frontend as 🖥️ Browser
    participant Backend as 🦁 Django View
    participant Logic as 🧠 Utils.py
    participant DB as 🛢️ Database

    User->>Frontend: Uploads "contract.pdf"
    Frontend->>Backend: POST /verify (File Data)
    Backend->>DB: SQL: SELECT * FROM profiles WHERE name="contract.pdf"
    
    alt Profile Not Found
        DB-->>Backend: Empty Result
        Backend-->>Frontend: Error "Please Register First"
    else Profile Found
        DB-->>Backend: Returns JSON Profile
        
        loop For Every 4KB Chunk
            Backend->>Logic: Read Chunk
            Logic->>Logic: Compute SHA-256
            Logic->>Logic: Compute Entropy
        end
        
        Backend->>Logic: compare(stored_data, new_data)
        Logic-->>Backend: Returns Analysis (Heatmap, Threat Level)
        
        Backend-->>Frontend: Render Result.html with Graphs
        Frontend-->>User: Visual Report Displayed
    end
```

### B. Use Case Diagram
**"Who does what?"**

```mermaid
graph LR
    User((👤 User))
    
    subgraph "File Integrity System"
        direction TB
        UC1["📝 Register New File"]
        UC2["🔍 Verify File Integrity"]
        UC3["📊 View Forensic Report"]
        UC4["🌡️ Analyze Entropy Heatmap"]
    end
    
    User -->|Uploads| UC1
    User -->|Uploads| UC2
    UC2 -.->|Includes| UC3
    UC3 -.->|Includes| UC4
    
    style UC1 fill:#e8f5e9,stroke:#2e7d32,stroke-width:2px,color:black
    style UC2 fill:#e3f2fd,stroke:#1565c0,stroke-width:2px,color:black
    style UC3 fill:#fff3e0,stroke:#ef6c00,stroke-width:2px,color:black
    style UC4 fill:#fce4ec,stroke:#c2185b,stroke-width:2px,color:black
```

### C. Class Diagram
**"The code structure."**

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
**"The logic flow for classifying threats."**

```mermaid
flowchart TD
    classDef default fill:#fff,stroke:#333,stroke-width:1px,color:black;
    Start([🚀 Start]) --> Upload[/User Uploads File/]
    Upload --> DBQuery{"Profile Exists?"}
    
    DBQuery -- No --> Error["❌ Error: File Unknown"]
    DBQuery -- Yes --> Process["⚙️ Compute Hash & Entropy"]
    
    Process --> Compare{"Hashes Match?"}
    
    Compare -- Yes --> Safe(["✅ Safe: No Changes"])
    
    Compare -- No --> Analysis["🕵️ Deep Forensic Analysis"]
    
    Analysis --> CheckEntropy{"Check Entropy Delta"}
    
    CheckEntropy -- "Spike (> 7.5)" --> Ransom["💀 DETECTED: Ransomware"]
    CheckEntropy -- "No Change (~ 0.0)" --> BitRot["🍂 DETECTED: Bit-Rot"]
    CheckEntropy -- "Stable Header" --> Trojan["💉 DETECTED: Code Injection"]
    
    Ransom & BitRot & Trojan --> Report["📄 Generate Incident Report"]
    Report --> End([🏁 End])

    style Ransom fill:#ffcdd2,stroke:#b71c1c,color:black
    style BitRot fill:#fff9c4,stroke:#fbc02d,color:black
    style Trojan fill:#ffcc80,stroke:#e65100,color:black
    style Safe fill:#c8e6c9,stroke:#2e7d32,color:black
```
