# Zero-Knowledge Verification Workflow

## Objective
To verify file integrity without uploading the entire file or exposing its sensitive content to the server.

## Workflow Overview

1.  **Initiation**:
    -   User selects a file in the browser.
    -   Client sends the **File Name** and **File Size** to the server.

2.  **Challenge Generation (Server-Side)**:
    -   Server looks up the stored `IntegrityProfile` for the file.
    -   Server generates a **Challenge Vector**: A random selection of Block Indices (e.g., 50 random blocks out of 1000).
    -   Server sends this list of `block_indices` and a `nonce` to the client.

3.  **Local Processing (Client-Side)**:
    -   Browser uses the File API (`FileReader`) to read *only* the requested 4KB chunks based on the indices.
    -   Client calculates SHA-256 hash for each requested chunk.
    -   Client constructs a response: `{ block_index: hash, ... }`.
    -   *Optional*: Client can salt the hashes with the `nonce` to prevent replay attacks, but since the server needs to compare with stored raw hashes, this requires the server to also salt its stored hashes dynamically for comparison.
        -   *Better Approach*: `HMAC(stored_hash, nonce)` vs `HMAC(calculated_hash, nonce)`.

4.  **Verification (Server-Side)**:
    -   Server receives the list of hashes.
    -   Server compares them against the stored `chunk_hashes` for those specific indices.
    -   If all match, the server returns a "Verified" status.
    -   If any mismatch, the server flags the file as compromised.

## Benefits
-   **Privacy**: The server never receives the file content, only hashes of random blocks.
-   **Bandwidth Efficiency**: Only small hashes are transferred, not the multi-gigabyte file.
-   **Speed**: Verification is near-instantaneous.

## Implementation Details (Draft)

### API Endpoints

-   `POST /api/initiate-verification/`
    -   Input: `{ filename: "secret.pdf", filesize: 102400 }`
    -   Output: `{ challenge_id: "xyz", blocks: [0, 5, 12, ...] }`

-   `POST /api/verify-challenge/`
    -   Input: `{ challenge_id: "xyz", responses: { "0": "hash...", "5": "hash..." } }`
    -   Output: `{ verified: true/false, confidence: 100 }`

### Client-Side Logic (JavaScript)

```javascript
async function handleVerification(file) {
    // 1. Initiate
    const initResponse = await fetch('/api/initiate-verification/', {
        method: 'POST',
        body: JSON.stringify({ filename: file.name, filesize: file.size })
    });
    const challenge = await initResponse.json();

    // 2. Process Blocks
    const responses = {};
    for (const index of challenge.blocks) {
        const start = index * 4096;
        const end = start + 4096;
        const blob = file.slice(start, end);
        const buffer = await blob.arrayBuffer();
        const hashBuffer = await crypto.subtle.digest('SHA-256', buffer);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
        responses[index] = hashHex;
    }

    // 3. Send Proof
    const verifyResponse = await fetch('/api/verify-challenge/', {
        method: 'POST',
        body: JSON.stringify({ challenge_id: challenge.challenge_id, responses })
    });
    
    const result = await verifyResponse.json();
    console.log("Verification Result:", result);
}
```
