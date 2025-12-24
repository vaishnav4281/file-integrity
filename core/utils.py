
import math
import hashlib

# 4KB chunk size for granular integrity checking (Better for small files)
CHUNK_SIZE = 4 * 1024 

def calculate_entropy(data):
    """
    Calculates the Shannon Entropy of a byte array.
    Returns a float between 0.0 (constant) and 8.0 (completely random).
    """
    if not data:
        return 0.0
    
    entropy = 0
    length = len(data)
    counts = {}
    
    for byte in data:
        counts[byte] = counts.get(byte, 0) + 1
        
    for count in counts.values():
        p_x = count / length
        entropy -= p_x * math.log2(p_x)
        
    return entropy

def generate_file_hashes(file_obj):
    """
    Generates SHA-256 hash for the entire file and for each chunk.
    Also calculates Shannon Entropy for each chunk.
    Does not store the file.
    """
    full_hasher = hashlib.sha256()
    chunk_hashes = []
    chunk_entropies = []
    
    # Ensure we are at the beginning of the file
    if hasattr(file_obj, 'seek'):
        file_obj.seek(0)
    
    file_size = 0
    
    while True:
        chunk = file_obj.read(CHUNK_SIZE)
        if not chunk:
            break
            
        file_size += len(chunk)
        
        # Update full hash
        full_hasher.update(chunk)
        
        # Calculate chunk hash
        chunk_hasher = hashlib.sha256()
        chunk_hasher.update(chunk)
        chunk_hashes.append(chunk_hasher.hexdigest())

        # Calculate chunk entropy
        chunk_entropies.append(round(calculate_entropy(chunk), 4))
        
    return {
        'full_hash': full_hasher.hexdigest(),
        'chunk_hashes': chunk_hashes,
        'chunk_entropies': chunk_entropies,
        'file_size': file_size,
        'first_chunk': file_obj.read(32) if file_size > 0 else b'' # Read small header sample. Wait, we are at end of file.
    }

def generate_file_hashes(file_obj):
    """
    Generates SHA-256 hash for the entire file and for each chunk.
    Also calculates Shannon Entropy for each chunk and extracts header.
    Does not store the file.
    """
    full_hasher = hashlib.sha256()
    chunk_hashes = []
    chunk_entropies = []
    
    # Ensure we are at the beginning of the file
    if hasattr(file_obj, 'seek'):
        file_obj.seek(0)
    
    # Extract Header (first 16 bytes)
    header_bytes = file_obj.read(16)
    file_header = header_bytes.hex().upper()
    file_obj.seek(0) # Reset to start
    
    file_size = 0
    
    while True:
        chunk = file_obj.read(CHUNK_SIZE)
        if not chunk:
            break
            
        file_size += len(chunk)
        
        # Update full hash
        full_hasher.update(chunk)
        
        # Calculate chunk hash
        chunk_hasher = hashlib.sha256()
        chunk_hasher.update(chunk)
        chunk_hashes.append(chunk_hasher.hexdigest())

        # Calculate chunk entropy
        chunk_entropies.append(round(calculate_entropy(chunk), 4))
        
    return {
        'full_hash': full_hasher.hexdigest(),
        'chunk_hashes': chunk_hashes,
        'chunk_entropies': chunk_entropies,
        'file_size': file_size,
        'file_header': file_header
    }

def classify_anomaly(original_meta, current_meta, file_context):
    """
    Heuristic Decision Matrix (The Brain)
    """
    hash_mismatch = original_meta['hash'] != current_meta['hash']
    entropy_delta = abs(current_meta['entropy'] - original_meta['entropy'])
    current_entropy = current_meta['entropy']
    
    size_change = file_context['size_change']
    is_block_0 = original_meta['index'] == 0
    block_0_stable = file_context['block_0_stable']

    # Default Verdict
    verdict = {
        'label': 'Modification',
        'description': 'General data modification detected in this block.',
        'severity': 'medium'
    }

    # Bit-Rot: Hash Mismatch == True AND Size Change == 0 AND Entropy Delta < 0.05
    if hash_mismatch and size_change == 0 and entropy_delta < 0.05:
        verdict = {
            'label': 'Bit-Rot',
            'description': 'Hardware-level Bit-Rot detected. Minimal data loss, no structural threat.',
            'severity': 'low'
        }

    # Injection/Trojan: Hash Mismatch == True AND Size Change > 0 AND Block 0 Entropy is stable
    elif hash_mismatch and size_change > 0 and block_0_stable:
        verdict = {
            'label': 'Trojan/Injection',
            'description': 'Unauthorized Data Insertion. Potential File Binder or Trojan payload.',
            'severity': 'critical'
        }

    # Ransomware/Encryption: Entropy Delta > 1.0 OR Current Entropy > 7.5
    elif entropy_delta > 1.0 or current_entropy > 7.5:
        verdict = {
            'label': 'Ransomware',
            'description': 'Cryptographic Anomaly. Entropy spike suggests block-level encryption.',
            'severity': 'critical'
        }
    
    # Metadata Tampering
    elif is_block_0 and hash_mismatch:
        verdict = {
            'label': 'Header Tamper',
            'description': 'Critical file header modification. May break file execution or hide content.',
            'severity': 'critical'
        }

    return verdict

def compare_hashes(stored_profile, uploaded_file_data):
    """
    Compares stored profile with uploaded file data.
    Includes forensic entropy analysis, hex dumps, and heatmap generation.
    """
    matched_chunks = 0
    total_chunks = len(stored_profile.chunk_hashes)
    upload_chunks = uploaded_file_data['chunk_hashes']
    upload_entropies = uploaded_file_data['chunk_entropies']
    stored_entropies = stored_profile.chunk_entropies
    
    # Default stored entropies to 0.0 if old data doesn't have them
    if not stored_entropies:
        stored_entropies = [0.0] * total_chunks

    min_len = min(total_chunks, len(upload_chunks))
    max_len = max(total_chunks, len(upload_chunks))
    
    detailed_mismatches = []
    heatmap_data = [] # For Task 2: The "Heatmap" Visualization
    
    size_change = uploaded_file_data['file_size'] - stored_profile.file_size
    
    # Check Block 0 stability for context
    block_0_stable = False
    if total_chunks > 0 and len(upload_chunks) > 0:
        if stored_profile.chunk_hashes[0] == upload_chunks[0]:
            block_0_stable = True
        elif abs(stored_entropies[0] - upload_entropies[0]) < 0.05:
             block_0_stable = True

    file_context = {
        'size_change': size_change,
        'block_0_stable': block_0_stable
    }

    full_analysis = []
    
    for i in range(max_len):
        # Determine status for Heatmap and Analysis
        
        # Case 1: Exists in both
        if i < min_len:
            stored_h = stored_profile.chunk_hashes[i]
            uploaded_h = upload_chunks[i]
            stored_e = stored_entropies[i]
            uploaded_e = upload_entropies[i]
            
            entropy_change = round(uploaded_e - stored_e, 4)
            if entropy_change > 0:
                change_summary = f"+{abs(entropy_change):.2f} (Higher)"
            elif entropy_change < 0:
                change_summary = f"-{abs(entropy_change):.2f} (Lower)"
            else:
                change_summary = "0.00 (Stable)"

            start_byte = i * CHUNK_SIZE
            end_byte = start_byte + CHUNK_SIZE
            byte_range = f"{start_byte:,} - {end_byte:,}"

            if stored_h == uploaded_h:
                matched_chunks += 1
                heatmap_data.append({
                    'index': i + 1,
                    'status': 'MATCH',
                    'color': 'bg-success',
                    'tooltip_title': f"Block #{i+1}",
                    'tooltip_body': "Verified Match"
                })
                full_analysis.append({
                    'chunk_index': i + 1,
                    'byte_range': byte_range,
                    'stored_hash': stored_h,
                    'uploaded_hash': uploaded_h,
                    'stored_entropy': stored_e,
                    'uploaded_entropy': uploaded_e,
                    'entropy_delta': entropy_change,
                    'change_summary': change_summary,
                    'anomaly_type': 'Verified',
                    'threat_description': 'Integrity confirmed. No modifications detected.',
                    'severity': 'safe',
                    'status': 'MATCH'
                })
            else:
                # Mismatch Logic
                entropy_delta = abs(uploaded_e - stored_e)
                
                # Heatmap Color Logic
                if uploaded_e > 7.5:
                    color = 'bg-rose' # High Entropy
                    short_status = "High Entropy"
                elif entropy_delta < 0.05: # Low Entropy Change
                    color = 'bg-warning'
                    short_status = "Low Entropy Change"
                else:
                    color = 'bg-rose' # General Mismatch
                    short_status = "Mismatch"
                
                # Classify Anomaly
                verdict = classify_anomaly(
                    {'hash': stored_h, 'entropy': stored_e, 'index': i, 'size': stored_profile.file_size},
                    {'hash': uploaded_h, 'entropy': uploaded_e, 'size': uploaded_file_data['file_size']},
                    file_context
                )
                
                heatmap_data.append({
                    'index': i + 1,
                    'status': 'MISMATCH',
                    'color': color,
                    'tooltip_title': f"Block #{i+1} - {verdict['label']}",
                    'tooltip_body': f"{short_status} (ΔE: {round(entropy_delta, 4)}) - {verdict['description']}"
                })
                
                analysis_item = {
                    'chunk_index': i + 1,
                    'byte_range': byte_range,
                    'stored_hash': stored_h,
                    'uploaded_hash': uploaded_h,
                    'stored_entropy': stored_e,
                    'uploaded_entropy': uploaded_e,
                    'entropy_delta': entropy_change,
                    'change_summary': change_summary,
                    'anomaly_type': verdict['label'],
                    'threat_description': verdict['description'],
                    'severity': verdict['severity'],
                    'status': 'MISMATCH'
                }
                detailed_mismatches.append(analysis_item)
                full_analysis.append(analysis_item)

        # Case 2: Missing in Uploaded (File truncated)
        elif i < total_chunks:
            heatmap_data.append({
                'index': i + 1,
                'status': 'MISSING',
                'color': 'bg-white/10',
                'tooltip_title': f"Block #{i+1} - Truncation",
                'tooltip_body': "Data removed from file (Truncated)"
            })
            # We treat this as a mismatch too
            entropy_change = -stored_entropies[i]
            analysis_item = {
                'chunk_index': i + 1,
                'byte_range': "N/A",
                'stored_hash': stored_profile.chunk_hashes[i],
                'uploaded_hash': "MISSING",
                'stored_entropy': stored_entropies[i],
                'uploaded_entropy': 0.0,
                'entropy_delta': entropy_change,
                'change_summary': f"-{abs(entropy_change):.2f} (Removed)",
                'anomaly_type': "Truncation",
                'threat_description': "Data has been removed from this section of the file.",
                'severity': 'medium',
                'status': 'MISSING'
            }
            detailed_mismatches.append(analysis_item)
            full_analysis.append(analysis_item)

        # Case 3: New in Uploaded (File appended)
        else:
            heatmap_data.append({
                'index': i + 1,
                'status': 'APPENDED',
                'color': 'bg-violet',
                'tooltip_title': f"Block #{i+1} - Appended",
                'tooltip_body': "New data added to the end of the file"
            })
            
            start_byte = i * CHUNK_SIZE
            end_byte = start_byte + CHUNK_SIZE
            
            entropy_change = upload_entropies[i]
            analysis_item = {
                'chunk_index': i + 1,
                'byte_range': f"{start_byte:,} - {end_byte:,}",
                'stored_hash': "N/A",
                'uploaded_hash': upload_chunks[i],
                'stored_entropy': 0.0,
                'uploaded_entropy': upload_entropies[i],
                'entropy_delta': entropy_change,
                'change_summary': f"+{entropy_change:.2f} (New Block)",
                'anomaly_type': "Appended",
                'threat_description': "New data block detected at the end of the file. Potential payload injection.",
                'severity': 'high',
                'status': 'APPENDED'
            }
            detailed_mismatches.append(analysis_item)
            full_analysis.append(analysis_item)

    # File Header Analysis
    header_status = "MATCH"
    if hasattr(stored_profile, 'file_header') and stored_profile.file_header:
        if stored_profile.file_header != uploaded_file_data['file_header']:
             header_status = "MISMATCH (Type Tampering Detected)"
    
    confidence_score = (matched_chunks / max_len) * 100 if max_len > 0 else 0
    
    result_type = "NO_CHANGE"
    if stored_profile.full_hash != uploaded_file_data['full_hash']:
        if confidence_score == 0:
            result_type = "COMPLETE_MODIFICATION"
        else:
            result_type = "PARTIAL_MODIFICATION"
            
    return {
        'result_type': result_type,
        'confidence_score': round(confidence_score, 2),
        'heatmap_data': heatmap_data,
        'total_chunks': max_len,
        'matched_chunks': matched_chunks,
        'detailed_mismatches': detailed_mismatches[:50],
        'full_analysis': full_analysis[:200], # Limit to 200 for UI performance
        'mismatch_count': len(detailed_mismatches),
        'size_diff': size_change,
        'size_diff_abs': abs(size_change),
        'full_entropy_profile': {
            'stored': stored_entropies,
            'uploaded': upload_entropies
        },
        'header_analysis': {
            'stored': stored_profile.file_header if hasattr(stored_profile, 'file_header') else "N/A",
            'uploaded': uploaded_file_data['file_header'],
            'status': header_status
        }
    }

