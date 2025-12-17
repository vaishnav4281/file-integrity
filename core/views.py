
from django.shortcuts import render, redirect
from django.contrib import messages
from django.http import HttpResponseBadRequest
from .models import IntegrityProfile
from .utils import generate_file_hashes, compare_hashes

MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB

def index(request):
    return render(request, 'core/landing.html')

def register_integrity(request):
    if request.method == 'POST' and request.FILES.get('file'):
        file_obj = request.FILES['file']
        
        if file_obj.size > MAX_FILE_SIZE:
             messages.error(request, "File too large. Max size is 5MB.")
             return redirect('index')
             
        # Generate hashes (in memory)
        try:
            hash_data = generate_file_hashes(file_obj)
        except Exception as e:
            messages.error(request, f"Error processing file: {str(e)}")
            return redirect('index')

        # Check if exists (optional logic: overwrite or create new version? 
        # Requirement says "Fetch stored integrity profile using file name", implies uniqueness or latest.
        # We will create a new one for log/audit, but verify will pick latest.)
        
        profile = IntegrityProfile.objects.create(
            file_name=file_obj.name,
            file_size=hash_data['file_size'],
            full_hash=hash_data['full_hash'],
            chunk_hashes=hash_data['chunk_hashes'],
            chunk_entropies=hash_data['chunk_entropies'],
            file_header=hash_data['file_header']
        )
        
        context = {
            'success': True,
            'profile': profile,
            'action': 'registered'
        }
        return render(request, 'core/landing.html', context)
    
    return redirect('index')

def verify_integrity(request):
    if request.method == 'POST' and request.FILES.get('file'):
        file_obj = request.FILES['file']
        
        if file_obj.size > MAX_FILE_SIZE:
             messages.error(request, "File too large. Max size is 5MB.")
             return redirect('index')
             
        # Find latest profile with this name
        profile = IntegrityProfile.objects.filter(file_name=file_obj.name).order_by('-created_at').first()
        
        if not profile:
            messages.error(request, f"No integrity profile found for '{file_obj.name}'. Please register it first.")
            return redirect('index')
            
        # Generate hashes
        hash_data = generate_file_hashes(file_obj)
        
        # Compare
        result = compare_hashes(profile, hash_data)
        
        context = {
            'verification_result': True,
            'profile': profile,
            'result': result,
            'file_name': file_obj.name
        }
        return render(request, 'core/result.html', context)

    return redirect('index')
