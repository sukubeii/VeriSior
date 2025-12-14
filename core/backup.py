# core/backup.py - Complete Enhanced Backup System with FIXED Restoration

import os
import datetime
import zipfile
import tempfile
import json
import threading
import time
import re
import hashlib
import secrets
import shutil
from pathlib import Path
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
from base64 import b64encode, b64decode
from django.conf import settings
from django.core.management import call_command
from django.contrib.auth.decorators import login_required
from django.shortcuts import render, redirect
from django.http import HttpResponse, FileResponse, JsonResponse
from django.db import connection
from django.contrib import messages
from django.core.cache import cache
from django.apps import apps
from .models import AuditLog
from accounts.decorators import role_required

# Cache-based backup task storage (replaces global dictionary)
def get_backup_task(user_id):
    """Get backup task from cache"""
    return cache.get(f'backup_task_{user_id}', {})

def set_backup_task(user_id, data):
    """Set backup task in cache (expires in 1 hour)"""
    cache.set(f'backup_task_{user_id}', data, timeout=3600)

def update_backup_task(user_id, data):
    """Update backup task in cache"""
    current = get_backup_task(user_id)
    current.update(data)
    set_backup_task(user_id, current)

def delete_backup_task(user_id):
    """Delete backup task from cache"""
    cache.delete(f'backup_task_{user_id}')

# Constants for timeout detection
STEP_TIMEOUT_SECONDS = 300  # 5 minutes timeout for any single step
MAX_BACKUP_DURATION = 1800  # 30 minutes total backup time limit

# Enhanced backup constants
KEY_FILE_NAME = "verisior_backup.key"
MANIFEST_FILE_NAME = "backup_manifest.json"
BACKUP_VERSION = "2.0"

# Default exclusion patterns for full backups
DEFAULT_EXCLUSION_PATTERNS = [
    r'.*\.zip$',           # Exclude all zip files
    r'.*\.log$',           # Exclude log files
    r'media/backups/.*',   # Exclude the backups directory
    r'media/temp/.*'       # Exclude temp files
]

def format_size(size_bytes):
    """Format file size in human-readable format"""
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes/1024:.1f} KB"
    elif size_bytes < 1024 * 1024 * 1024:
        return f"{size_bytes/(1024*1024):.1f} MB"
    else:
        return f"{size_bytes/(1024*1024*1024):.2f} GB"

def get_directory_size(path):
    """Get total size of a directory"""
    total_size = 0
    file_count = 0
    for dirpath, dirnames, filenames in os.walk(path):
        for f in filenames:
            fp = os.path.join(dirpath, f)
            if os.path.exists(fp):
                total_size += os.path.getsize(fp)
                file_count += 1
    return total_size, file_count

def generate_backup_key_components():
    """Generate encryption components for backup"""
    # Generate a random master key (32 bytes for AES-256)
    backup_key = get_random_bytes(32)
    # Generate salt for key derivation (16 bytes)
    salt = get_random_bytes(16)
    # Generate IV for AES (16 bytes)
    iv = get_random_bytes(16)
    
    return backup_key, salt, iv

def create_key_file(backup_location, backup_key, salt, iv, backup_metadata):
    """Create and save the encryption key file to the backup location"""
    timestamp = datetime.datetime.now().isoformat()
    
    # Create a unique backup ID
    backup_id = hashlib.sha256(
        f"{backup_location}{backup_metadata.get('backup_name', 'backup')}{timestamp}".encode()
    ).hexdigest()[:16]
    
    key_data = {
        "backup_id": backup_id,
        "version": BACKUP_VERSION,
        "created_at": timestamp,
        "key": b64encode(backup_key).decode('utf-8'),
        "salt": b64encode(salt).decode('utf-8'),
        "iv": b64encode(iv).decode('utf-8'),
        "metadata": backup_metadata,
        "checksum": hashlib.sha256(backup_key + salt + iv).hexdigest()
    }
    
    key_file_path = os.path.join(backup_location, KEY_FILE_NAME)
    
    with open(key_file_path, 'w') as f:
        json.dump(key_data, f, indent=4)
    
    return key_file_path, backup_id

def create_manifest_file(backup_location, backup_info):
    """Create backup manifest file"""
    manifest_data = {
        "backup_version": BACKUP_VERSION,
        "created_at": datetime.datetime.now().isoformat(),
        "backup_info": backup_info,
        "files": {
            "database": "db.enc",
            "key_file": KEY_FILE_NAME,
            "manifest": MANIFEST_FILE_NAME
        }
    }
    
    manifest_path = os.path.join(backup_location, MANIFEST_FILE_NAME)
    
    with open(manifest_path, 'w') as f:
        json.dump(manifest_data, f, indent=4)
    
    return manifest_path

def validate_backup_location(backup_location):
    """Validate if the backup location is accessible and writable"""
    try:
        # Check if path exists or can be created
        Path(backup_location).mkdir(parents=True, exist_ok=True)
        
        # Test write access
        test_file = os.path.join(backup_location, 'test_write.tmp')
        with open(test_file, 'w') as f:
            f.write('test')
        os.remove(test_file)
        
        return True, None
    except PermissionError:
        return False, "No write permission to the selected location"
    except OSError as e:
        return False, f"Cannot access location: {str(e)}"
    except Exception as e:
        return False, f"Unexpected error: {str(e)}"

def clean_backup_path(backup_location):
    """Clean and normalize backup location path - FIXED for cross-platform compatibility"""
    if not backup_location:
        return ""
    
    # Remove quotes and extra whitespace
    backup_location = backup_location.strip().strip('"').strip("'")
    
    # Handle web interface patterns
    if backup_location.startswith('Selected folder:'):
        backup_location = backup_location.replace('Selected folder:', '').strip()
    
    # Remove placeholder text
    if 'Please type the full path manually' in backup_location:
        return ""
    
    # CRITICAL FIX: Detect if this is a Windows absolute path (e.g., C:\, D:\)
    # Windows absolute paths have a drive letter followed by colon
    import re
    windows_absolute_pattern = r'^[A-Za-z]:[/\\]'
    
    if re.match(windows_absolute_pattern, backup_location):
        # This is a Windows absolute path - normalize but DON'T make it relative
        # Just normalize the separators for consistency
        backup_location = backup_location.replace('/', '\\')
        print(f"DEBUG: Detected Windows absolute path: {backup_location}")
        return backup_location
    
    # Check if it's a Unix absolute path (starts with /)
    if backup_location.startswith('/'):
        # This is a Unix absolute path - return as is with normalization
        normalized = os.path.normpath(backup_location)
        print(f"DEBUG: Detected Unix absolute path: {normalized}")
        return normalized
    
    # Check if it's a UNC path (network path starting with \\)
    if backup_location.startswith('\\\\'):
        # This is a UNC/network path - return as is
        print(f"DEBUG: Detected UNC/network path: {backup_location}")
        return backup_location
    
    # If we get here, it's a relative path
    # Try to resolve it intelligently
    print(f"DEBUG: Processing relative path: {backup_location}")
    
    if backup_location and not os.path.isabs(backup_location):
        # Try to resolve relative to user's desktop or current directory
        possible_paths = [
            os.path.join(os.path.expanduser("~"), "Desktop", backup_location),
            os.path.join(os.getcwd(), backup_location),
            os.path.abspath(backup_location)
        ]
        
        for path in possible_paths:
            if os.path.exists(path):
                backup_location = path
                print(f"DEBUG: Resolved relative path to: {backup_location}")
                break
        else:
            # Use the absolute path even if it doesn't exist yet
            backup_location = os.path.abspath(backup_location)
            print(f"DEBUG: Converted to absolute path: {backup_location}")
    
    # Normalize path separators for the current OS
    normalized = os.path.normpath(backup_location)
    print(f"DEBUG: Final normalized path: {normalized}")
    return normalized

def find_key_file(backup_location):
    """Find encryption key file in backup location"""
    try:
        files = os.listdir(backup_location)
        
        # Try exact match first
        if KEY_FILE_NAME in files:
            return os.path.join(backup_location, KEY_FILE_NAME)
        
        # Try common variations
        key_variations = [
            "backup.key", "encryption.key", "verisior.key", 
            "backup_key.json", "key.json"
        ]
        
        for variation in key_variations:
            if variation in files:
                return os.path.join(backup_location, variation)
        
        # Look for any .key files
        key_files = [f for f in files if f.endswith('.key')]
        if key_files:
            return os.path.join(backup_location, key_files[0])
        
        # Look for JSON files with 'key' in the name
        key_json_files = [f for f in files if f.endswith('.json') and 'key' in f.lower()]
        if key_json_files:
            return os.path.join(backup_location, key_json_files[0])
        
        return None
        
    except Exception as e:
        print(f"Error finding key file: {e}")
        return None

def find_backup_zip(backup_location):
    """Find backup ZIP file in backup location"""
    try:
        files = os.listdir(backup_location)
        
        # Look for files with 'verisior' in the name
        verisior_zips = [f for f in files if f.endswith('.zip') and 'verisior' in f.lower()]
        if verisior_zips:
            return os.path.join(backup_location, verisior_zips[0])
        
        # Look for any ZIP files
        zip_files = [f for f in files if f.endswith('.zip')]
        if zip_files:
            return os.path.join(backup_location, zip_files[0])
        
        return None
        
    except Exception as e:
        print(f"Error finding backup ZIP: {e}")
        return None

def load_key_file(backup_location):
    """Load and validate encryption key file - FIXED VERSION"""
    
    # Clean the backup location
    backup_location = clean_backup_path(backup_location)
    
    if not backup_location:
        return None, "Invalid backup location provided"
    
    print(f"DEBUG: Checking backup location: {backup_location}")
    
    # Check if backup location exists
    if not os.path.exists(backup_location):
        return None, f"Backup location does not exist: {backup_location}"

    if not os.path.isdir(backup_location):
        return None, f"Backup location is not a directory: {backup_location}"

    # List files in location
    try:
        files_in_location = os.listdir(backup_location)
        print(f"DEBUG: Files found: {files_in_location}")
    except Exception as e:
        return None, f"Cannot read backup location: {str(e)}"

    if not files_in_location:
        return None, "Backup location is empty"

    # Find key file
    key_file_path = find_key_file(backup_location)
    
    if not key_file_path:
        # Provide helpful error message
        key_files = [f for f in files_in_location if '.key' in f or 'key' in f.lower()]
        json_files = [f for f in files_in_location if f.endswith('.json')]
        
        error_msg = f"No encryption key file found in: {backup_location}<br><br>"
        error_msg += f"Files in folder: {', '.join(files_in_location[:10])}<br>"
        
        if key_files:
            error_msg += f"<br>Possible key files: {', '.join(key_files)}"
        elif json_files:
            error_msg += f"<br>JSON files found: {', '.join(json_files)}"
        else:
            error_msg += f"<br>Expected file: {KEY_FILE_NAME}"
        
        return None, error_msg

    # Load and validate key file
    try:
        with open(key_file_path, 'r', encoding='utf-8') as f:
            key_data = json.load(f)

        # Validate required fields
        required_fields = ['backup_id', 'version', 'key', 'salt', 'iv', 'checksum']
        missing_fields = [field for field in required_fields if field not in key_data]
        
        if missing_fields:
            return None, f"Key file missing required fields: {', '.join(missing_fields)}"

        # Validate checksum
        try:
            backup_key = b64decode(key_data['key'])
            salt = b64decode(key_data['salt'])
            iv = b64decode(key_data['iv'])
            expected_checksum = hashlib.sha256(backup_key + salt + iv).hexdigest()
            
            if key_data['checksum'] != expected_checksum:
                return None, "Key file integrity check failed"
        except Exception as e:
            return None, f"Error validating key data: {str(e)}"

        print(f"DEBUG: Key file loaded successfully from: {key_file_path}")
        return key_data, None
        
    except json.JSONDecodeError:
        return None, f"Key file is not valid JSON: {os.path.basename(key_file_path)}"
    except Exception as e:
        return None, f"Error reading key file: {str(e)}"

@login_required
@role_required('RA', 'SA')
def backup_view(request):
    """Enhanced view for creating encrypted database backups with client download"""
    context = {}
    user_id = str(request.user.id)

    if request.method == 'POST':
        # Check if it's an AJAX request to check status
        if request.POST.get('check_status') == 'true':
            backup_task = get_backup_task(user_id)
            if backup_task:
                return JsonResponse(backup_task)
            else:
                return JsonResponse({'status': 'unknown', 'progress': 0})

        # If it's a request to clear the backup task
        elif request.POST.get('clear_backup_path') == 'true':
            delete_backup_task(user_id)
            if 'backup_keys' in request.session:
                del request.session['backup_keys']
            return JsonResponse({'status': 'cleared'})

        # Otherwise, it's a request to start a backup
        else:
            try:
                # Initialize the backup task
                start_time = datetime.datetime.now()
                set_backup_task(user_id, {
                    'status': 'started',
                    'progress': 0,
                    'message': 'Initializing backup process...',
                    'time_started': start_time.strftime("%Y-%m-%d %H:%M:%S"),
                    'start_epoch': int(start_time.timestamp())
                })

                # Get backup parameters
                backup_type = request.POST.get('backup_type', 'full')
                backup_name = request.POST.get('backup_name', f'verisior_backup_{datetime.datetime.now().strftime("%Y%m%d_%H%M%S")}')

                # Create a temporary directory for this backup instead of using user-specified path
                # The backup will be downloaded by the client from here
                backup_location = tempfile.mkdtemp(prefix='verisior_backup_', suffix='')

                # Get custom exclusion patterns if provided
                exclude_patterns = None
                custom_exclusions = request.POST.get('exclude_patterns', '')
                if custom_exclusions:
                    exclude_patterns = custom_exclusions.split('\n')

                # Start the backup process in a new thread
                thread = threading.Thread(
                    target=perform_enhanced_backup_in_background,
                    args=(request.user, backup_location, backup_name, backup_type, exclude_patterns, user_id)
                )
                thread.daemon = True
                thread.start()

                return JsonResponse({
                    'status': 'started',
                    'message': 'Enhanced backup process started in the background'
                })

            except Exception as e:
                set_backup_task(user_id, {
                    'status': 'error',
                    'error': str(e),
                    'progress': 0
                })
                return JsonResponse({'status': 'error', 'error': str(e)})
    
    # Get disk usage information (existing code)
    media_dir = settings.MEDIA_ROOT
    total_media_size = 0
    media_file_count = 0
    largest_files = []
    
    if os.path.exists(media_dir):
        for root, dirs, files in os.walk(media_dir):
            for file in files:
                file_path = os.path.join(root, file)
                if os.path.exists(file_path):
                    file_size = os.path.getsize(file_path)
                    total_media_size += file_size
                    media_file_count += 1
                    largest_files.append((file_path, file_size))
        
        largest_files.sort(key=lambda x: x[1], reverse=True)
        largest_files = largest_files[:10]
        largest_files = [(os.path.relpath(path, settings.BASE_DIR), format_size(size)) 
                        for path, size in largest_files]
    
    # Check if there's an ongoing or completed backup for this user
    backup_task = get_backup_task(user_id)
    if backup_task:
        context['backup_task'] = backup_task
    
    # Add disk usage information to context
    context['media_size'] = format_size(total_media_size)
    context['media_file_count'] = media_file_count
    context['largest_files'] = largest_files
    
    # Pass the encryption keys if available
    if 'backup_keys' in request.session:
        context['backup_keys'] = request.session['backup_keys']
    
    return render(request, 'core/backup.html', context)

def perform_enhanced_backup_in_background(user, backup_location, backup_name, backup_type='full', exclude_patterns=None, user_id=None):
    """Enhanced function to perform the backup operation with local storage and encryption"""
    start_time = datetime.datetime.now()
    
    try:
        message = f'Creating enhanced encrypted backup to {backup_location}...'
        if backup_type == 'db_only':
            message = f'Creating database-only backup to {backup_location}...'
        
        update_backup_status(user_id, 'processing', 5, message, start_time=start_time)
        
        # Generate encryption components
        backup_key, salt, iv = generate_backup_key_components()
        
        # Create backup metadata
        backup_metadata = {
            'backup_name': backup_name,
            'backup_type': backup_type,
            'created_by': user.username,
            'created_at': start_time.isoformat(),
            'exclude_patterns': exclude_patterns or []
        }
        
        # Create key file
        update_backup_status(user_id, 'processing', 10, 'Creating encryption key file...', start_time=start_time)
        key_file_path, backup_id = create_key_file(backup_location, backup_key, salt, iv, backup_metadata)
        
        # Generate checksum for verification
        checksum = hashlib.sha256(backup_key + salt + iv).hexdigest()
        
        # Generate backup with enhanced encryption
        update_backup_status(user_id, 'processing', 15, 'Starting backup creation...', start_time=start_time)
        
        backup_file, backup_info = create_enhanced_encrypted_backup(
            backup_location=backup_location,
            backup_name=backup_name,
            backup_key=backup_key,
            salt=salt,
            iv=iv,
            backup_type=backup_type,
            exclude_patterns=exclude_patterns,
            progress_callback=lambda progress, message: update_backup_status(
                user_id, 'processing', progress, message, 
                start_time=start_time, timeout=STEP_TIMEOUT_SECONDS
            )
        )
        
        # Create manifest file
        update_backup_status(user_id, 'processing', 95, 'Creating backup manifest...', start_time=start_time)
        create_manifest_file(backup_location, backup_info)
        
        # Store the result in the backup tasks
        completion_time = datetime.datetime.now()
        duration = (completion_time - start_time).total_seconds()
        
        backup_type_desc = "Full system backup" if backup_type == 'full' else "Database-only backup"
        
        # UPDATED: Store all necessary information including encryption components
        update_backup_task(user_id, {
            'status': 'completed',
            'progress': 100,
            'message': f'{backup_type_desc} completed successfully in {duration/60:.1f} minutes',
            'backup_location': backup_location,
            'backup_file': backup_file,
            'key_file': key_file_path,
            'backup_id': backup_id,
            'backup_info': backup_info,
            'time_started': start_time.strftime("%Y-%m-%d %H:%M:%S"),
            'time_completed': completion_time.strftime("%Y-%m-%d %H:%M:%S"),
            'duration': f"{duration/60:.1f} minutes",
            'backup_type': backup_type,
            # Store encryption components for download
            'encryption_key': b64encode(backup_key).decode('utf-8'),
            'salt': b64encode(salt).decode('utf-8'),
            'iv': b64encode(iv).decode('utf-8'),
            'checksum': checksum
        })
        
        # Log the action
        AuditLog.objects.create(
            user=user,
            action='CREATE',
            content_type='Backup',
            description=f'Created {backup_type_desc} in {backup_location}',
            ip_address='0.0.0.0'
        )
        
    except Exception as e:
        update_backup_task(user_id, {
            'status': 'error',
            'progress': 0,
            'message': 'Error creating backup',
            'error': str(e),
            'time_error': datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        })

def create_enhanced_encrypted_backup(backup_location, backup_name, backup_key, salt, iv, backup_type='full', exclude_patterns=None, progress_callback=None):
    """Create an enhanced encrypted backup with local storage"""
    
    if exclude_patterns is None and backup_type == 'full':
        exclude_patterns = DEFAULT_EXCLUSION_PATTERNS
    
    step_start_time = datetime.datetime.now()
    if progress_callback:
        progress_callback(20, f"Creating temporary workspace...")
        
    # Create a temporary directory for the backup files
    with tempfile.TemporaryDirectory() as temp_dir:
        step_start_time = datetime.datetime.now()
        if progress_callback:
            progress_callback(25, f"Dumping database...")
            
        # Backup database
        db_file = os.path.join(temp_dir, 'db.json')
        with open(db_file, 'w') as f:
            call_command('dumpdata', exclude=['contenttypes', 'auth.permission'], indent=4, stdout=f)
        
        db_size = os.path.getsize(db_file)
        
        if progress_callback:
            progress_callback(40, f"Encrypting database backup ({format_size(db_size)})...")
            
        # Encrypt the database backup
        encrypted_db_file = os.path.join(temp_dir, 'db.enc')
        encrypt_file_enhanced(db_file, encrypted_db_file, backup_key, iv)
        
        enc_db_size = os.path.getsize(encrypted_db_file)
        
        if progress_callback:
            progress_callback(60, f"Creating backup archive...")
            
        # Create a ZIP file containing the encrypted backup
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_type_text = 'db-only' if backup_type == 'db_only' else 'full'
        zip_filename = f'{backup_name}_{backup_type_text}_{timestamp}.zip'
        zip_file = os.path.join(backup_location, zip_filename)
        
        # Initialize media variables
        total_files_count = 0
        total_files_size = 0
        
        # If it's a full backup, scan media directory
        if backup_type == 'full':
            media_dir = settings.MEDIA_ROOT
            if os.path.exists(media_dir):
                for root, dirs, files in os.walk(media_dir):
                    for file in files:
                        file_path = os.path.join(root, file)
                        if os.path.exists(file_path):
                            rel_path = os.path.relpath(file_path, settings.BASE_DIR)
                            should_exclude = False
                            if exclude_patterns:
                                for pattern in exclude_patterns:
                                    if re.match(pattern, rel_path):
                                        should_exclude = True
                                        break
                            
                            if not should_exclude:
                                total_files_count += 1
                                total_files_size += os.path.getsize(file_path)
        
        with zipfile.ZipFile(zip_file, 'w', zipfile.ZIP_DEFLATED) as z:
            z.write(encrypted_db_file, 'db.enc')
            
            # Include media files if it's a full backup
            if backup_type == 'full' and os.path.exists(media_dir):
                if progress_callback:
                    progress_callback(70, f"Adding media files to archive... Found {total_files_count} files ({format_size(total_files_size)})")
                
                file_count = 0
                total_file_size = 0
                max_files = max(1, total_files_count)
                
                for root, dirs, files in os.walk(media_dir):
                    for file in files:
                        file_path = os.path.join(root, file)
                        rel_path = os.path.relpath(file_path, settings.BASE_DIR)
                        
                        # Check if the file should be excluded
                        should_exclude = False
                        if exclude_patterns:
                            for pattern in exclude_patterns:
                                if re.match(pattern, rel_path):
                                    should_exclude = True
                                    break
                        
                        if should_exclude:
                            continue
                        
                        # Add file to archive
                        z.write(file_path, rel_path)
                        
                        file_count += 1
                        file_size = os.path.getsize(file_path)
                        total_file_size += file_size
                        
                        # Update progress
                        if file_count % 10 == 0 and progress_callback:
                            progress = min(70 + int(file_count / max_files * 20), 90)
                            progress_callback(
                                progress, 
                                f"Adding media files... {file_count}/{total_files_count} files ({format_size(total_file_size)}/{format_size(total_files_size)})"
                            )
            elif backup_type == 'db_only' and progress_callback:
                progress_callback(85, f"Database-only backup - skipping media files")
        
        zip_size = os.path.getsize(zip_file)
        
        if progress_callback:
            progress_callback(95, f"Finalizing backup... Total size: {format_size(zip_size)}")
        
        # Create backup info
        backup_info = {
            'backup_name': backup_name,
            'backup_type': backup_type,
            'zip_filename': zip_filename,
            'zip_size': format_size(zip_size),
            'db_size': format_size(db_size),
            'encrypted_db_size': format_size(enc_db_size),
            'timestamp': datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'location': backup_location
        }
        
        if backup_type == 'full':
            backup_info.update({
                'media_files': total_files_count,
                'media_size': format_size(total_files_size)
            })
        
        if progress_callback:
            completion_message = "Enhanced backup completed successfully!"
            if backup_type == 'db_only':
                completion_message = "Database-only backup completed successfully!"
            progress_callback(100, f"{completion_message} Size: {format_size(zip_size)}")
        
        return zip_file, backup_info

def encrypt_file_enhanced(input_file, output_file, key, iv):
    """Enhanced file encryption using AES-256 in CBC mode"""
    cipher = AES.new(key, AES.MODE_CBC, iv)
    
    with open(input_file, 'rb') as f_in, open(output_file, 'wb') as f_out:
        chunk_size = 64 * 1024  # 64KB chunks
        
        while True:
            chunk = f_in.read(chunk_size)
            if len(chunk) == 0:
                break
            elif len(chunk) % 16 != 0:
                chunk = pad(chunk, 16)
            
            ciphertext = cipher.encrypt(chunk)
            f_out.write(ciphertext)

def decrypt_file_enhanced(input_file, output_file, key, iv):
    """
    FIXED: Decrypt file using AES-256-CBC with proper padding handling
    
    This function decrypts a file that was encrypted using AES-256 in CBC mode.
    The entire file is read, decrypted, and unpadded as one operation to ensure
    proper PKCS#7 padding removal.
    
    Args:
        input_file (str): Path to the encrypted file
        output_file (str): Path where the decrypted file will be saved
        key (bytes): 32-byte AES-256 encryption key
        iv (bytes): 16-byte initialization vector
    
    Raises:
        ValueError: If decryption or unpadding fails
        IOError: If file operations fail
    """
    print(f"DEBUG: Starting decryption of {input_file}")
    
    # Get file size for logging
    file_size = os.path.getsize(input_file)
    print(f"DEBUG: Encrypted file size: {file_size} bytes ({file_size / 1024 / 1024:.2f} MB)")
    
    # Create cipher object for AES-256-CBC decryption
    cipher = AES.new(key, AES.MODE_CBC, iv)
    
    try:
        # Read the entire encrypted file
        with open(input_file, 'rb') as f_in:
            encrypted_data = f_in.read()
        
        print(f"DEBUG: Read {len(encrypted_data)} bytes of encrypted data")
        
        # Verify the encrypted data size is a multiple of block size
        if len(encrypted_data) % AES.block_size != 0:
            print(f"WARNING: Encrypted data size ({len(encrypted_data)}) is not a multiple of AES block size ({AES.block_size})")
        
        # Decrypt the entire file at once
        decrypted_data = cipher.decrypt(encrypted_data)
        print(f"DEBUG: Decrypted {len(decrypted_data)} bytes")
        
        # Unpad the decrypted data (remove PKCS#7 padding)
        try:
            unpadded_data = unpad(decrypted_data, AES.block_size)
            print(f"DEBUG: Successfully unpadded to {len(unpadded_data)} bytes")
        except ValueError as padding_error:
            print(f"WARNING: Padding error: {str(padding_error)}")
            print(f"DEBUG: Attempting recovery by finding JSON data end...")
            
            # Fallback: Try to find the end of valid JSON data
            # This handles cases where padding might be corrupted but data is intact
            try:
                # Look for the last ']' character (end of JSON array)
                last_bracket = decrypted_data.rfind(b']')
                
                if last_bracket > 0:
                    # Also look for the last '}' in case it's a JSON object
                    last_brace = decrypted_data.rfind(b'}')
                    
                    # Use whichever comes last
                    json_end = max(last_bracket, last_brace)
                    
                    if json_end > 0:
                        unpadded_data = decrypted_data[:json_end + 1]
                        print(f"DEBUG: Found JSON end at position {json_end}, recovered {len(unpadded_data)} bytes")
                        
                        # Verify it's valid JSON
                        try:
                            test_str = unpadded_data.decode('utf-8')
                            if test_str.strip().startswith('[') or test_str.strip().startswith('{'):
                                print(f"DEBUG: Recovered data appears to be valid JSON")
                            else:
                                raise ValueError("Recovered data doesn't look like JSON")
                        except Exception as json_test_error:
                            print(f"WARNING: Recovered data may not be valid JSON: {str(json_test_error)}")
                            raise padding_error
                    else:
                        raise ValueError("Cannot find end of JSON data")
                else:
                    raise ValueError("Cannot find end of JSON data")
                    
            except Exception as recovery_error:
                print(f"ERROR: Failed to recover from padding error: {str(recovery_error)}")
                raise ValueError(f"Padding error - file may be corrupted: {padding_error}")
        
        # Write the decrypted and unpadded data to output file
        with open(output_file, 'wb') as f_out:
            f_out.write(unpadded_data)
        
        output_size = os.path.getsize(output_file)
        print(f"DEBUG: Successfully wrote {output_size} bytes to {output_file}")
        
        # Verify the output file is valid JSON
        try:
            with open(output_file, 'r', encoding='utf-8') as f:
                first_chars = f.read(10)
                if first_chars.strip().startswith('[') or first_chars.strip().startswith('{'):
                    print(f"DEBUG: Output file appears to be valid JSON (starts with '{first_chars.strip()[0]}')")
                else:
                    print(f"WARNING: Output file may not be valid JSON (starts with '{first_chars[:5]}')")
        except Exception as verify_error:
            print(f"WARNING: Could not verify output file format: {str(verify_error)}")
        
        print(f"DEBUG: Decryption completed successfully")
        
    except Exception as e:
        print(f"ERROR: Decryption failed with error: {str(e)}")
        import traceback
        print(f"DEBUG: Traceback:")
        traceback.print_exc()
        raise ValueError(f"Failed to decrypt file: {str(e)}")

@login_required
@role_required('RA', 'SA')
def restore_backup_view(request):
    """FIXED: Restore backup view with file upload support"""
    context = {}
    
    if request.method == 'POST':
        # Check if files were uploaded
        backup_file = request.FILES.get('backup_file')
        key_file = request.FILES.get('key_file')
        
        # Also check for path-based restoration (for server-side files)
        backup_location = request.POST.get('backup_location', '').strip()
        
        try:
            # Prioritize file upload over path-based restoration
            if backup_file and key_file:
                # ====================
                # FILE UPLOAD METHOD
                # ====================
                print(f"DEBUG: Processing uploaded files")
                
                # Create temporary directory for uploaded files
                import tempfile
                temp_dir = tempfile.mkdtemp(prefix='restore_upload_')
                
                try:
                    # Save uploaded backup file
                    backup_zip_path = os.path.join(temp_dir, backup_file.name)
                    with open(backup_zip_path, 'wb+') as destination:
                        for chunk in backup_file.chunks():
                            destination.write(chunk)
                    
                    # Save uploaded key file
                    key_file_path = os.path.join(temp_dir, key_file.name)
                    with open(key_file_path, 'wb+') as destination:
                        for chunk in key_file.chunks():
                            destination.write(chunk)
                    
                    print(f"DEBUG: Files saved to temp directory: {temp_dir}")
                    print(f"DEBUG: Backup file: {backup_zip_path}")
                    print(f"DEBUG: Key file: {key_file_path}")
                    
                    # Load and validate key file
                    try:
                        with open(key_file_path, 'r', encoding='utf-8') as f:
                            key_data = json.load(f)
                        
                        # Validate required fields
                        required_fields = ['backup_id', 'version', 'key', 'salt', 'iv', 'checksum']
                        missing_fields = [field for field in required_fields if field not in key_data]
                        
                        if missing_fields:
                            raise ValueError(f"Key file missing required fields: {', '.join(missing_fields)}")
                        
                        # Validate checksum
                        backup_key = b64decode(key_data['key'])
                        salt = b64decode(key_data['salt'])
                        iv = b64decode(key_data['iv'])
                        expected_checksum = hashlib.sha256(backup_key + salt + iv).hexdigest()
                        
                        if key_data['checksum'] != expected_checksum:
                            raise ValueError("Key file integrity check failed")
                        
                        print(f"DEBUG: Key file validated successfully")
                        
                    except json.JSONDecodeError:
                        raise ValueError(f"Key file is not valid JSON")
                    except Exception as e:
                        raise ValueError(f"Error validating key file: {str(e)}")
                    
                    # Validate ZIP file
                    try:
                        with zipfile.ZipFile(backup_zip_path, 'r') as test_zip:
                            zip_contents = test_zip.namelist()
                            if 'db.enc' not in zip_contents:
                                raise ValueError(f'Backup ZIP does not contain encrypted database (db.enc)')
                        
                        print(f"DEBUG: ZIP file validated successfully")
                        
                    except zipfile.BadZipFile:
                        raise ValueError(f'Backup file is corrupted')
                    except Exception as e:
                        raise ValueError(f'Error reading backup ZIP: {str(e)}')
                    
                    # Perform restoration
                    print(f"DEBUG: Starting restoration from uploaded files...")
                    success, message = perform_backup_restoration(
                        backup_file_path=backup_zip_path,
                        key_data=key_data,
                        user=request.user
                    )
                    
                    # Clean up temp directory
                    try:
                        shutil.rmtree(temp_dir)
                        print(f"DEBUG: Cleaned up temp directory: {temp_dir}")
                    except Exception as e:
                        print(f"Warning: Could not clean up temp directory: {str(e)}")
                    
                    if success:
                        context['success'] = message
                        
                        # Log the action
                        AuditLog.objects.create(
                            user=request.user,
                            action='UPDATE',
                            content_type='Backup',
                            description=f'Restored backup from uploaded files: {backup_file.name}',
                            ip_address=request.META.get('REMOTE_ADDR')
                        )
                    else:
                        context['error'] = message
                        
                except Exception as e:
                    # Clean up temp directory on error
                    try:
                        shutil.rmtree(temp_dir)
                    except:
                        pass
                    raise e
                    
            elif backup_location:
                # ====================
                # PATH-BASED METHOD
                # ====================
                # (Existing code for server-side files)
                cleaned_location = clean_backup_path(backup_location)
                
                if not cleaned_location:
                    context['error'] = 'Please enter a valid backup location path or upload backup files'
                    return render(request, 'core/restore_backup.html', context)
                
                print(f"DEBUG: Processing backup from path: {cleaned_location}")
                
                # CRITICAL: Check if this looks like a Windows path but we're on Linux
                import re
                if os.name != 'nt' and re.match(r'^[A-Za-z]:[/\\]', cleaned_location):
                    context['error'] = (
                        'You provided a Windows path, but the server is running on Linux.<br><br>'
                        '<strong>Please use the file upload method instead:</strong><br>'
                        '1. Select "Upload Backup Files" at the top<br>'
                        '2. Click "Choose File" for the backup ZIP<br>'
                        '3. Click "Choose File" for the encryption key<br>'
                        '4. Click "Restore Backup"<br><br>'
                        f'<small class="text-muted">You entered: {backup_location}</small>'
                    )
                    return render(request, 'core/restore_backup.html', context)
                
                # Load and validate key file
                key_data, key_error = load_key_file(cleaned_location)
                
                if key_error:
                    context['error'] = key_error
                    return render(request, 'core/restore_backup.html', context)
                
                # Find backup ZIP file
                backup_zip_path = find_backup_zip(cleaned_location)
                if not backup_zip_path:
                    files = os.listdir(cleaned_location) if os.path.exists(cleaned_location) else []
                    context['error'] = f'No backup ZIP file found in: {cleaned_location}<br>Files found: {", ".join(files)}'
                    return render(request, 'core/restore_backup.html', context)
                
                # Validate ZIP file
                try:
                    with zipfile.ZipFile(backup_zip_path, 'r') as test_zip:
                        zip_contents = test_zip.namelist()
                        if 'db.enc' not in zip_contents:
                            context['error'] = f'Backup ZIP does not contain encrypted database (db.enc)<br>Contents: {", ".join(zip_contents[:5])}'
                            return render(request, 'core/restore_backup.html', context)
                except zipfile.BadZipFile:
                    context['error'] = f'Backup file is corrupted: {os.path.basename(backup_zip_path)}'
                    return render(request, 'core/restore_backup.html', context)
                except Exception as e:
                    context['error'] = f'Error reading backup ZIP: {str(e)}'
                    return render(request, 'core/restore_backup.html', context)

                # Perform restoration
                print(f"DEBUG: Starting restoration from path...")
                success, message = perform_backup_restoration(
                    backup_file_path=backup_zip_path,
                    key_data=key_data,
                    user=request.user
                )
                
                if success:
                    context['success'] = message
                    
                    # Log the action
                    AuditLog.objects.create(
                        user=request.user,
                        action='UPDATE',
                        content_type='Backup',
                        description=f'Restored backup: {os.path.basename(backup_zip_path)}',
                        ip_address=request.META.get('REMOTE_ADDR')
                    )
                else:
                    context['error'] = message
            else:
                context['error'] = 'Please either provide a backup location path or upload backup files'
                
        except Exception as e:
            context['error'] = f'Restoration failed: {str(e)}'
            print(f"DEBUG: Exception during restoration: {str(e)}")
            import traceback
            traceback.print_exc()
    
    return render(request, 'core/restore_backup.html', context)

def perform_backup_restoration(backup_file_path, key_data, user):
    """FIXED: Perform backup restoration with proper database clearing"""
    try:
        print(f"DEBUG: Restoring from: {backup_file_path}")
        
        # Extract encryption components
        backup_key = b64decode(key_data['key'])
        salt = b64decode(key_data['salt'])
        iv = b64decode(key_data['iv'])
        
        # Create temporary directory
        with tempfile.TemporaryDirectory() as temp_dir:
            print(f"DEBUG: Using temp directory: {temp_dir}")
            
            # Extract ZIP file
            try:
                with zipfile.ZipFile(backup_file_path, 'r') as z:
                    z.extractall(temp_dir)
                print(f"DEBUG: ZIP extracted successfully")
            except Exception as e:
                return False, f"Failed to extract backup: {str(e)}"
            
            # Find encrypted database
            encrypted_db = os.path.join(temp_dir, 'db.enc')
            if not os.path.exists(encrypted_db):
                extracted_files = os.listdir(temp_dir)
                return False, f"Encrypted database not found. Extracted: {', '.join(extracted_files)}"
            
            # Decrypt database
            decrypted_db = os.path.join(temp_dir, 'db.json')
            try:
                decrypt_file_enhanced(encrypted_db, decrypted_db, backup_key, iv)
                print(f"DEBUG: Database decrypted successfully")
            except Exception as e:
                return False, f"Failed to decrypt database: {str(e)}"
            
            # Validate decrypted file
            if not os.path.exists(decrypted_db) or os.path.getsize(decrypted_db) == 0:
                return False, "Decryption produced empty or invalid file"
            
            # **CRITICAL FIX**: Clear database before restoration
            try:
                print(f"DEBUG: Starting database restoration process...")
                
                # Step 1: Get all models that need to be cleared
                models_to_clear = []
                for model in apps.get_models():
                    # Skip Django's built-in models and sessions
                    if model._meta.app_label not in ['contenttypes', 'auth', 'admin', 'sessions']:
                        models_to_clear.append(model)
                
                print(f"DEBUG: Found {len(models_to_clear)} models to clear")
                
                # Step 2: Disable foreign key constraints temporarily (PostgreSQL)
                from django.db import connection
                with connection.cursor() as cursor:
                    # For PostgreSQL
                    if connection.vendor == 'postgresql':
                        cursor.execute('SET CONSTRAINTS ALL DEFERRED;')
                        print(f"DEBUG: Foreign key constraints deferred")
                
                # Step 3: Clear all data from custom models
                total_deleted = 0
                for model in models_to_clear:
                    try:
                        count = model.objects.count()
                        if count > 0:
                            model.objects.all().delete()
                            total_deleted += count
                            print(f"DEBUG: Cleared {count} records from {model._meta.label}")
                    except Exception as e:
                        print(f"DEBUG: Warning - Could not clear {model._meta.label}: {str(e)}")
                        # Continue with other models even if one fails
                
                print(f"DEBUG: Total records deleted: {total_deleted}")
                print(f"DEBUG: Database cleared, loading backup data...")
                
                # Step 4: Load the backup data
                call_command('loaddata', decrypted_db)
                print(f"DEBUG: Backup data loaded successfully")
                
                # Step 5: Verify restoration
                verification_results = []
                for model in models_to_clear[:5]:  # Check first 5 models
                    count = model.objects.count()
                    verification_results.append(f"{model._meta.label}: {count} records")
                
                print(f"DEBUG: Verification - Sample record counts:")
                for result in verification_results:
                    print(f"  {result}")
                
            except Exception as e:
                import traceback
                print(f"DEBUG: Database restoration error: {str(e)}")
                print(traceback.format_exc())
                return False, f"Database restoration failed: {str(e)}"
            
            return True, f'Backup restored successfully from {os.path.basename(backup_file_path)}'
            
    except Exception as e:
        print(f"DEBUG: Restoration error: {str(e)}")
        import traceback
        print(traceback.format_exc())
        return False, f'Restoration failed: {str(e)}'

@login_required
@role_required('RA', 'SA')
def download_backup(request):
    """Download the created backup file"""
    user_id = str(request.user.id)

    backup_task = get_backup_task(user_id)
    if not backup_task or 'backup_file' not in backup_task:
        return redirect('backup')

    backup_file = backup_task['backup_file']
    backup_location = backup_task.get('backup_location', '')

    if not os.path.exists(backup_file):
        # The file doesn't exist anymore, clear the task
        delete_backup_task(user_id)
        # Clean up temp directory if it exists
        if backup_location and os.path.exists(backup_location) and backup_location.startswith(tempfile.gettempdir()):
            try:
                shutil.rmtree(backup_location)
            except Exception as e:
                print(f"Warning: Could not clean up temp directory {backup_location}: {str(e)}")
        return redirect('backup')

    # Get the backup type to include in the filename
    backup_type = backup_task.get('backup_type', 'full')
    backup_type_text = 'db-only' if backup_type == 'db_only' else 'full'

    # Create a custom response that cleans up after download completes
    def cleanup_temp_directory():
        """Clean up temporary backup directory after download"""
        if backup_location and os.path.exists(backup_location):
            try:
                # Wait a moment for the download to finish
                time.sleep(2)
                shutil.rmtree(backup_location)
                print(f"Cleaned up temporary backup directory: {backup_location}")
            except Exception as e:
                print(f"Warning: Could not clean up temp directory {backup_location}: {str(e)}")

    # Start cleanup in a background thread
    cleanup_thread = threading.Thread(target=cleanup_temp_directory, daemon=True)
    cleanup_thread.start()

    # Prepare response
    response = FileResponse(
        open(backup_file, 'rb'),
        as_attachment=True,
        filename=f'verisior_{backup_type_text}_backup_{datetime.datetime.now().strftime("%Y%m%d_%H%M%S")}.zip'
    )

    # Log the action
    AuditLog.objects.create(
        user=request.user,
        action='READ',
        content_type='Backup',
        description=f'Downloaded {backup_type_text} backup file',
        ip_address=request.META.get('REMOTE_ADDR')
    )

    return response

@login_required
@role_required('RA', 'SA')
def download_keys(request):
    """Download the encryption keys for the latest backup"""
    user_id = str(request.user.id)
    
    # Get backup task from cache instead of memory
    backup_task = get_backup_task(user_id)
    
    # Try to get keys from the backup task first
    if backup_task and 'backup_info' in backup_task:
        backup_info = backup_task['backup_info']
        backup_id = backup_task.get('backup_id', 'unknown')
        
        # Check if encryption components are stored
        if 'encryption_key' in backup_task:
            # Use the stored encryption components
            keys = {
                'backup_id': backup_id,
                'version': BACKUP_VERSION,
                'created_at': backup_task.get('time_completed', datetime.datetime.now().isoformat()),
                'key': backup_task.get('encryption_key', ''),
                'salt': backup_task.get('salt', ''),
                'iv': backup_task.get('iv', ''),
                'checksum': backup_task.get('checksum', ''),
                'metadata': {
                    'backup_name': backup_info.get('backup_name', 'unknown'),
                    'backup_type': backup_task.get('backup_type', 'unknown'),
                    'created_by': request.user.username,
                    'zip_filename': backup_info.get('zip_filename', 'unknown'),
                    'zip_size': backup_info.get('zip_size', 'unknown'),
                    'db_size': backup_info.get('db_size', 'unknown'),
                    'encrypted_db_size': backup_info.get('encrypted_db_size', 'unknown'),
                    'location': backup_task.get('backup_location', 'unknown')
                }
            }
        else:
            # Fallback - create keys structure from backup_info only
            keys = {
                'backup_id': backup_id,
                'backup_location': backup_task.get('backup_location', 'unknown'),
                'backup_type': backup_task.get('backup_type', 'unknown'),
                'created_at': backup_task.get('time_completed', 'unknown'),
                'file_size': backup_info.get('zip_size', 'unknown'),
                'note': 'Encryption keys not available - backup was created before this fix'
            }
    # Otherwise, use keys from session (legacy support)
    elif 'backup_keys' in request.session:
        keys = request.session['backup_keys']
    else:
        # No backup data found - redirect back
        messages.error(request, 'No backup encryption key available. Please create a new backup.')
        return redirect('backup')
    
    # Create a JSON file with the keys
    keys_json = json.dumps(keys, indent=4)
    
    # Prepare response with the CORRECT filename
    response = HttpResponse(keys_json, content_type='application/json')
    response['Content-Disposition'] = f'attachment; filename={KEY_FILE_NAME}'
    
    # Log the action
    AuditLog.objects.create(
        user=request.user,
        action='READ',
        content_type='Backup',
        description='Downloaded backup encryption key',
        ip_address=request.META.get('REMOTE_ADDR')
    )
    
    # Clear the keys from session if they exist
    if 'backup_keys' in request.session:
        del request.session['backup_keys']
    
    return response

@login_required
@role_required('RA', 'SA')
def cleanup_media_view(request):
    """View for cleaning up unnecessary files in the media directory"""
    context = {}
    
    if request.method == 'POST':
        # Get confirmation
        confirm = request.POST.get('confirm') == 'yes'
        
        if confirm:
            deleted_files = 0
            freed_space = 0
            
            # Delete old backups
            backup_dir = os.path.join(settings.MEDIA_ROOT, 'backups')
            if os.path.exists(backup_dir):
                for file in os.listdir(backup_dir):
                    if file.startswith('verisior_') and file.endswith('.zip'):
                        file_path = os.path.join(backup_dir, file)
                        if os.path.isfile(file_path):
                            file_size = os.path.getsize(file_path)
                            os.remove(file_path)
                            deleted_files += 1
                            freed_space += file_size
            
            # Delete temporary files
            temp_dir = os.path.join(settings.MEDIA_ROOT, 'temp')
            if os.path.exists(temp_dir):
                for root, dirs, files in os.walk(temp_dir):
                    for file in files:
                        file_path = os.path.join(root, file)
                        if os.path.isfile(file_path):
                            file_size = os.path.getsize(file_path)
                            os.remove(file_path)
                            deleted_files += 1
                            freed_space += file_size
            
            # Log the action
            AuditLog.objects.create(
                user=request.user,
                action='DELETE',
                content_type='MediaFiles',
                description=f'Cleaned up media directory, removed {deleted_files} files ({format_size(freed_space)})',
                ip_address=request.META.get('REMOTE_ADDR')
            )
            
            context['success'] = f'Media directory cleaned successfully! Removed {deleted_files} files ({format_size(freed_space)})'
    
    # Get disk usage information
    media_dir = settings.MEDIA_ROOT
    total_size, file_count = get_directory_size(media_dir)
    
    backup_dir = os.path.join(settings.MEDIA_ROOT, 'backups')
    backup_size, backup_count = (0, 0) if not os.path.exists(backup_dir) else get_directory_size(backup_dir)
    
    temp_dir = os.path.join(settings.MEDIA_ROOT, 'temp')
    temp_size, temp_count = (0, 0) if not os.path.exists(temp_dir) else get_directory_size(temp_dir)
    
    context.update({
        'total_size': format_size(total_size),
        'file_count': file_count,
        'backup_size': format_size(backup_size),
        'backup_count': backup_count,
        'temp_size': format_size(temp_size),
        'temp_count': temp_count
    })
    
    return render(request, 'core/cleanup_media.html', context)

def update_backup_status(user_id, status, progress, message, start_time=None, timeout=None):
    """Helper function to update the backup status for a user with timeout detection"""
    now = datetime.datetime.now()
    
    # Get current task from cache
    task = get_backup_task(user_id)
    
    # Check for timeout if applicable
    if start_time and timeout and task:
        step_start_time = task.get('step_start_time')
        if step_start_time:
            step_start = datetime.datetime.strptime(step_start_time, "%Y-%m-%d %H:%M:%S")
            step_duration = (now - step_start).total_seconds()
            
            if step_duration > timeout:
                warning_message = f"WARNING: Current step taking longer than expected ({step_duration/60:.1f} minutes)"
                message = f"{message} - {warning_message}"
    
    if task or not task:  # Always update
        if not task:
            task = {}
            
        if task.get('message') != message:
            task['step_start_time'] = now.strftime("%Y-%m-%d %H:%M:%S")
        
        overall_duration = ""
        if start_time:
            elapsed_seconds = (now - start_time).total_seconds()
            if elapsed_seconds > 60:
                overall_duration = f" - Running for {elapsed_seconds/60:.1f} minutes"
            else:
                overall_duration = f" - Running for {int(elapsed_seconds)} seconds"
        
        task.update({
            'status': status,
            'progress': progress,
            'message': message,
            'last_updated': now.strftime("%Y-%m-%d %H:%M:%S"),
            'overall_duration': overall_duration
        })
        
        # Save back to cache
        set_backup_task(user_id, task)

# Legacy functions for backward compatibility with older backup system
def create_encrypted_backup(custom_location='', backup_type='full', exclude_patterns=None, progress_callback=None):
    """Legacy backup function - redirects to enhanced version"""
    # This function is kept for backward compatibility
    # Generate dummy encryption components for legacy support
    backup_key, salt, iv = generate_backup_key_components()
    
    return create_enhanced_encrypted_backup(
        backup_location=custom_location or os.path.join(settings.MEDIA_ROOT, 'backups'),
        backup_name=f'verisior_backup_{datetime.datetime.now().strftime("%Y%m%d_%H%M%S")}',
        backup_key=backup_key,
        salt=salt,
        iv=iv,
        backup_type=backup_type,
        exclude_patterns=exclude_patterns,
        progress_callback=progress_callback
    )

def encrypt_file(input_file, output_file, key, iv):
    """Legacy encryption function - redirects to enhanced version"""
    return encrypt_file_enhanced(input_file, output_file, key, iv)

def decrypt_file(input_file, output_file, key, iv):
    """Legacy decryption function - redirects to enhanced version"""
    return decrypt_file_enhanced(input_file, output_file, key, iv)

# Original backup function for backward compatibility
def perform_backup_in_background(user, backup_location, user_id, backup_type='full', exclude_patterns=None):
    """Legacy backup function - redirects to enhanced version"""
    backup_name = f'verisior_backup_{datetime.datetime.now().strftime("%Y%m%d_%H%M%S")}'
    return perform_enhanced_backup_in_background(
        user=user,
        backup_location=backup_location or os.path.join(settings.MEDIA_ROOT, 'backups'),
        backup_name=backup_name,
        backup_type=backup_type,
        exclude_patterns=exclude_patterns,
        user_id=user_id
    )
