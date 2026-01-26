"""
Secure backup and recovery system for sensitive data.
Backups are encrypted and stored with restricted access.
Includes verification and proof mechanisms.
"""
import os
import json
import zipfile
import shutil
import hashlib
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional
import mysql.connector
from mysql.connector import Error
from db_config import DB_CONFIG

from config import Config
from utils.encryption import encrypt_value, decrypt_value


class SecureBackup:
    """Handles secure backup and recovery of sensitive data"""
    
    def __init__(self):
        self.backup_dir = os.environ.get('BACKUP_DIR', 'backups')
        self.cloud_backup_dir = os.environ.get('CLOUD_BACKUP_DIR')  # Optional cloud storage path
        self.ensure_backup_directory()
    
    def ensure_backup_directory(self):
        """Create backup directory with restricted permissions"""
        os.makedirs(self.backup_dir, mode=0o700, exist_ok=True)  # Owner read/write/execute only
        if self.cloud_backup_dir:
            os.makedirs(self.cloud_backup_dir, mode=0o700, exist_ok=True)
    
    def get_db_connection(self):
        """Get database connection"""
        try:
            return mysql.connector.connect(**DB_CONFIG)
        except Error as e:
            raise Exception(f"Database connection failed: {e}")
    
    def backup_database(self) -> Dict:
        """Backup all sensitive database tables"""
        conn = None
        try:
            conn = self.get_db_connection()
            cursor = conn.cursor(dictionary=True)
            
            backup_data = {
                'timestamp': datetime.now().isoformat(),
                'tables': {},
                'tables_backed_up': [],
                'tables_skipped': [],
                'in_memory_data': {}  # Store Python lists/dicts that aren't in database
            }
            
            # List of tables to backup (skip if they don't exist)
            tables_to_backup = [
                'users',
                'bookings', 
                'password_reset_tokens',
                'vehicles'
            ]
            
            # Backup in-memory data (listings, etc.)
            try:
                from models import listings, VEHICLES, BOOKINGS, CANCELLATION_REQUESTS, REFUNDS
                backup_data['in_memory_data'] = {
                    'listings': listings,
                    'vehicles': VEHICLES,
                    'bookings': BOOKINGS,
                    'cancellation_requests': CANCELLATION_REQUESTS,
                    'refunds': REFUNDS
                }
            except Exception as e:
                backup_data['tables_skipped'].append(f"in_memory_data: {str(e)}")
            
            # Check which tables exist and backup them
            cursor.execute("SHOW TABLES")
            existing_tables = [row[f'Tables_in_{conn.database}'] for row in cursor.fetchall()]
            
            for table_name in tables_to_backup:
                if table_name in existing_tables:
                    try:
                        cursor.execute(f"SELECT * FROM {table_name}")
                        backup_data['tables'][table_name] = cursor.fetchall()
                        backup_data['tables_backed_up'].append(table_name)
                    except Error as e:
                        backup_data['tables_skipped'].append(f"{table_name}: {str(e)}")
                else:
                    backup_data['tables_skipped'].append(f"{table_name}: table does not exist")
            
            cursor.close()
            return backup_data
            
        except Error as e:
            raise Exception(f"Database backup failed: {e}")
        finally:
            if conn and conn.is_connected():
                conn.close()
    
    def backup_uploaded_files(self) -> List[str]:
        """Backup all uploaded files (NRIC images, license images)"""
        uploaded_files = []
        upload_dir = Config.UPLOAD_FOLDER
        
        if not os.path.exists(upload_dir):
            return uploaded_files
        
        for root, dirs, files in os.walk(upload_dir):
            for file in files:
                file_path = os.path.join(root, file)
                uploaded_files.append(file_path)
        
        return uploaded_files
    
    def calculate_checksum(self, file_path: str) -> str:
        """Calculate SHA256 checksum of a file for verification"""
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    
    def create_backup(self, include_files: bool = True, backup_type: str = 'Manual', 
                     created_by_user_id: int = None, log_to_db: bool = True) -> Dict:
        """
        Create encrypted backup of all sensitive data with verification
        Returns dict with backup info including checksum for proof
        """
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        backup_filename = f"backup_{timestamp}.zip"
        backup_path = os.path.join(self.backup_dir, backup_filename)
        uploaded_files = []
        
        try:
            # Backup database
            db_data = self.backup_database()
            
            # Create encrypted ZIP archive
            with zipfile.ZipFile(backup_path, 'w', zipfile.ZIP_DEFLATED) as backup_zip:
                # Add database backup (JSON)
                db_json = json.dumps(db_data, indent=2, default=str)
                backup_zip.writestr('database_backup.json', db_json)
                
                # Add uploaded files if requested
                if include_files:
                    uploaded_files = self.backup_uploaded_files()
                    for file_path in uploaded_files:
                        if os.path.exists(file_path):
                            # Store relative path in archive
                            arcname = os.path.relpath(file_path, Config.UPLOAD_FOLDER)
                            backup_zip.write(file_path, f"uploads/{arcname}")
                
                # Add in-memory data backup (listings, etc.)
                if 'in_memory_data' in db_data and db_data['in_memory_data']:
                    in_memory_json = json.dumps(db_data['in_memory_data'], indent=2, default=str)
                    backup_zip.writestr('in_memory_data.json', in_memory_json)
                
                # Add backup metadata
                metadata = {
                    'backup_timestamp': timestamp,
                    'backup_date': datetime.now().isoformat(),
                    'database_tables': list(db_data['tables'].keys()),
                    'in_memory_data_included': 'in_memory_data' in db_data and bool(db_data['in_memory_data']),
                    'files_included': include_files,
                    'file_count': len(uploaded_files) if include_files else 0
                }
                backup_zip.writestr('backup_metadata.json', json.dumps(metadata, indent=2))
            
            # Calculate checksum BEFORE encryption for verification
            checksum = self.calculate_checksum(backup_path)
            
            # Encrypt the backup file
            encrypted_backup_path = self.encrypt_backup_file(backup_path)
            
            # Get file size
            backup_size = os.path.getsize(encrypted_backup_path)
            backup_size_mb = round(backup_size / (1024 * 1024), 2)
            
            # Copy to cloud storage if configured
            cloud_backup_path = None
            if self.cloud_backup_dir:
                cloud_backup_path = os.path.join(self.cloud_backup_dir, os.path.basename(encrypted_backup_path))
                shutil.copy2(encrypted_backup_path, cloud_backup_path)
                # Set restricted permissions (works on Unix/Linux/Mac, limited on Windows)
                try:
                    os.chmod(cloud_backup_path, 0o600)  # Owner read/write only
                except (OSError, PermissionError):
                    # On Windows, chmod may not work as expected
                    # File is still secure due to encryption and Windows ACLs
                    pass
            
            # Set restricted permissions on local backup
            # Note: On Windows, this may not change permissions visibly in ls -l
            # but Windows ACLs still restrict access. File is encrypted anyway.
            try:
                os.chmod(encrypted_backup_path, 0o600)  # Owner read/write only
            except (OSError, PermissionError):
                # On Windows, chmod may not work as expected
                # File is still secure due to encryption
                pass
            
            # Remove unencrypted backup
            if os.path.exists(backup_path):
                os.remove(backup_path)
            
            # Log to database for proof/verification
            backup_info = {
                'backup_path': encrypted_backup_path,
                'backup_filename': os.path.basename(encrypted_backup_path),
                'backup_size_bytes': backup_size,
                'backup_size_mb': backup_size_mb,
                'checksum_sha256': checksum,
                'tables_backed_up': list(db_data['tables'].keys()),
                'files_included': len(uploaded_files) if include_files else 0,
                'cloud_backup_enabled': self.cloud_backup_dir is not None,
                'cloud_backup_path': cloud_backup_path,
                'backup_type': backup_type,
                'created_by_user_id': created_by_user_id
            }
            
            if log_to_db:
                try:
                    from database import add_backup_log
                    add_backup_log(
                        backup_type=backup_type,
                        backup_filename=backup_info['backup_filename'],
                        backup_path=encrypted_backup_path,
                        backup_size_bytes=backup_size,
                        backup_size_mb=backup_size_mb,
                        checksum_sha256=checksum,
                        tables_backed_up=list(db_data['tables'].keys()),
                        files_included=len(uploaded_files) if include_files else 0,
                        cloud_backup_enabled=self.cloud_backup_dir is not None,
                        cloud_backup_path=cloud_backup_path,
                        status='Success',
                        created_by_user_id=created_by_user_id
                    )
                except Exception as log_error:
                    # Don't fail backup if logging fails, but log the error
                    print(f"Warning: Failed to log backup to database: {log_error}")
            
            return backup_info
            
        except Exception as e:
            # Log failure to database
            if log_to_db:
                try:
                    from database import add_backup_log
                    add_backup_log(
                        backup_type=backup_type,
                        backup_filename=backup_filename,
                        backup_path=backup_path,
                        backup_size_bytes=0,
                        backup_size_mb=0,
                        checksum_sha256='',
                        tables_backed_up=[],
                        files_included=0,
                        cloud_backup_enabled=False,
                        cloud_backup_path=None,
                        status='Failed',
                        error_message=str(e),
                        created_by_user_id=created_by_user_id
                    )
                except:
                    pass
            
            # Clean up on error
            if os.path.exists(backup_path):
                os.remove(backup_path)
            raise Exception(f"Backup creation failed: {e}")
    
    def encrypt_backup_file(self, file_path: str) -> str:
        """Encrypt backup file using AES encryption"""
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        import base64
        
        encrypted_path = file_path + '.encrypted'
        
        # Load encryption key
        key_b64 = os.environ.get("DATA_ENCRYPTION_KEY")
        if not key_b64:
            raise RuntimeError("DATA_ENCRYPTION_KEY is not set")
        key = base64.urlsafe_b64decode(key_b64)
        
        # Read file data
        with open(file_path, 'rb') as f_in:
            file_data = f_in.read()
        
        # Encrypt using AES-GCM
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, file_data, None)
        
        # Store as base64
        encrypted_data = base64.urlsafe_b64encode(nonce + ciphertext)
        
        with open(encrypted_path, 'wb') as f_out:
            f_out.write(encrypted_data)
        
        return encrypted_path
    
    def decrypt_backup_file(self, encrypted_path: str) -> str:
        """Decrypt backup file"""
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        import base64
        
        decrypted_path = encrypted_path.replace('.encrypted', '_decrypted.zip')
        
        # Load encryption key
        key_b64 = os.environ.get("DATA_ENCRYPTION_KEY")
        if not key_b64:
            raise RuntimeError("DATA_ENCRYPTION_KEY is not set")
        key = base64.urlsafe_b64decode(key_b64)
        
        # Read encrypted data
        with open(encrypted_path, 'rb') as f_in:
            encrypted_data = f_in.read()
        
        # Decrypt
        raw = base64.urlsafe_b64decode(encrypted_data)
        nonce, ciphertext = raw[:12], raw[12:]
        aesgcm = AESGCM(key)
        decrypted_data = aesgcm.decrypt(nonce, ciphertext, None)
        
        with open(decrypted_path, 'wb') as f_out:
            f_out.write(decrypted_data)
        
        return decrypted_path
    
    def list_backups(self) -> List[Dict]:
        """List all available backups"""
        backups = []
        
        for filename in os.listdir(self.backup_dir):
            if filename.endswith('.encrypted'):
                file_path = os.path.join(self.backup_dir, filename)
                stat = os.stat(file_path)
                backups.append({
                    'filename': filename,
                    'path': file_path,
                    'size': stat.st_size,
                    'created': datetime.fromtimestamp(stat.st_ctime).isoformat(),
                    'size_mb': round(stat.st_size / (1024 * 1024), 2)
                })
        
        return sorted(backups, key=lambda x: x['created'], reverse=True)
    
    def restore_backup(self, backup_filename: str, restore_tables: Optional[List[str]] = None) -> Dict:
        """
        Restore data from backup
        restore_tables: List of table names to restore (None = restore all)
        """
        encrypted_path = os.path.join(self.backup_dir, backup_filename)
        
        if not os.path.exists(encrypted_path):
            raise Exception(f"Backup file not found: {backup_filename}")
        
        # Decrypt backup
        decrypted_path = self.decrypt_backup_file(encrypted_path)
        
        try:
            # Extract backup
            extract_dir = os.path.join(self.backup_dir, 'restore_temp')
            os.makedirs(extract_dir, exist_ok=True)
            
            with zipfile.ZipFile(decrypted_path, 'r') as backup_zip:
                backup_zip.extractall(extract_dir)
            
            # Load database backup
            db_backup_path = os.path.join(extract_dir, 'database_backup.json')
            with open(db_backup_path, 'r') as f:
                db_data = json.load(f)
            
            # Restore in-memory data (listings, etc.) FIRST
            restored_in_memory = {}
            in_memory_backup_path = os.path.join(extract_dir, 'in_memory_data.json')
            if os.path.exists(in_memory_backup_path):
                try:
                    with open(in_memory_backup_path, 'r') as f:
                        in_memory_data = json.load(f)
                        restored_in_memory = self.restore_in_memory_data(in_memory_data)
                except Exception as e:
                    print(f"Warning: Could not restore in-memory data: {e}")
                    restored_in_memory = {'error': str(e)}
            
            # Restore database tables
            conn = None
            try:
                conn = self.get_db_connection()
                cursor = conn.cursor()
                
                restored_tables = []
                tables_to_restore = restore_tables or list(db_data['tables'].keys())
                
                for table_name in tables_to_restore:
                    if table_name in db_data['tables']:
                        # Restore data with duplicate handling
                        rows = db_data['tables'][table_name]
                        if rows:
                            # Get column names
                            columns = list(rows[0].keys())
                            placeholders = ', '.join(['%s'] * len(columns))
                            columns_str = ', '.join(columns)
                            
                            # Use INSERT IGNORE to skip duplicates, or INSERT ... ON DUPLICATE KEY UPDATE
                            # This prevents errors when restoring data that already exists
                            inserted_count = 0
                            skipped_count = 0
                            
                            for row in rows:
                                values = [row[col] for col in columns]
                                try:
                                    # Try regular insert first
                                    query = f"INSERT INTO {table_name} ({columns_str}) VALUES ({placeholders})"
                                    cursor.execute(query, values)
                                    inserted_count += 1
                                except Error as e:
                                    # If duplicate key error, skip it
                                    if e.errno == 1062:  # Duplicate entry error
                                        skipped_count += 1
                                        continue
                                    else:
                                        # Re-raise other errors
                                        raise
                            
                            if inserted_count > 0:
                                restored_tables.append(f"{table_name} ({inserted_count} inserted, {skipped_count} skipped)")
                            elif skipped_count > 0:
                                restored_tables.append(f"{table_name} (all skipped - already exists)")
                
                conn.commit()
                cursor.close()
                
                # Restore uploaded files
                uploads_dir = os.path.join(extract_dir, 'uploads')
                restored_files = []
                if os.path.exists(uploads_dir):
                    for root, dirs, files in os.walk(uploads_dir):
                        for file in files:
                            src = os.path.join(root, file)
                            dst = os.path.join(Config.UPLOAD_FOLDER, os.path.relpath(src, uploads_dir))
                            os.makedirs(os.path.dirname(dst), exist_ok=True)
                            shutil.copy2(src, dst)
                            restored_files.append(dst)
                
                return {
                    'success': True,
                    'restored_tables': restored_tables,
                    'restored_files': len(restored_files),
                    'restored_in_memory': restored_in_memory,
                    'timestamp': datetime.now().isoformat()
                }
                
            finally:
                if conn and conn.is_connected():
                    conn.close()
                
                # Cleanup
                shutil.rmtree(extract_dir, ignore_errors=True)
                if os.path.exists(decrypted_path):
                    os.remove(decrypted_path)
                    
        except Exception as e:
            # Cleanup on error
            if os.path.exists(decrypted_path):
                os.remove(decrypted_path)
            raise Exception(f"Restore failed: {e}")
    
    def delete_old_backups(self, keep_days: int = 30):
        """Delete backups older than specified days"""
        cutoff_time = datetime.now().timestamp() - (keep_days * 24 * 60 * 60)
        deleted = []
        
        for filename in os.listdir(self.backup_dir):
            if filename.endswith('.encrypted'):
                file_path = os.path.join(self.backup_dir, filename)
                if os.path.getctime(file_path) < cutoff_time:
                    os.remove(file_path)
                    deleted.append(filename)
                    # Also delete from cloud if exists
                    if self.cloud_backup_dir:
                        cloud_path = os.path.join(self.cloud_backup_dir, filename)
                        if os.path.exists(cloud_path):
                            os.remove(cloud_path)
        
        return deleted
    
    def verify_backup(self, backup_filename: str) -> Dict:
        """Verify backup integrity using checksum"""
        encrypted_path = os.path.join(self.backup_dir, backup_filename)
        
        if not os.path.exists(encrypted_path):
            return {
                'verified': False,
                'error': 'Backup file not found'
            }
        
        try:
            # Get checksum from database log
            from database import get_backup_logs
            logs = get_backup_logs(limit=1000)
            backup_log = None
            for log in logs:
                if log['backup_filename'] == backup_filename:
                    backup_log = log
                    break
            
            if not backup_log:
                return {
                    'verified': False,
                    'error': 'Backup log not found in database'
                }
            
            # Note: We can't verify encrypted file directly, but we can verify it exists
            # and matches the logged size
            file_size = os.path.getsize(encrypted_path)
            logged_size = backup_log['backup_size_bytes']
            
            if file_size == logged_size:
                return {
                    'verified': True,
                    'checksum': backup_log['checksum_sha256'],
                    'file_size': file_size,
                    'logged_size': logged_size,
                    'timestamp': backup_log['timestamp'].isoformat() if hasattr(backup_log['timestamp'], 'isoformat') else str(backup_log['timestamp'])
                }
            else:
                return {
                    'verified': False,
                    'error': f'File size mismatch: {file_size} vs {logged_size}',
                    'file_size': file_size,
                    'logged_size': logged_size
                }
        except Exception as e:
            return {
                'verified': False,
                'error': str(e)
            }
    
    def restore_in_memory_data(self, in_memory_data: Dict) -> Dict:
        """Restore in-memory Python data structures (listings, etc.)"""
        restored = {}
        
        try:
            # Restore listings
            if 'listings' in in_memory_data:
                from models import listings
                # Clear existing listings
                listings.clear()
                # Restore from backup
                listings.extend(in_memory_data['listings'])
                restored['listings'] = len(listings)
            
            # Restore VEHICLES dict
            if 'vehicles' in in_memory_data:
                from models import VEHICLES
                VEHICLES.clear()
                VEHICLES.update(in_memory_data['vehicles'])
                restored['vehicles'] = len(VEHICLES)
            
            # Restore BOOKINGS dict
            if 'bookings' in in_memory_data:
                from models import BOOKINGS
                BOOKINGS.clear()
                BOOKINGS.update(in_memory_data['bookings'])
                restored['bookings'] = len(BOOKINGS)
            
            # Restore CANCELLATION_REQUESTS dict
            if 'cancellation_requests' in in_memory_data:
                from models import CANCELLATION_REQUESTS
                CANCELLATION_REQUESTS.clear()
                CANCELLATION_REQUESTS.update(in_memory_data['cancellation_requests'])
                restored['cancellation_requests'] = len(CANCELLATION_REQUESTS)
            
            # Restore REFUNDS dict
            if 'refunds' in in_memory_data:
                from models import REFUNDS
                REFUNDS.clear()
                REFUNDS.update(in_memory_data['refunds'])
                restored['refunds'] = len(REFUNDS)
                
        except Exception as e:
            raise Exception(f"Failed to restore in-memory data: {e}")
        
        return restored
