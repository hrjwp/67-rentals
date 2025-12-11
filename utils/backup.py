"""
Secure backup and recovery system for sensitive data.
Backups are encrypted and stored with restricted access.
"""
import os
import json
import zipfile
import shutil
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional
import mysql.connector
from mysql.connector import Error

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
            return mysql.connector.connect(
                host="mysql-67rentals-mymail-e67.e.aivencloud.com",
                user="avnadmin",
                password="AVNS_zofo1mZWBotNQUe8XAx",
                database="defaultdb",
                port="11215"
            )
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
                'tables_skipped': []
            }
            
            # List of tables to backup (skip if they don't exist)
            tables_to_backup = [
                'users',
                'bookings', 
                'password_reset_tokens',
                'vehicles'
            ]
            
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
    
    def create_backup(self, include_files: bool = True) -> str:
        """
        Create encrypted backup of all sensitive data
        Returns path to backup file
        """
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        backup_filename = f"backup_{timestamp}.zip"
        backup_path = os.path.join(self.backup_dir, backup_filename)
        
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
                
                # Add backup metadata
                metadata = {
                    'backup_timestamp': timestamp,
                    'backup_date': datetime.now().isoformat(),
                    'database_tables': list(db_data['tables'].keys()),
                    'files_included': include_files,
                    'file_count': len(uploaded_files) if include_files else 0
                }
                backup_zip.writestr('backup_metadata.json', json.dumps(metadata, indent=2))
            
            # Encrypt the backup file
            encrypted_backup_path = self.encrypt_backup_file(backup_path)
            
            # Copy to cloud storage if configured
            if self.cloud_backup_dir:
                cloud_path = os.path.join(self.cloud_backup_dir, os.path.basename(encrypted_backup_path))
                shutil.copy2(encrypted_backup_path, cloud_path)
                # Set restricted permissions
                os.chmod(cloud_path, 0o600)  # Owner read/write only
            
            # Set restricted permissions on local backup
            os.chmod(encrypted_backup_path, 0o600)
            
            # Remove unencrypted backup
            if os.path.exists(backup_path):
                os.remove(backup_path)
            
            return encrypted_backup_path
            
        except Exception as e:
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
            
            # Restore database tables
            conn = None
            try:
                conn = self.get_db_connection()
                cursor = conn.cursor()
                
                restored_tables = []
                tables_to_restore = restore_tables or list(db_data['tables'].keys())
                
                for table_name in tables_to_restore:
                    if table_name in db_data['tables']:
                        # Clear existing data (optional - you may want to merge instead)
                        # cursor.execute(f"TRUNCATE TABLE {table_name}")
                        
                        # Restore data
                        rows = db_data['tables'][table_name]
                        if rows:
                            # Get column names
                            columns = list(rows[0].keys())
                            placeholders = ', '.join(['%s'] * len(columns))
                            columns_str = ', '.join(columns)
                            
                            for row in rows:
                                values = [row[col] for col in columns]
                                query = f"INSERT INTO {table_name} ({columns_str}) VALUES ({placeholders})"
                                cursor.execute(query, values)
                            
                            restored_tables.append(table_name)
                
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
        
        return deleted

