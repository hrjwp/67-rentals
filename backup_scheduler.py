"""
Scheduled backup script for automated backups.
Run this as a cron job or scheduled task for regular backups.
"""
import time
import schedule
from utils.backup import SecureBackup
from config import Config

def run_backup():
    """Execute backup and log results"""
    try:
        print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Starting automated backup...")
        backup_system = SecureBackup()
        backup_path = backup_system.create_backup(include_files=True)
        print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Backup completed: {backup_path}")
        
        # Cleanup old backups
        deleted = backup_system.delete_old_backups(keep_days=Config.BACKUP_RETENTION_DAYS)
        if deleted:
            print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Deleted {len(deleted)} old backup(s)")
        
        return True
    except Exception as e:
        print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Backup failed: {e}")
        return False

if __name__ == "__main__":
    if Config.AUTO_BACKUP_ENABLED:
        # Schedule backups
        schedule.every(Config.AUTO_BACKUP_INTERVAL_HOURS).hours.do(run_backup)
        
        print(f"Backup scheduler started. Backups will run every {Config.AUTO_BACKUP_INTERVAL_HOURS} hours.")
        print("Press Ctrl+C to stop.")
        
        # Run initial backup
        run_backup()
        
        # Keep running
        while True:
            schedule.run_pending()
            time.sleep(60)  # Check every minute
    else:
        print("Auto-backup is disabled. Set AUTO_BACKUP_ENABLED=true to enable.")
        # Run one-time backup
        run_backup()

