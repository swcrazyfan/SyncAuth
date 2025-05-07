import os
import shutil
import sqlite3
from pathlib import Path
import time
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Flag to track if encryption is available
ENCRYPTION_AVAILABLE = False

try:
    # Use SQLCipher for encrypted database
    from pysqlcipher3 import dbapi2 as sqlcipher
    ENCRYPTION_AVAILABLE = True
except ImportError:
    # Fall back to standard sqlite3 if pysqlcipher3 is not available
    ENCRYPTION_AVAILABLE = False
    print("WARNING: pysqlcipher3 not found, falling back to unencrypted database")

# Database status to track the state for UI feedback
DB_STATUS = {
    'status': 'unknown',  # 'ok', 'unencrypted', 'needs_key', 'error', 'encrypted_or_corrupt'
    'message': '',
    'has_data': False,
    'key_provided': False
}

# API key encryption
API_KEY_ENCRYPTION_KEY = None  # Will be derived from app secret key

def init_api_key_encryption(secret_key=None):
    """Initialize the API key encryption using the app's secret key"""
    global API_KEY_ENCRYPTION_KEY
    if not secret_key:
        # Use a default key if no secret key is provided
        # This still provides some obfuscation even without db encryption
        secret_key = os.environ.get('API_ENCRYPTION_KEY', 'syncauth-api-key-encryption')
    
    # Derive a key for API encryption
    salt = b'syncauth-salt'  # Fixed salt, as we need to decrypt consistently
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(secret_key.encode()))
    API_KEY_ENCRYPTION_KEY = Fernet(key)

def encrypt_api_key(api_key):
    """Encrypt an API key"""
    if not API_KEY_ENCRYPTION_KEY:
        init_api_key_encryption()
    if not api_key:
        return None
    return API_KEY_ENCRYPTION_KEY.encrypt(api_key.encode()).decode()

def decrypt_api_key(encrypted_api_key):
    """Decrypt an API key"""
    if not API_KEY_ENCRYPTION_KEY:
        init_api_key_encryption()
    if not encrypted_api_key:
        return None
    return API_KEY_ENCRYPTION_KEY.decrypt(encrypted_api_key.encode()).decode()

def get_db_path():
    """Get the database file path."""
    data_dir = os.environ.get('DATA_DIR', '.')
    return os.path.join(data_dir, 'syncauth.db')

def get_db_backup_path():
    """Get the backup database file path."""
    timestamp = time.strftime("%Y%m%d%H%M%S")
    data_dir = os.environ.get('DATA_DIR', '.')
    return os.path.join(data_dir, f'syncauth.db.backup.{timestamp}')

def get_db_status():
    """Get the current database status for UI feedback."""
    return DB_STATUS

def update_db_status(status, message='', has_data=None, key_provided=None):
    """Update the database status."""
    DB_STATUS['status'] = status
    if message:
        DB_STATUS['message'] = message
    if has_data is not None:
        DB_STATUS['has_data'] = has_data
    if key_provided is not None:
        DB_STATUS['key_provided'] = key_provided
    print(f"DB Status updated: {DB_STATUS}")

def test_encrypted_connection(key):
    """Test if we can connect to the database with the given key."""
    if not os.path.exists(get_db_path()):
        return False
        
    try:
        conn = sqlite3.connect(f'file:{get_db_path()}?mode=ro', uri=True)
        conn.close()
        # If we can open it without encryption, it's not encrypted
        return False
    except sqlite3.OperationalError:
        # File is not a database or is encrypted
        try:
            # Try with the provided key
            conn = sqlcipher.connect(get_db_path())
            conn.execute(f'PRAGMA key="{key}"')
            conn.execute('SELECT count(*) FROM sqlite_master')
            conn.close()
            return True
        except Exception as e:
            print(f"Failed to open with encryption key: {e}")
            return False

def init_db():
    """Initialize the database with tables if they don't exist."""
    # Initialize API key encryption
    init_api_key_encryption(os.environ.get('SECRET_KEY', ''))
    
    # Check if the database file exists
    db_exists = os.path.exists(get_db_path())
    
    # Check if a key is provided
    key_provided = bool(os.environ.get('SECRET_KEY', ''))
    
    # Update status with key information
    update_db_status('checking', 'Checking database state...', has_data=False, key_provided=key_provided)
    
    # If database doesn't exist, create it
    if not db_exists:
        # Database will be initialized via SQLAlchemy in app startup
        update_db_status('ok', 'New database created successfully.', has_data=False, key_provided=key_provided)
        return
        
    # Test if we can open the database without encryption
    database_state = 'unknown'
    try:
        # First, try to actually use the database (not just connect)
        conn = sqlite3.connect(get_db_path())
        try:
            # Try to perform a real operation to fully validate db integrity
            conn.execute('SELECT count(*) FROM sqlite_master')
            conn.close()
            
            # If we get here, database is truly unencrypted and valid
            has_data = os.path.getsize(get_db_path()) > 0
            
            # Database is unencrypted
            if key_provided:
                # Key provided but DB is not encrypted - ask if they want to encrypt
                update_db_status('unencrypted', 'Database is not encrypted but a SECRET_KEY was provided in your environment. You have two options:\n1. Encrypt the database (recommended for security)\n2. Remove the SECRET_KEY from your .env file and restart the container', 
                                has_data=has_data, key_provided=key_provided)
            else:
                # No key and DB is not encrypted (normal state)
                update_db_status('ok', 'Database is working normally (unencrypted).', has_data=has_data, key_provided=key_provided)
            
            database_state = 'unencrypted'
        except sqlite3.DatabaseError as sqlerr:
            conn.close()
            # Database file exists but isn't a valid SQLite database
            database_state = 'encrypted_or_corrupt'
            update_db_status('encrypted_or_corrupt', 
                           f'Database file exists but appears to be encrypted or corrupt: {str(sqlerr)}', 
                            has_data=True, key_provided=key_provided)
    except sqlite3.OperationalError as e:
        # Database might be encrypted or corrupt
        database_state = 'encrypted_or_corrupt'
        update_db_status('encrypted_or_corrupt', 
                        f'Database appears to be encrypted or corrupt: {str(e)}', 
                        has_data=True, key_provided=key_provided)
        
        # If a key is provided, try it
        if key_provided:
            key_works = test_encrypted_connection(os.environ.get('SECRET_KEY', ''))
            if key_works:
                # Key works
                database_state = 'encrypted'
                update_db_status('ok', 'Database is properly encrypted with the provided key.', has_data=True, key_provided=True)
    
    # If database is in an unusable state, return early
    if database_state in ['encrypted_or_corrupt', 'unknown']:
        return
    
    # Tables are managed by SQLAlchemy in app startup
    if DB_STATUS['status'] in ['ok', 'unencrypted']:
        update_db_status(DB_STATUS['status'], 'Database initialized successfully.', has_data=True, key_provided=key_provided)

def encrypt_database(key):
    """Encrypt an unencrypted database with the given key."""
    print(f"Starting encryption process with key length: {len(key)}")
    db_path = get_db_path()
    backup_path = f"{db_path}.unencrypted.bak"
    temp_sql = f"{db_path}.temp.sql"
    
    if not os.path.exists(db_path):
        error_msg = 'Cannot encrypt: Database file does not exist.'
        print(f"ERROR: {error_msg}")
        update_db_status('error', error_msg)
        return False
        
    try:
        # Check if SQLCipher is actually available
        if not ENCRYPTION_AVAILABLE:
            error_msg = 'Cannot encrypt: SQLCipher support not available'
            print(f"ERROR: {error_msg}")
            update_db_status('error', error_msg)
            return False
        
        # First check if already encrypted
        try:
            print("Checking if database is already encrypted...")
            conn = sqlite3.connect(f'file:{db_path}?mode=ro', uri=True)
            conn.close()
            print("Database is not encrypted (standard SQLite connection succeeded)")
        except sqlite3.OperationalError as e:
            print(f"Database connection test error: {e}")
            error_msg = 'Database is already encrypted or corrupted.'
            print(f"ERROR: {error_msg}")
            update_db_status('error', error_msg)
            return False
            
        # Create a backup of the unencrypted database
        print(f"Creating backup at {backup_path}")
        try:
            shutil.copy2(db_path, backup_path)
            print(f"Backup created successfully at {backup_path}")
        except Exception as backup_err:
            error_msg = f'Failed to create backup: {str(backup_err)}'
            print(f"ERROR: {error_msg}")
            update_db_status('error', error_msg)
            return False
        
        # Export the database schema and data to a SQL script
        print(f"Exporting database to SQL script at {temp_sql}")
        try:
            conn = sqlite3.connect(db_path)
            with open(temp_sql, 'w') as f:
                for line in conn.iterdump():
                    f.write(f"{line}\n")
            conn.close()
            print("Database exported successfully")
        except Exception as export_err:
            error_msg = f'Failed to export database: {str(export_err)}'
            print(f"ERROR: {error_msg}")
            update_db_status('error', error_msg)
            return False
        
        # Remove the original database
        try:
            print(f"Removing original database at {db_path}")
            os.remove(db_path)
            print("Original database removed successfully")
        except Exception as remove_err:
            error_msg = f'Failed to remove original database: {str(remove_err)}'
            print(f"ERROR: {error_msg}")
            update_db_status('error', error_msg)
            return False
        
        # Create a new encrypted database
        try:
            print("Creating new encrypted database")
            conn = sqlcipher.connect(db_path)
            conn.execute(f'PRAGMA key="{key}"')
            
            # Test encryption by creating and dropping a test table
            conn.execute('CREATE TABLE test_encryption (id INTEGER PRIMARY KEY)')
            conn.execute('DROP TABLE test_encryption')
            print("Encryption test successful")
            
            # Import the SQL script
            print("Importing SQL script to encrypted database")
            with open(temp_sql, 'r') as f:
                sql_script = f.read()
                conn.executescript(sql_script)
                
            conn.commit()
            conn.close()
            print("SQL import completed successfully")
        except Exception as encrypt_err:
            error_msg = f'Failed to create encrypted database: {str(encrypt_err)}'
            print(f"ERROR: {error_msg}")
            
            # Try to restore from backup
            try:
                if os.path.exists(backup_path):
                    shutil.copy2(backup_path, db_path)
                    print("Restored original database from backup")
            except Exception as restore_err:
                print(f"Failed to restore backup: {str(restore_err)}")
                
            update_db_status('error', error_msg)
            return False
        
        # Clean up temporary files
        try:
            print("Cleaning up temporary files")
            if os.path.exists(temp_sql):
                os.remove(temp_sql)
                print("Temporary SQL file removed")
        except Exception as cleanup_err:
            print(f"Warning: Failed to remove temporary file: {str(cleanup_err)}")
        
        print("Database encryption completed successfully!")
        update_db_status('ok', 'Database encrypted successfully.', has_data=True, key_provided=True)
        return True
        
    except Exception as e:
        error_msg = f'Failed to encrypt database: {str(e)}'
        print(f"ERROR: {error_msg}")
        import traceback
        print(f"Traceback: {traceback.format_exc()}")
        
        # Try to restore from backup if it exists
        try:
            if os.path.exists(backup_path) and not os.path.exists(db_path):
                shutil.copy2(backup_path, db_path)
                print("Restored database from backup after error")
        except Exception as restore_err:
            print(f"Failed to restore backup: {str(restore_err)}")
            
        update_db_status('error', error_msg)
        return False

def decrypt_database(key, create_backup=True):
    """Decrypt an encrypted database with the given key, optionally backing up the original."""
    db_path = get_db_path()
    if not os.path.exists(db_path):
        update_db_status('error', 'Cannot decrypt: Database file does not exist.')
        return False
    try:
        if create_backup:
            backup_path = get_db_backup_path()
            shutil.copy2(db_path, backup_path)
        # Dump encrypted DB to SQL
        temp_sql = f"{db_path}.temp.sql"
        conn = sqlcipher.connect(db_path)
        conn.execute(f'PRAGMA key="{key}"')
        with open(temp_sql, 'w') as f:
            for line in conn.iterdump():
                f.write(f"{line}\n")
        conn.close()
        # Remove encrypted DB and create unencrypted
        os.remove(db_path)
        conn = sqlite3.connect(db_path)
        with open(temp_sql, 'r') as f:
            conn.executescript(f.read())
        conn.commit()
        conn.close()
        os.remove(temp_sql)
        update_db_status('ok', 'Database decrypted successfully.', has_data=True, key_provided=False)
        return True
    except Exception as e:
        update_db_status('error', f'Failed to decrypt database: {str(e)}')
        return False

def reset_database(key=None, create_backup=True):
    """Reset the database. Optionally encrypt with key."""
    import os
    import traceback
    import shutil
    
    try:
        # Store current directory and database path for logging
        current_dir = os.getcwd()
        db_path = os.path.join(os.environ.get('DATA_DIR', '.'), "syncauth.db")
        
        # Output detailed information about paths and existence
        print(f"Reset database called with key={key} and create_backup={create_backup}")
        print(f"Current working directory: {current_dir}")
        print(f"Full database path: {os.path.abspath(db_path)}")
        print(f"Database file exists: {os.path.exists(db_path)}")
        print(f"Database file permissions: {oct(os.stat(db_path).st_mode)}" if os.path.exists(db_path) else "Database file does not exist")
        print(f"User running process: {os.getuid()}:{os.getgid()}")
        
        if os.path.exists(db_path):
            if create_backup:
                backup_path = get_db_backup_path()
                print(f"Creating backup at {backup_path}")
                shutil.copy2(db_path, backup_path)
                print(f"Backup created: {os.path.exists(backup_path)}")
                
            try:
                os.remove(db_path)
                print(f"Successfully deleted database file at {db_path}")
            except Exception as e:
                print(f"Error deleting database file: {e}")
                print(traceback.format_exc())
                return False
        else:
            print(f"No database file found at {db_path}, continuing with initialization")
        
        # If a key is provided, set it for encryption
        if key:
            print(f"Setting SECRET_KEY environment variable for encryption")
            os.environ['SECRET_KEY'] = key
            update_db_status('encrypted', 'Database reset and encrypted successfully.', has_data=False, key_provided=True)
        else:
            # Remove SECRET_KEY environment variable if exists
            if 'SECRET_KEY' in os.environ:
                print("Removing SECRET_KEY environment variable")
                try:
                    del os.environ['SECRET_KEY']
                    print("SECRET_KEY environment variable removed")
                except Exception as e:
                    print(f"Error removing SECRET_KEY environment variable: {e}")
            update_db_status('ok', 'Database reset successfully (unencrypted).', has_data=False, key_provided=False)
        
        # Initialize a new database
        print("Initializing new database")
        try:
            init_db()
            print("New database initialized successfully")
            return True
        except Exception as e:
            print(f"Error initializing new database: {e}")
            print(traceback.format_exc())
            return False
    except Exception as e:
        print(f"Unexpected error in reset_database: {str(e)}")
        print(traceback.format_exc())
        update_db_status('error', f'Failed to reset database: {str(e)}')
        return False

def delete_and_recreate_database():
    """Delete the current database and create a new one."""
    try:
        # Get database path
        db_path = get_db_path()
        
        # Create backup
        backup_path = f"{db_path}.bak.{int(time.time())}"
        if os.path.exists(db_path):
            shutil.copy2(db_path, backup_path)
            print(f"Database backed up to {backup_path}")
            
            # Delete the database file
            os.remove(db_path)
            print(f"Database deleted: {db_path}")
        
        # Initialize a new database
        init_db()
        print("New database initialized")
        
        return True
    except Exception as e:
        print(f"Error in delete_and_recreate_database: {e}")
        return False
