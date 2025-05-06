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
        conn = get_db_connection()
        if conn:
            create_tables(conn)
            conn.close()
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
                update_db_status('unencrypted', 'Database is not encrypted but a key was provided. You can encrypt it or remove the SECRET_KEY.', 
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
    
    # Create the database and tables
    conn = get_db_connection()
    if not conn:
        return
        
    create_tables(conn)
    conn.close()
    
    if DB_STATUS['status'] in ['ok', 'unencrypted']:
        update_db_status(DB_STATUS['status'], 'Database initialized successfully.', has_data=True, key_provided=key_provided)

def create_tables(conn):
    """Create tables if they don't exist."""
    conn.execute('''
    CREATE TABLE IF NOT EXISTS master_config (
        id INTEGER PRIMARY KEY,
        address TEXT NOT NULL,
        api_key TEXT NOT NULL
    )
    ''')
    
    conn.execute('''
    CREATE TABLE IF NOT EXISTS clients (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        label TEXT NOT NULL,
        device_id TEXT NOT NULL,
        address TEXT NOT NULL,
        api_key TEXT NOT NULL,
        sync_enabled BOOLEAN DEFAULT 1
    )
    ''')
    
    conn.commit()

def get_db_connection():
    """Get a database connection based on whether encryption is enabled."""
    try:
        # Check if database exists
        db_exists = os.path.exists(get_db_path())
        
        # Try to connect without encryption first
        try:
            # This will fail if the database is encrypted
            conn = sqlite3.connect(get_db_path())
            conn.row_factory = sqlite3.Row
            return conn
        except sqlite3.OperationalError as e:
            # Database might be encrypted or corrupt
            if 'file is not a database' in str(e) or 'file is encrypted' in str(e):
                # Try with encryption if we have a key
                key = os.environ.get('SECRET_KEY', '')
                if key:
                    try:
                        conn = sqlcipher.connect(get_db_path())
                        conn.execute(f'PRAGMA key="{key}"')
                        # Verify we can actually read the database
                        conn.execute('SELECT 1')
                        conn.row_factory = sqlite3.Row
                        return conn
                    except Exception as e2:
                        update_db_status('error', f'Failed to connect with encryption key: {str(e2)}')
                        # If the database exists but we can't access it with or without a key,
                        # it might be corrupt or using a different key
                        if db_exists:
                            # Create a backup and reset if this is a new run
                            backup_path = get_db_backup_path()
                            try:
                                shutil.copy2(get_db_path(), backup_path)
                                os.remove(get_db_path())
                                update_db_status('warning', f'Created backup at {backup_path} and reset database.')
                                # Now try to create a fresh database
                                if key:
                                    conn = sqlcipher.connect(get_db_path())
                                    conn.execute(f'PRAGMA key="{key}"')
                                else:
                                    conn = sqlite3.connect(get_db_path())
                                conn.row_factory = sqlite3.Row
                                return conn
                            except Exception as e3:
                                update_db_status('error', f'Failed to reset database: {str(e3)}')
                                return None
                else:
                    # No encryption key, but database is encrypted or corrupt
                    update_db_status('needs_key', 'Database appears to be encrypted but no key was provided.')
                    return None
            else:
                # Some other operational error
                update_db_status('error', f'Database connection error: {str(e)}')
                return None
    except Exception as e:
        update_db_status('error', f'Unexpected database error: {str(e)}')
        return None

def encrypt_database(key):
    """Encrypt an unencrypted database with the given key."""
    if not os.path.exists(get_db_path()):
        update_db_status('error', 'Cannot encrypt: Database file does not exist.')
        return False
        
    try:
        # First, check if already encrypted
        encrypted = False
        try:
            conn = sqlite3.connect(f'file:{get_db_path()}?mode=ro', uri=True)
            conn.close()
        except sqlite3.OperationalError:
            encrypted = True
            
        if encrypted:
            update_db_status('error', 'Database is already encrypted.')
            return False
            
        # Create a backup
        backup_path = get_db_backup_path()
        shutil.copy2(get_db_path(), backup_path)
        
        # Export the database to a temporary SQL file
        temp_sql = f"{get_db_path()}.temp.sql"
        conn = sqlite3.connect(get_db_path())
        with open(temp_sql, 'w') as f:
            for line in conn.iterdump():
                f.write(f"{line}\n")
        conn.close()
        
        # Create a new encrypted database
        os.remove(get_db_path())  # Remove the old database file
        conn = sqlcipher.connect(get_db_path())
        conn.execute(f'PRAGMA key="{key}"')
        
        # Import the SQL
        with open(temp_sql, 'r') as f:
            sql_script = f.read()
            conn.executescript(sql_script)
        
        conn.commit()
        conn.close()
        
        # Clean up
        os.remove(temp_sql)
        
        # Update environment variable for future access
        os.environ['SECRET_KEY'] = key
        
        update_db_status('ok', 'Database encrypted successfully.', has_data=True, key_provided=True)
        return True
        
    except Exception as e:
        update_db_status('error', f'Failed to encrypt database: {str(e)}')
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
                print(f"Error deleting database file: {str(e)}")
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
                    print(f"Error removing SECRET_KEY environment variable: {str(e)}")
            update_db_status('ok', 'Database reset successfully (unencrypted).', has_data=False, key_provided=False)
        
        # Initialize a new database
        print("Initializing new database")
        try:
            init_db()
            print("New database initialized successfully")
            return True
        except Exception as e:
            print(f"Error initializing new database: {str(e)}")
            print(traceback.format_exc())
            return False
    except Exception as e:
        print(f"Unexpected error in reset_database: {str(e)}")
        print(traceback.format_exc())
        update_db_status('error', f'Failed to reset database: {str(e)}')
        return False

def get_master_config():
    """Get the master Syncthing instance configuration."""
    conn = get_db_connection()
    if not conn:
        return None
        
    try:
        result = conn.execute('SELECT id, address, api_key FROM master_config WHERE id = 1').fetchone()
        if result:
            config = dict(result)
            # Decrypt the API key
            if config.get('api_key'):
                config['api_key'] = decrypt_api_key(config['api_key'])
            return config
        else:
            return None
    except Exception as e:
        print(f"Error getting master config: {e}")
        return None
    finally:
        conn.close()

def set_master_config(address, api_key):
    """Set or update the master Syncthing instance configuration."""
    conn = get_db_connection()
    if not conn:
        return False
        
    try:
        # Encrypt the API key
        encrypted_api_key = encrypt_api_key(api_key)
        
        # Check if a record already exists
        existing = conn.execute('SELECT id FROM master_config WHERE id = 1').fetchone()
        
        if existing:
            # Update existing record
            conn.execute('UPDATE master_config SET address = ?, api_key = ? WHERE id = 1', 
                        (address, encrypted_api_key))
        else:
            # Insert new record
            conn.execute('INSERT INTO master_config (id, address, api_key) VALUES (1, ?, ?)', 
                        (address, encrypted_api_key))
        
        conn.commit()
        return True
    except Exception as e:
        print(f"Error setting master config: {e}")
        return False
    finally:
        conn.close()

def add_client(label, device_id, address, api_key, sync_enabled=1):
    """Add a new Syncthing client to the database."""
    conn = get_db_connection()
    if not conn:
        return None
        
    try:
        # Encrypt the API key
        encrypted_api_key = encrypt_api_key(api_key)
        
        cursor = conn.execute(
            'INSERT INTO clients (label, device_id, address, api_key, sync_enabled) VALUES (?, ?, ?, ?, ?)',
            (label, device_id, address, encrypted_api_key, sync_enabled)
        )
        conn.commit()
        return cursor.lastrowid
    except Exception as e:
        print(f"Error adding client: {e}")
        return None
    finally:
        conn.close()

def update_client(client_id, label=None, device_id=None, address=None, api_key=None, sync_enabled=None):
    """Update an existing Syncthing client in the database."""
    conn = get_db_connection()
    if not conn:
        return False
        
    try:
        # Use a safer approach with fully parameterized queries
        update_fields = []
        params = []
        
        if label is not None:
            update_fields.append(('label', label))
            
        if device_id is not None:
            update_fields.append(('device_id', device_id))
            
        if address is not None:
            update_fields.append(('address', address))
            
        if api_key is not None:
            # Encrypt the API key
            update_fields.append(('api_key', encrypt_api_key(api_key)))
            
        if sync_enabled is not None:
            update_fields.append(('sync_enabled', sync_enabled))
            
        if not update_fields:
            return True  # Nothing to update
            
        # Build a fully parameterized query
        set_clauses = [f"{field} = ?" for field, _ in update_fields]
        query = f"UPDATE clients SET {', '.join(set_clauses)} WHERE id = ?"
        
        # Extract values in the same order as the fields
        params = [value for _, value in update_fields]
        params.append(client_id)  # Add the WHERE clause parameter
        
        conn.execute(query, params)
        conn.commit()
        return True
    except Exception as e:
        print(f"Error updating client: {e}")
        return False
    finally:
        conn.close()

def delete_client(client_id):
    """Delete a Syncthing client from the database."""
    conn = get_db_connection()
    if not conn:
        return False
        
    try:
        conn.execute('DELETE FROM clients WHERE id = ?', (client_id,))
        conn.commit()
        return True
    except Exception as e:
        print(f"Error deleting client: {e}")
        return False
    finally:
        conn.close()

def list_clients():
    """List all Syncthing clients in the database."""
    conn = get_db_connection()
    if not conn:
        return []
        
    try:
        clients = [dict(c) for c in conn.execute('SELECT * FROM clients').fetchall()]
        # Decrypt the API keys
        for client in clients:
            if client.get('api_key'):
                client['api_key'] = decrypt_api_key(client['api_key'])
        return clients
    except Exception as e:
        print(f"Error listing clients: {e}")
        return []
    finally:
        conn.close()

def get_client(client_id):
    """Get a specific Syncthing client by ID."""
    conn = get_db_connection()
    if not conn:
        return None
        
    try:
        client = conn.execute('SELECT * FROM clients WHERE id = ?', (client_id,)).fetchone()
        if client:
            client_dict = dict(client)
            # Decrypt the API key
            if client_dict.get('api_key'):
                client_dict['api_key'] = decrypt_api_key(client_dict['api_key'])
            return client_dict
        return None
    except Exception as e:
        print(f"Error getting client: {e}")
        return None
    finally:
        conn.close()

def get_all_clients():
    """Alias for list_clients() for backward compatibility."""
    return list_clients()
