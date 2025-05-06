import os
from flask import Flask, request, render_template, jsonify, session, redirect, url_for, flash, current_app, send_from_directory
from flask.views import MethodView
from functools import wraps
from flask_wtf.csrf import CSRFProtect
import time
import json
import logging
import argparse
import subprocess
import uuid
import sys
import atexit
import signal
import threading
from datetime import timedelta

# Import local modules
import storage
from syncthing_api import (
    test_connection, get_configured_devices, set_gui_password, 
    SyncthingApiError, verify_gui_credentials, get_connections, 
    poll_events, check_for_config_saved_events, get_gui_config
)

# Configuration
class Config:
    """Centralized configuration management"""
    # Default values
    DEV_MODE = False
    SECRET_KEY = os.environ.get('SECRET_KEY', os.urandom(24).hex())
    DATA_DIR = os.environ.get('DATA_DIR', '.')
    HOST = os.environ.get('HOST', '0.0.0.0')
    PORT = int(os.environ.get('PORT', 5000))
    DEBUG = os.environ.get('DEBUG', 'False').lower() == 'true'
    SESSION_LIFETIME = timedelta(days=7)
    
    @classmethod
    def init_from_args(cls, args=None):
        """Initialize config from command line arguments"""
        if args and hasattr(args, 'dev'):
            cls.DEV_MODE = args.dev
            cls.DEBUG = True if args.dev else cls.DEBUG

# Set up logging
def setup_logging():
    """Configure logging for the application"""
    logging.basicConfig(level=logging.DEBUG)
    logger = logging.getLogger(__name__)
    
    # Create a custom logger to capture all output
    file_handler = logging.FileHandler('/data/debug.log')
    file_handler.setLevel(logging.DEBUG)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    
    # Redirect stdout and stderr to the log file
    class LoggerWriter:
        def __init__(self, level):
            self.level = level
            self.buffer = []
        
        def write(self, message):
            if message and message.strip():
                self.level(message)
        
        def flush(self):
            pass
    
    sys.stdout = LoggerWriter(logger.info)
    sys.stderr = LoggerWriter(logger.error)
    
    return logger

# API response helpers
def api_success(data=None, message=None, status_code=200):
    """Standard success response for API endpoints"""
    response = {'success': True}
    if message:
        response['message'] = message
    if data is not None:
        if isinstance(data, dict):
            response.update(data)
        else:
            response['data'] = data
    return jsonify(response), status_code

def api_error(message, status_code=400, redirect_url=None):
    """Standard error response for API endpoints"""
    response = {'success': False, 'error': message}
    if redirect_url:
        response['redirect'] = redirect_url
    return jsonify(response), status_code

# Custom exceptions
class ApiException(Exception):
    """Exception raised for API errors with status code"""
    def __init__(self, message, status_code=400, redirect_url=None):
        self.message = message
        self.status_code = status_code
        self.redirect_url = redirect_url
        super().__init__(self.message)

# Flask application setup
def create_app(config=None):
    """Create and configure the Flask application"""
    app = Flask(__name__)
    
    # Load configuration
    app.config['SECRET_KEY'] = Config.SECRET_KEY
    app.config['PERMANENT_SESSION_LIFETIME'] = Config.SESSION_LIFETIME
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
    
    # Only set secure flag in production
    if not Config.DEV_MODE:
        app.config['SESSION_COOKIE_SECURE'] = True
    
    # Initialize CSRF protection
    csrf = CSRFProtect(app)
    
    # Exception handlers
    @app.errorhandler(ApiException)
    def handle_api_exception(error):
        return api_error(error.message, error.status_code, error.redirect_url)
    
    # In production mode, serve the built Quasar SPA
    if not Config.DEV_MODE:
        @app.route('/', defaults={'path': ''})
        @app.route('/<path:path>')
        def serve_spa(path):
            # Check if the path exists as a file in the dist folder
            if path and os.path.exists(os.path.join('frontend/dist/spa', path)):
                return send_from_directory('frontend/dist/spa', path)
            # Otherwise return the index.html for SPA routing
            return send_from_directory('frontend/dist/spa', 'index.html')
    
    # Configure CSRF token access
    @app.route('/api/csrf-token', methods=['GET'])
    def get_csrf_token():
        """Return the CSRF token to the SPA client."""
        token = csrf._get_csrf_token()
        if not isinstance(token, str):
            token = str(token)
        return jsonify({'csrf_token': token})
    
    # Configure CSRF token to be accessible for SPA (only in dev mode)
    if Config.DEV_MODE:
        @app.after_request
        def set_csrf_cookie(response):
            if '/api/' in request.path:  # Only set for API requests
                csrf_token = csrf._get_csrf_token()
                if not isinstance(csrf_token, str):
                    csrf_token = str(csrf_token)
                response.set_cookie('csrf_token', csrf_token, samesite='Strict')
            return response

    # Authentication decorator
    def login_required(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # First check if master is configured
            master = storage.get_master_config()
            if not master:
                # If master is not configured, handle appropriately for APIs vs web pages
                if request.path.startswith('/api/'):
                    return api_error('Database not configured', 401, '/setup')
                else:
                    # Regular web pages redirect to setup
                    return redirect(url_for('setup'))
                
            # If master is configured but user not logged in, handle appropriately
            if 'db_authenticated' not in session:
                if request.path.startswith('/api/'):
                    return api_error('Authentication required', 401, '/login')
                else:
                    # Regular web pages redirect to login
                    return redirect(url_for('login', next=request.url))
                
            return f(*args, **kwargs)
        return decorated_function
    
    # Request validation decorator
    def validate_json(*required_fields):
        """Validate that the request has JSON data with required fields"""
        def decorator(f):
            @wraps(f)
            def decorated_function(*args, **kwargs):
                data = request.get_json()
                if not data:
                    return api_error('No data provided', 400)
                    
                for field in required_fields:
                    if field not in data or not data[field]:
                        return api_error(f'Missing required field: {field}', 400)
                        
                return f(*args, **kwargs)
            return decorated_function
        return decorator
    
    # CSRF exempt decorator for specific endpoints
    def csrf_exempt(route_function):
        """Mark a route as exempt from CSRF protection"""
        return csrf.exempt(route_function)
    
    # Make DB status available to all templates
    @app.context_processor
    def inject_db_status():
        return {'db_status': storage.get_db_status()}
    
    # Initialize database at startup
    with app.app_context():
        try:
            storage.init_db()
        except Exception as e:
            app.logger.error(f"Database initialization error: {e}")
            # We'll handle this in the routes
    
    # API Routes
    
    # Test connection to Syncthing API
    @csrf_exempt
    @app.route('/api/test-connection', methods=['POST'])
    def api_test_connection():
        """Test connection to the Syncthing API."""
        data = request.get_json()
        address = data.get('address', '')
        api_key = data.get('api_key', '')
        
        if not address or not api_key:
            return api_error('Address and API key are required', 400)
        
        try:
            result = test_connection(address, api_key)
            return jsonify(result)
        except Exception as e:
            return api_error(str(e), 500)
    
    # User authentication
    @csrf_exempt
    @app.route('/api/authenticate', methods=['POST'])
    def api_authenticate():
        """API endpoint for authenticating users for database management."""
        if request.method == 'POST':
            data = request.get_json()
            username = data.get('username', '')
            password = data.get('password', '')
            apikey = data.get('apikey', '')
            
            # Get master configuration
            master_config = storage.get_master_config()
            if not master_config:
                return api_error('Master configuration not found', 400)
            
            authenticated = False
            # Check if using master API key
            if apikey:
                if master_config and master_config.get('api_key') == apikey:
                    authenticated = True
                    session['db_authenticated'] = True
                    session['username'] = 'api_user'  # Special value for API key auth
                else:
                    return api_error('Invalid API key', 401)
            
            # Check if using username/password
            elif username and password:
                try:
                    # Use the existing verification function
                    if verify_gui_credentials(master_config['address'], master_config['api_key'], username, password):
                        authenticated = True
                        session['db_authenticated'] = True
                        session['username'] = username
                    else:
                        return api_error('Invalid username or password', 401)
                except Exception as e:
                    return api_error(f'Authentication error: {str(e)}', 500)
            else:
                return api_error('Please provide authentication credentials', 400)
            
            if authenticated:
                # Create a session cookie with longer expiration
                session.permanent = True  # Makes the session last longer
                # Return user info along with success message
                return api_success({
                    'message': 'Authentication successful',
                    'user': {
                        'username': session.get('username', 'user'),
                        'authenticated': True
                    }
                })
        
        return api_error('Invalid request', 400)
    
    # Database status endpoint
    @csrf_exempt
    @app.route('/api/db_status', methods=['GET'])
    def api_db_status():
        """API endpoint to get the database status.
        This is a public endpoint that doesn't require authentication."""
        return jsonify(storage.get_db_status())
    
    # Initial setup endpoint
    @csrf_exempt
    @app.route('/api/setup', methods=['POST'])
    def api_setup():
        """API endpoint for initial setup."""
        if request.method == 'POST':
            data = request.get_json()
            address = data.get('address', '')
            api_key = data.get('api_key', '')
            
            if not address or not api_key:
                return api_error('Address and API key are required', 400)
                
            # Test connection before saving
            try:
                connection_test = test_connection(address, api_key)
                if not connection_test.get('connected', False):
                    return api_error(connection_test.get('error', 'Connection test failed'), 400)
                    
                # Save configuration
                if storage.set_master_config(address, api_key):
                    return api_success()
                else:
                    return api_error('Failed to save configuration', 500)
            except Exception as e:
                return api_error(str(e), 500)
        
        return api_error('Invalid request', 400)
    
    # Login, logout, and web routes
    @app.route('/login', methods=['GET', 'POST'])
    def login():
        error = None
        
        # Check if master is configured
        master = storage.get_master_config()
        if not master:
            return redirect(url_for('setup'))
        
        if request.method == 'POST':
            username = request.form.get('username')
            password = request.form.get('password')
            
            try:
                # Verify credentials against master Syncthing
                if verify_gui_credentials(master['address'], master['api_key'], username, password):
                    # Clear and regenerate session for security
                    session.clear()
                    session['db_authenticated'] = True
                    session['username'] = username
                    
                    # If the login was triggered by trying to access a protected page
                    next_page = request.args.get('next')
                    if next_page:
                        return redirect(next_page)
                    return redirect(url_for('index'))
                else:
                    error = "Invalid credentials. Please try again."
            except Exception as e:
                error = f"Authentication error: {str(e)}"
        
        return render_template('login.html', error=error)
    
    @app.route('/logout')
    def logout():
        session.pop('db_authenticated', None)
        session.pop('username', None)
        return redirect(url_for('login'))
    
    @app.route('/')
    @login_required
    def index():
        """Serve the main HTML page."""
        db_status = storage.get_db_status()
        return render_template('index.html', db_status=db_status)
    
    # Database Management API
    @app.route('/manage_encryption', methods=['POST'])
    @login_required
    def manage_encryption():
        """Handle database encryption and reset actions."""
        action = request.form.get('action', '')
        app.logger.info(f"MANAGE ENCRYPTION ACTION: '{action}'")
        app.logger.info(f"FORM DATA: {request.form}")
        
        if action == 'encrypt':
            app.logger.info("=== ENCRYPTING DATABASE ===")
            # Encrypt the database with the current SECRET_KEY
            key = os.environ.get('SECRET_KEY', '')
            app.logger.info(f"SECRET_KEY from environment: {key[:5]}... (length: {len(key)})")
            
            if not key:
                app.logger.error("ERROR: No SECRET_KEY provided in environment")
                flash('No encryption key provided in SECRET_KEY', 'error')
                return redirect(request.referrer or url_for('setup'))
            
            # Attempt encryption using the improved encrypt_database function
            app.logger.info("Calling storage.encrypt_database...")  
            success = storage.encrypt_database(key)
            app.logger.info(f"Encryption result: {success}")
            
            if success:
                flash('Database encrypted successfully')
            else:
                flash('Failed to encrypt database', 'error')
            
            # Redirect back to the referring page, or setup if none
            return redirect(request.referrer or url_for('setup'))
            
        elif action == 'decrypt':
            # Decrypt the database to unencrypted, with optional backup
            key = request.form.get('decrypt_key', '')
            create_backup = request.form.get('create_backup') == 'on'
            success = storage.decrypt_database(key, create_backup)
            if success:
                flash('Database decrypted successfully')
            else:
                flash('Failed to decrypt database', 'error')
            return redirect(request.referrer or url_for('setup'))
            
        elif action == 'reset' or action == 'start_over':
            # More direct approach to delete and recreate the database
            try:
                app.logger.info("DIRECT DATABASE DELETION ATTEMPT")
                db_path = os.path.join(os.environ.get('DATA_DIR', '.'), "syncauth.db")
                
                # Check if file exists
                if os.path.exists(db_path):
                    app.logger.info(f"Database exists at {db_path}, attempting to delete...")
                    os.remove(db_path)
                    app.logger.info(f"Database deletion result: {not os.path.exists(db_path)}")
                else:
                    app.logger.info(f"No database found at {db_path}")
                    
                # Now initialize a new database
                app.logger.info("Initializing new database...")
                storage.init_db()
                
                flash('Database has been deleted and recreated successfully')
                return redirect(request.referrer or url_for('setup'))
                
            except Exception as e:
                app.logger.error(f"DIRECT DELETION ERROR: {str(e)}")
                import traceback
                app.logger.error(f"Traceback: {traceback.format_exc()}")
                flash(f'Error deleting database: {str(e)}', 'error')
                return redirect(request.referrer or url_for('setup'))
            
        else:
            flash('Invalid action specified', 'error')
            return redirect(request.referrer or url_for('setup'))
    
    # Master configuration endpoint
    @app.route('/api/master', methods=['GET', 'POST'])
    @login_required
    def master_config():
        """Get or update the master Syncthing instance configuration."""
        if request.method == 'GET':
            config = storage.get_master_config()
            if not config:
                return jsonify({'configured': False})
            # Don't return the actual API key in the response for security
            return jsonify({
                'configured': True,
                'address': config['address'],
                'api_key_set': bool(config['api_key'])
            })
        
        elif request.method == 'POST':
            data = request.json
            address = data.get('address')
            api_key = data.get('api_key')
            
            if not address or not api_key:
                return api_error('Missing required fields', 400)
            
            # Test the connection before saving
            try:
                test_result = test_connection(address, api_key)
                if not test_result['connected']:
                    return api_error(f"Connection test failed: {test_result.get('error', 'Unknown error')}", 400)
                
                # If connection successful, save the configuration
                if storage.set_master_config(address, api_key):
                    return api_success({
                        'message': 'Master configuration saved',
                        'device_id': test_result.get('device_id')
                    })
                else:
                    return api_error('Database error', 500)
            except Exception as e:
                return api_error(str(e), 500)
    
    # Clients endpoint - Class-based view
    class ClientAPI(MethodView):
        decorators = [login_required]
        
        def get(self, client_id=None):
            """Get all clients or a specific client"""
            if client_id is None:
                return jsonify(storage.list_clients())
            else:
                client = storage.get_client(client_id)
                if client:
                    return jsonify(client)
                return api_error('Client not found', 404)
        
        def post(self):
            """Add a new client"""
            data = request.json
            
            # Validate required fields
            required_fields = ['label', 'device_id', 'address', 'api_key']
            for field in required_fields:
                if field not in data or not data[field]:
                    return api_error(f'Missing required field: {field}', 400)
            
            # Test the connection before saving
            try:
                test_result = test_connection(data['address'], data['api_key'])
                if not test_result['connected']:
                    return api_error(f"Connection test failed: {test_result.get('error', 'Unknown error')}", 400)
                
                # If connection successful, add the client
                client_id = storage.add_client(
                    data['label'],
                    data['device_id'],
                    data['address'],
                    data['api_key'],
                    data.get('sync_enabled', True)
                )
                
                if client_id:
                    return api_success({
                        'message': 'Client added successfully',
                        'client_id': client_id
                    })
                else:
                    return api_error('Database error', 500)
            except Exception as e:
                return api_error(str(e), 500)
        
        def put(self, client_id):
            """Update a client"""
            data = request.json
            
            # Handle simple sync_enabled toggle if that's all that was sent
            if list(data.keys()) == ['sync_enabled']:
                result = storage.update_client(client_id, sync_enabled=data['sync_enabled'])
                if result:
                    return api_success({'message': 'Client sync status updated'})
                return api_error('Client not found', 404)
            
            # For full updates, test the connection if address or API key changed
            if 'address' in data or 'api_key' in data:
                client = storage.get_client(client_id)
                if not client:
                    return api_error('Client not found', 404)
                
                address = data.get('address', client['address'])
                api_key = data.get('api_key', client['api_key'])
                
                try:
                    test_result = test_connection(address, api_key)
                    if not test_result['connected']:
                        return api_error(f"Connection test failed: {test_result.get('error', 'Unknown error')}", 400)
                except Exception as e:
                    return api_error(str(e), 500)
            
            # Perform the update
            result = storage.update_client(
                client_id,
                label=data.get('label'),
                device_id=data.get('device_id'),
                address=data.get('address'),
                api_key=data.get('api_key'),
                sync_enabled=data.get('sync_enabled')
            )
            
            if result:
                return api_success({'message': 'Client updated successfully'})
            return api_error('Client not found or update failed', 404)
        
        def delete(self, client_id):
            """Delete a client"""
            if storage.delete_client(client_id):
                return api_success({'message': 'Client deleted successfully'})
            return api_error('Client not found or delete failed', 404)
    
    # Register the ClientAPI view
    client_view = ClientAPI.as_view('client_api')
    app.add_url_rule('/api/clients', view_func=client_view, methods=['GET', 'POST'])
    app.add_url_rule('/api/clients/<int:client_id>', view_func=client_view, methods=['GET', 'PUT', 'DELETE'])
    
    # Device discovery endpoint
    @app.route('/api/discover', methods=['POST'])
    @login_required
    def discover_devices():
        """Discover devices from the master Syncthing instance."""
        master = storage.get_master_config()
        if not master:
            return api_error('Master not configured', 400)
        
        try:
            devices = get_configured_devices(master['address'], master['api_key'])
            return api_success({'devices': devices})
        except Exception as e:
            return api_error(str(e), 500)
    
    # Credential synchronization endpoint
    @app.route('/api/sync-credentials', methods=['POST'])
    @login_required
    def sync_credentials():
        """Synchronize GUI credentials from master to all enabled clients."""
        try:
            # Use the current logged-in user
            username = session.get('username')
            
            if not username:
                return api_error('Not logged in or username not available', 401)
            
            # Get master config
            master = storage.get_master_config()
            if not master:
                return api_error('Master not configured', 400)
                
            # Get all enabled clients
            clients = storage.list_clients()
            enabled_clients = [c for c in clients if c['sync_enabled']]
            
            if not enabled_clients:
                return api_error('No enabled clients to sync with', 400)
                
            # First, get the GUI configuration from the master
            try:
                master_gui_config = get_gui_config(master['address'], master['api_key'])
                
                # Ensure the master has GUI credentials set
                if not master_gui_config.get('user') or not master_gui_config.get('password'):
                    return api_error('Master has no GUI credentials configured', 400)
                    
                # Use the hashed password directly from the master config
                master_password_hash = master_gui_config.get('password')
                current_app.logger.info(f"Got hashed password from master: {master_password_hash[:10]}...")
            except SyncthingApiError as e:
                return api_error(f'Failed to get master GUI config: {str(e)}', 500)
            
            # Update each client
            results = []
            for client in enabled_clients:
                try:
                    # Use the master's hashed password for all clients
                    set_gui_password(client['address'], client['api_key'], username, master_password_hash)
                    results.append({
                        'client_id': client['id'],
                        'label': client['label'],
                        'success': True
                    })
                except SyncthingApiError as e:
                    results.append({
                        'client_id': client['id'],
                        'label': client['label'],
                        'success': False,
                        'error': str(e)
                    })
            
            # Count successes and failures
            successes = sum(1 for r in results if r['success'])
            
            return api_success({
                'message': f'Synced credentials to {successes}/{len(enabled_clients)} clients',
                'results': results
            })
            
        except Exception as e:
            current_app.logger.error(f"Error in sync_credentials: {str(e)}")
            return api_error(str(e), 500)
    
    # Test stored connection endpoint
    @app.route('/api/test-stored-connection', methods=['POST'])
    @login_required
    def test_stored_connection():
        """Test the connection using the stored API key for the given address."""
        data = request.json
        address = data.get('address')
        
        if not address:
            return api_error('Address is required', 400)
        
        # Get master configuration
        master = storage.get_master_config()
        if not master:
            return api_error('Master not configured', 400)
        
        # Use the stored API key from the database
        api_key = master['api_key']
        
        try:
            result = test_connection(address, api_key)
            return jsonify(result)
        except Exception as e:
            return api_error(str(e), 500)
    
    # Connections endpoint
    @app.route('/api/connections', methods=['GET'])
    @login_required
    def get_connection_status():
        """Get the current connections status from the master Syncthing instance."""
        try:
            # Get the master configuration
            master = storage.get_master_config()
            if not master:
                return api_error('Master configuration not found')
                
            try:
                # Get connection information
                connections = get_connections(master['address'], master['api_key'])
                
                # Log the raw connection data for debugging
                app.logger.info("RAW CONNECTION DATA FROM SYNCTHING API:")
                app.logger.info(json.dumps(connections, indent=2))
                
                # Get all clients from the database to match names
                clients = storage.get_all_clients()
                device_names = {}
                
                # Create a lookup for device names from clients
                for client in clients:
                    device_names[client['device_id']] = client['label']
                    
                # Format connections for the response
                formatted_connections = []
                for conn in connections:
                    device_id = conn['deviceID']
                    name = device_names.get(device_id, 'Unknown Device')
                    
                    # Extract all possible addresses from the connection
                    addresses = []
                    if conn.get('address'):
                        address_parts = conn['address'].split(',')
                        for part in address_parts:
                            if part.strip():
                                addresses.append(part.strip())
                                
                    # Add the primary address to the top
                    primary_address = conn.get('address', '').split(',')[0].strip() if conn.get('address') else ''
    
                    # Log the processed addresses
                    app.logger.info(f"Device {device_id} ({name}) addresses: {addresses}")
                    app.logger.info(f"Primary address: {primary_address}")
                    app.logger.info(f"Raw address field: {conn.get('address', 'None')}")
    
                    formatted_connections.append({
                        'deviceID': device_id,
                        'name': name,
                        'addresses': addresses,
                        'primary_address': primary_address,
                        'address': conn.get('address', ''),
                        'connected': conn.get('connected', False),
                        'type': conn.get('type', ''),
                    })
                
                return api_success({
                    'connections': formatted_connections,
                    'total_devices': len(formatted_connections)
                })
            except Exception as e:
                return api_error(str(e), 500)
        
        except Exception as e:
            return api_error(str(e), 500)
    
    # All devices endpoint
    @app.route('/api/all-devices', methods=['GET'])
    @login_required
    def get_all_devices():
        """Get a unified list of all devices - both connected and managed."""
        try:
            # Get master configuration
            master = storage.get_master_config()
            if not master:
                return api_error('Master not configured', 400)
            
            # Get all managed clients
            managed_clients = storage.list_clients()
            managed_device_ids = {client['device_id']: client for client in managed_clients}
            
            # Get all connections from the master
            try:
                connections = get_connections(master['address'], master['api_key'])
                devices = get_configured_devices(master['address'], master['api_key'])
                
                # Create a map of device IDs to names for easy lookup
                device_names = {device['deviceID']: device['name'] for device in devices}
                
                # Build a unified device list
                unified_devices = []
                
                # First add all connections, with managed status if applicable
                for connection in connections:
                    device_id = connection['deviceID']
                    device = {
                        'deviceID': device_id,
                        'name': device_names.get(device_id, connection.get('name', 'Unknown Device')),
                        'address': connection.get('address', ''),
                        'connected': connection.get('connected', False),
                        'type': connection.get('type', 'Unknown'),
                        'inBytesTotal': connection.get('inBytesTotal', 0),
                        'outBytesTotal': connection.get('outBytesTotal', 0),
                        'managed': device_id in managed_device_ids,
                    }
                    
                    # Add managed client details if this is a managed device
                    if device_id in managed_device_ids:
                        managed = managed_device_ids[device_id]
                        device.update({
                            'client_id': managed['id'],
                            'label': managed['label'],
                            'sync_enabled': managed['sync_enabled'],
                            'api_key_set': bool(managed['api_key'])
                        })
                    
                    unified_devices.append(device)
                
                # Then add any managed devices that aren't in the connections list
                for client in managed_clients:
                    if client['device_id'] not in [d['deviceID'] for d in unified_devices]:
                        unified_devices.append({
                            'deviceID': client['device_id'],
                            'name': client['label'],
                            'address': client['address'],
                            'connected': False,
                            'managed': True,
                            'client_id': client['id'],
                            'label': client['label'],
                            'sync_enabled': client['sync_enabled'],
                            'api_key_set': bool(client['api_key'])
                        })
                
                return api_success({
                    'devices': unified_devices,
                    'total_devices': len(unified_devices)
                })
            except Exception as e:
                return api_error(f'Error fetching devices: {str(e)}', 500)
        
        except Exception as e:
            return api_error(str(e), 500)
    
    # Config changes endpoint
    @app.route('/api/check-config-changes', methods=['GET'])
    @login_required
    def check_config_changes():
        """Check for ConfigSaved events in the Syncthing API that might indicate configuration changes."""
        try:
            config = storage.get_master_config()
            if not config:
                return api_error('Master configuration not found')
                
            address = config.get('address')
            api_key = config.get('api_key')
            
            # Get the last known event ID from the request
            since = request.args.get('since')
            if since:
                try:
                    since = int(since)
                except ValueError:
                    return api_error('Invalid event ID')
                    
            # Check for ConfigSaved events
            has_changes, latest_event_id = check_for_config_saved_events(address, api_key, since)
            
            return api_success({
                'hasConfigChanges': has_changes,
                'latestEventId': latest_event_id
            })
        except SyncthingApiError as e:
            return api_error(str(e))
        except Exception as e:
            return api_error(f'Unexpected error: {str(e)}')
    
    # Password change endpoint
    @app.route('/api/change-password', methods=['POST'])
    @login_required
    def change_password():
        """Change the Syncthing GUI password with option to sync to clients."""
        try:
            data = request.get_json()
            current_password = data.get('currentPassword')
            new_password = data.get('newPassword')
            sync_to_clients = data.get('syncToClients', False)
            
            if not current_password or not new_password:
                return api_error('Both current and new password are required', 400)
            
            # Get master config
            master = storage.get_master_config()
            if not master:
                return api_error('Master configuration not found', 404)
            
            # Verify current password against Syncthing
            try:
                username = session.get('username', 'syncauth')
                if not verify_gui_credentials(master['address'], master['api_key'], username, current_password):
                    return api_error('Current password is incorrect', 401)
            except SyncthingApiError as e:
                return api_error(f'Error verifying current password: {str(e)}', 500)
            
            # Set new password on master
            try:
                set_gui_password(master['address'], master['api_key'], username, new_password)
                
                # If sync to clients is requested, sync the new password to all enabled clients
                sync_results = []
                if sync_to_clients:
                    enabled_clients = storage.get_all_clients(sync_enabled=True)
                    
                    # Get the new password hash from the master (after we set it)
                    master_gui_config = get_gui_config(master['address'], master['api_key'])
                    master_password_hash = master_gui_config.get('password')
                    
                    for client in enabled_clients:
                        try:
                            # Use the master's new hashed password for the client
                            set_gui_password(client['address'], client['api_key'], username, master_password_hash)
                            sync_results.append({
                                'client': client['label'] or client['device_id'],
                                'success': True,
                                'message': 'Password updated successfully'
                            })
                        except Exception as client_error:
                            sync_results.append({
                                'client': client['label'] or client['device_id'],
                                'success': False,
                                'message': str(client_error)
                            })
                
                return api_success({
                    'message': 'Password changed successfully', 
                    'syncResults': sync_results if sync_to_clients else None
                })
                
            except SyncthingApiError as e:
                return api_error(f'Error setting new password: {str(e)}', 500)
                
        except Exception as e:
            return api_error(f'Unexpected error: {str(e)}', 500)
    
    # Database management endpoints
    @app.route('/delete_database', methods=['POST'])
    @login_required
    def delete_database():
        """Direct route to delete the database file with automatic backup"""
        try:
            app.logger.info("DIRECT DATABASE DELETION ENDPOINT")
            db_path = os.path.join(os.environ.get('DATA_DIR', '.'), "syncauth.db")
            
            # Check if file exists and create backup
            if os.path.exists(db_path):
                app.logger.info(f"Database exists at {db_path}, creating backup...")
                backup_path = os.path.join(os.environ.get('DATA_DIR', '.'), f"syncauth_backup_{int(time.time())}.db")
                try:
                    import shutil
                    shutil.copy2(db_path, backup_path)
                    app.logger.info(f"Backup created at {backup_path}")
                except Exception as backup_error:
                    app.logger.error(f"Warning: Failed to create backup: {str(backup_error)}")
                
                # Now delete the database
                app.logger.info(f"Attempting to delete database...")
                os.remove(db_path)
                app.logger.info(f"Database deletion result: {not os.path.exists(db_path)}")
            else:
                app.logger.info(f"No database file found at {db_path}")
                
            # Make sure SECRET_KEY is removed from environment
            if 'SECRET_KEY' in os.environ:
                app.logger.info("Removing SECRET_KEY from environment")
                del os.environ['SECRET_KEY']
                
            # Now initialize a new database
            app.logger.info("Initializing new database...")
            storage.init_db()
            
            flash('Database has been deleted and recreated successfully')
            return redirect(url_for('setup'))
            
        except Exception as e:
            app.logger.error(f"DIRECT DELETION ERROR: {str(e)}")
            import traceback
            app.logger.error(f"Traceback: {traceback.format_exc()}")
            flash(f'Error deleting database: {str(e)}', 'error')
            return redirect(url_for('setup'))
    
    @app.route('/direct_encrypt', methods=['GET'])
    def direct_encrypt():
        """Direct route for encrypting the database (no form submission)."""
        app.logger.info("=== DIRECT ENCRYPT DATABASE ===")
        try:
            secret_key = os.environ.get('SECRET_KEY', '')
            if not secret_key:
                return redirect(url_for('setup'))
            
            result = storage.encrypt_database(secret_key)
            if result:
                flash('Database encrypted successfully!')
            else:
                flash('Failed to encrypt database')
        except Exception as e:
            flash(f'Error: {str(e)}')
        
        return redirect(url_for('setup'))
    
    @app.route('/direct_reset', methods=['GET'])
    def direct_reset():
        """Direct route for resetting database encryption (no form submission)."""
        app.logger.info("=== DIRECT RESET DATABASE ===")
        try:
            # Get the SECRET_KEY
            secret_key = os.environ.get('SECRET_KEY', '')
            if not secret_key:
                return redirect(url_for('setup'))
            
            # Reset the database
            result = storage.reset_encryption(secret_key)
            if result:
                flash('Database encryption reset successfully!')
            else:
                flash('Failed to reset database encryption')
        except Exception as e:
            flash(f'Error: {str(e)}')
        
        return redirect(url_for('setup'))
    
    @app.route('/api/db_action', methods=['POST'])
    @login_required
    def api_db_action():
        """API endpoint for performing database actions after authentication."""
        if request.method == 'POST':
            data = request.get_json()
            action = data.get('action', '')
            
            # Only allow these actions if user is authenticated for database management
            if not session.get('db_authenticated', False):
                return api_error('Authentication required for database management', 403)
            
            if action == 'encrypt':
                try:
                    result = storage.encrypt_database(os.environ.get('SECRET_KEY', ''))
                    if result:
                        return api_success({'message': 'Database encrypted successfully!'})
                    else:
                        return api_error('Failed to encrypt database. Check logs for details.', 500)
                except Exception as e:
                    app.logger.error(f"Error encrypting database: {str(e)}")
                    return api_error(f'Error encrypting database: {str(e)}', 500)
                    
            elif action == 'reset':
                try:
                    result = storage.reset_encryption(os.environ.get('SECRET_KEY', ''))
                    if result:
                        return api_success({'message': 'Database encryption reset successfully!'})
                    else:
                        return api_error('Failed to reset database encryption. Check logs for details.', 500)
                except Exception as e:
                    app.logger.error(f"Error resetting encryption: {str(e)}")
                    return api_error(f'Error resetting encryption: {str(e)}', 500)
                    
            elif action == 'delete_recreate':
                try:
                    # Backup the database first
                    db_path = storage.get_db_path()
                    backup_path = f"{db_path}.bak.{int(time.time())}"
                    shutil.copy2(db_path, backup_path)
                    
                    # Remove the database file
                    os.remove(db_path)
                    
                    # Initialize a new encrypted database
                    storage.init_db()
                    
                    # Clear the authentication since we have a new DB
                    session.pop('db_authenticated', None)
                    
                    return api_success({
                        'message': f'Database deleted and recreated! Your old database was backed up to {backup_path}',
                        'redirect': url_for('setup')
                    })
                except Exception as e:
                    app.logger.error(f"Error recreating database: {str(e)}")
                    return api_error(f'Error recreating database: {str(e)}', 500)
            else:
                return api_error(f'Unknown action: {action}', 400)
        
        return api_error('Invalid request', 400)
    
    # Auth status endpoint
    @csrf_exempt
    @app.route('/api/auth_status', methods=['GET'])
    def api_auth_status():
        """Check if the user is authenticated for database management."""
        return jsonify({
            'authenticated': session.get('db_authenticated', False)
        })
    
    # Logout endpoint
    @csrf_exempt
    @app.route('/api/logout', methods=['POST'])
    def api_logout():
        """API endpoint for logging out."""
        session.pop('db_authenticated', None)
        return api_success({'message': 'Logged out successfully'})
    
    return app

# Main execution
def run_app(host='0.0.0.0', port=5000, debug=False, dev_mode=False):
    """Run the Flask application with optional development server"""
    app = create_app()
    
    quasar_process = None

    if dev_mode:
        # Start Quasar dev server when in dev mode
        print("Running in DEV mode: Starting Quasar dev server and Flask backend...")
        
        # Set up the Quasar dev server process
        frontend_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'frontend')
        cmd = ['yarn', 'quasar', 'dev']
        
        try:
            # Start Quasar as a subprocess, make sure its output is visible
            quasar_process = subprocess.Popen(
                cmd,
                cwd=frontend_dir,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                universal_newlines=True,
                bufsize=1
            )
            
            # Function to forward Quasar output to Flask's output
            def monitor_quasar_output():
                for line in quasar_process.stdout:
                    print(f"[Quasar] {line.strip()}")
            
            # Start a thread to monitor Quasar output without blocking Flask
            output_thread = threading.Thread(target=monitor_quasar_output)
            output_thread.daemon = True
            output_thread.start()
            
            # Register a cleanup function to terminate Quasar when Flask exits
            def cleanup_quasar():
                if quasar_process:
                    print("Shutting down Quasar dev server...")
                    # Try graceful termination first
                    quasar_process.terminate()
                    try:
                        quasar_process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        # Force kill if graceful termination doesn't work
                        quasar_process.kill()
            
            atexit.register(cleanup_quasar)
            
            # Also handle SIGINT (Ctrl+C) to ensure clean shutdown
            def signal_handler(sig, frame):
                print("Received interrupt signal, shutting down...")
                cleanup_quasar()
                sys.exit(0)
            
            signal.signal(signal.SIGINT, signal_handler)
            
            # Wait a moment for Quasar to start
            import time
            time.sleep(2)
            print("Quasar dev server starting... Flask backend will now start.")
            print("Access your app at http://localhost:9000")
            
        except Exception as e:
            print(f"Error starting Quasar dev server: {e}")
            print("Starting Flask without Quasar - you'll need to run Quasar separately.")
    else:
        print("Running in PRODUCTION mode: Flask will serve static frontend from frontend/dist/spa folder.")
    
    # Start the application
    app.run(host=host, port=port, debug=debug)

if __name__ == '__main__':
    # Set up argument parsing
    parser = argparse.ArgumentParser()
    parser.add_argument('--dev', action='store_true', help='Run in development mode with Quasar dev server')
    args = parser.parse_args()
    
    # Configure application from arguments
    Config.init_from_args(args)
    
    # Set up logging
    logger = setup_logging()
    logger.info("=== SyncAuth starting up ===")
    logger.info(f"Environment variables: SECRET_KEY={os.environ.get('SECRET_KEY', '')[:5]}...")
    
    # Run the application
    run_app(
        host=Config.HOST,
        port=Config.PORT,
        debug=Config.DEBUG,
        dev_mode=Config.DEV_MODE
    )