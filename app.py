import os
from flask import Flask, request, render_template, jsonify, session, redirect, url_for, flash
import storage
from syncthing_api import test_connection, get_configured_devices, set_gui_password, SyncthingApiError, verify_gui_credentials, get_connections, poll_events, check_for_config_saved_events
from functools import wraps
from flask_wtf.csrf import CSRFProtect
import time

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', os.urandom(24).hex())
app.config['SESSION_TYPE'] = 'filesystem'
# Add security settings for cookies
app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
)

# Initialize CSRF protection
csrf = CSRFProtect(app)

# Make DB status available to all templates
@app.context_processor
def inject_db_status():
    return {'db_status': storage.get_db_status()}

# Initialize database at startup
with app.app_context():
    try:
        storage.init_db()
    except Exception as e:
        print(f"Database initialization error: {e}")
        # We'll handle this in the routes

# Authentication decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # First check if master is configured
        master = storage.get_master_config()
        if not master:
            # If master is not configured, redirect to setup page
            return redirect(url_for('setup'))
            
        # If master is configured but user not logged in, redirect to login
        if 'logged_in' not in session:
            return redirect(url_for('login', next=request.url))
            
        return f(*args, **kwargs)
    return decorated_function

@app.route('/setup', methods=['GET', 'POST'])
def setup():
    """Initial setup page to configure master Syncthing instance."""
    # Check if master is already configured
    master = storage.get_master_config()
    if master and 'logged_in' in session:
        return redirect(url_for('index'))
        
    if request.method == 'POST':
        address = request.form.get('address')
        api_key = request.form.get('api_key')
        
        if not address or not api_key:
            return render_template('setup.html', error='Address and API key are required', db_status=storage.get_db_status())
            
        # Test the connection before saving
        try:
            test_result = test_connection(address, api_key)
            if not test_result['connected']:
                return render_template(
                    'setup.html', 
                    error=f"Connection test failed: {test_result.get('error', 'Unknown error')}",
                    db_status=storage.get_db_status()
                )
                
            # If connection successful, save the configuration
            if storage.set_master_config(address, api_key):
                return redirect(url_for('login'))
            else:
                return render_template('setup.html', error='Database error', db_status=storage.get_db_status())
        except Exception as e:
            return render_template('setup.html', error=str(e), db_status=storage.get_db_status())
    
    return render_template('setup.html', db_status=storage.get_db_status())

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
                session['logged_in'] = True
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
    session.pop('logged_in', None)
    session.pop('username', None)
    return redirect(url_for('login'))

@app.route('/')
@login_required
def index():
    """Serve the main HTML page."""
    db_status = storage.get_db_status()
    return render_template('index.html', db_status=db_status)

@app.route('/manage_encryption', methods=['POST'])
@login_required
def manage_encryption():
    """Handle database encryption and reset actions."""
    action = request.form.get('action', '')
    print(f"MANAGE ENCRYPTION ACTION: '{action}'")
    print(f"FORM DATA: {request.form}")
    
    if action == 'encrypt':
        # Encrypt the database with the current SECRET_KEY
        key = os.environ.get('SECRET_KEY', '')
        if not key:
            flash('No encryption key provided in SECRET_KEY')
            return redirect(request.referrer or url_for('setup'))
            
        success = storage.encrypt_database(key)
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
            print("DIRECT DATABASE DELETION ATTEMPT")
            db_path = os.path.join(os.environ.get('DATA_DIR', '.'), "syncauth.db")
            
            # Check if file exists
            if os.path.exists(db_path):
                print(f"Database exists at {db_path}, attempting to delete...")
                os.remove(db_path)
                print(f"Database deletion result: {not os.path.exists(db_path)}")
            else:
                print(f"No database found at {db_path}")
                
            # Now initialize a new database
            print("Initializing new database...")
            storage.init_db()
            
            flash('Database has been deleted and recreated successfully')
            return redirect(request.referrer or url_for('setup'))
            
        except Exception as e:
            print(f"DIRECT DELETION ERROR: {str(e)}")
            import traceback
            print(traceback.format_exc())
            flash(f'Error deleting database: {str(e)}', 'error')
            return redirect(request.referrer or url_for('setup'))
        
    else:
        flash('Invalid action specified', 'error')
        return redirect(request.referrer or url_for('setup'))

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
            return jsonify({'success': False, 'error': 'Missing required fields'}), 400
        
        # Test the connection before saving
        try:
            test_result = test_connection(address, api_key)
            if not test_result['connected']:
                return jsonify({
                    'success': False, 
                    'error': f"Connection test failed: {test_result.get('error', 'Unknown error')}"
                }), 400
            
            # If connection successful, save the configuration
            if storage.set_master_config(address, api_key):
                return jsonify({
                    'success': True, 
                    'message': 'Master configuration saved',
                    'device_id': test_result.get('device_id')
                })
            else:
                return jsonify({'success': False, 'error': 'Database error'}), 500
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/clients', methods=['GET', 'POST'])
@login_required
def clients():
    """List all clients or add a new client."""
    if request.method == 'GET':
        return jsonify(storage.list_clients())
    
    elif request.method == 'POST':
        data = request.json
        
        # Validate required fields
        required_fields = ['label', 'device_id', 'address', 'api_key']
        for field in required_fields:
            if field not in data or not data[field]:
                return jsonify({'success': False, 'error': f'Missing required field: {field}'}), 400
        
        # Test the connection before saving
        try:
            test_result = test_connection(data['address'], data['api_key'])
            if not test_result['connected']:
                return jsonify({
                    'success': False, 
                    'error': f"Connection test failed: {test_result.get('error', 'Unknown error')}"
                }), 400
            
            # If connection successful, add the client
            client_id = storage.add_client(
                data['label'],
                data['device_id'],
                data['address'],
                data['api_key'],
                data.get('sync_enabled', True)
            )
            
            if client_id:
                return jsonify({
                    'success': True,
                    'message': 'Client added successfully',
                    'client_id': client_id
                })
            else:
                return jsonify({'success': False, 'error': 'Database error'}), 500
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/clients/<int:client_id>', methods=['GET', 'PUT', 'DELETE'])
@login_required
def client(client_id):
    """Get, update, or delete a specific client."""
    # Get a specific client
    if request.method == 'GET':
        client = storage.get_client(client_id)
        if client:
            return jsonify(client)
        return jsonify({'error': 'Client not found'}), 404
    
    # Update a client
    elif request.method == 'PUT':
        data = request.json
        
        # Handle simple sync_enabled toggle if that's all that was sent
        if list(data.keys()) == ['sync_enabled']:
            result = storage.update_client(client_id, sync_enabled=data['sync_enabled'])
            if result:
                return jsonify({'success': True, 'message': 'Client sync status updated'})
            return jsonify({'success': False, 'error': 'Client not found'}), 404
        
        # For full updates, test the connection if address or API key changed
        if 'address' in data or 'api_key' in data:
            client = storage.get_client(client_id)
            if not client:
                return jsonify({'success': False, 'error': 'Client not found'}), 404
            
            address = data.get('address', client['address'])
            api_key = data.get('api_key', client['api_key'])
            
            try:
                test_result = test_connection(address, api_key)
                if not test_result['connected']:
                    return jsonify({
                        'success': False, 
                        'error': f"Connection test failed: {test_result.get('error', 'Unknown error')}"
                    }), 400
            except Exception as e:
                return jsonify({'success': False, 'error': str(e)}), 500
        
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
            return jsonify({'success': True, 'message': 'Client updated successfully'})
        return jsonify({'success': False, 'error': 'Client not found or update failed'}), 404
    
    # Delete a client
    elif request.method == 'DELETE':
        if storage.delete_client(client_id):
            return jsonify({'success': True, 'message': 'Client deleted successfully'})
        return jsonify({'success': False, 'error': 'Client not found or delete failed'}), 404

@app.route('/api/discover', methods=['POST'])
@login_required
def discover_devices():
    """Discover devices from the master Syncthing instance."""
    master = storage.get_master_config()
    if not master:
        return jsonify({'success': False, 'error': 'Master not configured'}), 400
    
    try:
        devices = get_configured_devices(master['address'], master['api_key'])
        return jsonify({
            'success': True,
            'devices': devices
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/sync-credentials', methods=['POST'])
@login_required
def sync_credentials():
    """Synchronize GUI credentials from master to all enabled clients."""
    try:
        # Use the current logged-in user
        username = session.get('username')
        
        if not username:
            return jsonify({
                'success': False,
                'error': 'Not logged in or username not available'
            }), 401
        
        # Get master config
        master = storage.get_master_config()
        if not master:
            return jsonify({
                'success': False, 
                'error': 'Master not configured'
            }), 400
            
        # Get all enabled clients
        clients = storage.list_clients()
        enabled_clients = [c for c in clients if c['sync_enabled']]
        
        if not enabled_clients:
            return jsonify({
                'success': False, 
                'error': 'No enabled clients to sync with'
            }), 400
        
        # Update each client
        results = []
        for client in enabled_clients:
            try:
                # Since we're already authenticated, set the current user's credentials
                # We don't need to verify them again as we trust the session
                set_gui_password(client['address'], client['api_key'], username, request.json.get('password', ''))
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
        
        return jsonify({
            'success': True,
            'message': f'Synced credentials to {successes}/{len(enabled_clients)} clients',
            'results': results
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/test-connection', methods=['POST'])
@login_required
def test_client_connection():
    """Test the connection to a client or master."""
    data = request.json
    address = data.get('address')
    api_key = data.get('api_key')
    
    if not address or not api_key:
        return jsonify({'success': False, 'error': 'Address and API key are required'}), 400
    
    try:
        result = test_connection(address, api_key)
        return jsonify(result)
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/test-stored-connection', methods=['POST'])
@login_required
def test_stored_connection():
    """Test the connection using the stored API key for the given address."""
    data = request.json
    address = data.get('address')
    
    if not address:
        return jsonify({'success': False, 'error': 'Address is required'}), 400
    
    # Get master configuration
    master = storage.get_master_config()
    if not master:
        return jsonify({'success': False, 'error': 'Master not configured'}), 400
    
    # Use the stored API key from the database
    api_key = master['api_key']
    
    try:
        result = test_connection(address, api_key)
        return jsonify(result)
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/connections', methods=['GET'])
@login_required
def get_connection_status():
    """Get the current connections status from the master Syncthing instance."""
    try:
        # Get the master configuration
        master = storage.get_master_config()
        if not master:
            return jsonify({'success': False, 'error': 'Master configuration not found'})
            
        try:
            # Get connection information
            connections = get_connections(master['address'], master['api_key'])
            
            # Log the raw connection data for debugging
            print("RAW CONNECTION DATA FROM SYNCTHING API:")
            import json
            print(json.dumps(connections, indent=2))
            
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
                print(f"Device {device_id} ({name}) addresses: {addresses}")
                print(f"Primary address: {primary_address}")
                print(f"Raw address field: {conn.get('address', 'None')}")

                formatted_connections.append({
                    'deviceID': device_id,
                    'name': name,
                    'addresses': addresses,
                    'primary_address': primary_address,
                    'address': conn.get('address', ''),
                    'connected': conn.get('connected', False),
                    'type': conn.get('type', ''),
                })
            
            return jsonify({
                'success': True,
                'connections': formatted_connections,
                'total_devices': len(formatted_connections)
            })
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)}), 500
    
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/all-devices', methods=['GET'])
@login_required
def get_all_devices():
    """Get a unified list of all devices - both connected and managed."""
    try:
        # Get master configuration
        master = storage.get_master_config()
        if not master:
            return jsonify({'success': False, 'error': 'Master not configured'}), 400
        
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
            
            return jsonify({
                'success': True,
                'devices': unified_devices,
                'total_devices': len(unified_devices)
            })
        except Exception as e:
            return jsonify({'success': False, 'error': f'Error fetching devices: {str(e)}'}), 500
    
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/check-config-changes', methods=['GET'])
@login_required
def check_config_changes():
    """Check for ConfigSaved events in the Syncthing API that might indicate configuration changes."""
    try:
        config = storage.get_master_config()
        if not config:
            return jsonify({'success': False, 'error': 'Master configuration not found'})
            
        address = config.get('address')
        api_key = config.get('api_key')
        
        # Get the last known event ID from the request
        since = request.args.get('since')
        if since:
            try:
                since = int(since)
            except ValueError:
                return jsonify({'success': False, 'error': 'Invalid event ID'})
                
        # Check for ConfigSaved events
        has_changes, latest_event_id = check_for_config_saved_events(address, api_key, since)
        
        return jsonify({
            'success': True,
            'hasConfigChanges': has_changes,
            'latestEventId': latest_event_id
        })
    except SyncthingApiError as e:
        return jsonify({'success': False, 'error': str(e)})
    except Exception as e:
        return jsonify({'success': False, 'error': f'Unexpected error: {str(e)}'})

@app.route('/delete_database', methods=['POST'])
@login_required
def delete_database():
    """Direct route to delete the database file with automatic backup"""
    try:
        print("DIRECT DATABASE DELETION ENDPOINT")
        db_path = os.path.join(os.environ.get('DATA_DIR', '.'), "syncauth.db")
        
        # Check if file exists and create backup
        if os.path.exists(db_path):
            print(f"Database exists at {db_path}, creating backup...")
            backup_path = os.path.join(os.environ.get('DATA_DIR', '.'), f"syncauth_backup_{int(time.time())}.db")
            try:
                import shutil
                shutil.copy2(db_path, backup_path)
                print(f"Backup created at {backup_path}")
            except Exception as backup_error:
                print(f"Warning: Failed to create backup: {str(backup_error)}")
            
            # Now delete the database
            print(f"Attempting to delete database...")
            os.remove(db_path)
            print(f"Database deletion result: {not os.path.exists(db_path)}")
        else:
            print(f"No database file found at {db_path}")
            
        # Make sure SECRET_KEY is removed from environment
        if 'SECRET_KEY' in os.environ:
            print("Removing SECRET_KEY from environment")
            del os.environ['SECRET_KEY']
            
        # Now initialize a new database
        print("Initializing new database...")
        storage.init_db()
        
        flash('Database has been deleted and recreated successfully')
        return redirect(url_for('setup'))
        
    except Exception as e:
        print(f"DIRECT DELETION ERROR: {str(e)}")
        import traceback
        print(traceback.format_exc())
        flash(f'Error deleting database: {str(e)}', 'error')
        return redirect(url_for('setup'))

if __name__ == '__main__':
    host = os.environ.get('HOST', '0.0.0.0')
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('DEBUG', 'False').lower() == 'true'
    
    # Start the application
    app.run(host=host, port=port, debug=debug)
