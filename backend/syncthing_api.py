import requests
import json
import base64
import bcrypt
import os
import logging
from urllib.parse import urlparse

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('syncthing_api')

# Environment variable to control SSL verification behavior
VERIFY_SSL = os.environ.get('SYNCTHING_VERIFY_SSL', 'true').lower() == 'true'

class SyncthingApiError(Exception):
    """Exception raised for errors in the Syncthing API interactions."""
    pass

def make_api_request(base_url, api_key, endpoint, method='GET', data=None, timeout=10, verify_ssl=None):
    """Make a request to the Syncthing API with error handling."""
    # Ensure base_url doesn't end with a slash
    if base_url.endswith('/'):
        base_url = base_url[:-1]
        
    url = f"{base_url}/rest/{endpoint.lstrip('/')}"
    headers = {'X-API-Key': api_key}
    
    # Determine SSL verification
    # If not explicitly provided, use the global VERIFY_SSL setting
    if verify_ssl is None:
        verify_ssl = VERIFY_SSL
    
    # Detect if the URL uses HTTPS
    parsed_url = urlparse(url)
    is_https = parsed_url.scheme == 'https'
    
    # If it's not HTTPS, no need for verification
    if not is_https:
        verify_ssl = False
    
    logger.info(f"API {method} request to: {url}")
    if data:
        logger.info(f"Request data: {data}")
    
    try:
        if method.upper() == 'GET':
            response = requests.get(url, headers=headers, timeout=timeout, verify=verify_ssl)
        elif method.upper() == 'POST':
            response = requests.post(url, headers=headers, json=data, timeout=timeout, verify=verify_ssl)
        elif method.upper() == 'PUT':
            response = requests.put(url, headers=headers, json=data, timeout=timeout, verify=verify_ssl)
        elif method.upper() == 'PATCH':
            response = requests.patch(url, headers=headers, json=data, timeout=timeout, verify=verify_ssl)
        else:
            raise SyncthingApiError(f"Unsupported HTTP method: {method}")
        
        # Log the response
        logger.info(f"Response status code: {response.status_code}")
        
        # Check for HTTP errors
        try:
            response.raise_for_status()
        except requests.exceptions.HTTPError as e:
            logger.error(f"HTTP error: {e}")
            if response.text:
                logger.error(f"Response content: {response.text}")
            raise
        
        # Return JSON response if available
        if response.headers.get('Content-Type', '').startswith('application/json'):
            return response.json()
        return response.text
    
    except requests.exceptions.SSLError as e:
        # Special handling for SSL verification failures
        error_message = (
            f"SSL certificate verification failed: {str(e)}. "
            "If you trust this certificate, you can set SYNCTHING_VERIFY_SSL=false in environment variables."
        )
        logger.error(error_message)
        raise SyncthingApiError(error_message)
    except requests.exceptions.RequestException as e:
        logger.error(f"API request failed: {str(e)}")
        raise SyncthingApiError(f"API request failed: {str(e)}")

def get_gui_config(base_url, api_key):
    """Get the current GUI configuration from a Syncthing instance."""
    try:
        logger.info(f"Getting GUI config for {base_url}")
        config = make_api_request(base_url, api_key, 'config')
        logger.info(f"Successfully retrieved GUI config for {base_url}")
        return config.get('gui', {})
    except Exception as e:
        logger.error(f"Failed to get GUI config: {str(e)}")
        raise SyncthingApiError(f"Failed to get GUI config: {str(e)}")

def set_gui_password(base_url, api_key, username, password):
    """Set the GUI username and password for a Syncthing instance."""
    try:
        logger.info(f"Setting GUI password for {base_url}")
        
        # Skip if password is empty (but allow hashed passwords which may start with $)
        if not password and not password.startswith('$'):
            logger.error("Cannot set empty password - skipping")
            raise SyncthingApiError("Empty password not allowed")
            
        # Create a GUI config object with only the user and password fields
        # Syncthing will hash the password automatically if needed
        gui_config = {
            'user': username,
            'password': password
        }
        
        # Use the specific GUI config endpoint as per Syncthing API docs
        # PUT replaces the entire object, PATCH updates only specified fields
        logger.info(f"Using PATCH method to /config/gui endpoint")
        make_api_request(base_url, api_key, 'config/gui', method='PATCH', data=gui_config)
        
        logger.info(f"Successfully updated GUI password for {base_url}")
        return True
    except Exception as e:
        logger.error(f"Failed to set GUI password: {str(e)}")
        raise SyncthingApiError(f"Failed to set GUI password: {str(e)}")

def restart_instance(base_url, api_key):
    """Restart a Syncthing instance."""
    try:
        logger.info(f"Restarting instance {base_url}")
        make_api_request(base_url, api_key, 'system/restart', method='POST')
        logger.info(f"Successfully restarted instance {base_url}")
        return True
    except Exception as e:
        logger.error(f"Failed to restart instance: {str(e)}")
        raise SyncthingApiError(f"Failed to restart instance: {str(e)}")

def get_configured_devices(base_url, api_key):
    """Get a list of devices configured on a Syncthing instance."""
    try:
        logger.info(f"Getting configured devices for {base_url}")
        config = make_api_request(base_url, api_key, 'config')
        devices = config.get('devices', [])
        logger.info(f"Successfully retrieved configured devices for {base_url}")
        return [
            {
                'deviceID': device.get('deviceID'),
                'name': device.get('name'),
                'address': device.get('addresses', [])
            }
            for device in devices
        ]
    except Exception as e:
        logger.error(f"Failed to get configured devices: {str(e)}")
        raise SyncthingApiError(f"Failed to get configured devices: {str(e)}")

def test_connection(base_url, api_key):
    """Test the connection to a Syncthing instance."""
    try:
        logger.info(f"Testing connection to {base_url}")
        status = make_api_request(base_url, api_key, 'system/status')
        logger.info(f"Successfully tested connection to {base_url}")
        return {
            'connected': True,
            'version': status.get('version', 'Unknown'),
            'device_id': status.get('myID', 'Unknown')
        }
    except Exception as e:
        logger.error(f"Failed to test connection: {str(e)}")
        return {
            'connected': False,
            'error': str(e)
        }

def verify_gui_credentials(base_url, api_key, username, password):
    """Verify if the provided GUI credentials are valid for the Syncthing instance."""
    try:
        logger.info(f"Verifying GUI credentials for {base_url}")
        # Get the current GUI config
        config = make_api_request(base_url, api_key, 'config')
        gui_config = config.get('gui', {})
        
        # Check if credentials match
        stored_username = gui_config.get('user', '')
        stored_password_hash = gui_config.get('password', '')
        
        # If no credentials are configured in Syncthing, any login is invalid
        if not stored_username or not stored_password_hash:
            logger.info(f"No GUI credentials configured for {base_url}")
            return False
            
        # Simple comparison for username
        if username != stored_username:
            logger.info(f"GUI username mismatch for {base_url}")
            return False
            
        # Verify the password with bcrypt
        # Syncthing stores the hash in $2a$... format
        # We need to encode both strings to bytes for bcrypt
        try:
            stored_hash_bytes = stored_password_hash.encode('utf-8')
            password_bytes = password.encode('utf-8')
            
            # Use bcrypt to check if the provided password matches the stored hash
            if bcrypt.checkpw(password_bytes, stored_hash_bytes):
                logger.info(f"GUI credentials verified for {base_url}")
                return True
            else:
                logger.info(f"GUI password mismatch for {base_url}")
                return False
        except Exception as e:
            logger.error(f"Bcrypt verification error: {e}")
            return False
            
    except Exception as e:
        logger.error(f"Credential verification error: {e}")
        return False

def get_connections(base_url, api_key):
    """Get active connections information from a Syncthing instance."""
    try:
        logger.info(f"Getting connections for {base_url}")
        connections_data = make_api_request(base_url, api_key, 'system/connections')
        
        if not connections_data or 'connections' not in connections_data:
            logger.info(f"No connections found for {base_url}")
            return []
            
        result = []
        for device_id, conn_info in connections_data['connections'].items():
            result.append({
                'deviceID': device_id,
                'connected': conn_info.get('connected', False),
                'address': conn_info.get('address', ''),
                'clientVersion': conn_info.get('clientVersion', ''),
                'type': conn_info.get('type', ''),
                'isLocal': conn_info.get('isLocal', False),
                'paused': conn_info.get('paused', False),
                'inBytesTotal': conn_info.get('inBytesTotal', 0),
                'outBytesTotal': conn_info.get('outBytesTotal', 0)
            })
        logger.info(f"Successfully retrieved connections for {base_url}")
        return result
    except Exception as e:
        logger.error(f"Failed to get connections: {str(e)}")
        raise SyncthingApiError(f"Failed to get connections: {str(e)}")

def poll_events(base_url, api_key, since=None, limit=100):
    """Poll for Syncthing events. 
    
    Args:
        base_url: The base URL of the Syncthing instance
        api_key: The API key for the Syncthing instance
        since: The event ID to poll from (exclusive). If None, only the latest events are returned.
        limit: Maximum number of events to return
        
    Returns:
        A list of events, each as a dictionary. The most recent events come first.
    """
    try:
        logger.info(f"Polling events for {base_url}")
        endpoint = 'events'
        params = {}
        
        if since is not None:
            endpoint += f"?since={since}&limit={limit}"
        else:
            endpoint += f"?limit={limit}"
            
        events = make_api_request(base_url, api_key, endpoint)
        logger.info(f"Successfully polled events for {base_url}")
        return events
    except Exception as e:
        logger.error(f"Failed to poll events: {str(e)}")
        raise SyncthingApiError(f"Failed to poll events: {str(e)}")

def check_for_config_saved_events(base_url, api_key, since=None):
    """Check for ConfigSaved events that indicate configuration changes.
    
    Args:
        base_url: The base URL of the Syncthing instance
        api_key: The API key for the Syncthing instance
        since: The event ID to check from (exclusive). If None, only the latest events are checked.
        
    Returns:
        A tuple (has_config_changes, latest_event_id) where:
            has_config_changes: Boolean indicating if any ConfigSaved events were found
            latest_event_id: The ID of the latest event seen, to be used for the next poll
    """
    try:
        logger.info(f"Checking for config saved events for {base_url}")
        events = poll_events(base_url, api_key, since)
        
        if not events:
            logger.info(f"No events found for {base_url}")
            return False, since
            
        # Get the latest event ID
        latest_event_id = events[0].get('id', 0) if events else 0
        
        # Check for ConfigSaved events
        for event in events:
            if event.get('type') == 'ConfigSaved':
                logger.info(f"Config saved event found for {base_url}")
                return True, latest_event_id
                
        logger.info(f"No config saved events found for {base_url}")
        return False, latest_event_id
    except Exception as e:
        logger.error(f"Error checking for config events: {e}")
        return False, since
