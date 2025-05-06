// SyncAuth Alpine.js Application
document.addEventListener('DOMContentLoaded', () => {
    // Add the CSRF token to all Axios requests
    axios.defaults.headers.common['X-CSRFToken'] = getCsrfToken();
    axios.defaults.headers.post['Content-Type'] = 'application/json';
});

function getCsrfToken() {
    const csrfTokenField = document.querySelector('input[name="csrf_token"]');
    return csrfTokenField ? csrfTokenField.value : '';
}

// HTML sanitizer function to prevent XSS
function sanitizeHTML(html) {
    if (!html) return '';
    
    // Create a temporary div element
    const tempDiv = document.createElement('div');
    
    // Allow only specific safe HTML tags and attributes
    const allowedTags = ['b', 'i', 'u', 'strong', 'em', 'span', 'ul', 'ol', 'li', 'p', 'br'];
    const allowedAttrs = ['class', 'style'];
    
    // Parse the HTML
    const fragment = document.createDocumentFragment();
    const div = document.createElement('div');
    div.innerHTML = html;
    
    // Helper function to sanitize a node
    function sanitizeNode(node) {
        // If it's a text node, it's safe
        if (node.nodeType === 3) {
            return node.cloneNode(true);
        }
        
        // If it's an element node, check if it's allowed
        if (node.nodeType === 1) {
            const tagName = node.tagName.toLowerCase();
            
            // If the tag is not in our allowlist, convert to text
            if (!allowedTags.includes(tagName)) {
                return document.createTextNode(node.outerHTML);
            }
            
            // Create a clean version of the allowed element
            const cleanEl = document.createElement(tagName);
            
            // Copy allowed attributes
            Array.from(node.attributes).forEach(attr => {
                if (allowedAttrs.includes(attr.name)) {
                    cleanEl.setAttribute(attr.name, attr.value);
                }
            });
            
            // Recursively sanitize child nodes
            Array.from(node.childNodes).forEach(child => {
                const sanitizedChild = sanitizeNode(child);
                cleanEl.appendChild(sanitizedChild);
            });
            
            return cleanEl;
        }
        
        // For other node types, ignore
        return document.createTextNode('');
    }
    
    // Sanitize all child nodes
    Array.from(div.childNodes).forEach(child => {
        const sanitized = sanitizeNode(child);
        fragment.appendChild(sanitized);
    });
    
    // Create a new div to hold the sanitized content
    const sanitizedDiv = document.createElement('div');
    sanitizedDiv.appendChild(fragment.cloneNode(true));
    
    return sanitizedDiv.innerHTML;
}

// Helper function to extract hostname
function extractHostname(address) {
    if (!address) return "";
    
    try {
        // If the address has a protocol, try to parse it as a URL
        if (address.includes('://')) {
            const url = new URL(address);
            return url.hostname || url.host;
        }
        
        // Otherwise, try to extract just the hostname part
        // This handles cases like "hostname:port"
        let hostname = address.split(':')[0];
        
        // Remove trailing slashes
        hostname = hostname.replace(/\/+$/, '');
        
        return hostname;
    } catch (error) {
        console.error('Error extracting hostname:', error);
        return address; // Return original if parsing fails
    }
}

// Helper function to format bytes
function formatBytes(bytes, decimals = 2) {
    if (bytes === 0) return '0 Bytes';
    
    const k = 1024;
    const dm = decimals < 0 ? 0 : decimals;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB', 'PB', 'EB', 'ZB', 'YB'];
    
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    
    return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
}

// Main application Alpine.js component
document.addEventListener('alpine:init', () => {
    Alpine.data('syncAuthApp', () => ({
        // Application state
        devices: [],
        latestEventId: null,
        configPollingInterval: null,
        editingClientId: null,
        statusMessages: {
            master: '',
            masterError: false,
            sync: '',
            syncError: false,
            devices: '',
            devicesError: false
        },
        
        // Form models
        masterConfig: {
            address: '',
            apiKey: ''
        },
        
        clientForm: {
            id: '',
            label: '',
            deviceId: '',
            address: '',
            apiKey: '',
            syncEnabled: true
        },
        
        // Modal state
        modals: {
            client: false,
            combined: false
        },
        
        // Combined modal state
        combinedModal: {
            deviceName: '',
            address: '',
            apiKey: '',
            deviceId: '',
            addressSuggestions: [],
            onConfirm: null
        },
        
        // Helper function to ensure address has the correct port (8384)
        formatSyncthingAddress(address) {
            if (!address) return '';
            
            try {
                // If it doesn't have a protocol, add http://
                if (!address.includes('://')) {
                    address = `http://${address}`;
                }
                
                // Parse the URL
                const url = new URL(address);
                
                // Always set the port to 8384 (Syncthing GUI port)
                url.port = '8384';
                
                return url.toString();
            } catch (error) {
                console.error('Error formatting Syncthing address:', error);
                
                // Fallback: basic string manipulation
                let result = address;
                
                // Add protocol if missing
                if (!result.includes('://')) {
                    result = `http://${result}`;
                }
                
                // Replace any port with 8384
                result = result.replace(/:\d+(?!\d*\/)/, ':8384');
                
                return result;
            }
        },
        
        // Initialize the application
        init() {
            console.log('Initializing SyncAuth Alpine.js app');
            this.loadMasterConfig();
            this.loadAllDevices();
            this.startConfigPolling();
        },
        
        // API Functions
        async loadMasterConfig() {
            try {
                console.log('Loading master config');
                const response = await axios.get('/api/master');
                
                if (response.data.configured) {
                    this.masterConfig.address = response.data.address || '';
                    // Set placeholder for API key if it's already set
                    if (response.data.api_key_set) {
                        document.getElementById('master-api-key').placeholder = '[API Key Set]';
                    }
                    console.log('Master config loaded successfully');
                } else {
                    console.log('Master not configured yet');
                }
            } catch (error) {
                console.error('Error loading master config:', error.response ? error.response.data : error.message);
                this.showStatus('master', 'Failed to load master configuration', true);
            }
        },
        
        async loadAllDevices() {
            try {
                this.showStatus('devices', 'Loading devices...');
                console.log('Loading all devices');
                const response = await axios.get('/api/all-devices');
                
                if (response.data.success) {
                    console.log(`Loaded ${response.data.devices.length} devices`);
                    this.devices = response.data.devices || [];
                    this.clearStatus('devices');
                } else {
                    throw new Error(response.data.error || 'Failed to load devices');
                }
            } catch (error) {
                console.error('Error loading devices:', error);
                this.showStatus('devices', `Error loading devices: ${error.response ? error.response.data.error : error.message}`, true);
            }
        },
        
        async saveMasterConfig() {
            try {
                this.showStatus('master', 'Saving master configuration...');
                
                const response = await axios.post('/api/master', {
                    address: this.masterConfig.address,
                    api_key: this.masterConfig.apiKey
                });
                
                if (response.data.success) {
                    this.showStatus('master', 'Master configuration saved successfully');
                    
                    // If API key field is not empty, clear it
                    if (this.masterConfig.apiKey) {
                        this.masterConfig.apiKey = '';
                        // Set placeholder to indicate API key is set
                        document.getElementById('master-api-key').placeholder = '[API Key Set]';
                    }
                    
                    // Refresh devices list
                    this.loadAllDevices();
                } else {
                    throw new Error(response.data.error || 'Failed to save master configuration');
                }
            } catch (error) {
                this.showStatus('master', `Failed to save master configuration: ${error.response ? error.response.data.error : error.message}`, true);
            }
        },
        
        async testMasterConnection() {
            try {
                const address = this.masterConfig.address;
                let apiKey = this.masterConfig.apiKey;
                
                if (!address) {
                    this.showStatus('master', 'Please enter address to test connection', true);
                    return;
                }
                
                this.clearStatus('master');
                this.showStatus('master', 'Testing connection...');
                
                // If API key field is empty but we have a stored key
                if (!apiKey && document.getElementById('master-api-key').placeholder === '[API Key Set]') {
                    try {
                        const response = await axios.post('/api/test-stored-connection', { address });
                        
                        if (response.data.connected) {
                            const deviceInfo = response.data.device_id ? ` (Device ID: ${response.data.device_id})` : '';
                            const version = response.data.version ? ` - Version: ${response.data.version}` : '';
                            
                            this.showStatus('master', `Connection successful${deviceInfo}${version}`);
                            return;
                        }
                    } catch (error) {
                        this.showStatus('master', `Connection test failed: ${error.response ? error.response.data.error : error.message}`, true);
                        return;
                    }
                }
                
                if (!apiKey) {
                    this.showStatus('master', 'Please enter API key to test connection', true);
                    return;
                }
                
                const testResponse = await axios.post('/api/test-connection', {
                    address,
                    api_key: apiKey
                });
                
                if (testResponse.data.connected) {
                    const deviceInfo = testResponse.data.device_id ? ` (Device ID: ${testResponse.data.device_id})` : '';
                    const version = testResponse.data.version ? ` - Version: ${testResponse.data.version}` : '';
                    
                    this.showStatus('master', `Connection successful${deviceInfo}${version}`);
                } else {
                    throw new Error(testResponse.data.error || 'Connection failed');
                }
            } catch (error) {
                this.showStatus('master', `Connection test failed: ${error.response ? error.response.data.error : error.message}`, true);
            }
        },
        
        async syncCredentials() {
            try {
                this.showStatus('sync', 'Synchronizing credentials...');
                
                const response = await axios.post('/api/sync-credentials', {}, {
                    headers: {
                        'Content-Type': 'application/json'
                    }
                });
                
                if (response.data.success) {
                    let resultMessage = 'Credentials synchronized successfully!';
                    
                    // Add details about sync results if available
                    if (response.data.results && response.data.results.length > 0) {
                        resultMessage += '<ul>';
                        response.data.results.forEach(r => {
                            const status = r.success ? 'Success' : 'Failed - ' + sanitizeHTML(r.error || 'Unknown error');
                            resultMessage += `<li>${r.label}: ${status}</li>`;
                        });
                        resultMessage += '</ul>';
                    }
                    
                    this.showStatus('sync', resultMessage, false, true);
                    
                    // Refresh device list to show updated status
                    this.loadAllDevices();
                } else {
                    throw new Error(response.data.error || 'Failed to synchronize credentials');
                }
            } catch (error) {
                console.error('Error syncing credentials:', error);
                this.showStatus('sync', `Error: ${error.response ? error.response.data.error : error.message}`, true);
            }
        },
        
        async discoverDevices() {
            try {
                this.showStatus('devices', 'Discovering devices...');
                
                const response = await axios.post('/api/discover');
                
                if (response.data.success) {
                    const count = response.data.devices ? response.data.devices.length : response.data.count || 0;
                    const message = `Discovered ${count} devices`;
                    this.showStatus('devices', message);
                    
                    // Reload devices list
                    this.loadAllDevices();
                } else {
                    throw new Error(response.data.error || 'Failed to discover devices');
                }
            } catch (error) {
                this.showStatus('devices', `Failed to discover devices: ${error.response ? error.response.data.error : error.message}`, true);
            }
        },
        
        async toggleClientSync(clientId, enabled) {
            try {
                const response = await axios.put(`/api/clients/${clientId}`, {
                    sync_enabled: enabled
                });
                
                if (response.data.success) {
                    // Refresh devices list
                    this.loadAllDevices();
                } else {
                    throw new Error(response.data.error || 'Failed to toggle sync');
                }
            } catch (error) {
                this.showStatus('devices', `Failed to toggle sync: ${error.response ? error.response.data.error : error.message}`, true);
            }
        },
        
        async deleteClient(clientId) {
            if (!confirm('Are you sure you want to delete this client?')) {
                return;
            }
            
            try {
                const response = await axios.delete(`/api/clients/${clientId}`);
                
                if (response.data.success) {
                    // Refresh devices list
                    this.loadAllDevices();
                } else {
                    throw new Error(response.data.error || 'Failed to delete client');
                }
            } catch (error) {
                this.showStatus('devices', `Failed to delete client: ${error.response ? error.response.data.error : error.message}`, true);
            }
        },
        
        async editClient(clientId) {
            try {
                const response = await axios.get(`/api/clients/${clientId}`);
                
                if (response.data) {
                    this.editingClientId = clientId;
                    this.clientForm.id = clientId;
                    this.clientForm.label = response.data.label;
                    this.clientForm.deviceId = response.data.device_id;
                    this.clientForm.address = this.formatSyncthingAddress(response.data.address);
                    this.clientForm.apiKey = '';  // Don't populate API key for security
                    this.clientForm.syncEnabled = response.data.sync_enabled;
                    
                    this.openModal('client');
                } else {
                    throw new Error('Failed to load client data');
                }
            } catch (error) {
                this.showStatus('devices', error.message, true);
            }
        },
        
        async saveClient() {
            try {
                const formData = {
                    label: this.clientForm.label,
                    device_id: this.clientForm.deviceId,
                    address: this.formatSyncthingAddress(this.clientForm.address),
                    api_key: this.clientForm.apiKey,
                    sync_enabled: this.clientForm.syncEnabled
                };
                
                const endpoint = this.clientForm.id ? `/api/clients/${this.clientForm.id}` : '/api/clients';
                const method = this.clientForm.id ? 'put' : 'post';
                
                const response = await axios({
                    method,
                    url: endpoint,
                    data: formData
                });
                
                if (response.data.success) {
                    this.closeModal('client');
                    this.resetClientForm();
                    this.loadAllDevices();
                } else {
                    throw new Error(response.data.error || 'Failed to save client');
                }
            } catch (error) {
                this.showStatus('devices', error.message, true);
            }
        },
        
        async testClientConnection() {
            try {
                const address = this.clientForm.address;
                const apiKey = this.clientForm.apiKey;
                
                if (!address || !apiKey) {
                    this.showStatus('devices', 'Address and API Key are required', true);
                    return;
                }
                
                this.showStatus('devices', 'Testing connection...');
                
                const response = await axios.post('/api/test-connection', {
                    address: this.formatSyncthingAddress(address),
                    api_key: apiKey
                });
                
                if (response.data.connected) {
                    this.showStatus('devices', 'Connection successful!');
                } else {
                    throw new Error(response.data.error || 'Connection failed');
                }
            } catch (error) {
                this.showStatus('devices', error.message, true);
            }
        },
        
        async enableSyncForDevice(deviceAddress, deviceId, deviceName) {
            // First, setup the basic modal regardless of API results
            this.combinedModal.deviceName = deviceName || 'Unknown Device';
            this.combinedModal.deviceId = deviceId;
            this.combinedModal.address = '';
            this.combinedModal.addressSuggestions = [];
            this.combinedModal.apiKey = '';
            
            // Default port for Syncthing Web UI
            const defaultPort = '8384';
            
            try {
                this.showStatus('devices', 'Setting up sync for device...');
                
                console.log('Initial deviceAddress:', deviceAddress);
                console.log('Device ID:', deviceId);
                console.log('Device Name:', deviceName);
                
                const addresses = [];
                let formattedAddress = '';
                
                if (deviceAddress) {
                    // If we have a device address, use it as default
                    formattedAddress = this.formatSyncthingAddress(deviceAddress);
                    
                    addresses.push({
                        display: formattedAddress,
                        value: formattedAddress
                    });
                }
                
                try {
                    // Fetch all connections to get possible addresses for this device
                    const connectionsResponse = await axios.get('/api/connections');
                    const connections = connectionsResponse.data.connections;
                    
                    // Check connections for addresses related to this device
                    if (connections && connections[deviceId]) {
                        // We have connection data for this device
                        const deviceConnections = connections[deviceId];
                        
                        for (const conn of deviceConnections) {
                            if (conn.address && conn.address !== '0.0.0.0:0') {
                                // Skip the outgoing address of the server itself
                                if (conn.type === 'TCP (outgoing)') {
                                    continue;
                                }
                                
                                const addressPart = conn.address.split(':')[0];
                                
                                // Skip loopback addresses if we're not running locally
                                if (addressPart !== '127.0.0.1' && addressPart !== 'localhost') {
                                    const httpAddress = this.formatSyncthingAddress(`http://${addressPart}`);
                                    const httpsAddress = this.formatSyncthingAddress(`https://${addressPart}`);
                                    
                                    // Add both http and https options
                                    addresses.push({
                                        display: `HTTP: ${addressPart}:${defaultPort}`,
                                        value: httpAddress
                                    });
                                    
                                    addresses.push({
                                        display: `HTTPS: ${addressPart}:${defaultPort}`,
                                        value: httpsAddress
                                    });
                                    
                                    // If we don't have a default address yet, use this one
                                    if (!formattedAddress) {
                                        formattedAddress = httpAddress;
                                    }
                                }
                            }
                        }
                    }
                } catch (connectionError) {
                    console.error('Error fetching connections:', connectionError);
                    // Continue without connections data
                }
                
                // If we don't have any addresses, add a default one using default port
                if (addresses.length === 0) {
                    formattedAddress = `http://:${defaultPort}`;
                    addresses.push({
                        display: "Default (port only)",
                        value: formattedAddress
                    });
                }
                
                console.log('Final addresses:', addresses);
                console.log('Default formatted address:', formattedAddress);
                
                // Update the modal with the addresses we found
                this.combinedModal.address = formattedAddress;
                this.combinedModal.addressSuggestions = addresses;
            } catch (error) {
                console.error('Error preparing device sync:', error);
                // Add a default address suggestion even if everything fails
                this.combinedModal.address = `http://:${defaultPort}`;
                this.combinedModal.addressSuggestions = [{
                    display: "Default (port only)",
                    value: `http://:${defaultPort}`
                }];
            }
            
            // Set up the confirm callback
            this.combinedModal.onConfirm = async () => {
                try {
                    // Test the connection
                    const testResponse = await axios.post('/api/test-connection', {
                        address: this.combinedModal.address,
                        api_key: this.combinedModal.apiKey
                    });
                    
                    if (!testResponse.data.connected) {
                        throw new Error(testResponse.data.error || 'Connection test failed');
                    }
                    
                    // Add the new client
                    const clientResponse = await axios.post('/api/clients', {
                        label: deviceName || 'New Device',
                        device_id: deviceId,
                        address: this.combinedModal.address,
                        api_key: this.combinedModal.apiKey,
                        sync_enabled: true
                    });
                    
                    if (!clientResponse.data.success) {
                        throw new Error(clientResponse.data.error || 'Failed to add client');
                    }
                    
                    this.showStatus('devices', 'Client added successfully');
                    this.closeModal('combined');
                    this.loadAllDevices();
                } catch (error) {
                    this.showStatus('devices', `Error: ${error.response ? error.response.data.error : error.message}`, true);
                }
            };
            
            // Always open the modal, even if there were errors
            this.openModal('combined');
        },
        
        async testCombinedConnection() {
            try {
                const address = this.combinedModal.address;
                const apiKey = this.combinedModal.apiKey;
                
                if (!address || !apiKey) {
                    alert('Address and API Key are required');
                    return;
                }
                
                const response = await axios.post('/api/test-connection', {
                    address,
                    api_key: apiKey
                });
                
                if (response.data.connected) {
                    const deviceInfo = response.data.device_id ? ` (Device ID: ${response.data.device_id})` : '';
                    const version = response.data.version ? ` - Version: ${response.data.version}` : '';
                    alert(`Connection successful!${deviceInfo}${version}`);
                } else {
                    throw new Error(response.data.error || 'Connection failed');
                }
            } catch (error) {
                alert(`Connection test failed: ${error.response ? error.response.data.error : error.message}`);
            }
        },
        
        confirmCombined() {
            if (this.combinedModal.onConfirm) {
                this.combinedModal.onConfirm();
            }
        },
        
        // Config change polling
        startConfigPolling() {
            // Start polling for config changes
            this.configPollingInterval = setInterval(() => {
                this.checkForConfigChanges();
            }, 10000); // Check every 10 seconds
        },
        
        stopConfigPolling() {
            if (this.configPollingInterval) {
                clearInterval(this.configPollingInterval);
                this.configPollingInterval = null;
            }
        },
        
        async checkForConfigChanges() {
            try {
                const url = this.latestEventId ? 
                    `/api/check-config-changes?since=${this.latestEventId}` : 
                    '/api/check-config-changes';
                
                const response = await axios.get(url);
                
                if (response.data.success) {
                    // Check if there are changes
                    if (response.data.hasConfigChanges) {
                        // Update latest event ID
                        this.latestEventId = response.data.latestEventId;
                        
                        // Show notification
                        this.notifyConfigChange(response.data.changes);
                        
                        // Reload devices
                        this.loadAllDevices();
                    } else {
                        // Just update the latest event ID
                        this.latestEventId = response.data.latestEventId;
                    }
                }
            } catch (error) {
                console.error('Error checking for config changes:', error);
            }
        },
        
        notifyConfigChange(changes) {
            if (!changes || changes.length === 0) return;
            
            // Show notification about config changes in the device section
            let message = 'Configuration changes detected:<ul>';
            
            changes.forEach(change => {
                let changeType = '';
                
                if (change.type === 'device') {
                    // Device changes
                    if (change.action === 'added') {
                        changeType = 'Device added';
                    } else if (change.action === 'removed') {
                        changeType = 'Device removed';
                    } else if (change.action === 'modified') {
                        changeType = 'Device modified';
                    }
                    
                    const deviceName = change.name || change.device_id || 'Unknown device';
                    message += `<li>${changeType}: ${deviceName}</li>`;
                } else if (change.type === 'folder') {
                    // Folder changes
                    if (change.action === 'added') {
                        changeType = 'Folder added';
                    } else if (change.action === 'removed') {
                        changeType = 'Folder removed';
                    } else if (change.action === 'modified') {
                        changeType = 'Folder modified';
                    }
                    
                    const folderName = change.label || change.id || 'Unknown folder';
                    message += `<li>${changeType}: ${folderName}</li>`;
                }
            });
            
            message += '</ul>';
            
            // Show notification
            this.showStatus('devices', sanitizeHTML(message), false, true);
        },
        
        // UI Helpers
        showStatus(type, message, isError = false, isHTML = false) {
            // Update status messages in the state
            this.statusMessages[type] = message;
            this.statusMessages[`${type}Error`] = isError;
            
            // Also update DOM elements for backward compatibility
            const elementId = `${type}-status`;
            const element = document.getElementById(elementId);
            
            if (element) {
                if (isHTML) {
                    element.innerHTML = sanitizeHTML(message);
                } else {
                    element.textContent = message;
                }
                
                element.style.display = message ? 'block' : 'none';
                element.classList.toggle('error', isError);
            }
        },
        
        clearStatus(type) {
            this.statusMessages[type] = '';
            this.statusMessages[`${type}Error`] = false;
            
            // Also update DOM elements for backward compatibility
            const elementId = `${type}-status`;
            const element = document.getElementById(elementId);
            
            if (element) {
                element.textContent = '';
                element.style.display = 'none';
                element.classList.remove('error');
            }
        },
        
        // Modal handling
        openModal(modalName) {
            this.modals[modalName] = true;
            
            // Also update the DOM for backward compatibility
            const modalElement = document.getElementById(`${modalName}-modal`);
            if (modalElement) {
                modalElement.classList.add('active');
            }
        },
        
        closeModal(modalName) {
            this.modals[modalName] = false;
            
            // Also update the DOM for backward compatibility
            const modalElement = document.getElementById(`${modalName}-modal`);
            if (modalElement) {
                modalElement.classList.remove('active');
            }
            
            if (modalName === 'client') {
                this.resetClientForm();
            }
        },
        
        resetClientForm() {
            this.clientForm = {
                id: '',
                label: '',
                deviceId: '',
                address: '',
                apiKey: '',
                syncEnabled: true
            };
            this.editingClientId = null;
        }
    }));
});
