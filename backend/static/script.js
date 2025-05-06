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
        syncing: false,
        changingPassword: false,
        
        // Status messages for different sections
        statusMessages: {
            master: '',
            masterError: false,
            sync: '',
            syncError: false,
            devices: '',
            devicesError: false,
            password: '',
            passwordError: false
        },
        
        // Master configuration
        masterConfig: {
            address: '',
            apiKey: ''
        },
        
        // Sync configuration
        syncConfig: {
            frequency: 'manual', // manual, hourly, daily, weekly, custom
            lastSync: '',
            nextSync: '',
            syncIntervalId: null,
            
            // Custom scheduling options
            customType: 'interval', // interval or specific
            intervalValue: 30,
            intervalUnit: 'minutes',
            syncTime: '12:00',
            syncDays: ['1', '2', '3', '4', '5'], // Monday to Friday by default
            
            // Advanced options
            showNotifications: false,
            quietHoursEnabled: false,
            quietHoursStart: '22:00',
            quietHoursEnd: '08:00'
        },
        
        // Modal states
        modals: {
            client: false,
            address: false,
            combined: false,
            password: false
        },
        
        // Client form data
        clientForm: {
            id: '',
            label: '',
            deviceId: '',
            address: '',
            apiKey: '',
            syncEnabled: true
        },
        
        editingClientId: null,
        
        // Combined modal state
        combinedModal: {
            deviceName: '',
            address: '',
            apiKey: '',
            deviceId: '',
            addressSuggestions: [],
            onConfirm: null
        },
        
        // Password change form data
        passwordForm: {
            currentPassword: '',
            newPassword: '',
            confirmPassword: '',
            syncOption: 'master' // 'master' or 'all'
        },
        
        // Computed property to check if password form is valid
        get isPasswordFormValid() {
            return this.passwordForm.currentPassword && 
                   this.passwordForm.newPassword && 
                   this.passwordForm.confirmPassword && 
                   this.passwordForm.newPassword === this.passwordForm.confirmPassword &&
                   this.passwordForm.newPassword.length >= 8;
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
            this.loadSyncConfig();
            this.checkAndScheduleSync();
            
            // Add a change password button to the header navigation
            this.addPasswordChangeButton();
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
                this.clearStatus('sync');
                this.showStatus('sync', 'Syncing credentials...', false);
                this.syncing = true;
                
                const response = await axios.post('/api/sync-credentials')
                    .then(response => {
                        if (response.data.success) {
                            // Update last sync time
                            const now = new Date();
                            this.syncConfig.lastSync = this.formatDateTime(now);
                            
                            // Calculate next sync time if not manual
                            if (this.syncConfig.frequency !== 'manual') {
                                this.calculateNextSyncTime(now);
                            }
                            
                            // Save sync config
                            this.saveSyncConfig();
                            
                            let message = 'Credentials synced successfully';
                            if (response.data.syncResults && response.data.syncResults.length > 0) {
                                message += ':<ul>';
                                response.data.syncResults.forEach(result => {
                                    const statusClass = result.success ? 'success' : 'error';
                                    const icon = result.success ? '✓' : '✗';
                                    message += `<li class="${statusClass}"><strong>${icon} ${result.client}</strong>: ${result.message}</li>`;
                                });
                                message += '</ul>';
                            }
                            this.showStatus('sync', message, false, true);
                        } else {
                            this.showStatus('sync', `Sync failed: ${response.data.error || 'Unknown error'}`, true);
                        }
                        this.syncing = false;
                        return response;
                    })
                    .catch(error => {
                        console.error('Sync error:', error);
                        this.showStatus('sync', `Sync failed: ${error.response?.data?.error || error.message || 'Unknown error'}`, true);
                        this.syncing = false;
                        throw error; // Re-throw for handling in the auto-sync function
                    });
                
                return response;
            } catch (error) {
                console.error('Error syncing credentials:', error);
                this.syncing = false;
                throw error;
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
        
        // Load sync configuration from localStorage
        loadSyncConfig() {
            try {
                const savedConfig = localStorage.getItem('syncConfig');
                if (savedConfig) {
                    const config = JSON.parse(savedConfig);
                    
                    // Load basic config
                    this.syncConfig.frequency = config.frequency || 'manual';
                    this.syncConfig.lastSync = config.lastSync || '';
                    
                    // Load custom scheduling options if saved
                    if (config.customType) this.syncConfig.customType = config.customType;
                    if (config.intervalValue) this.syncConfig.intervalValue = config.intervalValue;
                    if (config.intervalUnit) this.syncConfig.intervalUnit = config.intervalUnit;
                    if (config.syncTime) this.syncConfig.syncTime = config.syncTime;
                    if (config.syncDays) this.syncConfig.syncDays = config.syncDays;
                    
                    // Load advanced options if saved
                    if (config.showNotifications !== undefined) {
                        this.syncConfig.showNotifications = config.showNotifications;
                    }
                    if (config.quietHoursEnabled !== undefined) {
                        this.syncConfig.quietHoursEnabled = config.quietHoursEnabled;
                    }
                    if (config.quietHoursStart) this.syncConfig.quietHoursStart = config.quietHoursStart;
                    if (config.quietHoursEnd) this.syncConfig.quietHoursEnd = config.quietHoursEnd;
                    
                    // Calculate next sync time if applicable
                    if (this.syncConfig.frequency !== 'manual') {
                        if (config.lastSync) {
                            this.calculateNextSyncTime(new Date(config.lastSync));
                        } else {
                            this.calculateNextSyncTime(new Date());
                        }
                    }
                    
                    // Request notification permission if enabled
                    if (this.syncConfig.showNotifications) {
                        this.requestNotificationPermission();
                    }
                }
            } catch (error) {
                console.error('Error loading sync configuration:', error);
            }
        },
        
        // Request permission for browser notifications
        requestNotificationPermission() {
            if ('Notification' in window && this.syncConfig.showNotifications) {
                if (Notification.permission !== 'granted' && Notification.permission !== 'denied') {
                    Notification.requestPermission();
                }
            }
        },
        
        // Save sync configuration to localStorage
        saveSyncConfig() {
            try {
                localStorage.setItem('syncConfig', JSON.stringify({
                    frequency: this.syncConfig.frequency,
                    lastSync: this.syncConfig.lastSync,
                    
                    // Custom scheduling options
                    customType: this.syncConfig.customType,
                    intervalValue: this.syncConfig.intervalValue,
                    intervalUnit: this.syncConfig.intervalUnit,
                    syncTime: this.syncConfig.syncTime,
                    syncDays: this.syncConfig.syncDays,
                    
                    // Advanced options
                    showNotifications: this.syncConfig.showNotifications,
                    quietHoursEnabled: this.syncConfig.quietHoursEnabled,
                    quietHoursStart: this.syncConfig.quietHoursStart,
                    quietHoursEnd: this.syncConfig.quietHoursEnd
                }));
            } catch (error) {
                console.error('Error saving sync configuration:', error);
            }
        },
        
        // Update sync frequency when user changes the dropdown
        updateSyncFrequency() {
            // Clear any existing interval
            if (this.syncConfig.syncIntervalId) {
                clearInterval(this.syncConfig.syncIntervalId);
                this.syncConfig.syncIntervalId = null;
            }
            
            // Save the new frequency setting
            this.saveSyncConfig();
            
            // If not manual, set up the next sync time
            if (this.syncConfig.frequency !== 'manual') {
                // If we have a last sync time, calculate next from that
                if (this.syncConfig.lastSync) {
                    this.calculateNextSyncTime(new Date(this.syncConfig.lastSync));
                } else {
                    // Otherwise, set next sync based on now
                    this.calculateNextSyncTime(new Date());
                }
                
                // Set up checking interval (check every 30 seconds)
                this.syncConfig.syncIntervalId = setInterval(() => {
                    this.checkAndScheduleSync();
                }, 30000); // Check every 30 seconds
            } else {
                // If manual, clear the next sync time
                this.syncConfig.nextSync = '';
            }
        },
        
        // Calculate the next sync time based on frequency and last sync
        calculateNextSyncTime(lastSyncDate) {
            let nextSync = new Date();
            
            switch (this.syncConfig.frequency) {
                case 'hourly':
                    nextSync = new Date(lastSyncDate);
                    nextSync.setHours(nextSync.getHours() + 1);
                    break;
                    
                case 'daily':
                    nextSync = new Date(lastSyncDate);
                    nextSync.setDate(nextSync.getDate() + 1);
                    nextSync.setHours(12, 0, 0); // Noon by default
                    break;
                    
                case 'weekly':
                    nextSync = new Date(lastSyncDate);
                    nextSync.setDate(nextSync.getDate() + 7);
                    nextSync.setHours(12, 0, 0); // Noon by default
                    break;
                    
                case 'custom':
                    if (this.syncConfig.customType === 'interval') {
                        // For interval-based scheduling
                        nextSync = new Date(lastSyncDate);
                        if (this.syncConfig.intervalUnit === 'minutes') {
                            nextSync.setMinutes(nextSync.getMinutes() + this.syncConfig.intervalValue);
                        } else {
                            nextSync.setHours(nextSync.getHours() + this.syncConfig.intervalValue);
                        }
                    } else {
                        // For specific time-based scheduling
                        nextSync = this.getNextSpecificTime();
                    }
                    break;
                    
                default:
                    return; // Manual mode, no next sync
            }
            
            this.syncConfig.nextSync = this.formatDateTime(nextSync);
        },
        
        // Calculate the next sync time for specific time-based scheduling
        getNextSpecificTime() {
            // Parse the sync time
            const [hours, minutes] = this.syncConfig.syncTime.split(':').map(Number);
            
            // Get the current date and time
            const now = new Date();
            
            // If no days are selected, use all days
            const syncDays = this.syncConfig.syncDays.length > 0 
                ? this.syncConfig.syncDays.map(Number) 
                : [0, 1, 2, 3, 4, 5, 6];
            
            // Try each day, starting from today
            let nextSync = null;
            for (let i = 0; i < 7; i++) {
                // Create a date for "today + i days" at the specified sync time
                const testDate = new Date(now);
                testDate.setDate(testDate.getDate() + i);
                testDate.setHours(hours, minutes, 0, 0);
                
                // Check if this day of the week is in our sync days
                if (syncDays.includes(testDate.getDay())) {
                    // If it's today, make sure it's in the future
                    if (i === 0 && testDate <= now) {
                        continue; // Skip if it's in the past
                    }
                    
                    nextSync = testDate;
                    break;
                }
            }
            
            // If we didn't find a next sync time, use the first selected day next week
            if (!nextSync && syncDays.length > 0) {
                nextSync = new Date();
                // Find the first selected day
                const firstDay = Math.min(...syncDays);
                
                // Calculate days to add to get to that day next week
                const currentDay = nextSync.getDay();
                const daysToAdd = (7 - currentDay + firstDay) % 7;
                
                nextSync.setDate(nextSync.getDate() + daysToAdd);
                nextSync.setHours(hours, minutes, 0, 0);
            }
            
            return nextSync || new Date(now.setDate(now.getDate() + 1)); // Fallback to tomorrow
        },
        
        // Check if current time is within quiet hours
        isQuietHours() {
            if (!this.syncConfig.quietHoursEnabled) return false;
            
            const now = new Date();
            const currentTime = now.getHours() * 60 + now.getMinutes();
            
            // Parse quiet hours times
            const [startHours, startMinutes] = this.syncConfig.quietHoursStart.split(':').map(Number);
            const [endHours, endMinutes] = this.syncConfig.quietHoursEnd.split(':').map(Number);
            
            const quietStart = startHours * 60 + startMinutes;
            const quietEnd = endHours * 60 + endMinutes;
            
            // Check if current time is in quiet hours
            if (quietStart < quietEnd) {
                // Normal case: e.g., 22:00 to 08:00
                return currentTime >= quietStart && currentTime < quietEnd;
            } else {
                // Overnight case: e.g., 22:00 to 08:00
                return currentTime >= quietStart || currentTime < quietEnd;
            }
        },
        
        // Format a date for display
        formatDateTime(date) {
            if (!date) return '';
            
            // Format: YYYY-MM-DD HH:MM
            return `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, '0')}-${String(date.getDate()).padStart(2, '0')} ${String(date.getHours()).padStart(2, '0')}:${String(date.getMinutes()).padStart(2, '0')}`;
        },
        
        // Check if it's time to sync and perform sync if needed
        checkAndScheduleSync() {
            // Only proceed if not in manual mode and we have a next sync time
            if (this.syncConfig.frequency === 'manual' || !this.syncConfig.nextSync) {
                return;
            }
            
            const now = new Date();
            const nextSync = new Date(this.syncConfig.nextSync);
            
            // If it's time to sync and not in quiet hours
            if (now >= nextSync && !this.isQuietHours() && !this.syncing) {
                console.log('Auto-sync triggered at', this.formatDateTime(now));
                
                // Perform the sync
                this.syncCredentials()
                    .then(() => {
                        console.log('Auto-sync completed successfully');
                        
                        // Show browser notification if enabled
                        if (this.syncConfig.showNotifications && 'Notification' in window && Notification.permission === 'granted') {
                            new Notification('SyncAuth', {
                                body: 'Credentials synchronized successfully',
                                icon: '/static/favicon.ico'
                            });
                        }
                    })
                    .catch(error => {
                        console.error('Auto-sync failed:', error);
                        
                        // Show browser notification for failure if enabled
                        if (this.syncConfig.showNotifications && 'Notification' in window && Notification.permission === 'granted') {
                            new Notification('SyncAuth - Sync Failed', {
                                body: 'Failed to synchronize credentials: ' + (error.message || 'Unknown error'),
                                icon: '/static/favicon.ico'
                            });
                        }
                    });
            }
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
                syncEnabled: true // Keep default as true
            };
            this.editingClientId = null;
        },
        
        // Add password change button to the header navigation
        addPasswordChangeButton() {
            // Check if the button already exists
            if (document.getElementById('change-password-btn')) {
                return;
            }
            
            // Add the button before the logout button
            const logoutBtn = document.getElementById('logout-btn');
            if (logoutBtn) {
                const passwordBtn = document.createElement('a');
                passwordBtn.id = 'change-password-btn';
                passwordBtn.href = '#';
                passwordBtn.innerHTML = '<i class="fa-solid fa-key"></i> Change Password';
                passwordBtn.addEventListener('click', (e) => {
                    e.preventDefault();
                    this.openPasswordModal();
                });
                
                logoutBtn.parentNode.insertBefore(passwordBtn, logoutBtn);
            }
        },
        
        // Open the password change modal
        openPasswordModal() {
            this.resetPasswordForm();
            this.clearStatus('password');
            this.openModal('password');
        },
        
        // Reset the password change form
        resetPasswordForm() {
            this.passwordForm = {
                currentPassword: '',
                newPassword: '',
                confirmPassword: '',
                syncOption: 'master'
            };
        },
        
        // Change the Syncthing GUI password
        async changePassword() {
            try {
                // Clear previous status messages
                this.clearStatus('password');
                
                // Validate password form
                if (!this.passwordForm.currentPassword) {
                    this.showStatus('password', 'Current password is required', true);
                    return;
                }
                
                if (!this.passwordForm.newPassword) {
                    this.showStatus('password', 'New password is required', true);
                    return;
                }
                
                if (this.passwordForm.newPassword !== this.passwordForm.confirmPassword) {
                    this.showStatus('password', 'New password and confirmation do not match', true);
                    return;
                }
                
                if (this.passwordForm.newPassword.length < 8) {
                    this.showStatus('password', 'Password must be at least 8 characters long', true);
                    return;
                }
                
                // Set loading state
                this.changingPassword = true;
                this.showStatus('password', 'Changing password...', false);
                
                // Send password change request
                const response = await axios.post('/api/change-password', {
                    currentPassword: this.passwordForm.currentPassword,
                    newPassword: this.passwordForm.newPassword,
                    syncToClients: this.passwordForm.syncOption === 'all'
                });
                
                if (response.data.success) {
                    let message = 'Password changed successfully';
                    
                    // Add sync results if available
                    if (response.data.syncResults && response.data.syncResults.length > 0) {
                        message += ':<ul>';
                        response.data.syncResults.forEach(result => {
                            const statusClass = result.success ? 'success' : 'error';
                            const icon = result.success ? '✓' : '✗';
                            message += `<li class="${statusClass}"><strong>${icon} ${result.client}</strong>: ${result.message}</li>`;
                        });
                        message += '</ul>';
                    }
                    
                    this.showStatus('password', message, false, true);
                    
                    // Close the modal after a short delay if successful
                    setTimeout(() => {
                        this.closeModal('password');
                        this.resetPasswordForm();
                    }, 3000);
                } else {
                    this.showStatus('password', `Failed to change password: ${response.data.error}`, true);
                }
            } catch (error) {
                console.error('Error changing password:', error);
                this.showStatus('password', `Error: ${error.response?.data?.error || error.message || 'Unknown error'}`, true);
            } finally {
                this.changingPassword = false;
            }
        }
    }));
});
