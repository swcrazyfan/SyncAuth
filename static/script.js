// DOM Elements
const masterForm = document.getElementById('master-form');
const masterStatus = document.getElementById('master-status');
const testMasterConnectionBtn = document.getElementById('test-master-connection');
const credentialsForm = document.getElementById('credentials-form');
const syncStatus = document.getElementById('sync-status');
const discoverDevicesBtn = document.getElementById('discover-devices');
const refreshDevicesBtn = document.getElementById('refresh-devices');
const devicesStatus = document.getElementById('devices-status');
const devicesTable = document.getElementById('devices-table').querySelector('tbody');
const clientForm = document.getElementById('client-form');
const clientFormTitle = document.getElementById('client-form-title');
const cancelClientEditBtn = document.getElementById('cancel-client-edit');
const testClientConnectionBtn = document.getElementById('test-client-connection');
const logoutBtn = document.getElementById('logout-btn');
const encryptDbForm = document.getElementById('encrypt-db-form');
const resetDbForm = document.getElementById('reset-db-form');

// Get CSRF token from the form
const getCsrfToken = () => {
    const csrfTokenField = document.querySelector('input[name="csrf_token"]');
    return csrfTokenField ? csrfTokenField.value : '';
};

// Modal elements
const clientModal = document.getElementById('client-modal');
const apiKeyModal = document.getElementById('api-key-modal');
const addressModal = document.getElementById('address-modal');
const combinedModal = document.getElementById('combined-modal');
const addClientBtn = document.getElementById('add-client-btn');
const clientModalTitle = document.getElementById('client-modal-title');
const saveClientBtn = document.getElementById('save-client');
const modalCloseButtons = document.querySelectorAll('.modal-close');
const cancelClientBtn = document.getElementById('cancel-client-edit');
const cancelApiKeyBtn = document.getElementById('cancel-api-key');
const confirmApiKeyBtn = document.getElementById('confirm-api-key');
const cancelAddressBtn = document.getElementById('cancel-address');
const confirmAddressBtn = document.getElementById('confirm-address');
const cancelCombinedBtn = document.getElementById('cancel-combined');
const confirmCombinedBtn = document.getElementById('confirm-combined');
const testCombinedConnectionBtn = document.getElementById('test-combined-connection');
const apiKeyDeviceName = document.getElementById('api-key-device-name');
const addressDeviceName = document.getElementById('address-device-name');
const combinedDeviceName = document.getElementById('combined-device-name');
const modalApiKey = document.getElementById('modal-api-key');
const modalAddress = document.getElementById('modal-address');
const combinedAddress = document.getElementById('combined-address');
const combinedApiKey = document.getElementById('combined-api-key');
const combinedAddressSuggestions = document.getElementById('combined-address-suggestions');
const combinedAddressButtons = document.getElementById('combined-address-buttons');

// Global state
let editingClientId = null;
let latestEventId = null;
let configPollingInterval = null;

// Global variables for tracking modal callbacks
let onApiKeyConfirm = null;
let onAddressConfirm = null;
let onCombinedConfirm = null;
let currentEditingClientId = null;

// Helper Functions
function showStatus(element, message, isError = false, isHTML = false) {
    console.log(`Showing status: ${message} (isError: ${isError})`);
    if (!element) {
        console.error('Status element not found');
        return;
    }
    
    if (isHTML) {
        // Sanitize HTML before inserting to prevent XSS
        const sanitizedHTML = sanitizeHTML(message);
        element.innerHTML = sanitizedHTML;
    } else {
        element.textContent = message;
    }
    element.style.display = 'block';
    element.classList.toggle('error', isError);
}

function clearStatus(element) {
    if (!element) {
        console.error('Status element not found');
        return;
    }
    element.textContent = '';
    element.style.display = 'none';
    element.classList.remove('error');
}

async function fetchJSON(url, options = {}) {
    try {
        // Add CSRF token to headers for all requests
        const csrfToken = getCsrfToken();
        const headers = {
            'Content-Type': 'application/json',
            'X-CSRFToken': csrfToken,
            ...options.headers
        };
        
        const response = await fetch(url, {
            ...options,
            headers: headers
        });
        
        // Handle HTTP errors
        if (!response.ok) {
            if (response.status === 400 && response.statusText.includes('CSRF')) {
                throw new Error('CSRF token validation failed. Please refresh the page and try again.');
            }
            throw new Error(`Server error: ${response.status} ${response.statusText}`);
        }
        
        // Parse JSON response
        const data = await response.json();
        
        // Check for application-specific errors
        if (data.error) {
            throw new Error(data.error);
        }
        
        return data;
    } catch (error) {
        console.error('Fetch error:', error);
        throw error;
    }
}

// Modal functions
function openModal(modal) {
    modal.classList.add('active');
}

function closeModal(modal) {
    modal.classList.remove('active');
}

function closeAllModals() {
    closeModal(clientModal);
    closeModal(apiKeyModal);
    closeModal(addressModal);
    closeModal(combinedModal);
    // Reset callback functions
    onApiKeyConfirm = null;
    onAddressConfirm = null;
    onCombinedConfirm = null;
}

function resetClientForm() {
    clientForm.reset();
    document.getElementById('client-id').value = '';
    currentEditingClientId = null;
}

// Event listeners for modals
modalCloseButtons.forEach(button => {
    button.addEventListener('click', () => {
        closeAllModals();
    });
});

// Close modals when clicking outside
document.addEventListener('click', (e) => {
    if (e.target.classList.contains('modal-overlay')) {
        closeAllModals();
    }
});

// Add client button
addClientBtn.addEventListener('click', () => {
    resetClientForm();
    clientModalTitle.textContent = 'Add New Client';
    openModal(clientModal);
});

// Cancel client edit
cancelClientBtn.addEventListener('click', () => {
    closeModal(clientModal);
    resetClientForm();
});

// Cancel API key entry
cancelApiKeyBtn.addEventListener('click', () => {
    closeModal(apiKeyModal);
});

// Cancel address entry
cancelAddressBtn.addEventListener('click', () => {
    closeModal(addressModal);
});

// Cancel combined entry
cancelCombinedBtn.addEventListener('click', () => {
    closeModal(combinedModal);
});

// Prompt for combined address and API key
function promptForCombined(deviceName, addresses, defaultAddress) {
    return new Promise((resolve, reject) => {
        // Set device name
        combinedDeviceName.textContent = deviceName || 'device';
        
        // Clear previous input and suggestions
        combinedAddress.value = defaultAddress || '';
        combinedApiKey.value = '';
        combinedAddressButtons.innerHTML = '';
        
        // If we have multiple addresses, show the suggestions section
        if (addresses && addresses.length > 1) {
            combinedAddressSuggestions.style.display = 'block';
            
            // Add buttons for each address
            addresses.forEach(address => {
                const button = document.createElement('button');
                button.type = 'button';
                button.className = 'btn secondary address-option';
                button.textContent = address.display || 'Use default port';
                button.addEventListener('click', () => {
                    combinedAddress.value = address.value;
                });
                combinedAddressButtons.appendChild(button);
            });
        } else {
            combinedAddressSuggestions.style.display = 'none';
        }
        
        // Set up confirm action
        onCombinedConfirm = () => {
            const address = combinedAddress.value;
            const apiKey = combinedApiKey.value;
            
            if (!address) {
                alert('Address is required');
                return;
            }
            
            if (!apiKey) {
                alert('API key is required');
                return;
            }
            
            resolve({
                address: address,
                apiKey: apiKey
            });
            
            closeModal(combinedModal);
            
            // Clean up
            combinedAddressSuggestions.style.display = 'none';
            combinedAddressButtons.innerHTML = '';
        };
        
        // Open the modal
        openModal(combinedModal);
    });
}

// Confirm combined button
confirmCombinedBtn.addEventListener('click', () => {
    if (onCombinedConfirm) {
        onCombinedConfirm();
    }
});

// Test combined connection button
testCombinedConnectionBtn.addEventListener('click', async () => {
    try {
        const address = combinedAddress.value;
        const apiKey = combinedApiKey.value;
        
        if (!address || !apiKey) {
            showStatus(devicesStatus, 'Address and API Key are required', true);
            return;
        }
        
        showStatus(devicesStatus, 'Testing connection...');
        
        const response = await fetch('/api/test-connection', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ address, api_key: apiKey })
        });
        
        const data = await response.json();
        
        // Check the connected property which is how the API indicates success
        if (data.connected) {
            const deviceInfo = data.device_id ? ` (Device ID: ${data.device_id})` : '';
            const version = data.version ? ` - Version: ${data.version}` : '';
            alert(`Connection successful!${deviceInfo}${version}`);
        } else {
            throw new Error(data.error || 'Connection failed');
        }
    } catch (error) {
        alert(`Connection test failed: ${error.message}`);
    }
});

// Load Data Functions
async function loadMasterConfig() {
    try {
        const data = await fetchJSON('/api/master');
        
        if (data.configured) {
            document.getElementById('master-address').value = data.address;
            // Don't set the API key field for security
            document.getElementById('master-api-key').placeholder = '[API Key Set]';
        }
    } catch (error) {
        showStatus(masterStatus, `Failed to load master configuration: ${error.message}`, true);
    }
}

async function loadAllDevices() {
    try {
        showStatus(devicesStatus, 'Loading device status...');
        
        const data = await fetchJSON('/api/all-devices');
        renderDeviceTable(data.devices);
        
        // Clear the status message on success
        clearStatus(devicesStatus);
    } catch (error) {
        showStatus(devicesStatus, `Failed to load devices: ${error.message}`, true);
    }
}

// Render Functions
function renderDeviceTable(devices) {
    devicesTable.innerHTML = '';
    
    if (!devices || devices.length === 0) {
        const row = document.createElement('tr');
        row.innerHTML = '<td colspan="6" class="text-center">No devices found</td>';
        devicesTable.appendChild(row);
        return;
    }
    
    devices.forEach(device => {
        const row = document.createElement('tr');
        row.classList.add('device-row');
        row.dataset.deviceId = device.deviceID;
        
        const connectionStatus = device.connected ? 
            '<span class="status connected">Connected</span>' : 
            '<span class="status disconnected">Disconnected</span>';
            
        const bytesIn = device.inBytesTotal ? formatBytes(device.inBytesTotal) : '-';
        const bytesOut = device.outBytesTotal ? formatBytes(device.outBytesTotal) : '-';
        
        row.innerHTML = `
            <td>${device.name || device.deviceID.substring(0, 8)}</td>
            <td>${device.deviceID}</td>
            <td>${device.address || '-'}</td>
            <td>${connectionStatus}</td>
            <td>
                ${device.managed ? 
                    `<button class="btn ${device.sync_enabled ? 'warning' : 'success'} toggle-sync" 
                     data-client-id="${device.client_id}" 
                     data-enabled="${!device.sync_enabled}">
                     ${device.sync_enabled ? 'Disable Sync' : 'Enable Sync'}
                     </button>
                     <button class="btn secondary edit-client" data-client-id="${device.client_id}">Edit</button>
                     <button class="btn danger delete-client" data-client-id="${device.client_id}">Delete</button>` 
                    : 
                    `<button class="btn success enable-sync" data-device-id="${device.deviceID}" data-device-name="${device.name || device.deviceID.substring(0, 8)}" data-device-address="${device.address || ''}">Enable Sync</button>`
                }
            </td>
        `;
        
        devicesTable.appendChild(row);
    });
    
    // Add event listeners for buttons
    addDeviceActionListeners();
}

function addDeviceActionListeners() {
    // Add device buttons
    const addDeviceButtons = document.querySelectorAll('.enable-sync');
    addDeviceButtons.forEach(btn => {
        btn.addEventListener('click', async () => {
            const deviceId = btn.dataset.deviceId;
            const deviceName = btn.dataset.deviceName;
            const deviceAddress = btn.dataset.deviceAddress;
            
            enableSyncForDevice(deviceAddress, deviceId, deviceName);
        });
    });
    
    // Edit client buttons
    const editButtons = document.querySelectorAll('.edit-client');
    editButtons.forEach(btn => {
        btn.addEventListener('click', () => {
            const clientId = btn.dataset.clientId;
            editClient(clientId);
        });
    });
    
    // Delete client buttons
    const deleteButtons = document.querySelectorAll('.delete-client');
    deleteButtons.forEach(btn => {
        btn.addEventListener('click', () => {
            const clientId = btn.dataset.clientId;
            if (confirm('Are you sure you want to delete this client? This will not remove the device from Syncthing.')) {
                deleteClient(clientId);
            }
        });
    });
    
    // Enable sync buttons
    const toggleButtons = document.querySelectorAll('.toggle-sync');
    toggleButtons.forEach(btn => {
        btn.addEventListener('click', async () => {
            const clientId = btn.dataset.clientId;
            const enabled = btn.dataset.enabled === 'true';
            await toggleClientSync(clientId, enabled);
        });
    });
}

// Helper function to format bytes
function formatBytes(bytes, decimals = 2) {
    if (bytes === 0) return '0 Bytes';
    
    const k = 1024;
    const dm = decimals < 0 ? 0 : decimals;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
    
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    
    return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
}

// API Interaction Functions
async function toggleClientSync(clientId, enabled) {
    try {
        await fetchJSON(`/api/clients/${clientId}`, {
            method: 'PUT',
            body: JSON.stringify({ sync_enabled: enabled })
        });
        
        showStatus(devicesStatus, `Client sync ${enabled ? 'enabled' : 'disabled'}`);
        loadAllDevices();
    } catch (error) {
        // Revert the checkbox state on failure
        loadAllDevices();
        showStatus(devicesStatus, `Failed to update sync status: ${error.message}`, true);
    }
}

async function deleteClient(clientId) {
    try {
        await fetchJSON(`/api/clients/${clientId}`, {
            method: 'DELETE'
        });
        
        showStatus(devicesStatus, 'Client deleted successfully');
        loadAllDevices();
    } catch (error) {
        showStatus(devicesStatus, `Failed to delete client: ${error.message}`, true);
    }
}

async function testConnection(address, apiKey, statusElement) {
    try {
        console.log(`Testing connection to ${address} with API key`);
        const result = await fetchJSON('/api/test-connection', {
            method: 'POST',
            body: JSON.stringify({ address, api_key: apiKey })
        });
        
        console.log("Test connection result:", result);
        
        if (result.connected) {
            showStatus(statusElement, `Connection successful! Syncthing version: ${result.version}, Device ID: ${result.device_id}`);
            return true;
        } else {
            throw new Error(result.error || 'Connection failed');
        }
    } catch (error) {
        console.error("Test connection error:", error);
        showStatus(statusElement, `Connection test error: ${error.message}`, true);
        return false;
    }
}

// Client form submission
saveClientBtn.addEventListener('click', async () => {
    try {
        const form = document.getElementById('client-form');
        const formData = new FormData(form);
        const data = Object.fromEntries(formData.entries());
        
        // Convert sync_enabled to boolean
        data.sync_enabled = formData.has('sync_enabled');
        
        const endpoint = data.id ? `/api/clients/${data.id}` : '/api/clients';
        const method = data.id ? 'PUT' : 'POST';
        
        const response = await fetch(endpoint, {
            method: method,
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(data)
        });
        
        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.error || 'Failed to save client');
        }
        
        closeModal(clientModal);
        resetClientForm();
        loadAllDevices();
    } catch (error) {
        showStatus(devicesStatus, error.message, true);
    }
});

// Test client connection
document.getElementById('test-client-connection').addEventListener('click', async () => {
    try {
        const address = document.getElementById('client-address').value;
        const apiKey = document.getElementById('client-api-key').value;
        
        if (!address || !apiKey) {
            showStatus(devicesStatus, 'Address and API Key are required', true);
            return;
        }
        
        showStatus(devicesStatus, 'Testing connection...');
        
        const response = await fetch('/api/test-connection', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ address, api_key: apiKey })
        });
        
        const data = await response.json();
        
        if (data.connected) {
            showStatus(devicesStatus, 'Connection successful!');
        } else {
            throw new Error(data.error || 'Connection failed');
        }
    } catch (error) {
        showStatus(devicesStatus, error.message, true);
    }
});

// Edit client
function editClient(clientId) {
    fetch(`/api/clients/${clientId}`)
        .then(response => {
            if (!response.ok) {
                throw new Error('Failed to load client data');
            }
            return response.json();
        })
        .then(data => {
            currentEditingClientId = clientId;
            document.getElementById('client-id').value = clientId;
            document.getElementById('client-label').value = data.label;
            document.getElementById('client-device-id').value = data.device_id;
            document.getElementById('client-address').value = data.address;
            document.getElementById('client-api-key').value = data.api_key;
            document.getElementById('client-sync-enabled').checked = data.sync_enabled;
            
            clientModalTitle.textContent = 'Edit Client';
            openModal(clientModal);
        })
        .catch(error => {
            showStatus(devicesStatus, error.message, true);
        });
}

// Handle enable sync button click
async function enableSyncForDevice(deviceAddress, deviceId, deviceName) {
    try {
        showStatus(devicesStatus, 'Setting up sync for device...');
        
        console.log('Initial deviceAddress:', deviceAddress);
        console.log('Device ID:', deviceId);
        console.log('Device Name:', deviceName);
        
        // Fetch all connections to get possible addresses for this device
        const connectionsResponse = await fetch('/api/connections');
        const connectionsData = await connectionsResponse.json();
        
        if (!connectionsData.success) {
            throw new Error(connectionsData.error || 'Failed to get connections');
        }
        
        // Find all possible addresses for this device
        const addresses = [];
        const defaultPort = '8384'; // Default Syncthing GUI port
        let formattedAddress = `http://:${defaultPort}`; // Default fallback - use HTTP not HTTPS
        
        // Try to find the device in connections
        if (connectionsData.connections && deviceId in connectionsData.connections) {
            const connection = connectionsData.connections[deviceId];
            
            // Add connected address if available
            if (connection.address && connection.address.trim() !== '') {
                // Extract just the IP/domain part if there's a port
                let addressPart = connection.address;
                let portPart = defaultPort;
                
                if (connection.address.includes(':')) {
                    [addressPart, portPart] = connection.address.split(':');
                }
                
                // If addressPart is empty, just use the port
                const displayAddress = addressPart || "";
                const value = addressPart ? `http://${addressPart}:${defaultPort}` : `http://:${defaultPort}`;
                
                addresses.push({
                    display: displayAddress,
                    value: value
                });
                
                formattedAddress = value;
            }
            
            // Add other addresses if available (from Address list in Syncthing)
            if (connection.addresses && Array.isArray(connection.addresses)) {
                connection.addresses.forEach(addr => {
                    // Skip empty or duplicate addresses
                    if (!addr || addr.trim() === '' || addresses.some(a => a.value.includes(addr))) {
                        return;
                    }
                    
                    // Extract IP/domain part
                    let addressPart = addr;
                    
                    // Remove protocol if present
                    if (addressPart.includes('://')) {
                        addressPart = addressPart.split('://')[1];
                    }
                    
                    // Split off port if present
                    let portPart = defaultPort;
                    if (addressPart.includes(':')) {
                        [addressPart, portPart] = addressPart.split(':');
                    }
                    
                    // If addressPart is empty, just use the port
                    const displayAddress = addressPart || "";
                    const value = addressPart ? `http://${addressPart}:${defaultPort}` : `http://:${defaultPort}`;
                    
                    addresses.push({
                        display: displayAddress,
                        value: value
                    });
                });
            }
        }
        
        // If the device address is provided directly (not empty), add it as an option
        if (deviceAddress && deviceAddress.trim() !== '') {
            let addressPart = deviceAddress;
            
            // Remove protocol if present
            if (addressPart.includes('://')) {
                addressPart = addressPart.split('://')[1];
            }
            
            // Split off port if present
            let portPart = defaultPort;
            if (addressPart.includes(':')) {
                [addressPart, portPart] = addressPart.split(':');
            }
            
            // Only add if it's not already in the list
            if (!addresses.some(a => a.display === addressPart)) {
                addresses.push({
                    display: addressPart,
                    value: `http://${addressPart}:${defaultPort}`
                });
                
                // If this is the only address, use it as default
                if (addresses.length === 1) {
                    formattedAddress = `http://${addressPart}:${defaultPort}`;
                }
            }
        }
        
        // If we don't have any addresses, add a default one using default port
        if (addresses.length === 0) {
            addresses.push({
                display: "",
                value: `http://:${defaultPort}`
            });
        }
        
        console.log('Final addresses:', addresses);
        console.log('Default formatted address:', formattedAddress);
        
        // Now use the combined modal to get both address and API key
        const result = await promptForCombined(deviceName, addresses, formattedAddress);
        
        // Test the connection first
        const testResponse = await fetch('/api/test-connection', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                address: result.address,
                api_key: result.apiKey
            })
        });
        
        const testData = await testResponse.json();
        
        // Check the connected property which is how the API indicates success
        if (!testData.connected) {
            throw new Error(testData.error || 'Connection test failed');
        }
        
        // Get a label for the client, default to device name if available
        const clientLabel = deviceName || deviceId.substring(0, 8);
        
        // Now create the client record
        const addClientResponse = await fetch('/api/clients', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                label: clientLabel,
                device_id: deviceId,
                address: result.address,
                api_key: result.apiKey,
                sync_enabled: true
            })
        });
        
        const clientData = await addClientResponse.json();
        
        if (!clientData.success) {
            throw new Error(clientData.error || 'Failed to add client');
        }
        
        showStatus(devicesStatus, `Device "${clientLabel}" added successfully and sync enabled`);
        
        // Refresh the devices list
        loadAllDevices();
        
    } catch (error) {
        showStatus(devicesStatus, `Error: ${error.message}`, true);
    }
}

// Helper function to extract clean hostname
function extractHostname(address) {
    let result = address;
    
    // Remove protocol if present
    if (result.includes('://')) {
        result = result.split('://')[1];
    }
    
    // Remove port if present
    if (result.includes(':')) {
        result = result.split(':')[0];
    }
    
    return result;
}

// Event Listeners
document.addEventListener('DOMContentLoaded', () => {
    addGlobalStyles();
    
    // Load initial data
    loadMasterConfig();
    loadAllDevices();
    
    // Refresh devices button
    if (refreshDevicesBtn) {
        refreshDevicesBtn.addEventListener('click', loadAllDevices);
    }
    
    // Database encryption form handling
    if (encryptDbForm) {
        encryptDbForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            
            if (!confirm('Are you sure you want to encrypt the database? This will create a backup of your existing database before encryption.')) {
                return;
            }
            
            const formData = new FormData(encryptDbForm);
            
            try {
                const response = await fetch('/manage-encryption', {
                    method: 'POST',
                    body: formData
                });
                
                const result = await response.json();
                
                if (result.success) {
                    alert(result.message);
                    // Reload the page to reflect the new encryption status
                    window.location.reload();
                } else {
                    alert(`Error: ${result.error || 'Unknown error occurred during encryption'}`);
                }
            } catch (error) {
                alert(`Error: ${error.message || 'Failed to encrypt database'}`);
            }
        });
    }
    
    // Database reset form handling
    if (resetDbForm) {
        resetDbForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            
            if (!confirm('WARNING: This will reset your database to a new empty state. Your existing database will be backed up, but all current data will be lost. Are you absolutely sure?')) {
                return;
            }
            
            const formData = new FormData(resetDbForm);
            
            try {
                const response = await fetch('/manage-encryption', {
                    method: 'POST',
                    body: formData
                });
                
                const result = await response.json();
                
                if (result.success) {
                    alert(result.message);
                    // Reload the page to reflect the reset database
                    window.location.reload();
                } else {
                    alert(`Error: ${result.error || 'Unknown error occurred during database reset'}`);
                }
            } catch (error) {
                alert(`Error: ${error.message || 'Failed to reset database'}`);
            }
        });
    }
    
    // Master form submission
    masterForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        
        const address = document.getElementById('master-address').value;
        const apiKey = document.getElementById('master-api-key').value;
        
        clearStatus(masterStatus);
        
        try {
            await fetchJSON('/api/master', {
                method: 'POST',
                body: JSON.stringify({ address, api_key: apiKey })
            });
            
            showStatus(masterStatus, 'Master configuration saved');
            loadMasterConfig();
        } catch (error) {
            showStatus(masterStatus, `Failed to save master configuration: ${error.message}`, true);
        }
    });
    
    // Test master connection button
    testMasterConnectionBtn.addEventListener('click', async () => {
        const address = document.getElementById('master-address').value;
        let apiKey = document.getElementById('master-api-key').value;
        const placeholder = document.getElementById('master-api-key').placeholder;
        
        if (!address) {
            showStatus(masterStatus, 'Please enter address to test connection', true);
            return;
        }
        
        // Clear status before testing to ensure visibility of new status
        clearStatus(masterStatus);
        
        // If API key field is empty but has a placeholder indicating it's set, fetch it from the server
        if (!apiKey && placeholder === '[API Key Set]') {
            try {
                console.log("Testing with stored API key...");
                showStatus(masterStatus, 'Testing connection with stored API key...');
                
                const result = await fetchJSON('/api/test-stored-connection', {
                    method: 'POST',
                    body: JSON.stringify({ address })
                });
                
                if (result.connected) {
                    showStatus(masterStatus, `Successfully connected to ${result.device_id || 'device'}`);
                } else {
                    throw new Error(result.error || 'Connection failed');
                }
                return;
                
            } catch (error) {
                showStatus(masterStatus, `Connection test failed: ${error.message}`, true);
                return;
            }
        }
        
        if (!apiKey) {
            showStatus(masterStatus, 'Please enter API key to test connection', true);
            return;
        }
        
        await testConnection(address, apiKey, masterStatus);
    });
    
    // Credentials form submission (now without requiring password)
    credentialsForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        
        clearStatus(syncStatus);
        showStatus(syncStatus, 'Syncing credentials...');
        
        try {
            const result = await fetchJSON('/api/sync-credentials', {
                method: 'POST',
                body: JSON.stringify({})  // Empty object since we don't need to pass credentials
            });
            
            let resultMessage = result.message;
            
            // If there are detailed results, show them
            if (result.results && result.results.length > 0) {
                resultMessage += '<br><ul style="margin-top: 10px;">';
                result.results.forEach(r => {
                    resultMessage += `<li>${r.label}: ${r.success ? 'Success' : 'Failed - ' + (r.error || 'Unknown error')}</li>`;
                });
                resultMessage += '</ul>';
            }
            
            showStatus(syncStatus, resultMessage, false, true);
        } catch (error) {
            showStatus(syncStatus, `Failed to sync credentials: ${error.message}`, true);
        }
    });
    
    // Discover devices button
    discoverDevicesBtn.addEventListener('click', async () => {
        clearStatus(devicesStatus);
        
        try {
            showStatus(devicesStatus, 'Discovering devices...');
            const result = await fetchJSON('/api/discover', {
                method: 'POST'
            });
            
            if (result.devices && result.devices.length > 0) {
                showStatus(devicesStatus, `Discovered ${result.devices.length} devices. Refreshing device list...`);
                // Auto-refresh the device list after discovery
                setTimeout(loadAllDevices, 1000);
            } else {
                showStatus(devicesStatus, 'No new devices discovered.');
            }
        } catch (error) {
            showStatus(devicesStatus, `Failed to discover devices: ${error.message}`, true);
        }
    });
    
    // Start polling for config changes
    startConfigPolling();
});

// Function to start polling for config changes
function startConfigPolling() {
    // Clear any existing interval
    if (configPollingInterval) {
        clearInterval(configPollingInterval);
    }
    
    // Start with an immediate check
    checkForConfigChanges();
    
    // Then set up regular polling every 30 seconds
    configPollingInterval = setInterval(checkForConfigChanges, 30000);
}

// Function to stop polling
function stopConfigPolling() {
    if (configPollingInterval) {
        clearInterval(configPollingInterval);
        configPollingInterval = null;
    }
}

// Check for config changes via the API
async function checkForConfigChanges() {
    try {
        // Only check if we're logged in
        if (!isLoggedIn()) {
            return;
        }
        
        const url = latestEventId ? 
            `/api/check-config-changes?since=${latestEventId}` : 
            '/api/check-config-changes';
            
        const response = await fetch(url);
        if (!response.ok) {
            console.error('Failed to check for config changes');
            return;
        }
        
        const data = await response.json();
        
        if (!data.success) {
            console.error('Error checking for config changes:', data.error);
            return;
        }
        
        // Update our latest event ID
        if (data.latestEventId) {
            latestEventId = data.latestEventId;
        }
        
        // If there are changes, notify the user
        if (data.hasConfigChanges) {
            console.log('Configuration changes detected!');
            notifyConfigChange();
        }
    } catch (error) {
        console.error('Error polling for config changes:', error);
    }
}

// Notify the user about config changes
function notifyConfigChange() {
    // Create a notification message
    const notification = document.createElement('div');
    notification.className = 'notification config-change-notification';
    notification.innerHTML = `
        <div class="notification-content">
            <p><strong>Configuration Change Detected</strong></p>
            <p>Syncthing configuration changes were detected. Would you like to synchronize credentials now?</p>
            <div class="notification-actions">
                <button class="btn primary sync-now-btn">Sync Now</button>
                <button class="btn secondary dismiss-btn">Dismiss</button>
            </div>
        </div>
    `;
    
    // Add to the page
    document.body.appendChild(notification);
    
    // Show with animation
    setTimeout(() => {
        notification.classList.add('active');
    }, 10);
    
    // Handle buttons
    const syncNowBtn = notification.querySelector('.sync-now-btn');
    const dismissBtn = notification.querySelector('.dismiss-btn');
    
    syncNowBtn.addEventListener('click', () => {
        // Remove the notification
        notification.classList.remove('active');
        setTimeout(() => {
            notification.remove();
        }, 300);
        
        // Trigger credential sync
        syncCredentials();
    });
    
    dismissBtn.addEventListener('click', () => {
        // Just remove the notification
        notification.classList.remove('active');
        setTimeout(() => {
            notification.remove();
        }, 300);
    });
}

// Check if user is logged in
function isLoggedIn() {
    // Simple check - look for login form vs logged-in content
    return !document.getElementById('login-form') || 
           document.getElementById('login-form').style.display === 'none';
}

// Trigger credential synchronization
async function syncCredentials() {
    try {
        showStatus(syncStatus, 'Synchronizing credentials...');
        
        const response = await fetch('/api/sync-credentials', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({})
        });
        
        const data = await response.json();
        
        if (data.success) {
            let resultMessage = `Credentials synchronized successfully. ${data.message || ''}`;
            
            // Format results with HTML, now with XSS protection
            if (data.results && data.results.length > 0) {
                resultMessage += '<br><ul style="margin-top: 10px;">';
                data.results.forEach(r => {
                    // Use textContent-based concatenation for safety
                    const label = document.createTextNode(r.label).textContent;
                    const status = r.success ? 'Success' : 'Failed - ' + document.createTextNode(r.error || 'Unknown error').textContent;
                    resultMessage += `<li>${label}: ${status}</li>`;
                });
                resultMessage += '</ul>';
            }
            
            showStatus(syncStatus, resultMessage, false, true);
            
            // Refresh device list to show updated status
            loadAllDevices();
        } else {
            throw new Error(data.error || 'Failed to synchronize credentials');
        }
    } catch (error) {
        showStatus(syncStatus, `Error: ${error.message}`, true);
    }
}

// HTML sanitizer function to prevent XSS
function sanitizeHTML(html) {
    // Create a temporary div element
    const tempDiv = document.createElement('div');
    // Set the HTML content with just the text
    tempDiv.textContent = html;
    
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

// Also update the CSS rules for status messages to ensure they're visible
function addGlobalStyles() {
    const styleElement = document.createElement('style');
    styleElement.textContent = `
        .status-message {
            display: block !important;
            margin-top: 15px;
            padding: 10px;
            border-radius: 4px;
        }
        
        .status-message.success {
            background-color: #d5f5e3;
            color: #27ae60;
            border: 1px solid #2ecc71;
        }
        
        .status-message.error {
            background-color: #fadbd8;
            color: #c0392b;
            border: 1px solid #e74c3c;
        }
        
        .device-item {
            cursor: pointer;
            padding: 10px;
            margin: 5px 0;
            background-color: #f8f9fa;
            border-radius: 4px;
            transition: background-color 0.2s;
        }
        
        .device-item:hover {
            background-color: #e9ecef;
        }
    `;
    document.head.appendChild(styleElement);
}
