import { ref, computed } from 'vue';
import type { AxiosError } from 'axios';
import { api, initCSRF } from '../boot/axios';

// Define interfaces for API responses
export interface DbStatus {
  status: 'checking' | 'ok' | 'error' | 'needs_key' | 'encrypted_or_corrupt' | 'unencrypted';
  message: string;
  has_data: boolean;
  key_provided: boolean;
}

interface Device {
  id: string;
  name: string;
  address: string;
  last_sync?: string;
  status?: string;
}

// Define common response interfaces
interface ApiResponse {
  error?: string;
  message?: string;
}

// The main composable function
export function useSyncAuth() {
  // State
  const devices = ref<Device[]>([]);
  const syncing = ref(false);
  const error = ref('');
  const success = ref('');

  // Authentication state
  const isAuthenticated = ref(false);
  const isLoading = ref(true);
  const dbStatus = ref<DbStatus | null>(null);
  const user = ref<{username: string} | null>(null);

  // Check if the user is authenticated and get DB status
  const checkAuthStatus = async (): Promise<void> => {
    isLoading.value = true;
    try {
      // Get database status first - this endpoint doesn't require authentication
      const dbResp = await api.get<DbStatus>('/api/db_status');
      dbStatus.value = dbResp.data;
      console.log('DB Status check:', dbStatus.value);
      
      // Only check authentication if database is configured
      if (dbStatus.value && dbStatus.value.has_data) {
        // Check authentication status
        const authResp = await api.get('/api/auth_status');
        isAuthenticated.value = authResp.data.authenticated;
        console.log('Auth check:', isAuthenticated.value);
      } else {
        // If database is not configured, user cannot be authenticated
        isAuthenticated.value = false;
      }
    } catch (e) {
      console.error('Auth/DB check failed:', e);
      isAuthenticated.value = false;
    } finally {
      isLoading.value = false;
    }
  };
  
  // Login function
  const login = async (username: string, password: string): Promise<boolean> => {
    isLoading.value = true;
    error.value = '';
    try {
      // Ensure CSRF token is initialized before login
      await initCSRF();
      
      // Log request details for debugging
      console.log('Login request for user:', username);
      
      const resp = await api.post('/api/authenticate', {
        username,
        password
      });
      
      // Debug log to check response and cookies
      console.log('Authentication response:', resp.data);
      console.log('Response headers:', resp.headers);
      console.log('Cookies set (document.cookie):', document.cookie);
      
      if (resp.data.success) {
        isAuthenticated.value = true;
        // Store user information
        user.value = resp.data.user || { username };
        
        // Store last login in localStorage as a convenience
        if (typeof localStorage !== 'undefined') {
          localStorage.setItem('lastLoginUser', username);
        }
        
        return true;
      } else {
        error.value = resp.data.message || 'Login failed';
        return false;
      }
    } catch (e: unknown) {
      const err = e as AxiosError<ApiResponse>;
      error.value = err.response?.data?.message || 'Login failed';
      return false;
    } finally {
      isLoading.value = false;
    }
  };
  
  // Logout function
  const logout = async (): Promise<void> => {
    try {
      await api.post('/api/logout');
      isAuthenticated.value = false;
      user.value = null;
    } catch (e) {
      console.error('Logout error:', e);
    }
  };

  // Example: Load all devices
  const loadAllDevices = async (): Promise<void> => {
    try {
      const resp = await api.get<{ devices: Device[] }>('/api/all-devices');
      devices.value = resp.data.devices || [];
    } catch (e: unknown) {
      const err = e as AxiosError<ApiResponse>;
      error.value = err.response?.data?.error || 'Failed to load devices.';
    }
  };

  // Example: Sync credentials
  const syncCredentials = async (): Promise<void> => {
    syncing.value = true;
    try {
      const resp = await api.post<{ success: boolean; error?: string }>('/api/sync-credentials');
      if (resp.data.success) {
        success.value = 'Credentials synchronized!';
        await loadAllDevices();
      } else {
        error.value = resp.data.error || 'Sync failed.';
      }
    } catch (e: unknown) {
      const err = e as AxiosError<ApiResponse>;
      error.value = err.response?.data?.error || 'Sync failed.';
    } finally {
      syncing.value = false;
    }
  };
  
  // Save setup data
  const saveSetup = async (address: string, apiKey: string): Promise<boolean> => {
    isLoading.value = true;
    error.value = '';
    try {
      // Ensure CSRF token is initialized before setup
      await initCSRF();
      
      const resp = await api.post<{ success: boolean; error?: string }>('/api/setup', {
        address,
        api_key: apiKey
      });
      if (resp.data.success) {
        return true;
      } else {
        error.value = resp.data.error || 'Setup failed';
        return false;
      }
    } catch (e: unknown) {
      const err = e as AxiosError<ApiResponse>;
      error.value = err.response?.data?.error || 'Setup failed';
      return false;
    } finally {
      isLoading.value = false;
    }
  };

  // Computed properties for routing decisions
  const needsSetup = computed(() => {
    return !isLoading.value && 
           dbStatus.value && 
           (!dbStatus.value.has_data || dbStatus.value.status === 'error');
  });
  
  // Check if authentication is ready and DB is configured
  const isReady = computed(() => {
    return !isLoading.value && 
           isAuthenticated.value && 
           dbStatus.value && 
           dbStatus.value.has_data;
  });

  return {
    // State
    devices,
    syncing,
    error,
    success,
    isAuthenticated,
    isLoading,
    dbStatus,
    user,
    
    // Computed properties
    needsSetup,
    isReady,
    
    // Methods
    loadAllDevices,
    syncCredentials,
    checkAuthStatus,
    login,
    logout,
    saveSetup
  };
}
