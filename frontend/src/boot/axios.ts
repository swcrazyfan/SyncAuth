import { defineBoot } from '#q-app/wrappers';
import axios, { type AxiosInstance } from 'axios';

declare module 'vue' {
  interface ComponentCustomProperties {
    $axios: AxiosInstance;
    $api: AxiosInstance;
  }
}

// Create axios instance with CSRF support
const api = axios.create({
  baseURL: '/',
  withCredentials: true, // Important for cookies
});

// Add a debug log for request headers
api.interceptors.request.use(config => {
  console.log('Request headers:', config.headers);
  console.log('Request method:', config.method);
  return config;
});

// Flag to track if we've initialized CSRF
let csrfInitialized = false;
let csrfToken: string | null = null;

// Function to initialize CSRF protection
const initCSRF = async (): Promise<void> => {
  if (csrfInitialized) return;
  
  try {
    // Get CSRF token from dedicated endpoint
    const response = await axios.get('/api/csrf-token', { withCredentials: true });
    if (response.data && response.data.csrf_token) {
      csrfToken = response.data.csrf_token;
      // Set CSRF token in default headers for all future requests
      api.defaults.headers.common['X-CSRFToken'] = csrfToken;
      csrfInitialized = true;
      console.log('CSRF token initialized:', csrfToken);
    }
  } catch (error) {
    console.error('Failed to initialize CSRF token:', error);
  }
};

// Add request interceptor to include CSRF token
api.interceptors.request.use(async (config) => {
  // For non-GET requests, include CSRF token
  if (config.method !== 'get') {
    // If CSRF not initialized yet, initialize it
    if (!csrfInitialized) {
      await initCSRF();
    }
    
    // Add token to header if available
    if (csrfToken) {
      config.headers['X-CSRFToken'] = csrfToken;
      console.log('Adding CSRF token to request:', csrfToken);
    } else {
      console.warn('No CSRF token available for non-GET request!');
    }
  }
  return config;
});

export default defineBoot(async ({ app }) => {
  // Initialize CSRF as early as possible, awaiting to ensure it completes
  try {
    console.log('Initializing CSRF token in boot...');
    await initCSRF();
    console.log('CSRF initialization complete');
  } catch (e) {
    console.error('Failed to initialize CSRF in boot:', e);
  }
  
  // for use inside Vue files (Options API) through this.$axios and this.$api
  app.config.globalProperties.$axios = axios;
  // ^ ^ ^ this will allow you to use this.$axios (for Vue Options API form)
  //       so you won't necessarily have to import axios in each vue file

  app.config.globalProperties.$api = api;
  // ^ ^ ^ this will allow you to use this.$api (for Vue Options API form)
  //       so you can easily perform requests against your app's API
});

export { api, initCSRF };
