<template>
  <q-page class="flex flex-center">
    <q-card class="setup-container">
      <div class="setup-logo">
        <h1>SyncAuth</h1>
        <h2>Initial Setup</h2>
      </div>
      <q-banner v-if="error" class="bg-red-2 text-red-8 q-mb-md">{{ error }}</q-banner>
      <q-banner v-if="dbStatus && dbStatus.status !== 'ok'" :class="dbAlertClass">
        {{ dbStatus.message }}
      </q-banner>
      <q-form @submit.prevent="onSubmit" class="setup-form">
        <q-input filled v-model="address" label="Syncthing Master Address" required class="q-mb-md" />
        <q-input filled v-model="apiKey" label="Syncthing API Key" required type="password" class="q-mb-md" />
        <div class="row q-gutter-sm">
          <q-btn label="Test Connection" color="primary" @click="testConnection" :loading="testing" />
          <q-btn label="Save & Continue" type="submit" color="positive" :loading="saving" />
        </div>
      </q-form>
      <div class="setup-footer q-mt-lg">
        <span>Already configured? <router-link to="/login">Login</router-link></span>
      </div>
    </q-card>
  </q-page>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue';
import { useRouter } from 'vue-router';
import { useQuasar } from 'quasar';
import type { AxiosError } from 'axios';
import { useSyncAuth, type DbStatus } from '../composables/useSyncAuth';
import { api, initCSRF } from '../boot/axios';

// Define the types that match the backend response structure
interface ApiErrorResponse {
  error?: string;
  message?: string;
}

const router = useRouter();
const { notify } = useQuasar();
const auth = useSyncAuth();

const address = ref('');
const apiKey = ref('');
const testing = ref(false);
const saving = ref(false);
const connected = ref(false);

// Use error from the auth composable
const error = auth.error;
// Type assertion for dbStatus to help TypeScript understand its structure
const dbStatus = computed(() => auth.dbStatus.value as DbStatus | null);

const dbAlertClass = computed(() => {
  if (!dbStatus.value) return '';
  switch (dbStatus.value.status) {
    case 'error':
    case 'needs_key':
    case 'encrypted_or_corrupt':
      return 'bg-red-2 text-red-8';
    case 'unencrypted':
      return 'bg-orange-2 text-orange-8';
    default:
      return '';
  }
});

onMounted(() => {
  void auth.checkAuthStatus();
});

const testConnection = async () => {
  error.value = '';
  testing.value = true;
  try {
    // Ensure CSRF is initialized before making the request
    await initCSRF();
    
    const resp = await api.post<{ connected: boolean; error?: string }>('/api/test-connection', {
      address: address.value,
      api_key: apiKey.value
    });
    
    connected.value = resp.data.connected;
    if (!connected.value && resp.data.error) {
      error.value = resp.data.error;
    }
  } catch (e: unknown) {
    const err = e as AxiosError<ApiErrorResponse>;
    connected.value = false;
    error.value = err.response?.data?.message || 'Connection test failed';
    console.error('Connection test error:', err);
  } finally {
    testing.value = false;
  }
};

const onSubmit = async () => {
  error.value = '';
  saving.value = true;
  try {
    const result = await auth.saveSetup(address.value, apiKey.value);
    if (result) {
      // Update dbStatus to reflect configuration
      await auth.checkAuthStatus();
      
      // Notify user of success
      notify({
        type: 'positive',
        message: 'Setup completed successfully! Redirecting to login...'
      });
      
      // Redirect to login page
      setTimeout(() => {
        void router.push('/login');
      }, 1500); // Short delay to show notification
    }
  } catch (e) {
    console.error('Setup error:', e);
  } finally {
    saving.value = false;
  }
};
</script>

<style lang="scss" scoped>
.setup-container {
  max-width: 600px;
  margin: 80px auto;
  padding: 20px;
}
.setup-logo {
  text-align: center;
  margin-bottom: 30px;
}
.setup-form {
  padding: 20px 0;
}
.setup-footer {
  text-align: center;
  margin-top: 20px;
  font-size: 14px;
  color: $grey-7;
}
</style>
