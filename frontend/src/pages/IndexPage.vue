<template>
  <q-page class="q-pa-md">
    <div class="q-gutter-y-md">
      <q-banner v-if="error" class="bg-red-2 text-red-8">{{ error }}</q-banner>
      <q-banner v-if="success" class="bg-green-2 text-green-8">{{ success }}</q-banner>
      <div class="row items-center q-gutter-sm">
        <q-btn label="Sync Credentials" color="primary" @click="syncCredentials" :loading="syncing" />
        <q-btn label="Reload Devices" color="secondary" @click="loadAllDevices" />
      </div>
      <q-table
        title="Devices"
        :rows="devices"
        :columns="columns"
        row-key="id"
        flat
        bordered
        class="q-mt-md"
      >
        <template v-slot:body-cell-status="props">
          <q-td :props="props">
            <q-badge :color="props.row.status === 'connected' ? 'green' : 'red'">
              {{ props.row.status }}
            </q-badge>
          </q-td>
        </template>
      </q-table>
    </div>
  </q-page>
</template>

<script setup lang="ts">
import { onMounted, watch } from 'vue';
import { useRouter } from 'vue-router';
import { useSyncAuth } from '../composables/useSyncAuth';

const router = useRouter();
const { 
  devices, 
  syncing, 
  error, 
  success, 
  loadAllDevices, 
  syncCredentials, 
  isAuthenticated,
  checkAuthStatus 
} = useSyncAuth();

const columns = [
  { name: 'id', label: 'ID', field: 'id', align: 'left' as const },
  { name: 'label', label: 'Label', field: 'label', align: 'left' as const },
  { name: 'address', label: 'Address', field: 'address', align: 'left' as const },
  { name: 'status', label: 'Status', field: 'status', align: 'left' as const }
];

onMounted(async () => {
  // First ensure auth status is current
  await checkAuthStatus();
  
  // Only load devices if authenticated
  if (isAuthenticated.value) {
    void loadAllDevices();
  } else {
    // If not authenticated, redirect to login
    void router.push('/login');
  }
});

// Also watch for authentication changes
watch(isAuthenticated, (newValue) => {
  if (newValue) {
    void loadAllDevices();
  }
});
</script>

<style scoped>
.q-page {
  max-width: 1000px;
  margin: 0 auto;
}
</style>
