<template>
  <q-layout view="lHh Lpr lFf">
    <q-header elevated>
      <q-toolbar>
        <q-btn
          flat
          dense
          round
          icon="menu"
          aria-label="Menu"
          @click="toggleLeftDrawer"
          v-if="dbConfigured"
        />
        <q-toolbar-title>
          SyncAuth
        </q-toolbar-title>
        <q-space />
        <q-btn flat dense icon="logout" aria-label="Logout" @click="logout" v-if="isAuthenticated" />
      </q-toolbar>
    </q-header>

    <q-drawer
      v-model="leftDrawerOpen"
      show-if-above
      bordered
      v-if="dbConfigured"
    >
      <q-list>
        <q-item-label header>Navigation</q-item-label>
        
        <!-- Only show dashboard when authenticated -->
        <q-item clickable v-ripple to="/" exact v-if="isAuthenticated">
          <q-item-section avatar><q-icon name="dashboard" /></q-item-section>
          <q-item-section>Dashboard</q-item-section>
        </q-item>
        
        <!-- Setup is only available when not authenticated or explicitly navigating there -->
        <q-item clickable v-ripple to="/setup" v-if="!isAuthenticated || route.path === '/setup'">
          <q-item-section avatar><q-icon name="settings" /></q-item-section>
          <q-item-section>Setup</q-item-section>
        </q-item>
        
        <!-- Login is only available when not authenticated -->
        <q-item clickable v-ripple to="/login" v-if="!isAuthenticated">
          <q-item-section avatar><q-icon name="login" /></q-item-section>
          <q-item-section>Login</q-item-section>
        </q-item>
      </q-list>
    </q-drawer>

    <q-page-container>
      <router-view />
    </q-page-container>
  </q-layout>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue';
import { useRoute, useRouter } from 'vue-router';
import { useSyncAuth } from '../composables/useSyncAuth';

const leftDrawerOpen = ref(false);
const route = useRoute();
const router = useRouter();
const auth = useSyncAuth();

// Connect to our authentication system
const isAuthenticated = computed(() => auth.isAuthenticated.value);
const dbConfigured = computed(() => auth.dbStatus.value?.has_data || false);

function toggleLeftDrawer () {
  leftDrawerOpen.value = !leftDrawerOpen.value;
}

// Ensure auth status is checked when the layout mounts
onMounted(() => {
  void auth.checkAuthStatus();
});

async function logout() {
  await auth.logout();
  void router.push('/login');
}
</script>

<style scoped>
.q-toolbar-title {
  font-weight: bold;
  letter-spacing: 1px;
}
</style>
