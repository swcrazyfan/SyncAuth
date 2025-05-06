<template>
  <q-page class="flex flex-center">
    <q-card class="login-container">
      <div class="login-logo">
        <h1>SyncAuth</h1>
        <p>Syncthing Credential Manager</p>
      </div>
      <q-banner v-if="error" class="bg-red-2 text-red-8 q-mb-md">{{ error }}</q-banner>
      <q-form class="login-form" @submit.prevent="submitLogin">
        <q-input filled v-model="username" label="Username" required class="q-mb-md" />
        <q-input filled v-model="password" label="Password" type="password" required class="q-mb-md" />
        <div class="form-actions">
          <q-btn label="Log In" type="submit" color="primary" class="full-width" :loading="submitting" />
        </div>
      </q-form>
      <div class="login-footer q-mt-lg">
        <span>Log in using the credentials from your master Syncthing instance</span>
      </div>
    </q-card>
  </q-page>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue';
import { useRouter } from 'vue-router';
import { useQuasar } from 'quasar';
import { useSyncAuth } from '../composables/useSyncAuth';

const router = useRouter();
const { notify } = useQuasar();
const auth = useSyncAuth();

const username = ref('');
const password = ref('');
const submitting = ref(false);
const error = auth.error;

onMounted(() => {
  if (typeof localStorage !== 'undefined') {
    const lastUser = localStorage.getItem('lastLoginUser');
    if (lastUser) {
      username.value = lastUser;
    }
  }
});

async function submitLogin() {
  submitting.value = true;
  
  try {
    const success = await auth.login(username.value, password.value);
    if (success) {
      notify({ 
        type: 'positive', 
        message: `Welcome back, ${auth.user.value?.username}!` 
      });
      
      // Redirect to the dashboard
      void router.push('/');
    }
  } finally {
    submitting.value = false;
  }
}
</script>

<style lang="scss" scoped>
.login-container {
  max-width: 400px;
  margin: 80px auto;
  padding: 20px;
}
.login-logo {
  text-align: center;
  margin-bottom: 30px;
}
.login-form {
  padding: 20px 0;
}
.login-footer {
  text-align: center;
  margin-top: 20px;
  font-size: 14px;
  color: $grey-7;
}
.full-width {
  width: 100%;
}
</style>
