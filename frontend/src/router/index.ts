import { defineRouter } from '#q-app/wrappers';
import {
  createMemoryHistory,
  createRouter,
  createWebHashHistory,
  createWebHistory,
} from 'vue-router';
import routes from './routes';
import { useSyncAuth } from '../composables/useSyncAuth';

/*
 * If not building with SSR mode, you can
 * directly export the Router instantiation;
 *
 * The function below can be async too; either use
 * async/await or return a Promise which resolves
 * with the Router instance.
 */

export default defineRouter(function (/* { store, ssrContext } */) {
  const createHistory = process.env.SERVER
    ? createMemoryHistory
    : (process.env.VUE_ROUTER_MODE === 'history' ? createWebHistory : createWebHashHistory);

  const Router = createRouter({
    scrollBehavior: () => ({ left: 0, top: 0 }),
    routes,

    // Leave this as is and make changes in quasar.conf.js instead!
    // quasar.conf.js -> build -> vueRouterMode
    // quasar.conf.js -> build -> publicPath
    history: createHistory(process.env.VUE_ROUTER_BASE),
  });
  
  // Add navigation guard to protect routes
  Router.beforeEach(async (to, from, next) => {
    console.log('Router guard triggered, path:', to.path);
    const auth = useSyncAuth();
    
    try {
      // Important: Always check auth status first to get both authentication
      // state and db status in a single check
      await auth.checkAuthStatus();
      
      // Log the current state for debugging
      console.log('DB Status:', auth.dbStatus.value);
      console.log('Is Authenticated:', auth.isAuthenticated.value);
      
      const publicPages = ['/login', '/setup'];
      const authRequired = !publicPages.includes(to.path);
      
      // First check - If database is not configured or has errors, redirect to setup
      if (auth.dbStatus.value && !auth.dbStatus.value.has_data && to.path !== '/setup') {
        console.log('Database not configured, redirecting to setup');
        next('/setup');
        return;
      }
      
      // Second check - If database is configured but user is not authenticated
      if (auth.dbStatus.value && auth.dbStatus.value.has_data && !auth.isAuthenticated.value) {
        // Only redirect to login if attempting to access a protected page or root
        if (authRequired) {
          console.log('Not authenticated, redirecting to login');
          next('/login');
          return;
        }
      }
      
      // Third check - Logged in users shouldn't access login or setup
      if (auth.isAuthenticated.value && publicPages.includes(to.path)) {
        console.log('Already authenticated, redirecting to home');
        next('/');
        return;
      }
      
      // Continue to the requested page
      console.log('Proceeding to requested page', to.path);
      next();
    } catch (error) {
      console.error('Error in router guard:', error);
      // If there's an error during authentication check, direct to login as a fallback
      next('/login');
    }
  });

  return Router;
});
