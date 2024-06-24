
/**
 * router/index.ts
 *
 * Automatic routes for `./src/pages/*.vue`
 */

// Composables
import { createRouter, createWebHistory } from 'vue-router'
import HomePage from '../pages/Home.vue'
import RegisterPage from '../pages/Register.vue'
import LoginPage from '../pages/login.vue'
import TargetsPage from '../pages/Targets.vue'

const routes = [
  { path: '/', component: HomePage },
  { path: '/register', component: RegisterPage},
  { path: '/login', component: LoginPage},
  { path: '/targets',  component: TargetsPage },
];

const router = createRouter({
  history: createWebHistory(),
  routes,
})

export default router