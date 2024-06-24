<template>
  <v-app>
    <v-main>
      <app-nav-bar/>
      <router-view />
    </v-main>
  </v-app>
</template>

<script setup>
  import AppNavBar from "./components/AppBar.vue";
</script>
