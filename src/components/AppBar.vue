<template>
    <div class="home">
      <nav class="navbar">
        <div class="navbar-links">
          <router-link to="/"><v-btn id="homeButton">Home</v-btn></router-link>
          <router-link to="/targets"><v-btn id="homeButton">Targets</v-btn></router-link>
          <router-link to=""><v-btn id="homeButton">Scan</v-btn></router-link>
          <router-link to=""><v-btn id="homeButton">Dashboard</v-btn></router-link>
          <router-link to="/register"><v-btn id="homeButton">Register</v-btn></router-link>
          <router-link to="/login"><v-btn id="homeButton">Login</v-btn></router-link>
        </div>
      </nav>
    </div>
  </template>
  
  <script>
  export default {
    name: 'AppNavBar'
  }
  </script>
  
  <style scoped>
  
  /* Button Styling */
  #homeButton {
    display: inline-block;
    margin: 0.5rem;
    padding: 5px 5px;
    font-size: 16px;
    text-align: center;
    color: #007bff;
    background-color: transparent;
    border: 1px solid #007bff;
    border-radius: 4px;
    cursor: pointer;
    transition: background-color 0.3s, color 0.3s, border-color 0.3s;
  }
  
  nav {
    border-radius: 27px;
  }
  
  #homeButton:hover {
    background-color: #007bff;
    color: #fff;
  }
  
  #homeButton:active {
    background-color: #0056b3;
    border-color: #0056b3;
  }
  
  
  
  
  .home {
    padding: 20px;
    background-color: #1f2229; 
  }
  
  .navbar {
    display: flex;
    justify-content: center;
    align-items: center;
    background-color: #3c3836;
    border-bottom: 1px solid #504945;
  
  }
  
  .button { 
    margin: 0.5rem;
  }
  
  img { 
    height: 40px; /* Adjust as needed */
    float: left;
  }
  
  .navbar-links {
    display: flex;
  }
  
  .navbar-links router-link {
    margin-right: 20px;
    text-decoration: none;
    color: #fbf1c7;
  }
  
  .navbar-links router-link:hover {
    color: #fe8019;
  }
  /* Gruvbox theme styles */
  </style>
  