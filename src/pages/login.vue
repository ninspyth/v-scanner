<template>
    <div class="login">
      <div class="login-container">
        <h2>Login</h2>
        <form @submit.prevent="login">
          <div class="form-group">
            <label for="username">Username:</label>
            <v-text-field type="text" id="username" v-model="username" required/>
          </div>
          <div class="form-group">
            <label for="password">Password:</label>
            <v-text-field type="password" id="password" v-model="password" required/>
          </div>
          <v-btn type="submit">Login</v-btn>
        </form>
        <span class="register">
          Do not have an account? <router-link style="color: #458588;" to="/register">Register</router-link>
        </span>
      </div>
    </div>
    </template>
    
    <script>
    export default {
      name: 'LoginPage',
      data() {
        return {
          username: '',
          password: ''
        };
      },
      methods: {
        login() {
          // Implement login functionality here
          console.log('Logging in...');
          console.log('Username:', this.username);
          console.log('Password:', this.password);
          // Example: Send login request to backend API
        }
      }
    }
    </script>
    
    <style scoped>
  .login{
    height: 100vh;
    background-color:#1f2229;
  }
  
    .login-container {
      align-content: center;
      justify-content: center;
      max-width: 400px;
      margin: auto;
      padding: 20px;
      border: 1px solid #ccc;
      border-radius: 5px;
      
      color: #fbf1c7;
    }
    
    .form-group {
      margin: 20px;
    }
    
    label {
      display: block;
      margin-bottom: 5px;
    }
    .register{
      padding: 1rem;
    }
    input[type="text"],
    input[type="password"] {
      width: 100%;
      padding: 10px;
      font-size: 16px;
      border-radius: 5px;
      border: 1px solid #928374;
      background-color: #504945;
      color: #fbf1c7;
    }
    
    button {
      width: 100%;
      padding: 10px;
      font-size: 16px;
      border: none;
      border-radius: 5px;
      background-color: #458588;
      color: #fbf1c7;
      cursor: pointer;
      margin-bottom: 1rem;
    }
    
    button:hover {
      background-color: #689d6a;
    }
    </style>
    