<template>
    <div class="register">
        <div class="registerContainer">
            <h2 style="text-align: center;">Register</h2>
            <form @submit.prevent="login">
                <div class="form-group">
                <label for="username">Username:</label>
                <v-text-field type="text" id="username" :rules="nameRules" v-model="username" required/>
                </div>
                <div class="form-group">
                <label for="password">Password:</label>
                <v-text-field type="password" id="password" :rules="PassRules" v-model="password" required/>
                </div>
                <div class="form-group">
                <label for="Confirm Password">Confirm Password:</label>
                <v-text-field type="password" id="password" :rules="PassRules" v-model="confirmPassword" required/>
                </div>
                <v-btn type="submit">Register</v-btn>
            </form>
        </div>
    </div>
    </template>
    
    <script>
    export default {
      name: 'RegisterPage',
      data() {
        return {
          username: '',
          nameRules: [
            v => !!v || 'Name is required',
          ],
          PassRules: [
            v => !!v || 'Password is required',
          ],
          password: '',
          confirmPassword: ''
        };
      },
      methods: {
        login() {
          // Implement login functionality here
            if(this.confirmPassword===this.password){
                console.log('Logging in...');
                console.log('Username:', this.username);
                console.log('Password:', this.password);
                console.log("confirm password",this.confirmPassword)
            }
            else if(this.password.length<8){
                alert("password should contain a minimum of 8 characters")
            }
            else{
                alert('Password and Confirm Password should be same')
            }
          
          // Example: Send login request to backend API
        }
      }
    }
    </script>
    
    <style scoped>
  .register{
    height: 100vh;
    background-color:#1f2229;
  }
  
    .registerContainer {
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
    