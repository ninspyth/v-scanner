<template>
    <link href='https://fonts.googleapis.com/css?family=JetBrains Mono' rel='stylesheet'>
      <div id="page">
          <div class="page-content">
              <h1>Welcome to VulnGuard</h1>
              <p>VulnGuard is a powerful web vulnerability scanner designed to help you identify and mitigate security risks in your web applications.</p>
              <p>With VulnGuard, you can easily manage your targets, conduct scans, and analyze vulnerabilities to enhance the security posture of your websites.</p>
          </div>
      </div>
  </template>

  <script>
  export default {
    name: 'HomePage'
  }
  </script>

  <style>

  #page {
    display: flex;
    flex-direction: column;
    margin: -10px 0px 0px -10px;
    width: 102vw;
    height: 103vh;
    font-family: Arial, sans-serif;
    background-color: #1f2229;
    background-image: url("../img.jpg");
    background-size: cover;
    max-width: 100%;
  }

  .page-content {
    margin-top: 20px;
    text-align: center;
    color: #f2e5bc;
  }

  .page-content h1 {
    font-family: 'JetBrains Mono';
  }

  .page-content p {
    font-family: 'JetBrains Mono';
    font-size: 18px;
  }

  </style>
