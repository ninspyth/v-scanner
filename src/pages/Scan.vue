<template>
  <div class="scan-page">
    <h1>Web Vulnerability Scanner</h1>
    <input
      type="text"
      v-model="url"
      placeholder="Enter URL to scan for vulnerabilities"
      class="url-input"
    />
    <button @click="startScan">Scan</button>
    <p v-if="scanStatus">{{ scanStatus }}</p>
  </div>
</template>

<script>
import axios from "axios";

export default {
  name: "ScanPage",
  data() {
    return {
      url: "",
      scanStatus: ""
    };
  },
  methods: {
    /*async startScan() {
      if (!this.url) {
        alert("Please enter a URL to scan.");
        return;
      }

      this.scanStatus = "Scanning...";

      try {
        const response = await axios.post("http://localhost:8080/scan", { url: this.url });
        this.scanStatus = response.data.message || "Scan completed successfully!";
      } catch (error) {
        console.error("Error during scan:", error);
        this.scanStatus = "Scan failed. Please try again.";
      }
    }*/
    async startScan() {
      if (!this.url) {
        alert("Please enter a URL to scan.");
        return;
      }

      this.scanStatus = "Scanning...";

      try {
        const response = await axios.post("http://localhost:8080/scan", { url: this.url });

        // New part to handle vulnerabilities
        if (response.data.vulnerabilities && response.data.vulnerabilities.length > 0) {
          this.scanStatus = `Scan completed. ${response.data.vulnerabilities.length} vulnerabilities found.`;
          // You might want to store vulnerabilities in component state
          this.vulnerabilities = response.data.vulnerabilities;
        } else {
          this.scanStatus = "No vulnerabilities detected!";
        }
      } catch (error) {
        console.error("Error during scan:", error);
        this.scanStatus = "Scan failed. Please try again.";
      }
    }
  }
};
</script>

<style scoped>
.scan-page {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  min-height: 100vh;
  background-color: Black;
}

h1 {
  font-size: 24px;
  margin-bottom: 20px;
}

.url-input {
  width: 300px;
  padding: 10px;
  font-size: 16px;
  border: 1px solid #ccc;
  border-radius: 4px;
  margin-bottom: 20px;
}

button {
  padding: 10px 20px;
  font-size: 16px;
  color: white;
  background-color: #007bff;
  border: none;
  border-radius: 4px;
  cursor: pointer;
}

button:hover {
  background-color: #0056b3;
}

p {
  font-size: 14px;
  color: #555;
  margin-top: 10px;
}
</style>
