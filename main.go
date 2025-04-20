package main

import (
	"bytes"
	"crypto/md5"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"
    // "os"
    // "bufio"
    // "strings"
	"github.com/gin-gonic/gin"
	"github.com/patrickmn/go-cache"
)

// ScanRequest represents the incoming scan request
type ScanRequest struct {
	URL     string            `json:"url" binding:"required"`
	Method  string            `json:"method"`
	Headers map[string]string `json:"headers"`
	Body    string            `json:"body"`
	Params  []string          `json:"params"`
}

// Define a structure for the response body
// type ScanResponse struct {
// 	Status        string   `json:"status"`
// 	Message       string   `json:"message"`
// 	AvailableDirs []string `json:"available_dirs"`
// }

// Vulnerability represents a detected security issue
type Vulnerability struct {
	Type        string `json:"type"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
	Payload     string `json:"payload,omitempty"`
	Evidence    string `json:"evidence,omitempty"`
}

// ScanResult contains the full result of a scan
type ScanResult struct {
	URL             string          `json:"url"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
	ScannedAt       time.Time       `json:"scanned_at"`
	TimeElapsed     time.Duration   `json:"time_elapsed,omitempty"`
}

// VulnerabilityScanner is the main scanner structure
type VulnerabilityScanner struct {
	client       *http.Client
	scannedPages *cache.Cache
	payloads     map[string][]string
	mutex        sync.Mutex
	concurrency  int
}

// NewVulnerabilityScanner creates a new scanner with default settings
func NewVulnerabilityScanner() *VulnerabilityScanner {
	// Initialize with common payloads for different vulnerability types
	payloads := map[string][]string{
		"XSS": {
			"<script>alert(1)</script>",
			"<img src=x onerror=alert(1)>",
			"javascript:alert(1)",
			"\"><script>alert(1)</script>",
		},
		"SQLi": {
			"' OR 1=1 --",
			"admin' --",
			"1' OR '1'='1",
			"1; DROP TABLE users --",
			"' UNION SELECT 1,2,3--",
		},
		"IDOR": {
			"123",
			"456",
			"0",
			"-1",
		},
		"CommandInjection": {
			"; ls",
			"| cat /etc/passwd",
			"$(cat /etc/passwd)",
			"`ping -c 3 google.com`",
		},
	}

	return &VulnerabilityScanner{
		client: &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 10 {
					return fmt.Errorf("too many redirects")
				}
				return nil
			},
		},
		scannedPages: cache.New(24*time.Hour, 1*time.Hour),
		payloads:     payloads,
		concurrency:  10,
	}
}

// hashContent creates a hash of the page content to avoid scanning the same content multiple times
func (s *VulnerabilityScanner) hashContent(content []byte) string {
	hasher := md5.New()
	hasher.Write(content)
	return hex.EncodeToString(hasher.Sum(nil))
}

// isAlreadyScanned checks if a page with the same content has already been scanned
func (s *VulnerabilityScanner) isAlreadyScanned(url string, content []byte) bool {
	contentHash := s.hashContent(content)
	
	s.mutex.Lock()
	defer s.mutex.Unlock()
	
	// Check if we've already scanned this content
	if _, found := s.scannedPages.Get(contentHash); found {
		return true
	}
	
	// If not, add it to our cache
	s.scannedPages.Set(contentHash, url, cache.DefaultExpiration)
	return false
}

// createBaselineRequest performs the initial request to establish a baseline for comparison
func (s *VulnerabilityScanner) createBaselineRequest(url string, method string, headers map[string]string, body []byte) (*http.Response, []byte, error) {
	req, err := http.NewRequest(method, url, bytes.NewBuffer(body))
	if err != nil {
		return nil, nil, err
	}

	// Add headers
	for key, value := range headers {
		req.Header.Set(key, value)
	}

	// Set common headers if not provided
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")
	}
	if req.Header.Get("Accept") == "" {
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
	}

	startTime := time.Now()
	resp, err := s.client.Do(req)
	responseTime := time.Since(startTime)
	if err != nil {
		return nil, nil, err
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return nil, nil, err
	}

	// Don't scan the same page twice
	// if s.isAlreadyScanned(url, bodyBytes) {
	// 	return nil, nil, fmt.Errorf("page already scanned")
	// }

	// Store baseline metrics for comparison
	baselineMetrics := map[string]interface{}{
		"status":       resp.StatusCode,
		"responseTime": responseTime,
		"bodyLength":   len(bodyBytes),
		"headers":      resp.Header,
	}

	// Store this with the URL for later comparison
	s.scannedPages.Set(url+"_baseline", baselineMetrics, cache.DefaultExpiration)

	return resp, bodyBytes, nil
}

// sendModifiedRequest sends a request with a modified parameter to detect potential vulnerabilities
func (s *VulnerabilityScanner) sendModifiedRequest(url string, method string, headers map[string]string, body []byte, paramName string, payload string) (*http.Response, []byte, time.Duration, error) {
	// Copy the original request and modify the parameter
	modifiedURL := url
	modifiedBody := body
	
	// For simplicity, we'll just append the payload to the URL for GET requests
	if method == "GET" {
		if paramName != "" {
			// Simple example of adding or modifying a parameter
			if bytes.Contains([]byte(modifiedURL), []byte("?")) {
				modifiedURL = modifiedURL + "&" + paramName + "=" + payload
			} else {
				modifiedURL = modifiedURL + "?" + paramName + "=" + payload
			}
		}
	} else {
		// For POST/PUT requests, modify the body
		if len(body) > 0 && paramName != "" {
			modifiedBody = []byte(string(body) + "&" + paramName + "=" + payload)
		}
	}
	
	req, err := http.NewRequest(method, modifiedURL, bytes.NewBuffer(modifiedBody))
	if err != nil {
		return nil, nil, 0, err
	}

	// Copy the headers
	for key, value := range headers {
		req.Header.Set(key, value)
	}

	startTime := time.Now()
	resp, err := s.client.Do(req)
	responseTime := time.Since(startTime)
	if err != nil {
		return nil, nil, responseTime, err
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return nil, nil, responseTime, err
	}

	return resp, bodyBytes, responseTime, nil
}

// detectAnomalies checks for differences between baseline and modified requests
func (s *VulnerabilityScanner) detectAnomalies(
	baselineStatus int, 
	baselineResponseTime time.Duration, 
	baselineBodyLength int,
	baselineBody []byte,
	modifiedStatus int, 
	modifiedResponseTime time.Duration, 
	modifiedBodyLength int,
	modifiedBody []byte,
	vulnerabilityType string,
	payload string,
	url string,
	paramName string,
) []Vulnerability {
	var vulnerabilities []Vulnerability
	
	// Check for significant response time differences (timing attacks)
	if modifiedResponseTime > baselineResponseTime*3 {
		vulnerabilities = append(vulnerabilities, Vulnerability{
			Type:        "Potential Time-Based " + vulnerabilityType,
			Description: fmt.Sprintf("Significant response time difference detected with payload in parameter '%s'", paramName),
			Severity:    "Medium",
			Payload:     payload,
			Evidence:    fmt.Sprintf("Baseline: %v, Modified: %v", baselineResponseTime, modifiedResponseTime),
		})
	}
	
	// Check for error messages that might indicate vulnerability
	errorPatterns := []string{
		"SQL syntax", "mysql_fetch", "ORA-", "syntax error", "PostgreSQL",  // SQL Injection
		"Warning: ", "fatal error", "stack trace", "Exception", "traceback", // General errors
		"XSS", "script", // XSS reflection
	}
	
	for _, pattern := range errorPatterns {
		if bytes.Contains(modifiedBody, []byte(pattern)) && !bytes.Contains(baselineBody, []byte(pattern)) {
			vulnerabilities = append(vulnerabilities, Vulnerability{
				Type:        vulnerabilityType,
				Description: fmt.Sprintf("Error message detected with payload in parameter '%s'", paramName),
				Severity:    "High",
				Payload:     payload,
				Evidence:    fmt.Sprintf("Found pattern: %s", pattern),
			})
			break
		}
	}
	
	// Check for status code differences
	if baselineStatus != modifiedStatus {
		// Different response codes might indicate vulnerability
		if modifiedStatus >= 500 {
			vulnerabilities = append(vulnerabilities, Vulnerability{
				Type:        vulnerabilityType,
				Description: fmt.Sprintf("Server error triggered with payload in parameter '%s'", paramName),
				Severity:    "High",
				Payload:     payload,
				Evidence:    fmt.Sprintf("Baseline status: %d, Modified status: %d", baselineStatus, modifiedStatus),
			})
		} else if modifiedStatus >= 300 && modifiedStatus < 400 {
			vulnerabilities = append(vulnerabilities, Vulnerability{
				Type:        "Potential " + vulnerabilityType,
				Description: fmt.Sprintf("Redirect triggered with payload in parameter '%s'", paramName),
				Severity:    "Medium",
				Payload:     payload,
				Evidence:    fmt.Sprintf("Baseline status: %d, Modified status: %d", baselineStatus, modifiedStatus),
			})
		}
	}
	
	// Check for reflected payloads (XSS)
	if vulnerabilityType == "XSS" && bytes.Contains(modifiedBody, []byte(payload)) {
		vulnerabilities = append(vulnerabilities, Vulnerability{
			Type:        "Reflected XSS",
			Description: fmt.Sprintf("Payload reflected in response for parameter '%s'", paramName),
			Severity:    "High",
			Payload:     payload,
			Evidence:    "Payload found in response body",
		})
	}
	
	// For IDOR, check if access was granted unexpectedly
	if vulnerabilityType == "IDOR" {
		if baselineStatus == 403 && modifiedStatus == 200 {
			vulnerabilities = append(vulnerabilities, Vulnerability{
				Type:        "IDOR",
				Description: fmt.Sprintf("Access control bypass possible with parameter '%s'", paramName),
				Severity:    "Critical",
				Payload:     payload,
				Evidence:    fmt.Sprintf("Baseline denied access (403), but modified request granted access (200)"),
			})
		}
	}
	
	return vulnerabilities
}

// runADSScan performs an Advanced Differential Scan on a specific URL
func (s *VulnerabilityScanner) runADSScan(url string, method string, headers map[string]string, body []byte, params []string) ([]Vulnerability, error) {
	var allVulnerabilities []Vulnerability
	
	// Create baseline request for comparison
	_, baselineBody, err := s.createBaselineRequest(url, method, headers, body)
	if err != nil {
		return allVulnerabilities, err
	}
	
	baselineMetrics, found := s.scannedPages.Get(url + "_baseline")
	if !found {
		return allVulnerabilities, fmt.Errorf("baseline metrics not found")
	}
	
	metrics := baselineMetrics.(map[string]interface{})
	baselineStatus := metrics["status"].(int)
	baselineResponseTime := metrics["responseTime"].(time.Duration)
	baselineBodyLength := metrics["bodyLength"].(int)
	
	// Use goroutines to scan for different vulnerability types concurrently
	var wg sync.WaitGroup
	vulnChan := make(chan Vulnerability, 100)
	
	// If no params provided, try to detect them
	effectiveParams := params
	if len(effectiveParams) == 0 {
		// In a real scanner, you'd extract potential params from the URL, forms in the HTML, etc.
		effectiveParams = []string{"id", "user", "name", "search", "q", "page", "action"}
	}
	
	// Semaphore for limiting concurrent requests
	semaphore := make(chan struct{}, s.concurrency)
	
	// For each vulnerability type and each payload
	for vulnType, payloads := range s.payloads {
		for _, payload := range payloads {
			// For each parameter
			for _, param := range effectiveParams {
				wg.Add(1)
				
				// Acquire semaphore slot
				semaphore <- struct{}{}
				
				go func(vt string, pl string, pr string) {
					defer wg.Done()
					defer func() { <-semaphore }() // Release semaphore slot
					
					// Send modified request with the payload
					modResp, modBody, respTime, err := s.sendModifiedRequest(url, method, headers, body, pr, pl)
					if err != nil {
						// Log error but continue with other tests
						fmt.Printf("Error testing %s with payload %s: %v\n", url, pl, err)
						return
					}
					
					// Detect anomalies by comparing with baseline
					anomalies := s.detectAnomalies(
						baselineStatus,
						baselineResponseTime,
						baselineBodyLength,
						baselineBody,
						modResp.StatusCode,
						respTime,
						len(modBody),
						modBody,
						vt,
						pl,
						url,
						pr,
					)
					
					// Send findings to channel
					for _, vuln := range anomalies {
						vulnChan <- vuln
					}
				}(vulnType, payload, param)
			}
		}
	}
	
	// Start a goroutine to close the channel when all workers are done
	go func() {
		wg.Wait()
		close(vulnChan)
	}()
	
	// Collect results from channel
	for vuln := range vulnChan {
		allVulnerabilities = append(allVulnerabilities, vuln)
	}
	
	return allVulnerabilities, nil
}

// checkCSRF checks for CSRF vulnerabilities in the response
func (vs *VulnerabilityScanner) checkCSRF(resp *http.Response) []Vulnerability {
	var vulnerabilities []Vulnerability

	// Check for CSRF token
	csrfTokenHeaders := []string{
		"X-CSRF-Token",
		"X-XSRF-Token",
		"Csrf-Token",
	}

	hasCsrfProtection := false
	for _, header := range csrfTokenHeaders {
		if resp.Header.Get(header) != "" {
			hasCsrfProtection = true
			break
		}
	}

	if !hasCsrfProtection {
		vulnerabilities = append(vulnerabilities, Vulnerability{
			Type:        "CSRF Protection",
			Description: "Missing CSRF token protection mechanism",
			Severity:    "High",
		})
	}

	return vulnerabilities
}

// checkXSS performs tests for XSS vulnerabilities
func (vs *VulnerabilityScanner) checkXSS(targetURL string, method string, headers map[string]string, body []byte, params []string) ([]Vulnerability, error) {
	var vulnerabilities []Vulnerability
	
	// List of potential XSS test payloads
	xssPayloads := []string{
		"<script>alert(1)</script>",
		"<img src='x' onerror='alert(1)'>",
		"'><script>alert(1)</script>",
		"javascript:alert(1)",
		"<svg/onload=alert(1)>",
	}

	for _, payload := range xssPayloads {
		// For each parameter
		for _, param := range params {
			// Prepare the test URL with the payload
			modifiedURL := targetURL
			if method == "GET" {
				// If GET request, append payload to the URL
				if bytes.Contains([]byte(modifiedURL), []byte("?")) {
					modifiedURL = modifiedURL + "&" + param + "=" + url.QueryEscape(payload)
				} else {
					modifiedURL = modifiedURL + "?" + param + "=" + url.QueryEscape(payload)
				}
			} else {
				// For POST/PUT, include the payload in the body
				if len(body) > 0 {
					body = append(body, []byte("&"+param+"="+url.QueryEscape(payload))...)
				}
			}
			
			// Send the modified request with the payload
			req, err := http.NewRequest(method, modifiedURL, bytes.NewBuffer(body))
			if err != nil {
				return nil, err
			}

			// Copy headers
			for key, value := range headers {
				req.Header.Set(key, value)
			}

			resp, err := vs.client.Do(req)
			if err != nil {
				return nil, err
			}
			defer resp.Body.Close()

			// Check if the payload is reflected in the body of the response
			bodyBytes, err := io.ReadAll(resp.Body)
			if err != nil {
				return nil, err
			}

			// If the payload is found in the response body, it's a reflected XSS vulnerability
			if bytes.Contains(bodyBytes, []byte(payload)) {
				vulnerabilities = append(vulnerabilities, Vulnerability{
					Type:        "Reflected XSS",
					Description: fmt.Sprintf("Payload reflected in response for parameter '%s'", param),
					Severity:    "High",
					Payload:     payload,
					Evidence:    fmt.Sprintf("Payload '%s' found in the response body", payload),
				})
			}
		}
	}
	return vulnerabilities, nil
}

// checkSQLInjection performs basic SQL injection tests
func (vs *VulnerabilityScanner) checkSQLInjection(targetURL string) []Vulnerability {
	var vulnerabilities []Vulnerability

	// List of potential SQL injection test payloads
	sqlInjectionPayloads := []string{
		"' OR '1'='1",
		"\" OR \"1\"=\"1",
		"1 OR 1=1",
		"' OR 1=1--",
		"1 OR 1=1--",
		"1' ORDER BY 1--+",
		"1' UNION SELECT 1,2,3--+",
	}

	for _, payload := range sqlInjectionPayloads {
		// Prepare test URL with payload
		testURL := fmt.Sprintf("%s?id=%s", targetURL, url.QueryEscape(payload))

		req, err := http.NewRequest("GET", testURL, nil)
		if err != nil {
			continue
		}

		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

		resp, err := vs.client.Do(req)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		// Simple heuristic check for potential SQL injection vulnerability
		if resp.StatusCode == 200 {
			vulnerabilities = append(vulnerabilities, Vulnerability{
				Type:        "SQL Injection",
				Description: fmt.Sprintf("Potential SQL injection vulnerability detected with payload: %s", payload),
				Severity:    "High",
				Payload:     payload,
			})
		}
	}

	return vulnerabilities
}

// ScanURL performs a full security scan on the target URL
func (vs *VulnerabilityScanner) ScanURL(scanReq ScanRequest) ScanResult {
	startTime := time.Now()
	result := ScanResult{
		URL:       scanReq.URL,
		ScannedAt: startTime,
	}

	// Validate URL
	parsedURL, err := url.Parse(scanReq.URL)
	if err != nil {
		result.Vulnerabilities = append(result.Vulnerabilities, Vulnerability{
			Type:        "URL Parsing",
			Description: "Invalid URL format",
			Severity:    "Low",
		})
		return result
	}

	// Default to GET if no method specified
	if scanReq.Method == "" {
		scanReq.Method = "GET"
	}

	// Perform HTTP request
	req, err := http.NewRequest(scanReq.Method, scanReq.URL, bytes.NewBufferString(scanReq.Body))
	if err != nil {
		result.Vulnerabilities = append(result.Vulnerabilities, Vulnerability{
			Type:        "Connection",
			Description: "Failed to create request",
			Severity:    "Low",
		})
		return result
	}

	// Set headers
	for key, value := range scanReq.Headers {
		req.Header.Set(key, value)
	}

	// Set common headers if not provided
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
	}
	if req.Header.Get("Accept") == "" {
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
	}

	resp, err := vs.client.Do(req)
	if err != nil {
		result.Vulnerabilities = append(result.Vulnerabilities, Vulnerability{
			Type:        "Connection",
			Description: "Failed to connect to URL",
			Severity:    "High",
		})
		return result
	}
	defer resp.Body.Close()

	// HTTPS Check
	if parsedURL.Scheme != "https" {
		result.Vulnerabilities = append(result.Vulnerabilities, Vulnerability{
			Type:        "HTTPS",
			Description: "Website not using HTTPS",
			Severity:    "Medium",
		})
	}

	// Security Headers Check
	securityHeaderChecks := map[string]Vulnerability{
		"X-XSS-Protection": {
			Type:        "XSS Protection",
			Description: "Missing X-XSS-Protection header",
			Severity:    "Medium",
		},
		"X-Frame-Options": {
			Type:        "Clickjacking Protection",
			Description: "Missing X-Frame-Options header",
			Severity:    "Medium",
		},
		"Content-Security-Policy": {
			Type:        "CSP",
			Description: "Missing Content-Security-Policy header",
			Severity:    "Medium",
		},
	}

	for header, vuln := range securityHeaderChecks {
		if resp.Header.Get(header) == "" {
			result.Vulnerabilities = append(result.Vulnerabilities, vuln)
		}
	}

	// Server Information Disclosure
	server := resp.Header.Get("Server")
	if server != "" {
		result.Vulnerabilities = append(result.Vulnerabilities, Vulnerability{
			Type:        "Information Disclosure",
			Description: fmt.Sprintf("Server technology disclosed: %s", server),
			Severity:    "Low",
		})
	}

	// Basic CORS Check
	cors := resp.Header.Get("Access-Control-Allow-Origin")
	if cors == "*" {
		result.Vulnerabilities = append(result.Vulnerabilities, Vulnerability{
			Type:        "CORS Misconfiguration",
			Description: "Overly permissive CORS policy",
			Severity:    "Medium",
		})
	}

	// CSRF Check
	csrfVulnerabilities := vs.checkCSRF(resp)
	result.Vulnerabilities = append(result.Vulnerabilities, csrfVulnerabilities...)

	// SQL Injection Check (using existing method)
	sqlInjectionVulnerabilities := vs.checkSQLInjection(scanReq.URL)
	result.Vulnerabilities = append(result.Vulnerabilities, sqlInjectionVulnerabilities...)

    xssVulnerabilities, err := vs.checkXSS(scanReq.URL, scanReq.Method, scanReq.Headers, []byte(scanReq.Body), scanReq.Params)
	if err == nil {
		result.Vulnerabilities = append(result.Vulnerabilities, xssVulnerabilities...)
	}
	// Run Advanced Differential Scanning
	adsVulnerabilities, err := vs.runADSScan(
		scanReq.URL,
		scanReq.Method,
		scanReq.Headers,
		[]byte(scanReq.Body),
		scanReq.Params,
	)

	if err == nil {
		result.Vulnerabilities = append(result.Vulnerabilities, adsVulnerabilities...)
	}

	result.TimeElapsed = time.Since(startTime)
	return result
}

// func readDirsFromFile(filePath string) ([]string, error) {
// 	var dirs []string
//
// 	// Open the file
// 	file, err := os.Open(filePath)
// 	if err != nil {
// 		return nil, err
// 	}
// 	defer file.Close()
//
// 	// Read the file line by line
// 	scanner := bufio.NewScanner(file)
// 	for scanner.Scan() {
// 		// Clean up the line and add it to the dirs slice
// 		dir := strings.TrimSpace(scanner.Text())
// 		if dir != "" {
// 			dirs = append(dirs, dir)
// 		}
// 	}
//
// 	// Check for any error in reading the file
// 	if err := scanner.Err(); err != nil {
// 		return nil, err
// 	}
//
// 	return dirs, nil
// }
//
// func checkURLAvailability(url string) bool {
// 	// Send an HTTP GET request to the URL
// 	resp, err := http.Get(url)
// 	if err != nil {
// 		// If there's an error (e.g., network issue), return false
// 		return false
// 	}
// 	defer resp.Body.Close()
//
// 	// Return true if the status code is 200 OK
// 	return resp.StatusCode == http.StatusOK
// }

func main() {
	r := gin.Default()

	// CORS middleware
	r.Use(func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}
		c.Next()
	})

	scanner := NewVulnerabilityScanner()

	// Simple scan endpoint (compatible with existing code)
	r.POST("/scan", func(c *gin.Context) {
		var req ScanRequest

		// Bind JSON body
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Invalid request",
			})
			return
		}

		// Validate URL
		if req.URL == "" {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "URL is required",
			})
			return
		}

		// Perform scan
		result := scanner.ScanURL(req)

		// Prepare response
		c.JSON(http.StatusOK, gin.H{
			"message":         "Scan completed successfully",
			"vulnerabilities": result.Vulnerabilities,
			"scanned_at":      result.ScannedAt,
			"time_elapsed":    result.TimeElapsed.String(),
		})
	})

	//    r.POST("/scan/shed", func(c *gin.Context) {
	// 	// Declare a variable to hold the request body data
	// 	var scanRequest ScanRequest
	//
	// 	// Bind the JSON body to the ScanRequest struct
	// 	if err := c.ShouldBindJSON(&scanRequest); err != nil {
	// 		// If binding fails, return a bad request error
	// 		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid JSON format"})
	// 		return
	// 	}
	//
	// 	// Read directories from the file
	// 	dirs, err := readDirsFromFile("common.txt") // assuming "dirs.txt" is the file with directories
	// 	if err != nil {
	// 		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to read the file"})
	// 		return
	// 	}
	//
	// 	// Prepare an array to store available directories
	// 	var availableDirs []string
	//
	// 	// Iterate over the dirs array and check if the URL with the directory exists
	// 	for _, dir := range dirs {
	// 		// Create the full URL by appending the directory to the base URL
	// 		fullURL := scanRequest.URL + dir
	//            println("url = ", fullURL)
	//
	// 		// Check if the URL exists
	// 		if checkURLAvailability(fullURL) {
	// 			// If the URL exists, add it to the availableDirs array
	// 			availableDirs = append(availableDirs, fullURL)
	// 		}
	// 	}
	//
	// 	// Create a response struct
	// 	response := ScanResponse{
	// 		Status:        "success",
	// 		Message:       "Scan completed successfully",
	// 		AvailableDirs: availableDirs,
	// 	}
	//
	// 	// Send the response as JSON
	// 	c.JSON(http.StatusOK, response)
	// })

	// Advanced Differential Scanning specific endpoint
	r.POST("/scan/ads", func(c *gin.Context) {
		var req ScanRequest

		// Bind JSON body
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Invalid request",
			})
			return
		}

		// Validate URL
		if req.URL == "" {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "URL is required",
			})
			return
		}

		// Set default method if not provided
		if req.Method == "" {
			req.Method = "GET"
		}

		startTime := time.Now()

		// Run only the ADS scan
		adsVulnerabilities, err := scanner.runADSScan(
			req.URL,
			req.Method,
			req.Headers,
			[]byte(req.Body),
			req.Params,
		)

		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": err.Error(),
			})
			return
		}

		// Prepare response
		c.JSON(http.StatusOK, gin.H{
			"message":         "Advanced Differential Scan completed successfully",
			"url":             req.URL,
			"vulnerabilities": adsVulnerabilities,
			"scanned_at":      time.Now(),
			"time_elapsed":    time.Since(startTime).String(),
		})

	})

	// Start server
	port := ":8080"
	fmt.Printf("Server starting on port %s\n", port)
	r.Run(port)
}
