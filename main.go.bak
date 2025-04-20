package main

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/gin-gonic/gin"
)

type ScanRequest struct {
	URL string `json:"url" binding:"required"`
}

type Vulnerability struct {
	Type        string `json:"type"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
}

type ScanResult struct {
	URL             string          `json:"url"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
	ScannedAt       time.Time       `json:"scanned_at"`
}

type VulnerabilityScanner struct{}

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

		client := &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: false},
			},
		}

		req, err := http.NewRequest("GET", testURL, nil)
		if err != nil {
			continue
		}

		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

		resp, err := client.Do(req)
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
			})
		}
	}

	return vulnerabilities
}

func (vs *VulnerabilityScanner) ScanURL(targetURL string) ScanResult {
	result := ScanResult{
		URL:       targetURL,
		ScannedAt: time.Now(),
	}

	// Validate URL
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		result.Vulnerabilities = append(result.Vulnerabilities, Vulnerability{
			Type:        "URL Parsing",
			Description: "Invalid URL format",
			Severity:    "High",
		})
		return result
	}

	// Perform HTTP request
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: false},
		},
	}

	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		result.Vulnerabilities = append(result.Vulnerabilities, Vulnerability{
			Type:        "Connection",
			Description: "Failed to create request",
			Severity:    "High",
		})
		return result
	}

	// Set common headers to mimic browser
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")

	resp, err := client.Do(req)
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

	// SQL Injection Check
	sqlInjectionVulnerabilities := vs.checkSQLInjection(targetURL)
	result.Vulnerabilities = append(result.Vulnerabilities, sqlInjectionVulnerabilities...)

	return result
}

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

	scanner := &VulnerabilityScanner{}

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
		result := scanner.ScanURL(req.URL)

		// Prepare response
		c.JSON(http.StatusOK, gin.H{
			"message":         "Scan completed successfully",
			"vulnerabilities": result.Vulnerabilities,
			"scanned_at":      result.ScannedAt,
		})
	})

	// Start server
	port := ":8080"
	fmt.Printf("Server starting on port %s\n", port)
	r.Run(port)
}

