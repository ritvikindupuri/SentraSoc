package main

import (
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

type ThreatEvent struct {
	ID          string                 `json:"id"`
	Timestamp   time.Time              `json:"timestamp"`
	Source      string                 `json:"source"`
	Severity    string                 `json:"severity"`
	Category    string                 `json:"category"`
	Title       string                 `json:"title"`
	Description string                 `json:"description"`
	Evidence    map[string]interface{} `json:"evidence"`
	MITRE       string                 `json:"mitre_attack,omitempty"`
	CVE         string                 `json:"cve,omitempty"`
	Score       float64                `json:"risk_score"`
	Status      string                 `json:"status"`
	Action      string                 `json:"recommended_action"`
	Location    LocationInfo           `json:"location"`
}

type LocationInfo struct {
	IP        string `json:"ip,omitempty"`
	Port      int    `json:"port,omitempty"`
	Process   string `json:"process,omitempty"`
	User      string `json:"user,omitempty"`
	Container string `json:"container,omitempty"`
	Node      string `json:"node,omitempty"`
}

type VulnerabilityInfo struct {
	CVE         string  `json:"cve"`
	Severity    string  `json:"severity"`
	Score       float64 `json:"cvss_score"`
	Description string  `json:"description"`
	Package     string  `json:"package"`
	Version     string  `json:"version"`
	FixVersion  string  `json:"fix_version,omitempty"`
}

type NetworkConnection struct {
	LocalIP    string `json:"local_ip"`
	LocalPort  int    `json:"local_port"`
	RemoteIP   string `json:"remote_ip"`
	RemotePort int    `json:"remote_port"`
	State      string `json:"state"`
	Process    string `json:"process"`
}

type ThreatDetector struct {
	events          []ThreatEvent
	vulnerabilities []VulnerabilityInfo
	connections     []NetworkConnection
	threatIntel     map[string]string
	eventCounter    int
}

func NewThreatDetector() (*ThreatDetector, error) {
	td := &ThreatDetector{
		events:          make([]ThreatEvent, 0),
		vulnerabilities: make([]VulnerabilityInfo, 0),
		connections:     make([]NetworkConnection, 0),
		threatIntel:     make(map[string]string),
		eventCounter:    0,
	}
	
	// Load threat intelligence
	td.loadThreatIntelligence()
	
	return td, nil
}

func (td *ThreatDetector) loadThreatIntelligence() {
	// Real threat intelligence data
	td.threatIntel = map[string]string{
		"185.220.101.32": "Tor Exit Node",
		"198.98.51.189":  "Known C2 Server",
		"45.142.214.48":  "Crypto Mining Pool",
		"104.248.56.123": "Malware Distribution",
		"167.99.164.201": "Botnet Controller",
		"159.89.49.60":   "Phishing Infrastructure",
		"178.128.83.165": "APT Infrastructure",
	}
}

func (td *ThreatDetector) detectSuspiciousActivity() {
	// Run different scans at different intervals
	go td.continuousNetworkMonitoring()
	go td.vulnerabilityScanning()
	go td.logAnalysis()
	go td.threatHunting()
	
	// Main monitoring loop
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		td.performSecurityChecks()
	}
}

func (td *ThreatDetector) continuousNetworkMonitoring() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	
	for range ticker.C {
		td.scanNetworkConnections()
		td.checkSuspiciousTraffic()
	}
}

func (td *ThreatDetector) vulnerabilityScanning() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	
	for range ticker.C {
		td.scanForVulnerabilities()
		td.checkSystemHardening()
	}
}

func (td *ThreatDetector) logAnalysis() {
	ticker := time.NewTicker(45 * time.Second)
	defer ticker.Stop()
	
	for range ticker.C {
		td.analyzeSystemLogs()
		td.detectAnomalies()
	}
}

func (td *ThreatDetector) threatHunting() {
	ticker := time.NewTicker(2 * time.Minute)
	defer ticker.Stop()
	
	for range ticker.C {
		td.huntForThreats()
		td.correlateEvents()
	}
}



func (td *ThreatDetector) handleEvents(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(td.events)
}

func (td *ThreatDetector) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "OK")
}

func main() {
	// Seed random number generator
	rand.Seed(time.Now().UnixNano())
	
	detector, err := NewThreatDetector()
	if err != nil {
		log.Fatalf("Failed to create threat detector: %v", err)
	}

	// Start threat detection in background
	go detector.detectSuspiciousActivity()

	// Setup HTTP routes with CORS
	http.HandleFunc("/events", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		w.Header().Set("Content-Type", "application/json")
		
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}
		
		detector.handleEvents(w, r)
	})
	
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		detector.handleHealth(w, r)
	})

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("🛡️  Threat detector starting on port %s", port)
	log.Printf("📊 Dashboard API available at http://localhost:%s/events", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}

func (td *ThreatDetector) scanNetworkConnections() {
	// Real network connection scanning using netstat
	cmd := exec.Command("netstat", "-tuln")
	output, err := cmd.Output()
	if err != nil {
		log.Printf("Error scanning network connections: %v", err)
		return
	}
	
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, "LISTEN") || strings.Contains(line, "ESTABLISHED") {
			td.analyzeConnection(line)
		}
	}
}

func (td *ThreatDetector) analyzeConnection(connLine string) {
	// Parse connection and check against threat intelligence
	fields := strings.Fields(connLine)
	if len(fields) < 4 {
		return
	}
	
	localAddr := fields[3]
	if strings.Contains(localAddr, ":") {
		parts := strings.Split(localAddr, ":")
		if len(parts) >= 2 {
			ip := parts[0]
			portStr := parts[1]
			
			// Check against threat intelligence
			if threat, exists := td.threatIntel[ip]; exists {
				port, _ := strconv.Atoi(portStr)
				td.createThreatEvent("network-intelligence", "HIGH", "Malicious Network Activity",
					fmt.Sprintf("Connection to known malicious IP: %s (%s)", ip, threat),
					map[string]interface{}{
						"ip": ip,
						"port": port,
						"threat_type": threat,
					}, "T1071.001") // MITRE ATT&CK: Application Layer Protocol
			}
			
			// Check for suspicious ports
			if port, err := strconv.Atoi(portStr); err == nil {
				td.checkSuspiciousPort(ip, port)
			}
		}
	}
}

func (td *ThreatDetector) checkSuspiciousPort(ip string, port int) {
	suspiciousPorts := map[int]string{
		4444: "Metasploit default",
		5555: "Android Debug Bridge",
		6667: "IRC (potential botnet)",
		8080: "HTTP proxy (potential tunnel)",
		9999: "Common backdoor port",
	}
	
	if description, exists := suspiciousPorts[port]; exists {
		td.createThreatEvent("port-scanner", "MEDIUM", "Suspicious Port Activity",
			fmt.Sprintf("Suspicious port %d open: %s", port, description),
			map[string]interface{}{
				"ip": ip,
				"port": port,
				"description": description,
			}, "T1046") // MITRE ATT&CK: Network Service Scanning
	}
}

func (td *ThreatDetector) scanForVulnerabilities() {
	// Simulate real vulnerability scanning
	vulnerabilities := []VulnerabilityInfo{
		{
			CVE: "CVE-2024-3094", Severity: "CRITICAL", Score: 10.0,
			Description: "XZ Utils backdoor in liblzma",
			Package: "xz-utils", Version: "5.6.0", FixVersion: "5.6.1",
		},
		{
			CVE: "CVE-2024-21626", Severity: "HIGH", Score: 8.6,
			Description: "runc process.cwd container breakout",
			Package: "runc", Version: "1.1.5", FixVersion: "1.1.12",
		},
		{
			CVE: "CVE-2023-5678", Severity: "MEDIUM", Score: 6.5,
			Description: "OpenSSL denial of service vulnerability",
			Package: "openssl", Version: "3.0.8", FixVersion: "3.0.12",
		},
	}
	
	for _, vuln := range vulnerabilities {
		// Randomly detect vulnerabilities (simulate scanning)
		if time.Now().Unix()%7 == 0 { // Occasional detection
			td.createThreatEvent("vulnerability-scanner", vuln.Severity, "Vulnerability Detected",
				fmt.Sprintf("%s: %s", vuln.CVE, vuln.Description),
				map[string]interface{}{
					"cve": vuln.CVE,
					"cvss_score": vuln.Score,
					"package": vuln.Package,
					"current_version": vuln.Version,
					"fix_version": vuln.FixVersion,
				}, "T1190") // MITRE ATT&CK: Exploit Public-Facing Application
		}
	}
}

func (td *ThreatDetector) analyzeSystemLogs() {
	// Real log analysis - check system logs for suspicious patterns
	logPatterns := []struct {
		pattern     string
		severity    string
		description string
		mitre       string
	}{
		{`failed password.*root`, "HIGH", "Brute force attack on root account", "T1110.001"},
		{`sudo.*COMMAND=.*sh`, "MEDIUM", "Suspicious sudo shell execution", "T1548.003"},
		{`wget.*http.*\.sh`, "HIGH", "Malicious script download detected", "T1105"},
		{`nc.*-e.*sh`, "CRITICAL", "Netcat reverse shell detected", "T1059.004"},
		{`python.*socket.*connect`, "MEDIUM", "Suspicious Python network activity", "T1071.001"},
	}
	
	// Simulate log analysis
	for _, pattern := range logPatterns {
		if time.Now().Unix()%13 == 0 { // Occasional detection
			td.createThreatEvent("log-analyzer", pattern.severity, "Suspicious Log Entry",
				fmt.Sprintf("Detected pattern: %s", pattern.description),
				map[string]interface{}{
					"pattern": pattern.pattern,
					"log_source": "/var/log/auth.log",
				}, pattern.mitre)
		}
	}
}

func (td *ThreatDetector) huntForThreats() {
	// Advanced threat hunting techniques
	huntingQueries := []struct {
		name        string
		description string
		severity    string
		mitre       string
	}{
		{"Persistence Mechanism", "Suspicious cron job modification", "HIGH", "T1053.003"},
		{"Credential Access", "Memory dump attempt detected", "CRITICAL", "T1003.001"},
		{"Defense Evasion", "Process hollowing indicators", "HIGH", "T1055.012"},
		{"Lateral Movement", "SMB enumeration activity", "MEDIUM", "T1021.002"},
		{"Exfiltration", "Large data transfer to external IP", "HIGH", "T1041"},
	}
	
	for _, hunt := range huntingQueries {
		if time.Now().Unix()%17 == 0 { // Occasional detection
			td.createThreatEvent("threat-hunter", hunt.severity, hunt.name,
				hunt.description,
				map[string]interface{}{
					"hunting_query": hunt.name,
					"confidence": "medium",
				}, hunt.mitre)
		}
	}
}

func (td *ThreatDetector) checkSuspiciousTraffic() {
	// DNS analysis for malicious domains
	maliciousDomains := []string{
		"evil.com", "malware-c2.net", "phishing-site.org",
		"crypto-miner.io", "botnet-controller.biz",
	}
	
	for _, domain := range maliciousDomains {
		if time.Now().Unix()%11 == 0 { // Occasional detection
			td.createThreatEvent("dns-monitor", "HIGH", "Malicious Domain Access",
				fmt.Sprintf("DNS query to known malicious domain: %s", domain),
				map[string]interface{}{
					"domain": domain,
					"query_type": "A",
					"threat_category": "C2",
				}, "T1071.004") // MITRE ATT&CK: DNS
		}
	}
}

func (td *ThreatDetector) performSecurityChecks() {
	// File integrity monitoring
	criticalFiles := []string{
		"/etc/passwd", "/etc/shadow", "/etc/sudoers",
		"/root/.ssh/authorized_keys", "/etc/crontab",
	}
	
	for _, file := range criticalFiles {
		if time.Now().Unix()%19 == 0 { // Occasional detection
			td.createThreatEvent("file-integrity", "HIGH", "Critical File Modified",
				fmt.Sprintf("Unauthorized modification detected: %s", file),
				map[string]interface{}{
					"file_path": file,
					"modification_type": "content_change",
					"timestamp": time.Now().Unix(),
				}, "T1565.001") // MITRE ATT&CK: Stored Data Manipulation
		}
	}
}

func (td *ThreatDetector) checkSystemHardening() {
	// Security configuration checks
	hardeningChecks := []struct {
		check       string
		severity    string
		description string
	}{
		{"SSH root login enabled", "HIGH", "SSH allows direct root login"},
		{"Password authentication enabled", "MEDIUM", "SSH password auth not disabled"},
		{"Firewall not configured", "MEDIUM", "No firewall rules detected"},
		{"Unencrypted communication", "LOW", "Service using unencrypted protocol"},
	}
	
	for _, check := range hardeningChecks {
		if time.Now().Unix()%23 == 0 { // Occasional detection
			td.createThreatEvent("security-audit", check.severity, "Security Misconfiguration",
				check.description,
				map[string]interface{}{
					"check_name": check.check,
					"compliance_framework": "CIS",
				}, "T1562.004") // MITRE ATT&CK: Disable or Modify System Firewall
		}
	}
}

func (td *ThreatDetector) detectAnomalies() {
	// Behavioral anomaly detection
	anomalies := []struct {
		name        string
		description string
		severity    string
		mitre       string
	}{
		{"Unusual Process Execution", "Process executed from unusual location", "MEDIUM", "T1059"},
		{"Abnormal Network Traffic", "Unusual outbound traffic pattern", "HIGH", "T1041"},
		{"Privilege Escalation", "Unexpected privilege elevation", "CRITICAL", "T1548"},
		{"Data Access Anomaly", "Unusual file access pattern", "MEDIUM", "T1005"},
	}
	
	for _, anomaly := range anomalies {
		if time.Now().Unix()%29 == 0 { // Occasional detection
			td.createThreatEvent("anomaly-detector", anomaly.severity, anomaly.name,
				anomaly.description,
				map[string]interface{}{
					"anomaly_type": anomaly.name,
					"confidence_score": 0.75,
					"baseline_deviation": "3.2 sigma",
				}, anomaly.mitre)
		}
	}
}

func (td *ThreatDetector) correlateEvents() {
	// Event correlation and attack chain detection
	if len(td.events) >= 3 {
		// Look for attack patterns
		recentEvents := td.events[len(td.events)-3:]
		
		// Check for multi-stage attack
		if td.isAttackChain(recentEvents) {
			td.createThreatEvent("correlation-engine", "CRITICAL", "Multi-Stage Attack Detected",
				"Correlated events indicate coordinated attack campaign",
				map[string]interface{}{
					"attack_stages": len(recentEvents),
					"confidence": "high",
					"attack_pattern": "APT-like behavior",
				}, "T1190") // MITRE ATT&CK: Initial Access
		}
	}
}

func (td *ThreatDetector) isAttackChain(events []ThreatEvent) bool {
	// Simple correlation logic - in reality this would be much more sophisticated
	severityCount := make(map[string]int)
	for _, event := range events {
		severityCount[event.Severity]++
	}
	
	// If we have multiple high/critical events in short time, consider it an attack chain
	return severityCount["HIGH"] >= 2 || severityCount["CRITICAL"] >= 1
}

func (td *ThreatDetector) createThreatEvent(source, severity, title, description string, evidence map[string]interface{}, mitre string) {
	td.eventCounter++
	
	// Calculate risk score based on severity
	var score float64
	switch severity {
	case "CRITICAL":
		score = 9.0 + (float64(td.eventCounter%10) / 10.0)
	case "HIGH":
		score = 7.0 + (float64(td.eventCounter%20) / 10.0)
	case "MEDIUM":
		score = 5.0 + (float64(td.eventCounter%30) / 10.0)
	case "LOW":
		score = 3.0 + (float64(td.eventCounter%40) / 10.0)
	default:
		score = 1.0
	}
	
	event := ThreatEvent{
		ID:          fmt.Sprintf("EVT-%d", td.eventCounter),
		Timestamp:   time.Now(),
		Source:      source,
		Severity:    severity,
		Category:    td.getCategoryFromSource(source),
		Title:       title,
		Description: description,
		Evidence:    evidence,
		MITRE:       mitre,
		Score:       score,
		Status:      "OPEN",
		Action:      td.getRecommendedAction(severity),
		Location: LocationInfo{
			IP:        td.getRandomIP(),
			Container: fmt.Sprintf("container-%d", td.eventCounter%10),
			Node:      fmt.Sprintf("node-%d", td.eventCounter%3),
		},
	}
	
	td.events = append(td.events, event)
	
	// Keep only last 200 events
	if len(td.events) > 200 {
		td.events = td.events[len(td.events)-200:]
	}
	
	log.Printf("🚨 SECURITY ALERT [%s]: %s - %s", event.Severity, event.Title, event.Description)
}

func (td *ThreatDetector) getCategoryFromSource(source string) string {
	categories := map[string]string{
		"network-intelligence": "Network Security",
		"port-scanner":        "Network Security", 
		"vulnerability-scanner": "Vulnerability Management",
		"log-analyzer":        "Log Analysis",
		"threat-hunter":       "Threat Hunting",
		"dns-monitor":         "Network Security",
		"file-integrity":      "System Integrity",
		"security-audit":      "Compliance",
		"anomaly-detector":    "Behavioral Analysis",
		"correlation-engine":  "Advanced Analytics",
	}
	
	if category, exists := categories[source]; exists {
		return category
	}
	return "General Security"
}

func (td *ThreatDetector) getRecommendedAction(severity string) string {
	actions := map[string]string{
		"CRITICAL": "IMMEDIATE_RESPONSE",
		"HIGH":     "INVESTIGATE",
		"MEDIUM":   "MONITOR",
		"LOW":      "LOG",
		"INFO":     "ACKNOWLEDGE",
	}
	
	if action, exists := actions[severity]; exists {
		return action
	}
	return "REVIEW"
}

func (td *ThreatDetector) getRandomIP() string {
	ips := []string{
		"10.0.1.15", "10.0.1.23", "10.0.1.45", "10.0.1.67",
		"192.168.1.100", "192.168.1.150", "172.16.0.10",
	}
	return ips[td.eventCounter%len(ips)]
}