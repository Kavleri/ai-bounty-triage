package api

import (
	"fmt"
	"strings"
)

type aiTriageResult struct {
	Summary        string
	Recommendation string
	Priority       string
	Confidence     float64
}

func buildAITriage(title, severity, description string, cvssScore float64) aiTriageResult {
	content := strings.ToLower(title + " " + description)
	priority := normalizePriority(severity, cvssScore)
	recommendation := "Review the issue, reproduce safely, and prepare a remediation plan."
	summary := "AI triage found a security issue that needs analyst review."
	confidence := 0.72

	switch {
	case strings.Contains(content, "sql injection") || strings.Contains(content, "sqli"):
		summary = "Likely injection vulnerability with direct data access risk."
		recommendation = "Validate every query path, use parameterized SQL, and add regression tests for injection payloads."
		confidence = 0.94
		if priority != "critical" {
			priority = "high"
		}
	case strings.Contains(content, "xss") || strings.Contains(content, "cross-site scripting"):
		summary = "Likely browser-side script injection risk."
		recommendation = "Escape output, enforce CSP, and verify all user-controlled fields before rendering."
		confidence = 0.91
	case strings.Contains(content, "rce") || strings.Contains(content, "remote code execution"):
		summary = "Potential remote code execution path detected."
		recommendation = "Isolate the component, review deserialization and command execution paths, and patch immediately."
		priority = "critical"
		confidence = 0.96
	case strings.Contains(content, "auth bypass") || strings.Contains(content, "credential") || strings.Contains(content, "token"):
		summary = "Authentication or session boundary weakness is likely."
		recommendation = "Audit auth flows, rotate secrets, and validate session handling and token verification."
		if priority == "low" {
			priority = "high"
		}
		confidence = 0.89
	}

	if cvssScore >= 9.0 {
		priority = "critical"
		confidence = maxConfidence(confidence, 0.97)
	}

	return aiTriageResult{
		Summary:        summary,
		Recommendation: recommendation,
		Priority:       priority,
		Confidence:     confidence,
	}
}

func normalizePriority(severity string, cvssScore float64) string {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "critical":
		return "critical"
	case "high":
		return "high"
	case "medium":
		if cvssScore >= 7.0 {
			return "high"
		}
		return "medium"
	default:
		if cvssScore >= 8.0 {
			return "high"
		}
		return "low"
	}
}

func maxConfidence(values ...float64) float64 {
	result := 0.0
	for _, value := range values {
		if value > result {
			result = value
		}
	}
	return result
}

func (r aiTriageResult) String() string {
	return fmt.Sprintf("%s (%s)", r.Priority, r.Summary)
}
