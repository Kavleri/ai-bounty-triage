import React, { useEffect, useState } from "react";

export default function StitchPage({ pageName, data = {} }) {
  const [htmlContent, setHtmlContent] = useState("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  // Map page names to Stitch folder paths
  const pageMap = {
    dashboard: "dashboard_secure_bounty_board",
    findings: "findings_management_secure_bounty_board",
    triage: "triage_workflow_secure_bounty_board",
    audit: "audit_logs_secure_bounty_board",
    settings: "settings_secure_bounty_board",
  };

  useEffect(() => {
    let active = true;

    async function loadStitchPage() {
      try {
        setLoading(true);
        const stitchPath = pageMap[pageName] || pageMap.dashboard;
        const response = await fetch(`/stitch/${stitchPath}/code.html`);
        if (!response.ok) {
          throw new Error(`Failed to load ${stitchPath}`);
        }

        let html = await response.text();
        html = injectDynamicData(html, pageName, data);

        if (active) {
          setHtmlContent(html);
          setError(null);
        }
      } catch (err) {
        if (active) {
          setError(err.message);
        }
      } finally {
        if (active) {
          setLoading(false);
        }
      }
    }

    loadStitchPage();
    return () => {
      active = false;
    };
  }, [pageName, data]);

  if (loading) {
    return (
      <div className="flex items-center justify-center h-screen bg-gray-50">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary mx-auto mb-4"></div>
          <p className="text-gray-600">Loading page...</p>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="flex items-center justify-center h-screen bg-gray-50">
        <div className="text-center">
          <p className="text-red-600 font-semibold mb-2">Error loading page</p>
          <p className="text-gray-600 text-sm">{error}</p>
        </div>
      </div>
    );
  }

  return (
    <div className="stitch-page-wrapper">
      <iframe
        className="stitch-page-frame"
        title={`stitch-${pageName}`}
        srcDoc={htmlContent}
        sandbox="allow-scripts allow-forms allow-popups"
      />
    </div>
  );
}

/**
 * Inject dynamic data into Stitch HTML template
 */
function injectDynamicData(html, pageName, data) {
  if (pageName === "dashboard") {
    // Update KPI cards
    if (data.findingStats) {
      html = html.replace(
        /Open Findings<\/span>[\s\S]*?<span class="text-4xl[^>]*>(\d+)<\/span>/,
        `Open Findings</span>
        <div class="flex items-baseline gap-2">
        <span class="text-4xl font-extrabold text-primary tracking-tighter">${data.findingStats.open || 64}</span>`
      );
      html = html.replace(
        /Critical Items<\/span>[\s\S]*?<span class="text-4xl[^>]*>\d+<\/span>/,
        `Critical Items</span>
        <div class="flex items-baseline gap-2">
        <span class="text-4xl font-extrabold text-error tracking-tighter">${data.findingStats.critical || 12}</span>`
      );
    }

    // Update AI Triage Summary
    if (data.aiSummary) {
      html = html.replace(
        /High-Confidence SQLi Detected/,
        data.aiSummary.title || "High-Confidence SQLi Detected"
      );
      html = html.replace(
        /Synthetic analysis suggests a pattern matching[^<]*/,
        data.aiSummary.description || "Analysis in progress..."
      );
      html = html.replace(
        /<div class="text-2xl font-black text-tertiary-fixed">\d+%<\/div>/,
        `<div class="text-2xl font-black text-tertiary-fixed">${data.aiSummary.confidence || 0}%</div>`
      );
    }
  } else if (pageName === "findings") {
    // Inject findings list
    if (data.findings && data.findings.length > 0) {
      const findingsHtml = data.findings
        .map(
          (f) => `
        <tr class="border-b border-gray-200 hover:bg-gray-50">
          <td class="px-6 py-4 text-sm font-medium">${f.title || "N/A"}</td>
          <td class="px-6 py-4 text-sm"><span class="px-2 py-1 rounded text-xs font-bold bg-${getSeverityColor(f.severity)}">${f.severity || "unknown"}</span></td>
          <td class="px-6 py-4 text-sm">${f.status || "open"}</td>
          <td class="px-6 py-4 text-sm">${new Date(f.created_at).toLocaleDateString()}</td>
        </tr>
      `
        )
        .join("");
      
      // Try to replace findings table body
      html = html.replace(
        /(<tbody[^>]*>)[\s\S]*?(<\/tbody>)/,
        `$1${findingsHtml}$2`
      );
    }
  } else if (pageName === "audit") {
    // Inject audit logs
    if (data.auditLogs && data.auditLogs.length > 0) {
      const logsHtml = data.auditLogs
        .slice(0, 25)
        .map(
          (log) => `
        <tr class="border-b border-gray-200">
          <td class="px-6 py-4 text-sm">${new Date(log.created_at).toLocaleString()}</td>
          <td class="px-6 py-4 text-sm font-medium">${log.action || "unknown"}</td>
          <td class="px-6 py-4 text-sm">${log.entity_type || "N/A"}</td>
          <td class="px-6 py-4 text-sm text-gray-600">${log.metadata ? JSON.stringify(log.metadata).substring(0, 50) : ""}</td>
        </tr>
      `
        )
        .join("");
      
      html = html.replace(
        /(<tbody[^>]*>)[\s\S]*?(<\/tbody>)/,
        `$1${logsHtml}$2`
      );
    }
  }

  return html;
}

function getSeverityColor(severity) {
  const colors = {
    critical: "red-600",
    high: "orange-600",
    medium: "yellow-600",
    low: "green-600",
  };
  return colors[severity?.toLowerCase()] || "gray-600";
}
