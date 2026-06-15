const DEFAULT_API_BASE = window.location.hostname === "127.0.0.1" || window.location.hostname === "localhost"
  ? "http://127.0.0.1:8000"
  : "https://sh-security-production.up.railway.app";
const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3, unknown: 4 };
const SEVERITY_COLORS = {
  critical: "#7f1d1d",
  high: "#c2410c",
  medium: "#b45309",
  low: "#64748b",
  unknown: "#94a3b8",
};

const state = {
  apiBase: new URLSearchParams(window.location.search).get("api_base") || DEFAULT_API_BASE,
  scan: null,
  report: null,
  pollTimer: null,
  commandMode: "linux",
  findingsSort: { key: "severity", dir: "asc" },
  apiSort: { key: "method", dir: "asc" },
  findingsFilters: { search: "", severity: "all", category: "all" },
  apiSearch: "",
  severityChart: null,
  categoryChart: null,
};

const elements = {
  websiteUrlInput: document.getElementById("websiteUrlInput"),
  createScanButton: document.getElementById("createScanButton"),
  refreshScanButton: document.getElementById("refreshScanButton"),
  scanIdValue: document.getElementById("scanIdValue"),
  scanStatusValue: document.getElementById("scanStatusValue"),
  scanUpdatedValue: document.getElementById("scanUpdatedValue"),
  commandTabs: document.getElementById("commandTabs"),
  commandOutput: document.getElementById("commandOutput"),
  commandNote: document.getElementById("commandNote"),
  commandFallback: document.getElementById("commandFallback"),
  commandFallbackOutput: document.getElementById("commandFallbackOutput"),
  copyCommandButton: document.getElementById("copyCommandButton"),
  timelineContainer: document.getElementById("timelineContainer"),
  pollingBadge: document.getElementById("pollingBadge"),
  headerProject: document.getElementById("headerProject"),
  headerGenerated: document.getElementById("headerGenerated"),
  headerReportFile: document.getElementById("headerReportFile"),
  metricTotal: document.getElementById("metricTotal"),
  metricCritical: document.getElementById("metricCritical"),
  metricHigh: document.getElementById("metricHigh"),
  metricMedium: document.getElementById("metricMedium"),
  metricLow: document.getElementById("metricLow"),
  severityLegend: document.getElementById("severityLegend"),
  languagesTable: document.getElementById("languagesTable"),
  frameworkTags: document.getElementById("frameworkTags"),
  packageManagerTags: document.getElementById("packageManagerTags"),
  projectTypeTags: document.getElementById("projectTypeTags"),
  directoryTree: document.getElementById("directoryTree"),
  importantFilesList: document.getElementById("importantFilesList"),
  inventoryNotes: document.getElementById("inventoryNotes"),
  apiSearchInput: document.getElementById("apiSearchInput"),
  apiTableBody: document.getElementById("apiTableBody"),
  findingsSearchInput: document.getElementById("findingsSearchInput"),
  severityFilter: document.getElementById("severityFilter"),
  categoryFilter: document.getElementById("categoryFilter"),
  resultsCount: document.getElementById("resultsCount"),
  findingsTableBody: document.getElementById("findingsTableBody"),
  criticalHighlights: document.getElementById("criticalHighlights"),
};

function escapeHtml(value) {
  return String(value || "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/\"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function formatDate(value) {
  if (!value) return "-";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}

function normalizeSeverity(value) {
  return String(value || "unknown").toLowerCase();
}

function severityBadge(severity) {
  const level = normalizeSeverity(severity);
  return `<span class="badge ${level}">${escapeHtml(level)}</span>`;
}

function statusClass(status) {
  const level = String(status || "neutral").toLowerCase();
  if (["completed", "done"].includes(level)) return "completed";
  if (["running", "started", "progress", "uploading", "skipped"].includes(level)) return "running";
  if (["failed", "error"].includes(level)) return "failed";
  return "neutral";
}

function sortBySeverity(a, b) {
  return (SEVERITY_ORDER[normalizeSeverity(a)] ?? 9) - (SEVERITY_ORDER[normalizeSeverity(b)] ?? 9);
}

function makeUrl(path) {
  return `${state.apiBase.replace(/\/$/, "")}${path}`;
}

function parseEnvExports(commandText) {
  const exportsMap = {};
  const lines = String(commandText || "").split("\n");
  for (const line of lines) {
    const match = line.match(/^export\s+([A-Z0-9_]+)="([^"]*)"$/);
    if (match) {
      exportsMap[match[1]] = match[2];
    }
  }
  return exportsMap;
}

function formatCommandPresentation(mode, commands) {
  const rawCommand = commands[mode] || "";
  const base = {
    primary: rawCommand,
    fallback: "",
    note: commands.notes || "Run this from inside the project folder on the server.",
  };

  if (mode !== "linux") {
    return base;
  }

  const env = parseEnvExports(rawCommand);
  if (!env.SCAN_API_TOKEN || !env.SCAN_ID) {
    return base;
  }

  const targetLine = env.SCAN_TARGET_URL ? `export SCAN_TARGET_URL="${env.SCAN_TARGET_URL}"\n` : "";
  return {
    primary:
      `export SCAN_API_TOKEN="${env.SCAN_API_TOKEN}"\n` +
      `export SCAN_ID="${env.SCAN_ID}"\n` +
      targetLine +
      `bash <(curl -fsSL ${state.apiBase.replace(/\/$/, "")}/run.sh)`,
    fallback: rawCommand,
    note: "Use this on a Linux server or SSH terminal. Open the alternative method if curl is unavailable.",
  };
}

function summarizeEvent(event) {
  const stage = String(event.stage || "scan").toLowerCase();
  const status = String(event.status || "running").toLowerCase();
  const steps = {
    session: "Scan session prepared",
    scan: status === "completed" ? "Scan finished" : status === "failed" ? "Scan stopped" : "Scan started",
    rules: "Loading security rules",
    gitleaks: status === "skipped" ? "Secret history checks skipped" : "Checking for exposed secrets",
    "semgrep-sast": status === "skipped" ? "Application code checks skipped" : "Reviewing application code",
    "semgrep-iac": status === "skipped" ? "Infrastructure checks skipped" : "Reviewing infrastructure files",
    osv: status === "skipped" ? "Dependency audit skipped" : "Checking dependency risks",
    custom: "Reviewing exposed files and unsafe configs",
    merge: "Building the final report",
    upload: status === "completed" ? "Sending the report to the dashboard" : "Uploading the final report",
    report: "Report is ready to view",
  };
  const title = steps[stage] || "Processing scan data";
  const detail = status === "failed"
    ? "Something needs attention. Check the scan terminal output."
    : status === "skipped"
      ? "This step was not available in the current environment."
      : title;
  return { title, detail };
}

async function createScan() {
  const payload = {
    website_url: elements.websiteUrlInput.value.trim(),
  };
  const response = await fetch(makeUrl("/api/scans"), {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  if (!response.ok) {
    throw new Error(`Could not create scan session (${response.status})`);
  }
  const data = await response.json();
  state.scan = data.scan;
  renderSession();
  startPolling();
  updateQueryString();
}

async function fetchScan(scanId) {
  const response = await fetch(makeUrl(`/api/scans/${encodeURIComponent(scanId)}`));
  if (!response.ok) {
    throw new Error(`Could not load scan session (${response.status})`);
  }
  const data = await response.json();
  state.scan = data;
  state.report = data.report || state.report;
  renderSession();
  if (data.report) {
    renderReport(data.report);
  }
}

function startPolling() {
  stopPolling();
  if (!state.scan?.id) return;
  elements.pollingBadge.className = "status-badge running";
  elements.pollingBadge.textContent = "Polling";
  state.pollTimer = window.setInterval(async () => {
    try {
      await fetchScan(state.scan.id);
      const status = String(state.scan?.status || "").toLowerCase();
      if (["completed", "failed"].includes(status)) {
        stopPolling(status);
      }
    } catch (error) {
      elements.pollingBadge.className = "status-badge failed";
      elements.pollingBadge.textContent = "Polling error";
      console.error(error);
    }
  }, 4000);
}

function stopPolling(finalState = "waiting") {
  if (state.pollTimer) {
    clearInterval(state.pollTimer);
    state.pollTimer = null;
  }
  const klass = statusClass(finalState);
  elements.pollingBadge.className = `status-badge ${klass}`;
  elements.pollingBadge.textContent = finalState === "waiting" ? "Waiting" : finalState;
}

function renderSession() {
  const scan = state.scan;
  if (!scan) {
    elements.scanIdValue.textContent = "Not created";
    elements.scanStatusValue.textContent = "Idle";
    elements.scanUpdatedValue.textContent = "-";
    elements.commandOutput.textContent = "Prepare a command to begin.";
    elements.commandFallback.hidden = true;
    elements.commandFallback.open = false;
    elements.commandFallbackOutput.textContent = "";
    elements.commandTabs.innerHTML = "";
    elements.timelineContainer.innerHTML = '<div class="empty-state">No scan activity yet.</div>';
    return;
  }
  elements.scanIdValue.textContent = scan.id;
  elements.scanStatusValue.textContent = scan.status || "pending";
  elements.scanUpdatedValue.textContent = formatDate(scan.updated_at);
  renderCommandTabs(scan.commands || {});
  renderTimeline(scan.events || []);
}

function renderCommandTabs(commands) {
  const modes = [
    ["linux", "Linux"],
    ["git_bash", "Git Bash"],
    ["powershell", "PowerShell"],
    ["cmd", "CMD"],
  ].filter(([key]) => commands[key]);

  if (!modes.length) {
    elements.commandTabs.innerHTML = "";
    elements.commandOutput.textContent = "No command available yet.";
    elements.commandNote.textContent = "Choose the command that matches the server environment.";
    return;
  }

  if (!commands[state.commandMode]) {
    state.commandMode = modes[0][0];
  }

  elements.commandTabs.innerHTML = modes.map(([key, label]) => (
    `<button type="button" class="${key === state.commandMode ? "active" : ""}" data-command-mode="${key}">${label}</button>`
  )).join("");
  const presentation = formatCommandPresentation(state.commandMode, commands);
  elements.commandOutput.textContent = presentation.primary;
  elements.commandNote.textContent = presentation.note;
  elements.commandFallback.hidden = !presentation.fallback;
  elements.commandFallback.open = false;
  elements.commandFallbackOutput.textContent = presentation.fallback;
}

function renderTimeline(events) {
  if (!events.length) {
    elements.timelineContainer.innerHTML = '<div class="empty-state">No scan activity yet.</div>';
    return;
  }
  const ordered = [...events].sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
  elements.timelineContainer.innerHTML = ordered.map((event) => {
    const summary = summarizeEvent(event);
    return `
      <article class="timeline-item compact">
        <div class="timeline-time">${escapeHtml(formatDate(event.timestamp))}</div>
        <div><span class="status-badge ${statusClass(event.status)}">${escapeHtml(event.status || "running")}</span></div>
        <div>
          <strong>${escapeHtml(summary.title)}</strong>
          <div class="subtle">${escapeHtml(summary.detail)}</div>
        </div>
      </article>
    `;
  }).join("");
}

function renderReport(report) {
  const summary = report.summary || {};
  const codebase = report.codebase || {};

  elements.headerProject.textContent = report.root || state.scan?.website_url || "Unknown project";
  elements.headerGenerated.textContent = formatDate(report.generated_at || state.scan?.updated_at);
  elements.headerReportFile.textContent = report.report_file || state.scan?.report_summary?.report_file || "Unknown report";
  elements.metricTotal.textContent = summary.total || 0;
  elements.metricCritical.textContent = summary.critical || 0;
  elements.metricHigh.textContent = summary.high || 0;
  elements.metricMedium.textContent = summary.medium || 0;
  elements.metricLow.textContent = summary.low || 0;

  renderSeverityChart(summary);
  renderCategoryChart(summary.by_category || {}, report.findings || []);
  renderCodebase(codebase);
  renderApiTable(codebase.apis || []);
  renderCriticalHighlights(report.findings || []);
  populateCategoryFilter(report.findings || []);
  renderFindings(report.findings || []);
}

function renderSeverityChart(summary) {
  const labels = ["critical", "high", "medium", "low"];
  const values = labels.map((label) => Number(summary[label] || 0));
  const total = values.reduce((acc, value) => acc + value, 0) || 1;

  if (state.severityChart) state.severityChart.destroy();
  state.severityChart = new Chart(document.getElementById("severityChart"), {
    type: "doughnut",
    data: {
      labels,
      datasets: [{ data: values, backgroundColor: labels.map((label) => SEVERITY_COLORS[label]), borderWidth: 0 }],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { display: false } },
    },
  });

  elements.severityLegend.innerHTML = labels.map((label, index) => {
    const value = values[index];
    const pct = Math.round((value / total) * 100);
    return `<div class="legend-item"><span class="legend-swatch" style="background:${SEVERITY_COLORS[label]}"></span>${escapeHtml(label)}: ${value} (${pct}%)</div>`;
  }).join("");
}

function renderCategoryChart(byCategory, findings) {
  const items = Object.entries(byCategory).sort((a, b) => b[1] - a[1]);
  const labels = items.map(([name]) => name);
  const values = items.map(([, count]) => count);
  const colors = labels.map((category) => dominantSeverityColor(category, findings));

  if (state.categoryChart) state.categoryChart.destroy();
  state.categoryChart = new Chart(document.getElementById("categoryChart"), {
    type: "bar",
    data: {
      labels,
      datasets: [{ data: values, backgroundColor: colors, borderWidth: 0, borderRadius: 6 }],
    },
    options: {
      indexAxis: "y",
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: {
        x: { ticks: { precision: 0 } },
        y: { grid: { display: false } },
      },
    },
  });
}

function dominantSeverityColor(category, findings) {
  const matches = findings.filter((item) => item.category === category);
  if (!matches.length) return "#94a3b8";
  matches.sort((a, b) => sortBySeverity(a.severity, b.severity));
  return SEVERITY_COLORS[normalizeSeverity(matches[0].severity)] || "#94a3b8";
}

function renderCodebase(codebase) {
  renderTags(elements.frameworkTags, codebase.detected_frameworks || []);
  renderTags(elements.packageManagerTags, codebase.package_managers || []);
  renderTags(elements.projectTypeTags, codebase.project_type || []);

  const languages = codebase.languages || [];
  const maxFiles = Math.max(...languages.map((item) => item.files || 0), 1);
  elements.languagesTable.innerHTML = languages.length ? `<div class="languages-table">${languages.map((item) => `
    <div class="language-row">
      <strong>${escapeHtml(item.name)}</strong>
      <div class="language-bar"><span style="width:${Math.max(8, ((item.files || 0) / maxFiles) * 100)}%"></span></div>
      <span>${item.files || 0}</span>
    </div>`).join("")}</div>` : '<div class="empty-state">No language data.</div>';

  elements.directoryTree.innerHTML = buildDirectoryTree(codebase.directories || []);
  elements.importantFilesList.innerHTML = (codebase.important_files || []).map((item) => `<li>${escapeHtml(item)}</li>`).join("") || '<li>No important files listed.</li>';
  elements.inventoryNotes.innerHTML = (codebase.notes || []).map((item) => `<li>${escapeHtml(item)}</li>`).join("") || '<li>No notes.</li>';
}

function renderTags(element, values) {
  element.innerHTML = values.length ? values.map((value) => `<span class="tag">${escapeHtml(value)}</span>`).join("") : '<span class="tag">None detected</span>';
}

function buildDirectoryTree(paths) {
  if (!paths.length) return '<div class="empty-state">No directory tree data.</div>';
  const root = {};
  for (const path of paths) {
    let node = root;
    for (const part of String(path).split("/")) {
      node[part] = node[part] || {};
      node = node[part];
    }
  }
  function renderNode(node) {
    return `<ul>${Object.keys(node).sort().map((key) => `<li>${escapeHtml(key)}${renderNode(node[key])}</li>`).join("")}</ul>`;
  }
  return renderNode(root);
}

function getFilteredApis(apis) {
  const search = state.apiSearch.trim().toLowerCase();
  let filtered = [...apis];
  if (search) {
    filtered = filtered.filter((api) => [api.method, api.path, api.file, api.framework_hint].join(" ").toLowerCase().includes(search));
  }
  const { key, dir } = state.apiSort;
  filtered.sort((a, b) => compareValues(a[key], b[key], dir));
  return filtered;
}

function renderApiTable(apis) {
  const filtered = getFilteredApis(apis);
  if (!filtered.length) {
    elements.apiTableBody.innerHTML = '<tr><td colspan="5" class="empty-cell">No API inventory loaded.</td></tr>';
    return;
  }
  elements.apiTableBody.innerHTML = filtered.map((api) => `
    <tr>
      <td>${escapeHtml(api.method || "ANY")}</td>
      <td><code>${escapeHtml(api.path || "")}</code></td>
      <td>${escapeHtml(api.file || "")}</td>
      <td>${escapeHtml(api.line || 1)}</td>
      <td>${escapeHtml(api.framework_hint || "")}</td>
    </tr>
  `).join("");
}

function renderCriticalHighlights(findings) {
  const criticals = findings.filter((item) => normalizeSeverity(item.severity) === "critical").slice(0, 3);
  if (!criticals.length) {
    elements.criticalHighlights.innerHTML = "";
    return;
  }
  elements.criticalHighlights.innerHTML = criticals.map((item) => `
    <article class="critical-card">
      <span class="badge critical">critical</span>
      <h3>${escapeHtml(item.title)}</h3>
      <p><strong>${escapeHtml(item.file)}:${escapeHtml(item.line || 1)}</strong></p>
      <p>${escapeHtml(item.remediation || "Review and remediate immediately.")}</p>
    </article>
  `).join("");
}

function populateCategoryFilter(findings) {
  const categories = [...new Set(findings.map((item) => item.category).filter(Boolean))].sort();
  const current = state.findingsFilters.category;
  elements.categoryFilter.innerHTML = '<option value="all">All categories</option>' + categories.map((category) => `<option value="${escapeHtml(category)}">${escapeHtml(category)}</option>`).join("");
  elements.categoryFilter.value = categories.includes(current) ? current : "all";
}

function getFilteredFindings(findings) {
  let filtered = [...findings];
  const { search, severity, category } = state.findingsFilters;
  const normalizedSearch = search.trim().toLowerCase();
  if (severity !== "all") {
    filtered = filtered.filter((item) => normalizeSeverity(item.severity) === severity);
  }
  if (category !== "all") {
    filtered = filtered.filter((item) => item.category === category);
  }
  if (normalizedSearch) {
    filtered = filtered.filter((item) => [item.title, item.file, item.evidence, item.description, item.remediation].join(" ").toLowerCase().includes(normalizedSearch));
  }
  const { key, dir } = state.findingsSort;
  filtered.sort((a, b) => {
    if (key === "severity") {
      return dir === "asc" ? sortBySeverity(a.severity, b.severity) : sortBySeverity(b.severity, a.severity);
    }
    return compareValues(a[key], b[key], dir);
  });
  return filtered;
}

function renderFindings(findings) {
  const filtered = getFilteredFindings(findings);
  elements.resultsCount.textContent = `${filtered.length} results`;
  if (!filtered.length) {
    elements.findingsTableBody.innerHTML = '<tr><td colspan="6" class="empty-cell">No findings match the current filters.</td></tr>';
    return;
  }

  elements.findingsTableBody.innerHTML = filtered.map((item, index) => {
    const detailId = `finding-detail-${index}`;
    return `
      <tr class="finding-row" data-detail-target="${detailId}">
        <td>${severityBadge(item.severity)}</td>
        <td>${escapeHtml(item.category || "")}</td>
        <td>${escapeHtml(item.title || "")}</td>
        <td>${escapeHtml(item.file || "")}</td>
        <td>${escapeHtml(item.line || 1)}</td>
        <td>${escapeHtml(item.tool || "")}</td>
      </tr>
      <tr class="detail-row" id="${detailId}" hidden>
        <td colspan="6">
          <div class="detail-content">
            <div><strong>Note:</strong> ${escapeHtml(item.note || "-")}</div>
            <div><strong>Description:</strong> ${escapeHtml(item.description || "-")}</div>
            <div><strong>Remediation:</strong> ${escapeHtml(item.remediation || "-")}</div>
            <div><strong>Evidence:</strong><pre>${escapeHtml(item.evidence || "No evidence captured.")}</pre></div>
          </div>
        </td>
      </tr>`;
  }).join("");
}

function compareValues(a, b, dir) {
  const left = typeof a === "number" ? a : String(a || "").toLowerCase();
  const right = typeof b === "number" ? b : String(b || "").toLowerCase();
  if (left < right) return dir === "asc" ? -1 : 1;
  if (left > right) return dir === "asc" ? 1 : -1;
  return 0;
}

function updateQueryString() {
  const params = new URLSearchParams(window.location.search);
  if (state.scan?.id) params.set("scan_id", state.scan.id);
  const apiBaseIsCustom = state.apiBase && state.apiBase !== DEFAULT_API_BASE;
  if (apiBaseIsCustom) {
    params.set("api_base", state.apiBase);
  } else {
    params.delete("api_base");
  }
  const query = params.toString();
  const nextUrl = `${window.location.pathname}${query ? `?${query}` : ""}`;
  window.history.replaceState({}, "", nextUrl);
}

function bindEvents() {
  elements.createScanButton.addEventListener("click", async () => {
    try {
      await createScan();
    } catch (error) {
      alert(error.message);
    }
  });

  elements.refreshScanButton.addEventListener("click", async () => {
    if (!state.scan?.id) return;
    try {
      await fetchScan(state.scan.id);
    } catch (error) {
      alert(error.message);
    }
  });

  elements.commandTabs.addEventListener("click", (event) => {
    const button = event.target.closest("[data-command-mode]");
    if (!button || !state.scan?.commands) return;
    state.commandMode = button.getAttribute("data-command-mode");
    renderCommandTabs(state.scan.commands);
  });

  elements.copyCommandButton.addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(elements.commandOutput.textContent);
      elements.copyCommandButton.textContent = "Copied";
      window.setTimeout(() => { elements.copyCommandButton.textContent = "Copy command"; }, 1200);
    } catch (error) {
      alert("Could not copy command.");
    }
  });

  elements.apiSearchInput.addEventListener("input", () => {
    state.apiSearch = elements.apiSearchInput.value;
    renderApiTable(state.report?.codebase?.apis || state.scan?.report?.codebase?.apis || []);
  });

  document.querySelectorAll("[data-api-sort]").forEach((header) => {
    header.addEventListener("click", () => {
      const key = header.getAttribute("data-api-sort");
      state.apiSort.dir = state.apiSort.key === key && state.apiSort.dir === "asc" ? "desc" : "asc";
      state.apiSort.key = key;
      renderApiTable(state.report?.codebase?.apis || state.scan?.report?.codebase?.apis || []);
    });
  });

  elements.findingsSearchInput.addEventListener("input", () => {
    state.findingsFilters.search = elements.findingsSearchInput.value;
    renderFindings(state.report?.findings || state.scan?.report?.findings || []);
  });

  elements.severityFilter.addEventListener("change", () => {
    state.findingsFilters.severity = elements.severityFilter.value;
    renderFindings(state.report?.findings || state.scan?.report?.findings || []);
  });

  elements.categoryFilter.addEventListener("change", () => {
    state.findingsFilters.category = elements.categoryFilter.value;
    renderFindings(state.report?.findings || state.scan?.report?.findings || []);
  });

  document.querySelectorAll("[data-findings-sort]").forEach((header) => {
    header.addEventListener("click", () => {
      const key = header.getAttribute("data-findings-sort");
      state.findingsSort.dir = state.findingsSort.key === key && state.findingsSort.dir === "asc" ? "desc" : "asc";
      state.findingsSort.key = key;
      renderFindings(state.report?.findings || state.scan?.report?.findings || []);
    });
  });

  elements.findingsTableBody.addEventListener("click", (event) => {
    const row = event.target.closest(".finding-row");
    if (!row) return;
    const detail = document.getElementById(row.getAttribute("data-detail-target"));
    if (detail) detail.hidden = !detail.hidden;
  });
}

async function boot() {
  bindEvents();
  renderSession();

  const scanId = new URLSearchParams(window.location.search).get("scan_id");
  if (scanId) {
    try {
      await fetchScan(scanId);
      const status = String(state.scan?.status || "").toLowerCase();
      if (!["completed", "failed"].includes(status)) {
        startPolling();
      } else {
        stopPolling(status);
      }
    } catch (error) {
      console.error(error);
    }
  }
}

boot();
