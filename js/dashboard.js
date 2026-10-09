/**
 * PhishGuard AI - Responsive Security Dashboard & Telemetry Visualizer
 * Member 1 Frontend Core Engine
 */

class SecurityDashboard {
  constructor() {
    this.storageKey = 'phishguard_scan_history_v1';
    this.history = this.loadHistory();
    this.currentFilter = 'all';
    this.searchQuery = '';

    // Sample initial demo history if user starts fresh
    if (this.history.length === 0) {
      this.seedDefaultHistory();
    }
  }

  seedDefaultHistory() {
    const demoItems = [
      {
        url: 'http://paypa1-security-verification.xyz/login.php',
        hostname: 'paypa1-security-verification.xyz',
        riskScore: 94,
        verdict: 'PHISHING DETECTED',
        verdictSeverity: 'danger',
        impersonatedBrand: 'PayPal',
        scannedAt: new Date(Date.now() - 1000 * 60 * 14).toISOString(),
        latencyMs: 240,
        flagsCount: 4
      },
      {
        url: 'https://www.google.com',
        hostname: 'www.google.com',
        riskScore: 3,
        verdict: 'SAFE',
        verdictSeverity: 'safe',
        impersonatedBrand: null,
        scannedAt: new Date(Date.now() - 1000 * 60 * 45).toISOString(),
        latencyMs: 185,
        flagsCount: 0
      },
      {
        url: 'http://free-crypto-giveaway.top/claim-bonus',
        hostname: 'free-crypto-giveaway.top',
        riskScore: 68,
        verdict: 'PHISHING DETECTED',
        verdictSeverity: 'danger',
        impersonatedBrand: null,
        scannedAt: new Date(Date.now() - 1000 * 60 * 120).toISOString(),
        latencyMs: 290,
        flagsCount: 3
      },
      {
        url: 'https://bit.ly/3xSecurityUpdate',
        hostname: 'bit.ly',
        riskScore: 42,
        verdict: 'SUSPICIOUS',
        verdictSeverity: 'warning',
        impersonatedBrand: null,
        scannedAt: new Date(Date.now() - 1000 * 60 * 240).toISOString(),
        latencyMs: 210,
        flagsCount: 1
      },
      {
        url: 'https://github.com',
        hostname: 'github.com',
        riskScore: 4,
        verdict: 'SAFE',
        verdictSeverity: 'safe',
        impersonatedBrand: null,
        scannedAt: new Date(Date.now() - 1000 * 60 * 360).toISOString(),
        latencyMs: 195,
        flagsCount: 0
      }
    ];

    this.history = demoItems;
    this.saveHistory();
  }

  loadHistory() {
    try {
      const data = localStorage.getItem(this.storageKey);
      return data ? JSON.parse(data) : [];
    } catch (e) {
      console.error('Failed to load scan history:', e);
      return [];
    }
  }

  saveHistory() {
    try {
      localStorage.setItem(this.storageKey, JSON.stringify(this.history));
    } catch (e) {
      console.error('Failed to save scan history:', e);
    }
  }

  addScanRecord(report) {
    const record = {
      url: report.url,
      hostname: report.hostname,
      riskScore: report.riskScore,
      verdict: report.verdict,
      verdictSeverity: report.verdictSeverity,
      impersonatedBrand: report.impersonatedBrand,
      scannedAt: report.scannedAt,
      latencyMs: report.latencyMs,
      flagsCount: report.flags ? report.flags.length : 0,
      fullReport: report
    };

    // Keep unique at top, limit to latest 50
    this.history = [record, ...this.history.filter(item => item.url !== report.url)].slice(0, 50);
    this.saveHistory();
    this.render();
  }

  clearHistory() {
    this.history = [];
    this.saveHistory();
    this.render();
  }

  render() {
    this.renderKPIs();
    this.renderWeeklyChart();
    this.renderHistoryTable();
  }

  renderKPIs() {
    const totalScansEl = document.getElementById('kpiTotalScans');
    const phishingEl = document.getElementById('kpiPhishingBlocked');
    const safeEl = document.getElementById('kpiSafeVerified');
    const speedEl = document.getElementById('kpiAvgSpeed');

    const total = this.history.length;
    const phishing = this.history.filter(h => h.verdictSeverity === 'danger').length;
    const safe = this.history.filter(h => h.verdictSeverity === 'safe').length;
    const avgLatency = total > 0 
      ? Math.round(this.history.reduce((acc, h) => acc + (h.latencyMs || 220), 0) / total)
      : 215;

    if (totalScansEl) this.animateValue(totalScansEl, total);
    if (phishingEl) this.animateValue(phishingEl, phishing);
    if (safeEl) this.animateValue(safeEl, safe);
    if (speedEl) speedEl.textContent = `${avgLatency}ms`;
  }

  animateValue(element, target) {
    let current = 0;
    const step = Math.max(1, Math.floor(target / 15));
    const interval = setInterval(() => {
      current += step;
      if (current >= target) {
        element.textContent = target.toLocaleString();
        clearInterval(interval);
      } else {
        element.textContent = current.toLocaleString();
      }
    }, 25);
  }

  renderWeeklyChart() {
    const chartContainer = document.getElementById('weeklyTrendChart');
    if (!chartContainer) return;

    // Days data
    const days = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];
    const maliciousData = [18, 26, 38, 30, 48, 54, 42];
    const safeData = [85, 98, 120, 110, 145, 130, 115];

    const width = 640;
    const height = 180;
    const padding = 25;
    const maxY = 160;

    // Map coordinates
    const getX = (idx) => padding + (idx * ((width - 2 * padding) / (days.length - 1)));
    const getY = (val) => height - padding - ((val / maxY) * (height - 2 * padding));

    const safePoints = safeData.map((val, idx) => `${getX(idx)},${getY(val)}`).join(' ');
    const malPoints = maliciousData.map((val, idx) => `${getX(idx)},${getY(val)}`).join(' ');

    const svg = `
      <svg viewBox="0 0 ${width} ${height}" class="trend-svg" style="width: 100%; height: 100%;">
        <defs>
          <linearGradient id="safeGrad" x1="0%" y1="0%" x2="0%" y2="100%">
            <stop offset="0%" stop-color="#00e676" stop-opacity="0.35"/>
            <stop offset="100%" stop-color="#00e676" stop-opacity="0.0"/>
          </linearGradient>
          <linearGradient id="malGrad" x1="0%" y1="0%" x2="0%" y2="100%">
            <stop offset="0%" stop-color="#ff2a5f" stop-opacity="0.4"/>
            <stop offset="100%" stop-color="#ff2a5f" stop-opacity="0.0"/>
          </linearGradient>
        </defs>

        <!-- Horizontal Guide Lines -->
        <line x1="${padding}" y1="${getY(40)}" x2="${width - padding}" y2="${getY(40)}" stroke="rgba(255,255,255,0.06)" stroke-dasharray="4"/>
        <line x1="${padding}" y1="${getY(80)}" x2="${width - padding}" y2="${getY(80)}" stroke="rgba(255,255,255,0.06)" stroke-dasharray="4"/>
        <line x1="${padding}" y1="${getY(120)}" x2="${width - padding}" y2="${getY(120)}" stroke="rgba(255,255,255,0.06)" stroke-dasharray="4"/>

        <!-- Area paths -->
        <polygon points="${getX(0)},${height - padding} ${safePoints} ${getX(days.length - 1)},${height - padding}" fill="url(#safeGrad)"/>
        <polygon points="${getX(0)},${height - padding} ${malPoints} ${getX(days.length - 1)},${height - padding}" fill="url(#malGrad)"/>

        <!-- Stroke lines -->
        <polyline points="${safePoints}" fill="none" stroke="#00e676" stroke-width="2.5" stroke-linecap="round"/>
        <polyline points="${malPoints}" fill="none" stroke="#ff2a5f" stroke-width="2.5" stroke-linecap="round"/>

        <!-- Data circles -->
        ${safeData.map((val, idx) => `
          <circle cx="${getX(idx)}" cy="${getY(val)}" r="4" fill="#00e676" stroke="#070a13" stroke-width="2"/>
        `).join('')}

        ${maliciousData.map((val, idx) => `
          <circle cx="${getX(idx)}" cy="${getY(val)}" r="4" fill="#ff2a5f" stroke="#070a13" stroke-width="2"/>
        `).join('')}

        <!-- X Axis labels -->
        ${days.map((day, idx) => `
          <text x="${getX(idx)}" y="${height - 4}" fill="#64748b" font-size="11" font-family="var(--font-mono)" text-anchor="middle">${day}</text>
        `).join('')}
      </svg>
    `;

    chartContainer.innerHTML = svg;
  }

  renderHistoryTable() {
    const tbody = document.getElementById('historyTableBody');
    if (!tbody) return;

    let filtered = this.history;

    if (this.currentFilter !== 'all') {
      filtered = filtered.filter(item => item.verdictSeverity === this.currentFilter);
    }

    if (this.searchQuery) {
      const q = this.searchQuery.toLowerCase();
      filtered = filtered.filter(item => item.url.toLowerCase().includes(q) || item.hostname.toLowerCase().includes(q));
    }

    if (filtered.length === 0) {
      tbody.innerHTML = `
        <tr>
          <td colspan="5">
            <div class="empty-history-state">
              <p>No security scans match the selected criteria.</p>
            </div>
          </td>
        </tr>
      `;
      return;
    }

    tbody.innerHTML = filtered.map((item, index) => {
      const dateFormatted = new Date(item.scannedAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
      return `
        <tr>
          <td>
            <span class="mono" style="color: var(--text-muted); font-size: 0.78rem;">${dateFormatted}</span>
          </td>
          <td>
            <div class="table-url-cell" title="${this.escapeHTML(item.url)}">
              <strong>${this.escapeHTML(item.hostname)}</strong>
              <div style="font-size: 0.75rem; color: var(--text-muted);">${this.escapeHTML(item.url)}</div>
            </div>
          </td>
          <td>
            <span class="mono" style="font-weight: 700; color: ${item.verdictSeverity === 'danger' ? 'var(--color-danger)' : (item.verdictSeverity === 'warning' ? 'var(--color-warning)' : 'var(--color-safe)')};">
              ${item.riskScore} / 100
            </span>
          </td>
          <td>
            <span class="table-badge ${item.verdictSeverity}">
              ${item.verdict}
            </span>
          </td>
          <td style="text-align: right;">
            <button class="table-action-btn" onclick="window.loadHistoricalReport(${index})">
              Inspect Report
            </button>
          </td>
        </tr>
      `;
    }).join('');
  }

  exportCSV() {
    if (this.history.length === 0) {
      alert('No scan history to export.');
      return;
    }

    const headers = ['Timestamp', 'URL', 'Hostname', 'Risk Score', 'Verdict', 'Severity', 'Latency(ms)'];
    const rows = this.history.map(item => [
      `"${item.scannedAt}"`,
      `"${item.url}"`,
      `"${item.hostname}"`,
      item.riskScore,
      `"${item.verdict}"`,
      `"${item.verdictSeverity}"`,
      item.latencyMs || 200
    ]);

    const csvContent = 'data:text/csv;charset=utf-8,' + [headers.join(','), ...rows.map(e => e.join(','))].join('\n');
    const encodedUri = encodeURI(csvContent);
    const link = document.createElement('a');
    link.setAttribute('href', encodedUri);
    link.setAttribute('download', `PhishGuard_Scan_History_${new Date().toISOString().slice(0, 10)}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  }

  escapeHTML(str) {
    if (!str) return '';
    return str.replace(/[&<>'"]/g, 
      tag => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;' }[tag] || tag)
    );
  }
}

// Global dashboard instance
window.securityDashboard = new SecurityDashboard();
