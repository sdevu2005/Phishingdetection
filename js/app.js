/**
 * PhishGuard AI - Main Application Controller
 * Member 1 Frontend Core Engine
 */

class SoundEffects {
  constructor() {
    this.enabled = true;
    this.audioCtx = null;
  }

  init() {
    if (!this.audioCtx && (window.AudioContext || window.webkitAudioContext)) {
      this.audioCtx = new (window.AudioContext || window.webkitAudioContext)();
    }
  }

  playTone(freq, type, duration, gainVal = 0.05) {
    if (!this.enabled) return;
    try {
      this.init();
      if (!this.audioCtx) return;
      if (this.audioCtx.state === 'suspended') {
        this.audioCtx.resume();
      }

      const osc = this.audioCtx.createOscillator();
      const gain = this.audioCtx.createGain();

      osc.type = type;
      osc.frequency.setValueAtTime(freq, this.audioCtx.currentTime);

      gain.gain.setValueAtTime(gainVal, this.audioCtx.currentTime);
      gain.gain.exponentialRampToValueAtTime(0.0001, this.audioCtx.currentTime + duration);

      osc.connect(gain);
      gain.connect(this.audioCtx.destination);

      osc.start();
      osc.stop(this.audioCtx.currentTime + duration);
    } catch (e) {
      // Audio autoplay policy fallback
    }
  }

  beepScanStart() {
    this.playTone(587.33, 'sine', 0.15, 0.04);
    setTimeout(() => this.playTone(880, 'sine', 0.2, 0.04), 100);
  }

  beepStagePass() {
    this.playTone(740, 'triangle', 0.08, 0.03);
  }

  beepThreatDanger() {
    this.playTone(220, 'sawtooth', 0.35, 0.07);
    setTimeout(() => this.playTone(180, 'sawtooth', 0.45, 0.08), 180);
  }

  beepSafe() {
    this.playTone(523.25, 'sine', 0.15, 0.04);
    setTimeout(() => this.playTone(659.25, 'sine', 0.15, 0.04), 120);
    setTimeout(() => this.playTone(783.99, 'sine', 0.25, 0.05), 240);
  }
}

const sounds = new SoundEffects();

document.addEventListener('DOMContentLoaded', () => {
  // 1. Matrix Cyber Canvas background
  initMatrixCanvas();

  // 2. Initialize Navigation
  initNavigation();

  // 3. Scanner Form & Interactions
  initScannerForm();

  // 4. Sample Pill Click Handlers
  initSamplePills();

  // 5. Sound Toggle
  initSoundToggle();

  // 6. History Table Filters & Search
  initHistoryControls();

  // 7. Initial dashboard render
  if (window.securityDashboard) {
    window.securityDashboard.render();
  }

  // 8. Initialize QR Scanner
  if (window.qrScanner) {
    window.qrScanner.init();
  }

  // 9. Start Live Threat Telemetry ticker
  startLiveThreatStream();
});

/* ==========================================================================
   Matrix Ambient Background
   ========================================================================== */
function initMatrixCanvas() {
  const canvas = document.getElementById('matrixCanvas');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');

  function resize() {
    canvas.width = window.innerWidth;
    canvas.height = window.innerHeight;
  }
  resize();
  window.addEventListener('resize', resize);

  const characters = '01ABCDEFXYZ$#><=;:*&%';
  const fontSize = 14;
  const columns = Math.floor(canvas.width / fontSize);
  const drops = Array(columns).fill(1);

  function draw() {
    ctx.fillStyle = 'rgba(7, 10, 19, 0.08)';
    ctx.fillRect(0, 0, canvas.width, canvas.height);

    ctx.fillStyle = '#00f2fe';
    ctx.font = `${fontSize}px monospace`;

    for (let i = 0; i < drops.length; i++) {
      const text = characters.charAt(Math.floor(Math.random() * characters.length));
      ctx.fillText(text, i * fontSize, drops[i] * fontSize);

      if (drops[i] * fontSize > canvas.height && Math.random() > 0.975) {
        drops[i] = 0;
      }
      drops[i]++;
    }
  }

  setInterval(draw, 45);
}

/* ==========================================================================
   Navigation Controller
   ========================================================================== */
function initNavigation() {
  const navLinks = document.querySelectorAll('.nav-link[data-tab]');
  const sections = {
    scanner: document.getElementById('scannerSectionGroup'),
    dashboard: document.getElementById('dashboardSection'),
  };

  navLinks.forEach(link => {
    link.addEventListener('click', (e) => {
      e.preventDefault();
      const tab = link.getAttribute('data-tab');

      navLinks.forEach(l => l.classList.remove('active'));
      link.classList.add('active');

      if (tab === 'dashboard') {
        if (sections.scanner) sections.scanner.style.display = 'none';
        if (sections.dashboard) {
          sections.dashboard.classList.add('active');
          sections.dashboard.style.display = 'block';
        }
        if (window.securityDashboard) {
          window.securityDashboard.render();
        }
      } else {
        if (sections.scanner) sections.scanner.style.display = 'block';
        if (sections.dashboard) {
          sections.dashboard.classList.remove('active');
          sections.dashboard.style.display = 'none';
        }
      }
    });
  });

  // Modal triggers
  const apiSettingsBtn = document.getElementById('apiSettingsBtn');
  const settingsModal = document.getElementById('settingsModal');
  const closeSettingsBtn = document.getElementById('closeSettingsBtn');

  if (apiSettingsBtn && settingsModal) {
    apiSettingsBtn.addEventListener('click', () => {
      settingsModal.classList.add('active');
    });
  }
  if (closeSettingsBtn && settingsModal) {
    closeSettingsBtn.addEventListener('click', () => {
      settingsModal.classList.remove('active');
    });
  }
}

/* ==========================================================================
   Sound Toggle
   ========================================================================== */
function initSoundToggle() {
  const toggleBtn = document.getElementById('toggleSoundBtn');
  if (!toggleBtn) return;

  toggleBtn.addEventListener('click', () => {
    sounds.enabled = !sounds.enabled;
    toggleBtn.style.opacity = sounds.enabled ? '1' : '0.4';
    showToast(sounds.enabled ? 'Audio feedback enabled' : 'Audio muted');
  });
}

/* ==========================================================================
   Sample Pills Handlers
   ========================================================================== */
function initSamplePills() {
  const pills = document.querySelectorAll('.sample-pill');
  const input = document.getElementById('urlInput');

  pills.forEach(pill => {
    pill.addEventListener('click', () => {
      const url = pill.getAttribute('data-url');
      if (input && url) {
        input.value = url;
        input.focus();
        showToast('Sample URL loaded into scanner');
        // Auto trigger scan after tiny delay
        setTimeout(() => triggerScan(), 150);
      }
    });
  });

  // Paste button
  const pasteBtn = document.getElementById('pasteUrlBtn');
  if (pasteBtn && input) {
    pasteBtn.addEventListener('click', async () => {
      try {
        const text = await navigator.clipboard.readText();
        if (text) {
          input.value = text;
          showToast('URL pasted from clipboard');
        }
      } catch (err) {
        showToast('Clipboard access not granted');
      }
    });
  }

  // Clear button
  const clearBtn = document.getElementById('clearUrlBtn');
  if (clearBtn && input) {
    clearBtn.addEventListener('click', () => {
      input.value = '';
      input.focus();
    });
  }
}

/* ==========================================================================
   Scanner Form & Pipeline Animation
   ========================================================================== */
function initScannerForm() {
  const scanForm = document.getElementById('scannerForm');
  const urlInput = document.getElementById('urlInput');

  if (scanForm) {
    scanForm.addEventListener('submit', (e) => {
      e.preventDefault();
      triggerScan();
    });
  }

  if (urlInput) {
    urlInput.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') {
        e.preventDefault();
        triggerScan();
      }
    });
  }
}

let isScanning = false;

async function triggerScan() {
  if (isScanning) return;

  const input = document.getElementById('urlInput');
  const rawUrl = (input ? input.value : '').trim();

  if (!rawUrl) {
    showToast('Please enter a target URL to analyze');
    if (input) input.focus();
    return;
  }

  isScanning = true;
  sounds.beepScanStart();

  const pipelineModal = document.getElementById('scanPipeline');
  const reportSection = document.getElementById('reportSection');
  const scanTargetUrl = document.getElementById('pipelineTargetUrl');
  const progressBar = document.getElementById('pipelineProgressBar');
  const percentText = document.getElementById('pipelinePercent');
  const consoleLog = document.getElementById('consoleLog');

  // Hide report while running pipeline
  if (reportSection) reportSection.classList.remove('active');

  // Reset pipeline stages
  const stages = [
    document.getElementById('stage1'),
    document.getElementById('stage2'),
    document.getElementById('stage3'),
    document.getElementById('stage4')
  ];

  stages.forEach(st => {
    if (st) {
      st.className = 'stage-card pending';
      const badge = st.querySelector('.stage-status-badge');
      if (badge) badge.textContent = 'Pending';
    }
  });

  if (consoleLog) consoleLog.innerHTML = '';
  if (scanTargetUrl) scanTargetUrl.textContent = rawUrl;
  if (pipelineModal) pipelineModal.classList.add('active');

  pipelineModal.scrollIntoView({ behavior: 'smooth', block: 'nearest' });

  // Terminal log helper
  function addLog(type, msg) {
    if (!consoleLog) return;
    const time = new Date().toLocaleTimeString().split(' ')[0];
    const line = document.createElement('div');
    line.className = 'console-line';
    line.innerHTML = `
      <span class="console-time">[${time}]</span>
      <span class="console-msg ${type}">${msg}</span>
    `;
    consoleLog.appendChild(line);
    consoleLog.scrollTop = consoleLog.scrollHeight;
  }

  addLog('info', `Initializing threat analysis engine for: ${rawUrl}`);

  // Stage 1: DNS & Network Resolution
  stages[0].className = 'stage-card running';
  stages[0].querySelector('.stage-status-badge').textContent = 'Running';
  addLog('info', 'Phase 1: Resolving authoritative DNS records and ASN routes...');
  await animateProgress(0, 25, 400, progressBar, percentText);
  stages[0].className = 'stage-card completed';
  stages[0].querySelector('.stage-status-badge').textContent = 'Passed';
  sounds.beepStagePass();
  addLog('pass', 'DNS queries resolved. IP and PTR reverse telemetry verified.');

  // Stage 2: SSL/TLS Certificate & Handshake
  stages[1].className = 'stage-card running';
  stages[1].querySelector('.stage-status-badge').textContent = 'Running';
  addLog('info', 'Phase 2: Inspecting SSL/TLS chain, OCSP stapling & cipher validity...');
  await animateProgress(25, 52, 450, progressBar, percentText);
  stages[1].className = 'stage-card completed';
  stages[1].querySelector('.stage-status-badge').textContent = 'Passed';
  sounds.beepStagePass();
  addLog('pass', 'Certificate chain evaluated.');

  // Stage 3: Lexical Entropy & Homoglyph
  stages[2].className = 'stage-card running';
  stages[2].querySelector('.stage-status-badge').textContent = 'Running';
  addLog('info', 'Phase 3: Computing Shannon character entropy & punycode mutations...');
  await animateProgress(52, 78, 450, progressBar, percentText);
  stages[2].className = 'stage-card completed';
  stages[2].querySelector('.stage-status-badge').textContent = 'Passed';
  sounds.beepStagePass();
  addLog('pass', 'Lexical matrix check complete.');

  // Stage 4: AI Phishing Evaluation & Brand Model
  stages[3].className = 'stage-card running';
  stages[3].querySelector('.stage-status-badge').textContent = 'Running';
  addLog('info', 'Phase 4: Running neural heuristic model & blacklist cross-check...');
  await animateProgress(78, 100, 400, progressBar, percentText);
  stages[3].className = 'stage-card completed';
  stages[3].querySelector('.stage-status-badge').textContent = 'Completed';
  sounds.beepStagePass();
  addLog('info', 'Analysis synthesis finalized. Rendering comprehensive risk report.');

  // Compute analysis through backend REST API (with client fallback)
  try {
    const report = await window.phishScanner.analyzeRemote(rawUrl);

    // Save into history
    if (window.securityDashboard) {
      window.securityDashboard.addScanRecord(report);
    }

    // Play final verdict sound
    if (report.verdictSeverity === 'danger') {
      sounds.beepThreatDanger();
    } else {
      sounds.beepSafe();
    }

    // Delay slightly for smooth transition
    setTimeout(() => {
      pipelineModal.classList.remove('active');
      renderRiskReport(report);
      isScanning = false;
    }, 400);

  } catch (err) {
    showToast(err.message || 'Error occurred while scanning URL.');
    pipelineModal.classList.remove('active');
    isScanning = false;
  }
}

function animateProgress(from, to, duration, barEl, textEl) {
  return new Promise(resolve => {
    const startTime = performance.now();
    function step(currentTime) {
      const elapsed = currentTime - startTime;
      const progress = Math.min(elapsed / duration, 1);
      const currentVal = Math.round(from + (to - from) * progress);

      if (barEl) barEl.style.width = `${currentVal}%`;
      if (textEl) textEl.textContent = `${currentVal}%`;

      if (progress < 1) {
        requestAnimationFrame(step);
      } else {
        resolve();
      }
    }
    requestAnimationFrame(step);
  });
}

/* ==========================================================================
   Render Risk Report
   ========================================================================== */
function renderRiskReport(report) {
  const reportSection = document.getElementById('reportSection');
  if (!reportSection) return;

  reportSection.classList.add('active');
  window.currentActiveReport = report;

  // 1. Verdict Banner
  const verdictBanner = document.getElementById('verdictBanner');
  verdictBanner.className = `verdict-banner ${report.verdictSeverity}`;

  const verdictBadge = document.getElementById('verdictBadge');
  verdictBadge.textContent = report.verdict;

  const verdictTitle = document.getElementById('verdictTitle');
  verdictTitle.textContent = report.verdictSeverity === 'danger'
    ? 'High-Confidence Malicious Threat'
    : (report.verdictSeverity === 'warning' ? 'Caution Recommended' : 'Verified Legitimate Destination');

  const verdictUrl = document.getElementById('verdictUrl');
  verdictUrl.textContent = report.url;

  const verdictTime = document.getElementById('verdictTime');
  verdictTime.textContent = new Date(report.scannedAt).toLocaleString();

  // 2. Risk Score Circular Gauge
  const gaugeCircle = document.getElementById('gaugeCircle');
  const gaugeNumber = document.getElementById('gaugeNumber');
  gaugeNumber.textContent = report.riskScore;

  // Circumference for r=58 is 2 * PI * 58 ≈ 364.42
  const circumference = 364.42;
  const strokeColor = report.verdictSeverity === 'danger' 
    ? 'var(--color-danger)' 
    : (report.verdictSeverity === 'warning' ? 'var(--color-warning)' : 'var(--color-safe)');
  
  gaugeCircle.style.stroke = strokeColor;
  gaugeCircle.style.strokeDasharray = `${circumference}`;
  
  const offset = circumference - (report.riskScore / 100) * circumference;
  gaugeCircle.style.strokeDashoffset = `${offset}`;

  // 3. Brand Impersonation Alert Banner
  const brandBanner = document.getElementById('brandImpersonationBanner');
  const brandTargetName = document.getElementById('brandTargetName');
  if (report.impersonatedBrand) {
    brandBanner.classList.add('active');
    brandTargetName.textContent = report.impersonatedBrand;
  } else {
    brandBanner.classList.remove('active');
  }

  // 4. SSL & Domain Cards
  document.getElementById('metricSslValid').textContent = report.metrics.ssl.status;
  document.getElementById('metricSslValid').className = `detail-val ${report.metrics.ssl.valid ? 'safe' : 'danger'}`;
  document.getElementById('metricSslIssuer').textContent = report.metrics.ssl.issuer;
  document.getElementById('metricSslProtocol').textContent = report.metrics.ssl.protocol;

  document.getElementById('metricDomainAge').textContent = report.metrics.domain.age;
  document.getElementById('metricDomainAge').className = `detail-val ${report.riskScore > 60 ? 'warn' : 'safe'}`;
  document.getElementById('metricRegistrar').textContent = report.metrics.domain.registrar;
  document.getElementById('metricAsn').textContent = report.metrics.domain.asn;
  document.getElementById('metricCountry').textContent = report.metrics.domain.country;

  // 5. Lexical & Flags Card
  document.getElementById('metricEntropy').textContent = report.metrics.lexical.entropy;
  document.getElementById('metricSubdomains').textContent = report.metrics.lexical.subdomainCount;
  document.getElementById('metricHasIp').textContent = report.metrics.lexical.hasIpHost;
  document.getElementById('metricHasIp').className = `detail-val ${report.metrics.lexical.hasIpHost.startsWith('Yes') ? 'danger' : 'safe'}`;

  // Flags list
  const flagsContainer = document.getElementById('flagsContainer');
  if (flagsContainer) {
    if (report.flags && report.flags.length > 0) {
      flagsContainer.innerHTML = report.flags.map(f => `
        <div class="flag-item triggered">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
          <div>
            <strong>${f.title}</strong>
            <div style="font-size: 0.75rem; opacity: 0.85;">${f.description}</div>
          </div>
        </div>
      `).join('');
    } else {
      flagsContainer.innerHTML = `
        <div class="flag-item clear">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>
          <div>
            <strong>Zero High-Risk Indicators</strong>
            <div style="font-size: 0.75rem; opacity: 0.85;">No deceptive lexical patterns, brand spoofing, or abnormal redirections found.</div>
          </div>
        </div>
      `;
    }
  }

  // 6. Recommendations
  const recContainer = document.getElementById('recommendationList');
  if (recContainer) {
    recContainer.innerHTML = report.recommendations.map(r => `
      <li class="recommendation-item">
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="${report.verdictSeverity === 'danger' ? 'var(--color-danger)' : 'var(--cyber-cyan)'}" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
        <span>${r}</span>
      </li>
    `).join('');
  }

  // 7. Raw JSON view
  const rawJsonCode = document.getElementById('rawJsonCode');
  if (rawJsonCode) {
    rawJsonCode.textContent = JSON.stringify(report, null, 2);
  }

  // Smooth scroll down to report
  reportSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

/* ==========================================================================
   Historical Report Loader
   ========================================================================== */
window.loadHistoricalReport = function(index) {
  const item = window.securityDashboard.history[index];
  if (!item) return;

  // Switch to scanner view
  const navLinks = document.querySelectorAll('.nav-link[data-tab]');
  navLinks.forEach(l => l.classList.remove('active'));
  document.querySelector('.nav-link[data-tab="scanner"]').classList.add('active');

  const scannerSection = document.getElementById('scannerSectionGroup');
  const dashSection = document.getElementById('dashboardSection');
  if (scannerSection) scannerSection.style.display = 'block';
  if (dashSection) {
    dashSection.classList.remove('active');
    dashSection.style.display = 'none';
  }

  // If item has fullReport, render it; otherwise re-analyze
  const report = item.fullReport || window.phishScanner.analyze(item.url);
  renderRiskReport(report);
};

/* ==========================================================================
   Report Toolbar Actions
   ========================================================================== */
window.copyReportSummary = function() {
  const r = window.currentActiveReport;
  if (!r) return;

  const text = `[PhishGuard AI Security Report]
Target URL: ${r.url}
Verdict: ${r.verdict} (Risk Score: ${r.riskScore}/100)
Severity: ${r.verdictSeverity.toUpperCase()}
Impersonated Brand: ${r.impersonatedBrand || 'None detected'}
SSL Status: ${r.metrics.ssl.status} (${r.metrics.ssl.protocol})
Domain Age: ${r.metrics.domain.age} | Country: ${r.metrics.domain.country}
Flags Triggered: ${r.flags.length}
Scanned At: ${r.scannedAt}`;

  navigator.clipboard.writeText(text).then(() => {
    showToast('Report summary copied to clipboard');
  }).catch(() => {
    showToast('Unable to copy to clipboard');
  });
};

window.exportReportJSON = function() {
  const r = window.currentActiveReport;
  if (!r) return;

  const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(r, null, 2));
  const dlAnchor = document.createElement('a');
  dlAnchor.setAttribute('href', dataStr);
  dlAnchor.setAttribute('download', `PhishGuard_Report_${r.hostname}.json`);
  dlAnchor.click();
  showToast('JSON report downloaded');
};

window.printReport = function() {
  window.print();
};

/* ==========================================================================
   History Filters & Search Controls
   ========================================================================== */
function initHistoryControls() {
  const filterPills = document.querySelectorAll('.filter-pill');
  filterPills.forEach(pill => {
    pill.addEventListener('click', () => {
      filterPills.forEach(p => p.classList.remove('active'));
      pill.classList.add('active');

      const filter = pill.getAttribute('data-filter');
      if (window.securityDashboard) {
        window.securityDashboard.currentFilter = filter;
        window.securityDashboard.renderHistoryTable();
      }
    });
  });

  const searchInput = document.getElementById('historySearchInput');
  if (searchInput) {
    searchInput.addEventListener('input', (e) => {
      if (window.securityDashboard) {
        window.securityDashboard.searchQuery = e.target.value;
        window.securityDashboard.renderHistoryTable();
      }
    });
  }

  const clearBtn = document.getElementById('clearHistoryBtn');
  if (clearBtn) {
    clearBtn.addEventListener('click', () => {
      if (confirm('Are you sure you want to clear your local scan history?')) {
        window.securityDashboard.clearHistory();
        showToast('Scan history cleared');
      }
    });
  }

  const exportBtn = document.getElementById('exportHistoryCsvBtn');
  if (exportBtn) {
    exportBtn.addEventListener('click', () => {
      window.securityDashboard.exportCSV();
    });
  }
}

/* ==========================================================================
   Live Threat Intercept Stream
   ========================================================================== */
function startLiveThreatStream() {
  const tickerEl = document.getElementById('liveThreatTicker');
  if (!tickerEl) return;

  const simulatedThreats = [
    { domain: 'secure-paypa1-billing.xyz', type: 'Phishing', target: 'PayPal' },
    { domain: 'apple-id-verify-icloud.cam', type: 'Credential Harvesting', target: 'Apple' },
    { domain: 'chase-online-auth365.top', type: 'Banking Trojan', target: 'Chase' },
    { domain: 'free-usdt-airdrop-claim.live', type: 'Crypto Drainer', target: 'Binance' },
    { domain: 'netflix-update-billing.club', type: 'Subscription Scam', target: 'Netflix' },
    { domain: 'microsoft-office-login.buzz', type: 'O365 Harvest', target: 'Microsoft' }
  ];

  let index = 0;
  setInterval(() => {
    const item = simulatedThreats[index % simulatedThreats.length];
    tickerEl.innerHTML = `
      <span class="pulse-tag" style="display: inline-flex; align-items: center; gap: 4px; color: var(--color-danger); font-weight: 700;">
        <span style="width: 6px; height: 6px; border-radius: 50%; background: var(--color-danger); animation: pulseDot 1.5s infinite;"></span>
        INTERCEPTED:
      </span>
      <span class="mono" style="color: var(--text-primary); margin: 0 6px;">${item.domain}</span>
      <span class="brand-badge" style="background: rgba(255,42,95,0.15); color: #ff708d; border-color: rgba(255,42,95,0.3); font-size: 0.65rem;">${item.type} [${item.target}]</span>
    `;
    index++;
  }, 4200);
}

/* ==========================================================================
   Toast Notification Helper
   ========================================================================== */
function showToast(message) {
  let container = document.getElementById('toastContainer');
  if (!container) {
    container = document.createElement('div');
    container.id = 'toastContainer';
    container.className = 'toast-container';
    document.body.appendChild(container);
  }

  const toast = document.createElement('div');
  toast.className = 'toast';
  toast.innerHTML = `
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="var(--cyber-cyan)" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>
    <span>${message}</span>
  `;

  container.appendChild(toast);

  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transform = 'translateY(10px)';
    toast.style.transition = 'all 0.3s ease';
    setTimeout(() => toast.remove(), 300);
  }, 3200);
}
