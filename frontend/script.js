/**
 * NetScan // Cyber Security Port Scanner - Frontend Logic
 * Vanilla JavaScript (No external frameworks/libraries)
 */

document.addEventListener('DOMContentLoaded', () => {
  // DOM Elements
  const scanForm = document.getElementById('scanForm');
  const targetInput = document.getElementById('targetInput');
  const startPortInput = document.getElementById('startPortInput');
  const endPortInput = document.getElementById('endPortInput');
  const scanBtn = document.getElementById('scanBtn');
  const btnText = document.getElementById('btnText');
  const btnSpinner = document.getElementById('btnSpinner');
  const btnIcon = document.getElementById('btnIcon');

  // Error Alert Elements
  const errorAlert = document.getElementById('errorAlert');
  const errorTitle = document.getElementById('errorTitle');
  const errorMessage = document.getElementById('errorMessage');
  const closeAlertBtn = document.getElementById('closeAlertBtn');

  // Metrics Elements
  const statTarget = document.getElementById('statTarget');
  const statIp = document.getElementById('statIp');
  const statRange = document.getElementById('statRange');
  const statTotalScanned = document.getElementById('statTotalScanned');
  const statOpenCount = document.getElementById('statOpenCount');
  const statOpenList = document.getElementById('statOpenList');
  const statStatus = document.getElementById('statStatus');
  const statDuration = document.getElementById('statDuration');

  // Table Elements
  const resultsTableBody = document.getElementById('resultsTableBody');
  const resultCountBadge = document.getElementById('resultCountBadge');
  const tabBtns = document.querySelectorAll('.tab-btn');
  const tableSearchInput = document.getElementById('tableSearchInput');
  const chipBtns = document.querySelectorAll('.chip-btn');
  const presetBtns = document.querySelectorAll('.preset-btn');
  const backendStatus = document.getElementById('backendStatus');

  // State
  let currentResults = [];
  let currentFilter = 'all'; // 'all', 'open', 'closed'
  let searchQuery = '';

  // Determine Backend API URL
  function getApiUrl() {
    if (window.location.protocol.startsWith('http')) {
      return `${window.location.origin}/api/scan`;
    }
    // Fallback if opened directly via file:// protocol
    return 'http://127.0.0.1:8000/api/scan';
  }

  // Check Backend Connection Status
  async function checkBackend() {
    try {
      const origin = window.location.protocol.startsWith('http') 
        ? window.location.origin 
        : 'http://127.0.0.1:8000';
      
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 2000);
      
      const res = await fetch(`${origin}/style.css`, { 
        method: 'HEAD',
        signal: controller.signal 
      });
      clearTimeout(timeoutId);

      if (res.ok) {
        backendStatus.textContent = 'Backend: Online';
        backendStatus.style.color = 'var(--accent-emerald)';
      }
    } catch {
      backendStatus.textContent = 'Backend: Offline / Standby';
      backendStatus.style.color = 'var(--accent-amber)';
    }
  }

  // Initial backend check
  checkBackend();

  // Show Error Alert
  function showError(title, message) {
    errorTitle.textContent = title || 'Scanning Error';
    errorMessage.textContent = message || 'An unknown error occurred.';
    errorAlert.classList.remove('hidden');
    errorAlert.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  }

  // Hide Error Alert
  function hideError() {
    errorAlert.classList.add('hidden');
  }

  if (closeAlertBtn) {
    closeAlertBtn.addEventListener('click', hideError);
  }

  // Quick Target Chip Listeners
  chipBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      const val = btn.getAttribute('data-target');
      if (val) {
        targetInput.value = val;
        hideError();
      }
    });
  });

  // Preset Range Listeners
  presetBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      const start = btn.getAttribute('data-start');
      const end = btn.getAttribute('data-end');
      if (start && end) {
        startPortInput.value = start;
        endPortInput.value = end;
        hideError();
      }
    });
  });

  // Filter Tabs
  tabBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      tabBtns.forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      currentFilter = btn.getAttribute('data-filter') || 'all';
      renderTable();
    });
  });

  // Search Filter
  if (tableSearchInput) {
    tableSearchInput.addEventListener('input', (e) => {
      searchQuery = e.target.value.toLowerCase().trim();
      renderTable();
    });
  }

  // Set Loading UI State
  function setLoading(isLoading) {
    if (isLoading) {
      scanBtn.disabled = true;
      btnSpinner.classList.remove('hidden');
      btnIcon.classList.add('hidden');
      btnText.textContent = 'Scanning Target...';
      statStatus.textContent = 'Scanning...';
      statStatus.style.color = 'var(--accent-cyan)';
      statDuration.textContent = 'In progress...';
    } else {
      scanBtn.disabled = false;
      btnSpinner.classList.add('hidden');
      btnIcon.classList.remove('hidden');
      btnText.textContent = 'Scan Ports';
    }
  }

  // Form Submission & Scan Trigger
  scanForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    hideError();

    const target = targetInput.value.trim();
    const startPort = parseInt(startPortInput.value, 10);
    const endPort = parseInt(endPortInput.value, 10);

    // Client-side Input Validation
    if (!target) {
      showError('Input Error', 'Please enter a target IP address or hostname.');
      return;
    }

    if (isNaN(startPort) || startPort < 1 || startPort > 65535) {
      showError('Invalid Port', 'Starting port must be a valid number between 1 and 65535.');
      return;
    }

    if (isNaN(endPort) || endPort < 1 || endPort > 65535) {
      showError('Invalid Port', 'Ending port must be a valid number between 1 and 65535.');
      return;
    }

    if (startPort > endPort) {
      showError('Port Range Error', `Starting port (${startPort}) cannot be greater than ending port (${endPort}).`);
      return;
    }

    if ((endPort - startPort + 1) > 1000) {
      showError('Range Limit', 'To keep scans responsive, maximum range is limited to 1000 ports at a time.');
      return;
    }

    setLoading(true);

    try {
      const apiUrl = getApiUrl();
      const response = await fetch(apiUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          target: target,
          start_port: startPort,
          end_port: endPort
        })
      });

      const data = await response.json();

      if (!response.ok || !data.success) {
        throw new Error(data.error || `Server responded with status ${response.status}`);
      }

      // Successful Scan
      currentResults = data.results || [];
      
      // Update Summary Cards
      statTarget.textContent = data.target;
      statIp.textContent = `IP: ${data.target_ip}`;
      statRange.textContent = `${data.start_port} – ${data.end_port}`;
      statTotalScanned.textContent = `Total: ${data.total_scanned} ports`;
      statOpenCount.textContent = `${data.open_count} OPEN`;
      
      if (data.open_ports && data.open_ports.length > 0) {
        statOpenList.textContent = `Ports: ${data.open_ports.join(', ')}`;
      } else {
        statOpenList.textContent = 'None identified';
      }

      statStatus.textContent = 'Completed';
      statStatus.style.color = 'var(--accent-emerald)';
      statDuration.textContent = `Duration: ${data.duration_seconds}s`;

      // Render Results Table
      renderTable();

    } catch (err) {
      console.error('Scan Error:', err);
      statStatus.textContent = 'Failed';
      statStatus.style.color = 'var(--accent-red)';
      statDuration.textContent = 'Error occurred';
      
      let msg = err.message;
      if (err.name === 'TypeError' && err.message.includes('fetch')) {
        msg = 'Could not connect to Python backend. Please ensure "python backend/scanner.py" is running on port 8000.';
      }
      showError('Scan Execution Failed', msg);
    } finally {
      setLoading(false);
    }
  });

  // Render Results Table based on filters and search
  function renderTable() {
    if (!currentResults || currentResults.length === 0) {
      resultsTableBody.innerHTML = `
        <tr class="empty-row">
          <td colspan="4">
            <div class="empty-state">
              <div class="empty-icon">📡</div>
              <h4>No Scan Results Yet</h4>
              <p>Specify a target IP/hostname and port range above, then click <strong>Scan Ports</strong>.</p>
            </div>
          </td>
        </tr>
      `;
      resultCountBadge.textContent = '0 ports';
      return;
    }

    // Filter by Tab (all / open / closed)
    let filtered = currentResults.filter(item => {
      if (currentFilter === 'open') return item.status === 'OPEN';
      if (currentFilter === 'closed') return item.status === 'CLOSED';
      return true;
    });

    // Filter by Search text
    if (searchQuery) {
      filtered = filtered.filter(item => {
        const portStr = String(item.port);
        const serviceStr = (item.service || '').toLowerCase();
        const statusStr = (item.status || '').toLowerCase();
        return portStr.includes(searchQuery) || serviceStr.includes(searchQuery) || statusStr.includes(searchQuery);
      });
    }

    resultCountBadge.textContent = `${filtered.length} of ${currentResults.length} ports`;

    if (filtered.length === 0) {
      resultsTableBody.innerHTML = `
        <tr class="empty-row">
          <td colspan="4">
            <div class="empty-state">
              <div class="empty-icon">🔍</div>
              <h4>No Matching Ports</h4>
              <p>No ports match the selected filter criteria or search query.</p>
            </div>
          </td>
        </tr>
      `;
      return;
    }

    // Build Table Rows
    const rowsHtml = filtered.map(item => {
      const isOpen = item.status === 'OPEN';
      const badgeClass = isOpen ? 'open' : 'closed';
      const statusIcon = isOpen ? '●' : '○';

      return `
        <tr>
          <td><span class="port-num-badge">#${item.port}</span></td>
          <td><span class="protocol-tag">${item.protocol || 'TCP'}</span></td>
          <td>${item.service || 'Unknown'}</td>
          <td style="text-align: right;">
            <span class="status-badge ${badgeClass}">
              <span>${statusIcon}</span>
              ${item.status}
            </span>
          </td>
        </tr>
      `;
    }).join('');

    resultsTableBody.innerHTML = rowsHtml;
  }
});
