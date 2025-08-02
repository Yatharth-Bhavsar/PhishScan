// Popup script for PhishScan extension

let enabled = true;
let scanComplete = false;
let scanTimeout = null;
let statusCheckInterval = null;

// DOM elements
const toggle = document.getElementById('toggle');
const toggleLabel = document.getElementById('toggle-label');
const statusDiv = document.getElementById('status');
const list = document.getElementById('malicious-list');
const refreshBtn = document.getElementById('refresh-btn');

// Initialize popup
document.addEventListener('DOMContentLoaded', () => {
  loadToggleState();
  updateStatusAndList();
  
  // Set up event listeners
  toggle.addEventListener('change', handleToggleChange);
  refreshBtn.addEventListener('click', handleRefresh);
});

// Load toggle state from storage
function loadToggleState() {
  chrome.storage.sync.get(['phishscan_enabled'], (result) => {
    enabled = result.phishscan_enabled !== false;
    toggle.checked = enabled;
    updateToggleLabel();
  });
}

// Update toggle label
function updateToggleLabel() {
  toggleLabel.textContent = enabled ? 'Detection ON' : 'Detection OFF';
}

// Handle toggle change
function handleToggleChange() {
  enabled = toggle.checked;
  chrome.storage.sync.set({ phishscan_enabled: enabled });
  updateToggleLabel();
  
  if (enabled) {
    // Force rescan when turning on
    forceRescanOnCurrentTab();
  } else {
    // Clear results when turning off
    chrome.storage.local.remove(['phishscan_found', 'phishscan_scanning']);
    updateStatusAndList();
  }
}

// Force rescan on current tab
function forceRescanOnCurrentTab() {
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    if (tabs[0]) {
      chrome.scripting.executeScript({
        target: { tabId: tabs[0].id },
        function: () => {
          // Clear previous results
          chrome.storage.local.remove(['phishscan_found', 'phishscan_scanning']);
          
          // Send message to content script to force rescan
          chrome.runtime.sendMessage({ type: 'FORCE_SCAN' });
        }
      });
    }
  });
}

// Handle refresh button
function handleRefresh() {
  if (enabled) {
    forceRescanOnCurrentTab();
  }
}

// Set body class for styling
function setBodyClass(status = '') {
  document.body.className = status;
}

// Copy URL to clipboard
function copyToClipboard(url) {
  navigator.clipboard.writeText(url).then(() => {
    // Show brief feedback
    const originalText = refreshBtn.textContent;
    refreshBtn.textContent = 'Copied!';
    setTimeout(() => {
      refreshBtn.textContent = originalText;
    }, 1000);
  });
}

// Enhanced status and list update with detection method awareness
function updateStatusAndList() {
  if (!enabled) {
    setBodyClass();
    statusDiv.textContent = 'Detection is OFF';
    statusDiv.className = 'status';
    list.innerHTML = '';
    return;
  }

  setBodyClass('scanning');
  statusDiv.textContent = '🔍 Scanning for malicious URLs...';
  statusDiv.className = 'status scanning';
  list.innerHTML = '';

  // Set a timeout for scan completion
  if (scanTimeout) {
    clearTimeout(scanTimeout);
  }
  scanTimeout = setTimeout(() => {
    setBodyClass('error');
    statusDiv.textContent = '⚠️ Scan timeout - please refresh';
    statusDiv.className = 'status error';
  }, 60000); // 60 second timeout for API calls

  // Check scan status with more frequent updates
  function checkScanStatus() {
    chrome.storage.local.get(['phishscan_scanning', 'phishscan_found', 'phishscan_rate_limited'], (result) => {
      if (scanTimeout) {
        clearTimeout(scanTimeout);
        scanTimeout = null;
      }

      const scanning = result.phishscan_scanning === true;
      const found = result.phishscan_found || [];
      const rateLimited = result.phishscan_rate_limited === true;

      if (scanning || !result.hasOwnProperty('phishscan_found')) {
        // Still scanning, check again in 500ms for faster updates
        setTimeout(checkScanStatus, 500);
        return;
      }

      scanComplete = true;
      list.innerHTML = '';

      if (rateLimited) {
        setBodyClass('error');
        statusDiv.textContent = '⚠️ API rate limit reached - some URLs may not be checked';
        statusDiv.className = 'status error';
      } else if (found.length === 0) {
        setBodyClass();
        statusDiv.textContent = '✅ Page appears safe';
        statusDiv.className = 'status';
      } else {
        setBodyClass('threat');
        statusDiv.textContent = `⚠️ ${found.length} malicious URL${found.length > 1 ? 's' : ''} detected!`;
        statusDiv.className = 'status threat';
        
        found.forEach((threat, index) => {
          const li = document.createElement('li');
          
          // Enhanced display with detection details
          let threatDisplay = `
            <span class="threat-number">${index + 1}.</span>
            <span class="threat-url">${threat.url}</span>
            <div class="threat-reason">${threat.reason}</div>`;
          
          // Add shortened URL info if applicable
          if (threat.isShortened && threat.resolvedUrl && threat.resolvedUrl !== threat.url) {
            threatDisplay += `
              <div class="threat-shortened">
                🔗 Resolved to: ${threat.resolvedUrl}
              </div>`;
          }
          
          // Add VirusTotal details if available
          if (threat.positives !== undefined && threat.total !== undefined) {
            threatDisplay += `
              <div class="threat-virustotal">
                🛡️ VirusTotal: ${threat.positives}/${threat.total} engines detected
              </div>`;
          }
          
          threatDisplay += `
            <button class="copy-btn" title="Copy URL" onclick="copyToClipboard('${threat.url}')">📋</button>`;
          
          li.innerHTML = threatDisplay;
          list.appendChild(li);
        });
      }
    });
  }

  // Start checking immediately
  checkScanStatus();
}

// Cleanup on popup close
window.addEventListener('beforeunload', () => {
  if (scanTimeout) {
    clearTimeout(scanTimeout);
  }
  if (statusCheckInterval) {
    clearInterval(statusCheckInterval);
  }
}); 