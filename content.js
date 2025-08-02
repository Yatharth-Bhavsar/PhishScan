// Prevent multiple executions of this script
if (window.phishScanLoaded) {
  console.log('PhishScan already loaded, skipping...');
} else {
  window.phishScanLoaded = true;

  // Configuration
  const SCAN_BATCH_SIZE = 5; // Smaller batch size for API calls
  const SCAN_DELAY = 500; // ms between batches
  const DEBOUNCE_DELAY = 1000; // ms for DOM change debouncing
  const API_TIMEOUT = 10000; // 10 second timeout for API calls

  // Cache for processed URLs to avoid re-scanning
  const processedUrls = new Set();
  let scanInProgress = false;
  let observer = null;
  let rateLimitReached = false;

  // Test phishing URLs for demonstration (including some real ones from the feed)
  const TEST_PHISHING_URLS = [
    'example-phishing-site.com',
    'fake-login-page.com',
    'malicious-download.net',
    'fake-phishing-form.com',
    'phishing-test.com',
    'malicious-site.org',
    'fake-bank-login.com',
    'steal-password.net',
    'fake-paypal.com',
    'malware-download.com',
    'auspostac.world',
    'auspostac.world/index.html',
    'fake-auspost.com',
    'phishing-auspost.net',
    'malicious-auspost.org',
    // Real URLs from the OpenPhish feed for testing
    'meta-maskloig.godaddysites.com',
    'litebluelogin-gov.com',
    'netflix-web.vercel.app',
    'connect-ledger-login.typedream.app',
    'walletconnect-website.vercel.app',
    'mettusmask_lodin.godaddysites.com',
    'schwabprotection.com',
    'coinbaselogindesk.blogspot.com.ee',
    'kreken_x_logins.godaddysites.com',
    'sgbybabit.cc',
    'upohold-logiinus.godaddysites.com',
    'trezoriosuite.m-pages.com',
    'gnnnin_1o-giin.godaddysites.com',
    'publictrezzorstart.m-pages.com',
    'steamcomunnitty.cc',
    'bradescard.express-k.com',
    'help-extension-coinbase-chrome.typedream.app',
    'ebays.663shoppingsvip.xyz',
    'secure-id-controll.com',
    'gemminnees_usaloogaan.godaddysites.com',
    'private-user-support-center.io.vn',
    'amazon-clone-amber-mu.vercel.app',
    'netflix-web.vercel.app',
    'meta_-mask_-logi.godaddysites.com',
    'trezor.en-safewallets.com'
  ];

  // Safe domains that should never be flagged
  const SAFE_DOMAINS = [
    'google.com', 'google.co.uk', 'google.ca', 'google.com.au',
    'microsoft.com', 'microsoft.co.uk', 'microsoft.ca',
    'github.com', 'github.io', 'githubusercontent.com',
    'apple.com', 'icloud.com', 'me.com',
    'amazon.com', 'amazon.co.uk', 'amazon.ca', 'amazon.com.au',
    'facebook.com', 'instagram.com', 'twitter.com', 'x.com',
    'linkedin.com', 'youtube.com', 'reddit.com',
    'stackoverflow.com', 'wikipedia.org', 'wikimedia.org',
    'mozilla.org', 'firefox.com', 'chrome.com',
    'cloudflare.com', 'fastly.com', 'akamai.com',
    'wordpress.com', 'tumblr.com', 'medium.com',
    'netflix.com', 'spotify.com', 'discord.com',
    'slack.com', 'zoom.us', 'teams.microsoft.com',
    'dropbox.com', 'box.com', 'onedrive.live.com',
    'paypal.com', 'stripe.com', 'square.com',
    'bankofamerica.com', 'wellsfargo.com', 'chase.com',
    'usps.com', 'fedex.com', 'ups.com',
    'weather.com', 'accuweather.com', 'weather.gov',
    'irs.gov', 'ssa.gov', 'usps.gov',
    'whitehouse.gov', 'congress.gov', 'supremecourt.gov'
  ];

  function highlightElement(el, reason = '', isShortened = false) {
    if (el.hasAttribute('data-phishscan')) return; // Already highlighted
    
    el.style.border = '2px solid red';
    el.style.backgroundColor = '#ffe6e6';
    el.setAttribute('data-phishscan', 'true');
    
    // Enhanced tooltip with detection details
    let tooltipText = `⚠️ MALICIOUS URL CONFIRMED!

🚨 DETECTION: ${reason}`;

    if (isShortened) {
      tooltipText += `

🔗 SHORTENED: This was a shortened URL that resolved to a malicious destination!`;
    }

    tooltipText += `

⚠️ WARNING: This URL has been flagged as malicious. Do not click this link!`;
    
    el.title = tooltipText;
    
    // Add visual indicator
    const warning = document.createElement('span');
    warning.textContent = isShortened ? '🔗⚠️' : '⚠️';
    warning.style.color = 'red';
    warning.style.marginLeft = '5px';
    warning.style.fontWeight = 'bold';
    el.appendChild(warning);
  }

  // Enhanced URL normalization - remove tracking params and ensure proper scheme
  function normalizeUrl(url) {
    if (!url) return '';
    
    try {
      // Create URL object to properly parse
      let urlObj;
      try {
        urlObj = new URL(url);
      } catch (e) {
        // If URL is relative, make it absolute
        urlObj = new URL(url, window.location.href);
      }
      
      // Remove tracking parameters
      const trackingParams = [
        'utm_source', 'utm_medium', 'utm_campaign', 'utm_term', 'utm_content',
        'fbclid', 'gclid', 'msclkid', 'ref', 'source', 'campaign', 'medium',
        'term', 'content', 'clickid', 'affiliate', 'partner', 'referrer'
      ];
      
      trackingParams.forEach(param => {
        urlObj.searchParams.delete(param);
      });
      
      // Ensure HTTPS scheme
      if (urlObj.protocol === 'http:') {
        urlObj.protocol = 'https:';
      }
      
      // Remove fragments
      urlObj.hash = '';
      
      // Normalize hostname (lowercase, remove www)
      urlObj.hostname = urlObj.hostname.toLowerCase().replace(/^www\./, '');
      
      return urlObj.toString();
    } catch (e) {
      console.error('Error normalizing URL:', url, e);
      return url;
    }
  }

  // Check if domain is in safe list
  function isSafeDomain(url) {
    try {
      const urlObj = new URL(url);
      const hostname = urlObj.hostname.toLowerCase().replace(/^www\./, '');
      
      // Check exact match
      if (SAFE_DOMAINS.includes(hostname)) {
        return true;
      }
      
      // Check subdomain matches
      for (const safeDomain of SAFE_DOMAINS) {
        if (hostname.endsWith('.' + safeDomain)) {
          return true;
        }
      }
      
      return false;
    } catch (e) {
      return false;
    }
  }

  // Check if URL is shortened
  async function isShortenedURL(url) {
    try {
      const response = await chrome.runtime.sendMessage({ 
        type: 'IS_SHORTENED_URL', 
        url: url 
      });
      return response?.isShortened || false;
    } catch (e) {
      console.error('Error checking if URL is shortened:', e);
      return false;
    }
  }

  // Resolve shortened URL
  async function resolveShortenedURL(url) {
    try {
      const response = await chrome.runtime.sendMessage({ 
        type: 'RESOLVE_SHORTENED_URL', 
        url: url 
      });
      return response?.resolvedUrl || url;
    } catch (e) {
      console.error('Error resolving shortened URL:', e);
      return url;
    }
  }

  // Google Safe Browsing API check
  async function checkSafeBrowsing(url) {
    try {
      // Get API key from background script
      const apiKeyResponse = await chrome.runtime.sendMessage({ type: 'GET_SAFE_BROWSING_KEY' });
      const apiKey = apiKeyResponse?.key;
      
      if (!apiKey || apiKey.trim() === '') {
        console.log('No API key configured, skipping Safe Browsing check');
        return { malicious: false, reason: 'API key not configured' };
      }
      
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), API_TIMEOUT);
      
      const response = await fetch(`https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${apiKey}`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          client: {
            clientId: 'phishscan-extension',
            clientVersion: '1.0'
          },
          threatInfo: {
            threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
            platformTypes: ['ANY_PLATFORM'],
            threatEntryTypes: ['URL'],
            threatEntries: [{ url: url }]
          }
        }),
        signal: controller.signal
      });
      
      clearTimeout(timeoutId);
      
      if (response.ok) {
        const data = await response.json();
        if (data.matches && data.matches.length > 0) {
          const threat = data.matches[0];
          return {
            malicious: true,
            reason: `Google Safe Browsing: ${threat.threatType}`,
            threatType: threat.threatType,
            platformType: threat.platformType
          };
        }
      } else if (response.status === 429) {
        // Rate limit exceeded
        rateLimitReached = true;
        return { malicious: false, reason: 'API rate limit exceeded', rateLimited: true };
      }
    } catch (e) {
      console.error('Safe Browsing API error:', e);
      if (e.name === 'AbortError') {
        return { malicious: false, reason: 'API request timeout' };
      }
    }
    
    return { malicious: false, reason: 'No threats detected' };
  }

  // VirusTotal API check
  async function checkVirusTotal(url) {
    try {
      const response = await chrome.runtime.sendMessage({ 
        type: 'CHECK_VIRUSTOTAL', 
        url: url 
      });
      return response;
    } catch (e) {
      console.error('VirusTotal API error:', e);
      return { malicious: false, reason: 'VirusTotal: Network error' };
    }
  }

  // Improved fallback detection using OpenPhish database with better matching
  function checkOpenPhishDatabase(url, phishingSet) {
    if (!phishingSet || phishingSet.size === 0) {
      console.log('OpenPhish database is empty, using test URLs');
      // Fallback to test URLs if database is empty
      const testSet = new Set(TEST_PHISHING_URLS);
      return checkOpenPhishDatabaseInternal(url, testSet);
    }
    
    return checkOpenPhishDatabaseInternal(url, phishingSet);
  }

  function checkOpenPhishDatabaseInternal(url, phishingSet) {
    // First check if it's a safe domain
    if (isSafeDomain(url)) {
      console.log('URL is in safe domain list:', url);
      return { malicious: false, reason: 'Safe domain (whitelisted)' };
    }
    
    const normalizedUrl = normalizeUrl(url);
    const urlObj = new URL(normalizedUrl);
    const hostname = urlObj.hostname.toLowerCase().replace(/^www\./, '');
    const domain = hostname.split('.').slice(-2).join('.'); // Get main domain (e.g., google.com from sub.google.com)
    
    console.log('Checking URL against phishing database:', {
      original: url,
      normalized: normalizedUrl,
      hostname: hostname,
      domain: domain,
      databaseSize: phishingSet.size
    });
    
    // Check exact match first (most precise)
    if (phishingSet.has(normalizedUrl)) {
      console.log('Exact match found in phishing database');
      return { malicious: true, reason: 'Exact match in phishing database' };
    }
    
    // Check hostname match (more precise than domain)
    if (phishingSet.has(hostname)) {
      console.log('Hostname match found in phishing database');
      return { malicious: true, reason: 'Hostname match in phishing database' };
    }
    
    // Check domain match (less precise, but still good)
    if (phishingSet.has(domain)) {
      console.log('Domain match found in phishing database');
      return { malicious: true, reason: 'Domain match in phishing database' };
    }
    
    // Check for broader matches (more flexible)
    for (const phishingUrl of phishingSet) {
      // Check if the phishing URL contains our hostname or domain
      if (phishingUrl.includes(hostname) || phishingUrl.includes(domain)) {
        console.log('Broad match found in phishing database:', phishingUrl);
        return { malicious: true, reason: 'Broad match in phishing database' };
      }
      
      // Check if our URL contains the phishing URL
      if (hostname.includes(phishingUrl) || domain.includes(phishingUrl)) {
        console.log('Reverse match found in phishing database:', phishingUrl);
        return { malicious: true, reason: 'Reverse match in phishing database' };
      }
    }
    
    console.log('No match found in phishing database');
    return { malicious: false, reason: 'No match in phishing database' };
  }

  // Main URL checking function with VirusTotal integration and shortened URL resolution
  async function checkUrlWithAPI(url) {
    if (!url) return { malicious: false, reason: 'No URL provided' };
    
    const normalizedUrl = normalizeUrl(url);
    console.log('Checking URL:', url, 'Normalized:', normalizedUrl);
    
    // Check if already processed
    if (processedUrls.has(normalizedUrl)) {
      console.log('URL already processed:', normalizedUrl);
      return null;
    }
    
    processedUrls.add(normalizedUrl);
    
    // Check if URL is shortened
    const isShortened = await isShortenedURL(normalizedUrl);
    let finalUrl = normalizedUrl;
    let resolvedUrl = null;
    
    if (isShortened) {
      console.log('Detected shortened URL, resolving...');
      resolvedUrl = await resolveShortenedURL(normalizedUrl);
      finalUrl = resolvedUrl;
      
      if (resolvedUrl !== normalizedUrl) {
        console.log('Resolved shortened URL:', normalizedUrl, '→', resolvedUrl);
        
        // Check if resolved URL is already processed
        if (processedUrls.has(resolvedUrl)) {
          console.log('Resolved URL already processed:', resolvedUrl);
          return null;
        }
        processedUrls.add(resolvedUrl);
      }
    }
    
    // Check if APIs are configured
    const apiKeyResponse = await chrome.runtime.sendMessage({ type: 'GET_SAFE_BROWSING_KEY' });
    const virusTotalKeyResponse = await chrome.runtime.sendMessage({ type: 'GET_VIRUSTOTAL_KEY' });
    
    const safeBrowsingKeyConfigured = apiKeyResponse?.key && apiKeyResponse.key.trim() !== '';
    const virusTotalKeyConfigured = virusTotalKeyResponse?.key && virusTotalKeyResponse.key.trim() !== '';
    
    console.log('API keys configured:', { safeBrowsing: safeBrowsingKeyConfigured, virusTotal: virusTotalKeyConfigured });
    
    // First, try Google Safe Browsing API if configured
    if (safeBrowsingKeyConfigured) {
      const safeBrowsingResult = await checkSafeBrowsing(finalUrl);
      
      if (safeBrowsingResult.malicious) {
        console.log('Found malicious URL via Safe Browsing API:', finalUrl, 'Reason:', safeBrowsingResult.reason);
        return {
          ...safeBrowsingResult,
          originalUrl: url,
          resolvedUrl: resolvedUrl,
          isShortened: isShortened
        };
      }
    }
    
    // If Safe Browsing didn't find anything or isn't configured, try VirusTotal
    if (virusTotalKeyConfigured) {
      const virusTotalResult = await checkVirusTotal(finalUrl);
      
      if (virusTotalResult.malicious) {
        console.log('Found malicious URL via VirusTotal:', finalUrl, 'Reason:', virusTotalResult.reason);
        return {
          ...virusTotalResult,
          originalUrl: url,
          resolvedUrl: resolvedUrl,
          isShortened: isShortened
        };
      }
    }
    
    // If APIs are not configured or didn't find anything, fall back to OpenPhish database
    if (!safeBrowsingKeyConfigured && !virusTotalKeyConfigured) {
      console.log('No API keys configured, using OpenPhish database fallback');
      const phishingList = await getPhishFeed();
      const phishingSet = new Set(phishingList);
      const openPhishResult = checkOpenPhishDatabase(finalUrl, phishingSet);
      
      if (openPhishResult.malicious) {
        console.log('Found malicious URL via OpenPhish database:', finalUrl, 'Reason:', openPhishResult.reason);
        return {
          ...openPhishResult,
          originalUrl: url,
          resolvedUrl: resolvedUrl,
          isShortened: isShortened
        };
      }
    }
    
    console.log('URL check result for:', finalUrl, 'Safe');
    return { 
      malicious: false, 
      reason: 'No threats detected by any service',
      originalUrl: url,
      resolvedUrl: resolvedUrl,
      isShortened: isShortened
    };
  }

  async function getPhishFeed() {
    return new Promise((resolve) => {
      console.log('Requesting phishing feed from background script...');
      chrome.runtime.sendMessage({ type: 'GET_PHISH_FEED' }, (response) => {
        console.log('Phish feed response:', response);
        const openPhishUrls = response?.phishingList || [];
        console.log(`Received ${openPhishUrls.length} URLs from OpenPhish feed`);
        
        if (openPhishUrls.length === 0) {
          console.log('OpenPhish feed is empty, will use test URLs as fallback');
        } else {
          console.log('Sample URLs from feed:', openPhishUrls.slice(0, 5));
        }
        
        resolve(openPhishUrls);
      });
    });
  }

  async function getToggleState() {
    return new Promise((resolve) => {
      chrome.runtime.sendMessage({ type: 'GET_TOGGLE_STATE' }, (response) => {
        resolve(response?.enabled !== false);
      });
    });
  }

  // Enhanced batch processing for API calls
  async function processBatch(elements, processFn) {
    const results = [];
    for (let i = 0; i < elements.length; i += SCAN_BATCH_SIZE) {
      const batch = elements.slice(i, i + SCAN_BATCH_SIZE);
      
      const batchPromises = batch.map(async (element) => {
        const result = await processFn(element);
        if (result) results.push(result);
      });
      
      await Promise.all(batchPromises);
      
      // Yield control to prevent blocking and respect API rate limits
      if (i + SCAN_BATCH_SIZE < elements.length) {
        await new Promise(resolve => setTimeout(resolve, SCAN_DELAY));
      }
    }
    return results;
  }

  // Debounced function to prevent excessive scanning
  function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
      const later = () => {
        clearTimeout(timeout);
        func(...args);
      };
      clearTimeout(timeout);
      timeout = setTimeout(later, wait);
    };
  }

  // Main scanning function with enhanced detection
  async function scanPage() {
    if (scanInProgress) return;
    
    scanInProgress = true;
    
    try {
      console.log('Starting enhanced page scan with VirusTotal integration...');
      
      // Set scan-in-progress flag
      await chrome.storage.local.set({ phishscan_scanning: true });
      await chrome.storage.local.remove('phishscan_found');

      const enabled = await getToggleState();
      if (!enabled) {
        await chrome.storage.local.set({ phishscan_scanning: false });
        scanInProgress = false;
        return;
      }
      
      // Clear processed URLs for fresh scan
      processedUrls.clear();
      
      const found = [];
      
      // Get all elements to scan
      const aTags = Array.from(document.querySelectorAll('a[href]'));
      const formTags = Array.from(document.querySelectorAll('form[action]'));
      
      console.log(`Scanning ${aTags.length} links, ${formTags.length} forms with enhanced detection`);
      
      // Process links in batches
      const linkResults = await processBatch(aTags, async (a) => {
        const url = a.href;
        if (url) {
          console.log('Processing link URL:', url);
          const result = await checkUrlWithAPI(url);
          console.log('Link check result:', url, result);
          if (result && result.malicious) {
            console.log('Found malicious link:', url, 'Reason:', result.reason);
            highlightElement(a, result.reason, result.isShortened);
            return { 
              url: result.originalUrl || url, 
              reason: result.reason, 
              threatType: result.threatType,
              isShortened: result.isShortened,
              resolvedUrl: result.resolvedUrl
            };
          }
        }
        return null;
      });
      
      // Process forms in batches
      const formResults = await processBatch(formTags, async (f) => {
        const url = f.action;
        if (url) {
          console.log('Processing form action URL:', url);
          const result = await checkUrlWithAPI(url);
          console.log('Form check result:', url, result);
          if (result && result.malicious) {
            console.log('Found malicious form:', url, 'Reason:', result.reason);
            highlightElement(f, result.reason, result.isShortened);
            return { 
              url: result.originalUrl || url, 
              reason: result.reason, 
              threatType: result.threatType,
              isShortened: result.isShortened,
              resolvedUrl: result.resolvedUrl
            };
          }
        }
        return null;
      });
      
      // Combine results
      const allResults = [...linkResults, ...formResults];
      
      // Store results
      await chrome.storage.local.set({ 
        phishscan_found: allResults, 
        phishscan_scanning: false,
        phishscan_rate_limited: rateLimitReached
      });
      
      console.log(`Enhanced scan complete. Found ${allResults.length} threats:`, allResults);
      
      if (rateLimitReached) {
        console.warn('API rate limit reached during scan');
      }
      
    } catch (error) {
      console.error('Error during enhanced scan:', error);
      await chrome.storage.local.set({ phishscan_scanning: false });
    } finally {
      scanInProgress = false;
    }
  }

  // Debounced scan function for DOM changes
  const debouncedScan = debounce(scanPage, DEBOUNCE_DELAY);

  // Initialize scanning
  function initializeScanning() {
    // Clear previous highlights
    document.querySelectorAll('[data-phishscan]').forEach(el => {
      el.removeAttribute('data-phishscan');
      el.style.border = '';
      el.style.backgroundColor = '';
      const warning = el.querySelector('span');
      if (warning) warning.remove();
    });
    
    // Clear processed URLs cache
    processedUrls.clear();
    
    // Reset rate limit flag
    rateLimitReached = false;
    
    // Start initial scan
    scanPage();
    
    // Set up DOM observer for dynamic content
    if (observer) {
      observer.disconnect();
    }
    
    observer = new MutationObserver((mutations) => {
      let shouldScan = false;
      
      for (const mutation of mutations) {
        if (mutation.type === 'childList' && mutation.addedNodes.length > 0) {
          for (const node of mutation.addedNodes) {
            if (node.nodeType === Node.ELEMENT_NODE) {
              if (node.querySelector && (node.querySelector('a[href]') || node.querySelector('form[action]'))) {
                shouldScan = true;
                break;
              }
            }
          }
        }
      }
      
      if (shouldScan && !rateLimitReached) {
        debouncedScan();
      }
    });
    
    observer.observe(document.body, { 
      childList: true, 
      subtree: true,
      attributes: false,
      characterData: false
    });
  }

  // Run on page load
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initializeScanning);
  } else {
    initializeScanning();
  }

  // Listen for messages from popup
  chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.type === 'FORCE_SCAN') {
      initializeScanning();
      sendResponse({ success: true });
    }
  });

  // Cleanup on page unload
  window.addEventListener('beforeunload', () => {
    if (observer) {
      observer.disconnect();
    }
    processedUrls.clear();
  });
} 