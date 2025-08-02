// Background script for PhishScan extension
// Manages phishing database and API configurations

// API Configuration
const API_CONFIG = {
  safeBrowsing: {
    key: '', // User needs to add their Google Safe Browsing API key here
    // Get your API key from: https://console.cloud.google.com/apis/credentials
  },
  virusTotal: {
    key: '', // User needs to add their VirusTotal API key here
    // Get your API key from: https://www.virustotal.com/gui/join-us
    url: 'https://www.virustotal.com/vtapi/v2/url/report',
    quota: 500 // Free tier: 500 requests/day
  }
};

// OpenPhish feed URL
const FEED_URL = 'https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt';

// Test phishing URLs for fallback
const TEST_PHISHING_URLS = [
  'auspostac.world',
  'auspostac.world/index.html',
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
  'meta_-mask_-logi.godaddysites.com',
  'trezor.en-safewallets.com'
];

// Cache for phishing URLs
let phishingUrls = new Set();
let lastFetchTime = 0;
const CACHE_DURATION = 30 * 60 * 1000; // 30 minutes

// URL shortener services to resolve
const URL_SHORTENERS = [
  'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'is.gd', 'v.gd', 'ow.ly', 'buff.ly',
  'adf.ly', 'sh.st', 'adfly.com', 'shorte.st', 'shorten.me', 'shorturl.com',
  'tiny.cc', 'short.to', 'snipurl.com', 'shorturl.com', 'tr.im', 'snipr.com',
  'shortlinks.co', 'shorten.me', 'shorturl.com', 'tiny.cc', 'short.to',
  'snipurl.com', 'shorturl.com', 'tr.im', 'snipr.com', 'shortlinks.co'
];

// Fetch phishing URLs from OpenPhish feed
async function fetchPhishingUrls() {
  try {
    console.log('Fetching phishing URLs from OpenPhish feed...');
    const response = await fetch(FEED_URL);
    
    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }
    
    const text = await response.text();
    console.log('Raw feed response length:', text.length);
    console.log('First 500 characters of feed:', text.substring(0, 500));
    
    const urls = text.split('\n').filter(url => url.trim() !== '');
    console.log('Filtered URLs count:', urls.length);
    console.log('Sample URLs from feed:', urls.slice(0, 10));
    
    // Clear and update the cache
    phishingUrls.clear();
    urls.forEach(url => phishingUrls.add(url.trim()));
    
    console.log(`Fetched ${phishingUrls.size} phishing URLs from OpenPhish feed`);
    lastFetchTime = Date.now();
    
    return Array.from(phishingUrls);
  } catch (error) {
    console.error('Error fetching phishing URLs:', error);
    console.log('Using test URLs as fallback due to fetch error');
    // Return test URLs as fallback
    return TEST_PHISHING_URLS;
  }
}

// Initialize phishing cache
async function initializePhishingCache() {
  if (Date.now() - lastFetchTime > CACHE_DURATION) {
    const urls = await fetchPhishingUrls();
    if (urls.length === 0) {
      console.log('No URLs fetched, using test URLs as fallback');
      phishingUrls.clear();
      TEST_PHISHING_URLS.forEach(url => phishingUrls.add(url));
      console.log(`Loaded ${phishingUrls.size} test URLs as fallback`);
    }
  }
}

// Check if a URL is a shortened URL
function isShortenedURL(url) {
  try {
    const urlObj = new URL(url);
    const hostname = urlObj.hostname.toLowerCase().replace(/^www\./, '');
    return URL_SHORTENERS.some(shortener => hostname === shortener);
  } catch (e) {
    return false;
  }
}

// Resolve shortened URL using HEAD request
async function resolveShortenedURL(url) {
  try {
    console.log('Resolving shortened URL:', url);
    
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 5000); // 5 second timeout
    
    const response = await fetch(url, {
      method: 'HEAD',
      redirect: 'follow',
      signal: controller.signal
    });
    
    clearTimeout(timeoutId);
    
    if (response.ok && response.url !== url) {
      console.log('Resolved shortened URL:', url, '→', response.url);
      return response.url;
    }
    
    return url; // Return original if no redirect
  } catch (error) {
    console.error('Error resolving shortened URL:', url, error);
    return url; // Return original on error
  }
}

// Check URL with VirusTotal API
async function checkVirusTotal(url) {
  if (!API_CONFIG.virusTotal.key || API_CONFIG.virusTotal.key.trim() === '') {
    return { malicious: false, reason: 'VirusTotal API key not configured' };
  }
  
  try {
    console.log('Checking URL with VirusTotal:', url);
    
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 10000); // 10 second timeout
    
    const formData = new FormData();
    formData.append('apikey', API_CONFIG.virusTotal.key);
    formData.append('url', url);
    
    const response = await fetch(API_CONFIG.virusTotal.url, {
      method: 'POST',
      body: formData,
      signal: controller.signal
    });
    
    clearTimeout(timeoutId);
    
    if (response.ok) {
      const data = await response.json();
      
      if (data.response_code === 1) {
        const positives = data.positives || 0;
        const total = data.total || 0;
        const scanDate = data.scan_date;
        
        if (positives > 0) {
          const detectionRate = (positives / total * 100).toFixed(1);
          return {
            malicious: true,
            reason: `VirusTotal: ${positives}/${total} engines detected (${detectionRate}%)`,
            positives: positives,
            total: total,
            scanDate: scanDate,
            permalink: data.permalink
          };
        } else {
          return {
            malicious: false,
            reason: `VirusTotal: Clean (0/${total} engines detected)`,
            positives: 0,
            total: total,
            scanDate: scanDate,
            permalink: data.permalink
          };
        }
      } else {
        return { malicious: false, reason: 'VirusTotal: URL not found in database' };
      }
    } else if (response.status === 429) {
      return { malicious: false, reason: 'VirusTotal: API rate limit exceeded', rateLimited: true };
    } else {
      return { malicious: false, reason: `VirusTotal: API error (${response.status})` };
    }
  } catch (error) {
    console.error('VirusTotal API error:', error);
    if (error.name === 'AbortError') {
      return { malicious: false, reason: 'VirusTotal: Request timeout' };
    }
    return { malicious: false, reason: 'VirusTotal: Network error' };
  }
}

// Message listener for communication with content scripts and popup
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  console.log('Background received message:', request.type);
  
  switch (request.type) {
    case 'GET_PHISH_FEED':
      // Return cached phishing URLs
      sendResponse({ phishingList: Array.from(phishingUrls) });
      break;
      
    case 'GET_TOGGLE_STATE':
      // Get toggle state from storage
      chrome.storage.sync.get(['phishscan_enabled'], (result) => {
        sendResponse({ enabled: result.phishscan_enabled !== false });
      });
      return true; // Keep message channel open for async response
      
    case 'SET_TOGGLE_STATE':
      // Set toggle state in storage
      chrome.storage.sync.set({ phishscan_enabled: request.enabled }, () => {
        sendResponse({ success: true });
      });
      return true; // Keep message channel open for async response
      
    case 'GET_SAFE_BROWSING_KEY':
      // Return Google Safe Browsing API key
      sendResponse({ key: API_CONFIG.safeBrowsing.key });
      break;
      
    case 'GET_VIRUSTOTAL_KEY':
      // Return VirusTotal API key
      sendResponse({ key: API_CONFIG.virusTotal.key });
      break;
      
    case 'CHECK_VIRUSTOTAL':
      // Check URL with VirusTotal API
      checkVirusTotal(request.url).then(result => {
        sendResponse(result);
      });
      return true; // Keep message channel open for async response
      
    case 'RESOLVE_SHORTENED_URL':
      // Resolve shortened URL
      resolveShortenedURL(request.url).then(resolvedUrl => {
        sendResponse({ resolvedUrl: resolvedUrl });
      });
      return true; // Keep message channel open for async response
      
    case 'IS_SHORTENED_URL':
      // Check if URL is shortened
      const isShortened = isShortenedURL(request.url);
      sendResponse({ isShortened: isShortened });
      break;
      
    default:
      sendResponse({ error: 'Unknown message type' });
  }
});

// Initialize on startup
initializePhishingCache();

// Set up periodic refresh of phishing database
setInterval(initializePhishingCache, CACHE_DURATION);

// Handle extension installation
chrome.runtime.onInstalled.addListener(() => {
  console.log('PhishScan extension installed');
  initializePhishingCache();
}); 