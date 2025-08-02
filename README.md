# 🛡️ PhishScan - Advanced Phishing URL Detection Chrome Extension

A powerful Chrome extension that detects and highlights phishing or malicious URLs on any webpage using multiple detection methods including real-time API scanning, shortened URL resolution, and comprehensive threat intelligence.

## ✨ Features

### 🔍 **Multi-Layer Detection System**
- **VirusTotal API Integration** - Real-time scanning with 70+ antivirus engines
- **Google Safe Browsing API** - Google's threat intelligence database
- **OpenPhish Database Fallback** - Local database for offline detection
- **Safe Domain Whitelist** - Prevents false positives on trusted sites

### 🔗 **Shortened URL Resolution**
- Automatically detects and resolves shortened URLs (bit.ly, tinyurl, t.co, etc.)
- Checks the final destination URL for malicious content
- Visual indicators for resolved malicious shortened URLs

### 🎯 **Smart Detection Logic**
- **Hierarchical Checking**: Exact URL → Hostname → Domain matching
- **URL Normalization**: Removes tracking parameters, normalizes schemes
- **Conservative Matching**: Reduces false positives while maintaining accuracy
- **Batch Processing**: Efficient API usage with rate limiting

### 🎨 **Enhanced User Interface**
- **Real-time Status Updates**: Live scanning progress and results
- **Detailed Threat Information**: Shows detection method, engine counts, and reasons
- **Visual Indicators**: Red borders, warning icons, and tooltips
- **Responsive Design**: Works on all screen sizes

### 🔧 **Developer-Friendly**
- **Manifest V3 Compatible**: Latest Chrome extension standards
- **Modular Architecture**: Clean separation of concerns
- **Comprehensive Logging**: Detailed console output for debugging
- **Easy Configuration**: Simple API key setup

## 🚀 Installation

### 1. **Download the Extension**
```bash
git clone https://github.com/Yatharth-Bhavsar/PhishScan
cd phishscan-extension
```

### 2. **Configure API Keys (Optional but Recommended)**
Edit `background.js` and add your API keys:

```javascript
const API_CONFIG = {
  safeBrowsing: {
    key: 'YOUR_GOOGLE_SAFE_BROWSING_API_KEY', // Get from: https://console.cloud.google.com/apis/credentials
  },
  virusTotal: {
    key: 'YOUR_VIRUSTOTAL_API_KEY', // Get from: https://www.virustotal.com/gui/join-us
  }
};
```

**Free API Limits:**
- **Google Safe Browsing**: 10,000 requests/day
- **VirusTotal**: 500 requests/day

### 3. **Load in Chrome**
1. Open Chrome and go to `chrome://extensions/`
2. Enable "Developer mode"
3. Click "Load unpacked" and select the extension folder
4. The PhishScan icon should appear in your toolbar

## 📋 Usage

### **Basic Usage**
1. **Enable Detection**: Click the PhishScan icon and ensure the toggle is ON
2. **Browse Normally**: The extension automatically scans all pages
3. **Check Results**: Click the icon to see detected threats
4. **Visual Indicators**: Malicious links have red borders and warning icons

### **Advanced Features**
- **Shortened URL Detection**: Automatically resolves and checks shortened URLs
- **Form Action Scanning**: Detects malicious form submission URLs
- **Dynamic Content**: Scans new content added via JavaScript
- **Real-time Updates**: Live status updates during scanning

## 🧪 Testing

### **Test Page**
Open `test.html` in your browser to test the extension with:
- Known malicious URLs from OpenPhish database
- Shortened URL examples
- Safe whitelisted domains
- Dynamic content generation
- Form action testing

### **Expected Results**
- ✅ **Malicious links**: Red borders with ⚠️ icons
- ✅ **Shortened URLs**: 🔗⚠️ icons if resolved to malicious sites
- ✅ **Safe links**: No red borders
- ✅ **Detailed popup**: Shows detection method and engine counts

## 🏗️ Architecture

### **File Structure**
```
phishscan-extension/
├── manifest.json          # Extension configuration
├── background.js          # Service worker & API management
├── content.js            # Page scanning & URL detection
├── popup.html            # Extension popup UI
├── popup.js              # Popup functionality
├── popup.css             # Popup styling
├── test.html             # Testing page
├── README.md             # Documentation
└── assets/               # Icons and images
    ├── icon16.png
    ├── icon48.png
    └── icon128.png
```

### **Detection Flow**
1. **URL Collection**: Scans all `<a href>` and `<form action>` elements
2. **URL Normalization**: Cleans and standardizes URLs
3. **Safe Domain Check**: Whitelist verification
4. **Shortened URL Resolution**: Expands shortened URLs if detected
5. **Multi-API Scanning**:
   - Google Safe Browsing API (if configured)
   - VirusTotal API (if configured)
   - OpenPhish Database (fallback)
6. **Result Processing**: Highlights malicious elements and updates UI

### **API Integration**
- **Background Script**: Manages API keys and handles requests
- **Content Script**: Performs URL checking and element highlighting
- **Popup**: Displays results and manages user preferences

## 🔧 Configuration

### **API Keys Setup**

#### **Google Safe Browsing API**
1. Go to [Google Cloud Console](https://console.cloud.google.com/apis/credentials)
2. Create a new project or select existing
3. Enable the "Safe Browsing API"
4. Create credentials (API key)
5. Add the key to `background.js`

#### **VirusTotal API**
1. Go to [VirusTotal](https://www.virustotal.com/gui/join-us)
2. Create a free account
3. Get your API key from the profile section
4. Add the key to `background.js`

### **Customization Options**
- **Scan Batch Size**: Adjust `SCAN_BATCH_SIZE` in `content.js`
- **Scan Delay**: Modify `SCAN_DELAY` for API rate limiting
- **Safe Domains**: Add trusted domains to `SAFE_DOMAINS` array
- **URL Shorteners**: Extend `URL_SHORTENERS` list in `background.js`

## 🛡️ Security Features

### **Privacy Protection**
- **No Data Collection**: All processing is client-side
- **Local Storage**: User preferences stored locally
- **No External Tracking**: No analytics or user tracking

### **Safe Browsing**
- **Whitelist Protection**: Prevents false positives on trusted sites
- **Rate Limiting**: Respects API quotas and limits
- **Timeout Protection**: Prevents hanging requests

### **Content Security**
- **Manifest V3**: Latest security standards
- **Minimal Permissions**: Only necessary permissions requested
- **Sandboxed Execution**: Content scripts run in isolated environment

## 🔍 Detection Methods

### **1. VirusTotal API**
- **Coverage**: 70+ antivirus engines
- **Accuracy**: Industry-standard threat detection
- **Real-time**: Live threat intelligence
- **Details**: Engine counts and detection rates

### **2. Google Safe Browsing**
- **Coverage**: Google's threat database
- **Speed**: Fast API responses
- **Categories**: Malware, phishing, unwanted software
- **Integration**: Native Chrome integration

### **3. OpenPhish Database**
- **Coverage**: 50,000+ known phishing URLs
- **Offline**: Works without internet connection
- **Updated**: Refreshed every 30 minutes
- **Fallback**: Reliable backup detection method

### **4. Shortened URL Resolution**
- **Services**: bit.ly, tinyurl, t.co, and 20+ others
- **Method**: HEAD requests with redirect following
- **Safety**: No actual navigation to malicious sites
- **Visual**: Special indicators for resolved URLs

## 🚨 Troubleshooting

### **Common Issues**

#### **Extension Not Detecting Threats**
1. Check if detection is enabled in popup
2. Verify API keys are configured correctly
3. Check browser console for error messages
4. Ensure OpenPhish database is loaded

#### **API Rate Limits**
- **VirusTotal**: 500 requests/day (free tier)
- **Google Safe Browsing**: 10,000 requests/day (free tier)
- **Solution**: Extension falls back to OpenPhish database

#### **False Positives**
- Check if URL is in safe domain whitelist
- Verify URL normalization is working correctly
- Review detection logic in console logs

### **Debug Mode**
Enable detailed logging by checking browser console (F12):
- URL processing steps
- API response details
- Detection method used
- Error messages and warnings

## 📈 Performance

### **Optimization Features**
- **Batch Processing**: Efficient API usage
- **Debounced Scanning**: Prevents excessive DOM scanning
- **Caching**: Avoids re-scanning processed URLs
- **Rate Limiting**: Respects API quotas

### **Resource Usage**
- **Memory**: Minimal impact (< 5MB)
- **CPU**: Low background processing
- **Network**: Only API calls when needed
- **Storage**: Local preferences only

## 🔮 Future Enhancements

### **Planned Features**
- **Machine Learning Integration**: AI-powered threat detection
- **Cloud Threat Sharing**: Collaborative threat intelligence
- **Advanced Heuristics**: Pattern-based detection
- **Mobile Support**: Android/iOS versions

### **API Expansions**
- **Additional Threat Feeds**: More threat intelligence sources
- **Real-time Updates**: Live threat database updates
- **Custom Rules**: User-defined detection rules
- **Threat Scoring**: Risk assessment algorithms

##🤝 **The Team** 

- **Yatharth Bhavsar**
- **Smeet Sadhu**
- **Mahi Panchal**

**⚠️ Disclaimer**: This extension is for educational and security purposes. Always verify URLs independently and use multiple security tools for comprehensive protection. 

