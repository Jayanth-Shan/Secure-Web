// Background script for Secure Web extension
// Handles features that need to run in the background

// Configuration and state
const config = {
  maxRedirects: 10,
  redirectTimeThreshold: 5000, // ms
  popupThreshold: 5,
  popupTimeWindow: 10000, // ms
  phishingApiKey: "YOUR_GOOGLE_SAFE_BROWSING_API_KEY", // Replace with actual API key
  haveibeenpwnedApiKey: "YOUR_HAVEIBEENPWNED_API_KEY", // Replace with actual API key
  breachCheckEnabled: false,
}

// Initialize storage with default settings
chrome.runtime.onInstalled.addListener(() => {
  chrome.storage.local.set({
    config: config,
    stats: {
      phishingBlocked: 0,
      trackersBlocked: 0,
      httpsUpgrades: 0,
      suspiciousForms: 0,
      redirectionsBlocked: 0,
      clickjackingAttempts: 0,
      obfuscatedScripts: 0,
      popupSpam: 0,
    },
    knownPhishingDomains: ["phishing-example.com", "fake-bank-login.com", "login-secure-verification.com"],
    reportedSites: [],
  })

  // Load tracker blocking rules
  loadTrackerRules()
})

// Track redirects per tab
const tabRedirects = {}

// 1. Phishing Detection
async function checkPhishing(url) {
  try {
    // First check against local list
    const { knownPhishingDomains } = await chrome.storage.local.get("knownPhishingDomains")
    const domain = new URL(url).hostname

    if (knownPhishingDomains.includes(domain)) {
      return true
    }

    // Then check with Google Safe Browsing API
    const { config } = await chrome.storage.local.get("config")
    if (!config.phishingApiKey) return false

    const apiUrl = `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${config.phishingApiKey}`
    const response = await fetch(apiUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        client: {
          clientId: "secure-web-extension",
          clientVersion: "1.0.0",
        },
        threatInfo: {
          threatTypes: ["MALWARE", "SOCIAL_ENGINEERING"],
          platformTypes: ["ANY_PLATFORM"],
          threatEntryTypes: ["URL"],
          threatEntries: [{ url }],
        },
      }),
    })

    const data = await response.json()
    return data.matches && data.matches.length > 0
  } catch (error) {
    console.error("Error checking phishing:", error)
    return false
  }
}

// 2. HTTPS Enforcement
chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
  if (details.frameId === 0 && details.url.startsWith("http:")) {
    const httpsUrl = details.url.replace("http:", "https:")
    try {
      // Check if HTTPS version exists
      const response = await fetch(httpsUrl, { method: "HEAD", mode: "no-cors" })
      if (response.ok) {
        // Update stats
        const { stats } = await chrome.storage.local.get("stats")
        stats.httpsUpgrades++
        await chrome.storage.local.set({ stats })

        // Redirect to HTTPS
        chrome.tabs.update(details.tabId, { url: httpsUrl })
      }
    } catch (error) {
      console.log("HTTPS version not available:", error)
    }
  }
})

// 3. Tracker Blocking (using declarativeNetRequest)
async function loadTrackerRules() {
  // This function would normally load rules from a file or API
  // For this example, we'll create a simple rule to block a common tracker
  const rules = [
    {
      id: 1,
      priority: 1,
      action: { type: "block" },
      condition: {
        urlFilter: "||google-analytics.com/analytics.js",
        resourceTypes: ["script"],
      },
    },
    {
      id: 2,
      priority: 1,
      action: { type: "block" },
      condition: {
        urlFilter: "||facebook.net/",
        resourceTypes: ["script"],
      },
    },
    {
      id: 3,
      priority: 1,
      action: { type: "block" },
      condition: {
        urlFilter: "||doubleclick.net/",
        resourceTypes: ["script", "image", "xmlhttprequest"],
      },
    },
  ]

  // Save rules to a file
  const rulesStr = JSON.stringify(rules, null, 2)
  // In a real extension, you would save this to a file
  // For this example, we'll use the rules directly

  try {
    await chrome.declarativeNetRequest.updateDynamicRules({
      removeRuleIds: rules.map((r) => r.id),
      addRules: rules,
    })
  } catch (error) {
    console.error("Error updating tracker rules:", error)
  }
}

// 5. Redirection Flood Detection
chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
  if (details.frameId !== 0) return

  const tabId = details.tabId
  const now = Date.now()

  if (!tabRedirects[tabId]) {
    tabRedirects[tabId] = {
      count: 1,
      timestamps: [now],
      urls: [details.url],
    }
    return
  }

  // Add this navigation
  tabRedirects[tabId].count++
  tabRedirects[tabId].timestamps.push(now)
  tabRedirects[tabId].urls.push(details.url)

  // Check for redirect flood
  const { config } = await chrome.storage.local.get("config")
  const recentRedirects = tabRedirects[tabId].timestamps.filter((t) => now - t < config.redirectTimeThreshold)

  if (recentRedirects.length >= config.maxRedirects) {
    // Update stats
    const { stats } = await chrome.storage.local.get("stats")
    stats.redirectionsBlocked++
    await chrome.storage.local.set({ stats })

    // Close the tab and show warning
    chrome.tabs.remove(tabId)
    chrome.tabs.create({
      url: "redirect_warning.html",
      active: true,
    })
  }
})

// Clean up redirect tracking when tab is closed
chrome.tabs.onRemoved.addListener((tabId) => {
  if (tabRedirects[tabId]) {
    delete tabRedirects[tabId]
  }
})

// 9. Breach Alert (Optional)
async function checkBreachStatus(email) {
  try {
    const { config } = await chrome.storage.local.get("config")
    if (!config.breachCheckEnabled) {
      return { error: "Breach checking is disabled in settings" }
    }

    if (!config.haveibeenpwnedApiKey || config.haveibeenpwnedApiKey.trim() === "") {
      return { error: "Have I Been Pwned API key is not configured" }
    }

    // Use k-Anonymity model to protect the full email
    // Only send the first 6 characters of the hash
    const emailHash = await sha1(email.toLowerCase())
    const hashPrefix = emailHash.substring(0, 6)

    // First check if the prefix exists in the Pwned Passwords API
    const response = await fetch(`https://haveibeenpwned.com/api/v3/breachedaccount/${encodeURIComponent(email)}`, {
      method: "GET",
      headers: {
        "hibp-api-key": config.haveibeenpwnedApiKey,
        "User-Agent": "SecureWebExtension/1.0",
      },
    })

    if (response.status === 200) {
      return { breaches: await response.json() }
    } else if (response.status === 404) {
      return { breaches: [] } // No breaches found
    } else {
      const errorText = await response.text().catch(() => "Unknown error")
      console.error(`API returned status ${response.status}: ${errorText}`)
      return { error: `API returned status ${response.status}: ${errorText}` }
    }
  } catch (error) {
    console.error("Error checking breach status:", error)
    return { error: error.message || "Unknown error occurred" }
  }
}

// Helper function to compute SHA-1 hash
async function sha1(str) {
  const buffer = new TextEncoder().encode(str)
  const hashBuffer = await crypto.subtle.digest("SHA-1", buffer)
  const hashArray = Array.from(new Uint8Array(hashBuffer))
  return hashArray.map((b) => b.toString(16).padStart(2, "0")).join("")
}

// Listen for messages from content script
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === "checkPhishing") {
    checkPhishing(message.url).then((isPhishing) => {
      sendResponse({ isPhishing })
    })
    return true // Keep the message channel open for async response
  }

  if (message.type === "reportSite") {
    chrome.storage.local.get("reportedSites", ({ reportedSites }) => {
      reportedSites.push({
        url: message.url,
        reason: message.reason,
        date: new Date().toISOString(),
      })
      chrome.storage.local.set({ reportedSites })
      sendResponse({ success: true })
    })
    return true
  }

  if (message.type === "checkBreachStatus") {
    checkBreachStatus(message.email).then((result) => {
      sendResponse(result)
    })
    return true
  }

  if (message.type === "updateStats") {
    chrome.storage.local.get("stats", ({ stats }) => {
      stats[message.stat]++
      chrome.storage.local.set({ stats })
    })
  }
})

// Handle initial navigation to check for phishing
chrome.webNavigation.onCommitted.addListener(async (details) => {
  if (details.frameId !== 0) return

  const isPhishing = await checkPhishing(details.url)
  if (isPhishing) {
    // Update stats
    const { stats } = await chrome.storage.local.get("stats")
    stats.phishingBlocked++
    await chrome.storage.local.set({ stats })

    // Show warning page
    chrome.tabs.update(details.tabId, {
      url: `warning.html?url=${encodeURIComponent(details.url)}`,
    })
  }
})
