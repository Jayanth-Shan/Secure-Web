// Options page script for Secure Web extension

// Load saved settings
document.addEventListener("DOMContentLoaded", async () => {
  try {
    // Check if chrome is defined, if not, define it (for testing environments)
    if (typeof chrome === "undefined") {
      global.chrome = {
        storage: {
          local: {
            get: (keys) => {
              return new Promise((resolve) => {
                const data = {}
                if (keys === null || keys === undefined || typeof keys !== "object") {
                  resolve({})
                  return
                }
                if (Array.isArray(keys)) {
                  keys.forEach((key) => {
                    if (localStorage.getItem(key)) {
                      data[key] = JSON.parse(localStorage.getItem(key))
                    }
                  })
                } else {
                  for (const key in keys) {
                    if (localStorage.getItem(key)) {
                      data[key] = JSON.parse(localStorage.getItem(key))
                    }
                  }
                }
                resolve(data)
              })
            },
            set: (items) => {
              return new Promise((resolve) => {
                for (const key in items) {
                  localStorage.setItem(key, JSON.stringify(items[key]))
                }
                resolve()
              })
            },
          },
        },
      }
    }

    const { config, reportedSites } = await chrome.storage.local.get(["config", "reportedSites"])

    if (config) {
      // Set checkboxes
      document.getElementById("phishing-detection").checked = true // Always enabled
      document.getElementById("https-enforcement").checked = true // Always enabled
      document.getElementById("tracker-blocking").checked = true // Always enabled
      document.getElementById("form-detection").checked = true // Always enabled
      document.getElementById("redirect-detection").checked = true // Always enabled
      document.getElementById("clickjacking-protection").checked = true // Always enabled
      document.getElementById("js-detection").checked = true // Always enabled
      document.getElementById("popup-detection").checked = true // Always enabled
      document.getElementById("breach-alert").checked = config.breachCheckEnabled

      // Set number inputs
      document.getElementById("max-redirects").value = config.maxRedirects
      document.getElementById("redirect-threshold").value = config.redirectTimeThreshold / 1000 // Convert ms to seconds
      document.getElementById("popup-threshold").value = config.popupThreshold
      document.getElementById("popup-time-window").value = config.popupTimeWindow / 1000 // Convert ms to seconds

      // Set API keys
      document.getElementById("google-api-key").value = config.phishingApiKey || ""
      document.getElementById("hibp-api-key").value = config.haveibeenpwnedApiKey || ""
    }

    // Display reported sites
    if (reportedSites && reportedSites.length > 0) {
      const container = document.getElementById("reported-sites-container")
      container.innerHTML = "" // Clear default message

      reportedSites.forEach((site) => {
        const siteElement = document.createElement("div")
        siteElement.className = "reported-site"

        const urlElement = document.createElement("div")
        urlElement.className = "reported-site-url"
        urlElement.textContent = site.url

        const reasonElement = document.createElement("div")
        reasonElement.className = "reported-site-reason"
        reasonElement.textContent = `Reason: ${site.reason}`

        const dateElement = document.createElement("div")
        dateElement.className = "reported-site-date"
        dateElement.textContent = `Reported on: ${new Date(site.date).toLocaleString()}`

        siteElement.appendChild(urlElement)
        siteElement.appendChild(reasonElement)
        siteElement.appendChild(dateElement)

        container.appendChild(siteElement)
      })
    }
  } catch (error) {
    console.error("Error loading settings:", error)
  }
})

// Save settings
document.getElementById("save-btn").addEventListener("click", async () => {
  try {
    const { config } = await chrome.storage.local.get("config")

    // Update config with new values
    config.breachCheckEnabled = document.getElementById("breach-alert").checked
    config.maxRedirects = Number.parseInt(document.getElementById("max-redirects").value)
    config.redirectTimeThreshold = Number.parseInt(document.getElementById("redirect-threshold").value) * 1000 // Convert seconds to ms
    config.popupThreshold = Number.parseInt(document.getElementById("popup-threshold").value)
    config.popupTimeWindow = Number.parseInt(document.getElementById("popup-time-window").value) * 1000 // Convert seconds to ms
    config.phishingApiKey = document.getElementById("google-api-key").value
    config.haveibeenpwnedApiKey = document.getElementById("hibp-api-key").value

    // Save updated config
    await chrome.storage.local.set({ config })

    alert("Settings saved successfully!")
  } catch (error) {
    console.error("Error saving settings:", error)
    alert("Error saving settings. Please try again.")
  }
})

// Reset to defaults
document.getElementById("reset-btn").addEventListener("click", async () => {
  if (confirm("Are you sure you want to reset all settings to their default values?")) {
    try {
      const defaultConfig = {
        maxRedirects: 10,
        redirectTimeThreshold: 5000, // ms
        popupThreshold: 5,
        popupTimeWindow: 10000, // ms
        phishingApiKey: "",
        haveibeenpwnedApiKey: "",
        breachCheckEnabled: false,
      }

      // Update config with default values
      await chrome.storage.local.set({ config: defaultConfig })

      // Reload the page to show updated settings
      location.reload()
    } catch (error) {
      console.error("Error resetting settings:", error)
      alert("Error resetting settings. Please try again.")
    }
  }
})
