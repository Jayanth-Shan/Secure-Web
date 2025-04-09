// Popup script for Secure Web extension

document.addEventListener("DOMContentLoaded", async () => {
  // Get current tab URL
  const tabs = await chrome.tabs.query({ active: true, currentWindow: true })
  const currentUrl = tabs[0]?.url || ""

  // Load stats
  const { stats } = await chrome.storage.local.get("stats")

  // Update stats display
  document.getElementById("phishing-blocked").textContent = stats.phishingBlocked
  document.getElementById("trackers-blocked").textContent = stats.trackersBlocked
  document.getElementById("https-upgrades").textContent = stats.httpsUpgrades
  document.getElementById("suspicious-forms").textContent = stats.suspiciousForms

  // Check current page status
  updatePageStatus(currentUrl)

  // Set up breach check functionality
  document.getElementById("check-email-btn").addEventListener("click", () => {
    const container = document.getElementById("breach-check-container")
    container.classList.toggle("hidden")
  })

  document.getElementById("submit-email-btn").addEventListener("click", async () => {
    const email = document.getElementById("breach-email").value
    if (!email || !email.includes("@")) {
      alert("Please enter a valid email address")
      return
    }

    const resultsDiv = document.getElementById("breach-results")
    resultsDiv.textContent = "Checking..."

    try {
      // First check if the API key is configured
      const { config } = await chrome.storage.local.get("config")
      if (!config.haveibeenpwnedApiKey || config.haveibeenpwnedApiKey.trim() === "") {
        resultsDiv.innerHTML =
          '<span style="color: orange;">API key not configured. Please add a Have I Been Pwned API key in the extension settings.</span>'
        return
      }

      const response = await chrome.runtime.sendMessage({
        type: "checkBreachStatus",
        email: email,
      })

      if (response && response.breaches !== null) {
        if (response.breaches.length === 0) {
          resultsDiv.innerHTML = '<span style="color: green;">Good news! No breaches found for this email.</span>'
        } else {
          resultsDiv.innerHTML = `
          <span style="color: red;">Found in ${response.breaches.length} data breaches:</span>
          <ul style="margin-top: 5px; padding-left: 20px;">
            ${response.breaches.map((breach) => `<li>${breach.Name} (${breach.BreachDate})</li>`).join("")}
          </ul>
        `
        }
      } else if (response && response.error) {
        resultsDiv.innerHTML = `<span style="color: red;">Error: ${response.error}</span>`
      } else {
        resultsDiv.textContent = "Error checking breach status. Please try again later."
      }
    } catch (error) {
      console.error("Error in breach check:", error)
      resultsDiv.textContent = `Error: ${error.message || "Unknown error occurred"}`
    }
  })

  // Options button
  document.getElementById("options-btn").addEventListener("click", () => {
    chrome.runtime.openOptionsPage()
  })
})

async function updatePageStatus(url) {
  if (!url || url.startsWith("chrome://")) {
    setAllStatusDisabled()
    return
  }

  try {
    // Check if current site is secure (HTTPS)
    const isHttps = url.startsWith("https://")
    updateStatusIcon("https-status", isHttps ? "safe" : "warning")

    // Check if current site has trackers (simplified for demo)
    updateStatusIcon("tracker-status", "safe")

    // Check if current site is a known phishing site
    const phishingResponse = await chrome.runtime.sendMessage({
      type: "checkPhishing",
      url: url,
    })
    updateStatusIcon("phishing-status", phishingResponse?.isPhishing ? "danger" : "safe")

    // Other statuses are set to safe by default
    // In a real extension, these would be updated based on actual checks
    updateStatusIcon("form-status", "safe")
    updateStatusIcon("redirect-status", "safe")
    updateStatusIcon("clickjacking-status", "safe")
    updateStatusIcon("js-status", "safe")
    updateStatusIcon("popup-status", "safe")

    // Breach alert status depends on configuration
    const { config } = await chrome.storage.local.get("config")
    updateStatusIcon("breach-status", config.breachCheckEnabled ? "safe" : "disabled")
  } catch (error) {
    console.error("Error updating page status:", error)
  }
}

function updateStatusIcon(id, status) {
  const element = document.getElementById(id)
  if (!element) return

  // Remove all existing status classes
  element.classList.remove("safe", "warning", "danger", "disabled")

  // Set icon content and class based on status
  switch (status) {
    case "safe":
      element.textContent = "✓"
      element.style.backgroundColor = "#2ecc71"
      break
    case "warning":
      element.textContent = "!"
      element.style.backgroundColor = "#f39c12"
      break
    case "danger":
      element.textContent = "✗"
      element.style.backgroundColor = "#e74c3c"
      break
    case "disabled":
      element.textContent = "-"
      element.style.backgroundColor = "#95a5a6"
      break
  }
}

function setAllStatusDisabled() {
  const statusIcons = document.querySelectorAll(".status-icon")
  statusIcons.forEach((icon) => {
    icon.textContent = "-"
    icon.style.backgroundColor = "#95a5a6"
  })
}
