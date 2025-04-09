// Content script for Secure Web extension
// Runs in the context of web pages

// Initialize state
let popupCount = 0
let lastPopupTime = Date.now()
let config = {
  popupThreshold: 5,
  popupTimeWindow: 10000, // ms
}

// Load configuration
chrome.storage.local.get("config", (data) => {
  if (data.config) {
    config = data.config
  }
})

// 1. Phishing Detection (backup check in content script)
async function checkCurrentPagePhishing() {
  const response = await chrome.runtime.sendMessage({
    type: "checkPhishing",
    url: window.location.href,
  })

  if (response && response.isPhishing) {
    // This is a backup - the background script should have already redirected
    document.body.innerHTML = `
      <div style="padding: 20px; background-color: #f44336; color: white; text-align: center;">
        <h1>Warning: Potential Phishing Site Detected</h1>
        <p>Secure Web has detected that this site may be attempting to steal your information.</p>
        <button id="back-button" style="padding: 10px; margin: 10px;">Go Back to Safety</button>
      </div>
    `

    document.getElementById("back-button").addEventListener("click", () => {
      history.back()
    })
  }
}

// 4. Suspicious Form Detection
function monitorForms() {
  // Find all forms
  const forms = document.querySelectorAll("form")

  forms.forEach((form) => {
    // Check if the form contains sensitive fields
    const hasSensitiveFields = Array.from(form.elements).some((element) => {
      const type = element.type?.toLowerCase()
      const name = element.name?.toLowerCase()
      const id = element.id?.toLowerCase()
      const placeholder = element.placeholder?.toLowerCase()

      // Check for password, credit card, SSN, etc.
      return (
        type === "password" ||
        /password|creditcard|credit-card|card-number|ssn|social|security/i.test(name) ||
        /password|creditcard|credit-card|card-number|ssn|social|security/i.test(id) ||
        /password|creditcard|credit-card|card-number|ssn|social|security/i.test(placeholder)
      )
    })

    if (hasSensitiveFields) {
      // Check if form submits to external domain
      form.addEventListener("submit", (e) => {
        const formAction = form.action || window.location.href
        const formDomain = new URL(formAction).hostname
        const currentDomain = window.location.hostname

        // Check if form submits to different domain
        if (formDomain !== currentDomain) {
          e.preventDefault()

          if (
            confirm(
              `Warning: This form is submitting sensitive information to an external domain (${formDomain}). Do you want to continue?`,
            )
          ) {
            form.submit()
          }

          // Update stats
          chrome.runtime.sendMessage({
            type: "updateStats",
            stat: "suspiciousForms",
          })
        }

        // Check if form submits over HTTP instead of HTTPS
        if (formAction.startsWith("http:")) {
          e.preventDefault()

          if (
            confirm(
              `Warning: This form is submitting sensitive information over an insecure connection. Do you want to continue?`,
            )
          ) {
            form.submit()
          }

          // Update stats
          chrome.runtime.sendMessage({
            type: "updateStats",
            stat: "suspiciousForms",
          })
        }
      })
    }
  })
}

// 6. Clickjacking Protection
function detectClickjacking() {
  // Check for hidden iframes
  const iframes = document.querySelectorAll("iframe")

  iframes.forEach((iframe) => {
    const style = window.getComputedStyle(iframe)
    const opacity = Number.parseFloat(style.opacity)
    const visibility = style.visibility
    const display = style.display
    const width = Number.parseFloat(style.width)
    const height = Number.parseFloat(style.height)

    // Check for potentially hidden iframes
    if ((opacity < 0.2 || visibility === "hidden" || display === "none") && width > 50 && height > 50) {
      // Potential clickjacking attempt
      iframe.style.border = "5px solid red"
      iframe.style.opacity = "0.8"

      const warning = document.createElement("div")
      warning.style.position = "absolute"
      warning.style.top = `${iframe.offsetTop}px`
      warning.style.left = `${iframe.offsetLeft}px`
      warning.style.backgroundColor = "red"
      warning.style.color = "white"
      warning.style.padding = "5px"
      warning.style.zIndex = "9999"
      warning.textContent = "Potential clickjacking attempt detected!"

      document.body.appendChild(warning)

      // Update stats
      chrome.runtime.sendMessage({
        type: "updateStats",
        stat: "clickjackingAttempts",
      })
    }
  })

  // Check for transparent overlays
  const divs = document.querySelectorAll("div")

  divs.forEach((div) => {
    const style = window.getComputedStyle(div)
    const opacity = Number.parseFloat(style.opacity)
    const zIndex = Number.parseInt(style.zIndex)
    const position = style.position

    if (
      opacity < 0.2 &&
      zIndex > 1000 &&
      (position === "absolute" || position === "fixed") &&
      div.offsetWidth > 100 &&
      div.offsetHeight > 100
    ) {
      // Potential clickjacking overlay
      div.style.border = "5px solid red"
      div.style.opacity = "0.8"

      const warning = document.createElement("div")
      warning.style.position = "absolute"
      warning.style.top = `${div.offsetTop}px`
      warning.style.left = `${div.offsetLeft}px`
      warning.style.backgroundColor = "red"
      warning.style.color = "white"
      warning.style.padding = "5px"
      warning.style.zIndex = "99999"
      warning.textContent = "Potential clickjacking overlay detected!"

      document.body.appendChild(warning)

      // Update stats
      chrome.runtime.sendMessage({
        type: "updateStats",
        stat: "clickjackingAttempts",
      })
    }
  })
}

// 7. JavaScript Obfuscation Detection
function detectObfuscatedJS() {
  // Get all script elements
  const scripts = document.querySelectorAll("script")

  scripts.forEach((script) => {
    if (!script.src && script.textContent) {
      const code = script.textContent

      // Check for signs of obfuscation
      const obfuscationIndicators = [
        // Long strings of hex or unicode
        /\\x[0-9a-f]{2,}/gi.test(code) && /\\x[0-9a-f]{2,}/gi.exec(code).length > 10,
        // Excessive eval usage
        /eval\(/gi.test(code) && /eval\(/gi.exec(code).length > 3,
        // String concatenation with many segments
        code.split("+").length > 50 && /["']\s*\+\s*["']/g.test(code),
        // Excessive use of escape sequences
        /\\[^xu]/g.test(code) && /\\[^xu]/g.exec(code).length > 20,
        // Very long lines
        code
          .split("\n")
          .some((line) => line.length > 500),
        // Excessive use of encoded strings
        /fromCharCode|String\.fromCharCode/g.test(code) && code.match(/fromCharCode/g).length > 5,
        // Use of suspicious global variables
        /\[(["'])_0x[0-9a-f]+\1\]/gi.test(code),
      ]

      if (obfuscationIndicators.filter(Boolean).length >= 3) {
        console.warn("Potentially obfuscated JavaScript detected:", script)

        // Create a warning
        const warning = document.createElement("div")
        warning.style.position = "fixed"
        warning.style.top = "10px"
        warning.style.right = "10px"
        warning.style.backgroundColor = "orange"
        warning.style.color = "black"
        warning.style.padding = "10px"
        warning.style.zIndex = "9999"
        warning.style.borderRadius = "5px"
        warning.textContent = "Warning: Potentially obfuscated JavaScript detected on this page."

        document.body.appendChild(warning)

        // Auto-remove after 5 seconds
        setTimeout(() => {
          if (document.body.contains(warning)) {
            document.body.removeChild(warning)
          }
        }, 5000)

        // Update stats
        chrome.runtime.sendMessage({
          type: "updateStats",
          stat: "obfuscatedScripts",
        })
      }
    }
  })
}

// 8. Popup Spam Detection
function setupPopupDetection() {
  // Override window.open
  const originalWindowOpen = window.open
  window.open = function () {
    const now = Date.now()
    popupCount++

    // Reset counter if outside time window
    if (now - lastPopupTime > config.popupTimeWindow) {
      popupCount = 1
      lastPopupTime = now
    }

    // Check if threshold exceeded
    if (popupCount > config.popupThreshold) {
      // Block popup
      console.warn("Popup spam detected, blocking popup")

      // Show notification
      const notification = document.createElement("div")
      notification.style.position = "fixed"
      notification.style.top = "10px"
      notification.style.left = "10px"
      notification.style.backgroundColor = "red"
      notification.style.color = "white"
      notification.style.padding = "10px"
      notification.style.zIndex = "9999"
      notification.style.borderRadius = "5px"
      notification.textContent = "Popup spam detected and blocked!"

      document.body.appendChild(notification)

      // Auto-remove after 3 seconds
      setTimeout(() => {
        if (document.body.contains(notification)) {
          document.body.removeChild(notification)
        }
      }, 3000)

      // Update stats
      chrome.runtime.sendMessage({
        type: "updateStats",
        stat: "popupSpam",
      })

      return null
    }

    // Allow popup if not spam
    return originalWindowOpen.apply(this, arguments)
  }
}

// 10. Site Reporting Tool
function addReportButton() {
  const reportButton = document.createElement("div")
  reportButton.style.position = "fixed"
  reportButton.style.bottom = "20px"
  reportButton.style.right = "20px"
  reportButton.style.backgroundColor = "#f44336"
  reportButton.style.color = "white"
  reportButton.style.padding = "10px"
  reportButton.style.borderRadius = "50%"
  reportButton.style.width = "40px"
  reportButton.style.height = "40px"
  reportButton.style.textAlign = "center"
  reportButton.style.lineHeight = "40px"
  reportButton.style.cursor = "pointer"
  reportButton.style.zIndex = "9999"
  reportButton.style.boxShadow = "0 2px 5px rgba(0,0,0,0.3)"
  reportButton.style.fontWeight = "bold"
  reportButton.textContent = "!"
  reportButton.title = "Report this site as suspicious"

  reportButton.addEventListener("click", () => {
    const reason = prompt("Why are you reporting this site?")
    if (reason) {
      chrome.runtime.sendMessage(
        {
          type: "reportSite",
          url: window.location.href,
          reason: reason,
        },
        (response) => {
          if (response && response.success) {
            alert("Thank you for your report. Our team will review this site.")
          } else {
            alert("There was an error submitting your report. Please try again.")
          }
        },
      )
    }
  })

  document.body.appendChild(reportButton)
}

// Run all checks when DOM is ready
document.addEventListener("DOMContentLoaded", () => {
  checkCurrentPagePhishing()
  monitorForms()
  detectClickjacking()
  detectObfuscatedJS()
  setupPopupDetection()
  addReportButton()

  // Re-run some checks periodically as page content might change
  setInterval(() => {
    monitorForms()
    detectClickjacking()
  }, 5000)
})
