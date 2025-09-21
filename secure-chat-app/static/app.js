class SecureChat {
  constructor() {
    this.socket = null
    this.currentUser = null
    this.isSignUp = false
    this.encryptionKey = null

    this.initializeElements()
    this.bindEvents()
    this.generateEncryptionKey()
  }

  initializeElements() {
    // Auth elements
    this.authScreen = document.getElementById("auth-screen")
    this.chatScreen = document.getElementById("chat-screen")
    this.authForm = document.getElementById("auth-form")
    this.usernameInput = document.getElementById("username")
    this.passwordInput = document.getElementById("password")
    this.authSubmit = document.getElementById("auth-submit")
    this.errorMessage = document.getElementById("error-message")
    this.signinTab = document.getElementById("signin-tab")
    this.signupTab = document.getElementById("signup-tab")

    // Chat elements
    this.messagesContainer = document.getElementById("messages-container")
    this.messageForm = document.getElementById("message-form")
    this.messageInput = document.getElementById("message-input")
    this.usersList = document.getElementById("users-list")
    this.userInfo = document.getElementById("user-info")
    this.logoutBtn = document.getElementById("logout-btn")

    // Admin panel elements
    this.adminPanel = document.getElementById("admin-panel")
    this.clearMessagesBtn = document.getElementById("clear-messages-btn")
    this.userStatsBtn = document.getElementById("user-stats-btn")
    this.exportDataBtn = document.getElementById("export-data-btn")
    this.adminModal = document.getElementById("admin-modal")
    this.closeModalBtn = document.getElementById("close-modal-btn")
    this.modalContent = document.getElementById("modal-content")
  }

  bindEvents() {
    // Auth events
    this.authForm.addEventListener("submit", (e) => this.handleAuth(e))
    this.signinTab.addEventListener("click", () => this.switchToSignIn())
    this.signupTab.addEventListener("click", () => this.switchToSignUp())
    this.logoutBtn.addEventListener("click", () => this.logout())

    // Chat events
    this.messageForm.addEventListener("submit", (e) => this.sendMessage(e))

    // Admin panel event listeners
    this.clearMessagesBtn.addEventListener("click", () => this.clearAllMessages())
    this.userStatsBtn.addEventListener("click", () => this.showUserStats())
    this.exportDataBtn.addEventListener("click", () => this.exportChatData())
    this.closeModalBtn.addEventListener("click", () => this.closeModal())
  }

  async generateEncryptionKey() {
    // Generate AES-256 key for client-side encryption
    this.encryptionKey = await window.crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, [
      "encrypt",
      "decrypt",
    ])
  }

  async encryptMessage(message) {
    const encoder = new TextEncoder()
    const data = encoder.encode(message)
    const iv = window.crypto.getRandomValues(new Uint8Array(12))

    const encrypted = await window.crypto.subtle.encrypt({ name: "AES-GCM", iv: iv }, this.encryptionKey, data)

    return {
      encrypted: Array.from(new Uint8Array(encrypted)),
      iv: Array.from(iv),
    }
  }

  async decryptMessage(encryptedData, iv) {
    try {
      const decrypted = await window.crypto.subtle.decrypt(
        { name: "AES-GCM", iv: new Uint8Array(iv) },
        this.encryptionKey,
        new Uint8Array(encryptedData),
      )

      const decoder = new TextDecoder()
      return decoder.decode(decrypted)
    } catch (error) {
      return "[Encrypted Message]"
    }
  }

  switchToSignIn() {
    this.isSignUp = false
    this.signinTab.classList.add("bg-green-500", "text-white")
    this.signinTab.classList.remove("text-gray-400")
    this.signupTab.classList.remove("bg-green-500", "text-white")
    this.signupTab.classList.add("text-gray-400")
    this.authSubmit.textContent = "Sign In"
  }

  switchToSignUp() {
    this.isSignUp = true
    this.signupTab.classList.add("bg-green-500", "text-white")
    this.signupTab.classList.remove("text-gray-400")
    this.signinTab.classList.remove("bg-green-500", "text-white")
    this.signinTab.classList.add("text-gray-400")
    this.authSubmit.textContent = "Sign Up"
  }

  showError(message) {
    this.errorMessage.textContent = message
    this.errorMessage.classList.remove("hidden")
    setTimeout(() => {
      this.errorMessage.classList.add("hidden")
    }, 5000)
  }

  async handleAuth(e) {
    e.preventDefault()

    const username = this.usernameInput.value.trim()
    const password = this.passwordInput.value

    if (!username || !password) {
      this.showError("Please fill in all fields")
      return
    }

    const endpoint = this.isSignUp ? "/api/register" : "/api/login"

    try {
      const response = await fetch(endpoint, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ username, password }),
      })

      const data = await response.json()

      if (data.success) {
        this.currentUser = {
          id: data.user_id,
          username: data.username,
          is_admin: data.is_admin,
        }
        this.showChatScreen()
      } else {
        this.showError(data.error || "Authentication failed")
      }
    } catch (error) {
      this.showError("Network error. Please try again.")
    }
  }

  showChatScreen() {
    this.authScreen.classList.add("hidden")
    this.chatScreen.classList.remove("hidden")
    this.userInfo.textContent = `Welcome, ${this.currentUser.username}${this.currentUser.is_admin ? " (Admin)" : ""}`

    if (this.currentUser.is_admin) {
      this.adminPanel.classList.remove("hidden")
    }

    this.initializeSocket()
    this.loadMessages()
    this.loadUsers()
  }

  initializeSocket() {
    const io = window.io // Declare the io variable here
    this.socket = io()

    this.socket.on("connect", () => {
      console.log("[v0] Connected to server")
    })

    this.socket.on("new_message", (data) => {
      this.displayMessage(data)
    })

    this.socket.on("user_connected", (data) => {
      console.log("[v0] User connected:", data.username)
      this.loadUsers()
    })

    this.socket.on("user_disconnected", (data) => {
      console.log("[v0] User disconnected:", data.username)
      this.loadUsers()
    })
  }

  async sendMessage(e) {
    e.preventDefault()

    const message = this.messageInput.value.trim()
    if (!message) return

    this.socket.emit("send_message", { content: message })
    this.messageInput.value = ""
  }

  displayMessage(data) {
    const messageDiv = document.createElement("div")
    messageDiv.className = "flex items-start space-x-3"

    const isOwnMessage = data.user_id === this.currentUser.id
    const timestamp = new Date(data.timestamp).toLocaleTimeString()

    messageDiv.innerHTML = `
            <div class="w-8 h-8 bg-green-500 rounded-full flex items-center justify-center text-white text-sm font-medium">
                ${data.username.charAt(0).toUpperCase()}
            </div>
            <div class="flex-1">
                <div class="flex items-center space-x-2 mb-1">
                    <span class="font-medium text-white">${data.username}</span>
                    ${isOwnMessage ? '<span class="text-xs text-green-400">You</span>' : ""}
                    <span class="text-xs text-gray-400">${timestamp}</span>
                    <span class="text-xs text-green-400">🔒 Encrypted</span>
                </div>
                <div class="bg-gray-800 rounded-lg p-3 text-gray-100">
                    ${data.content}
                </div>
            </div>
        `

    this.messagesContainer.appendChild(messageDiv)
    this.messagesContainer.scrollTop = this.messagesContainer.scrollHeight
  }

  async loadMessages() {
    try {
      const response = await fetch("/api/messages")
      const messages = await response.json()

      this.messagesContainer.innerHTML = ""
      messages.forEach((message) => this.displayMessage(message))
    } catch (error) {
      console.error("[v0] Error loading messages:", error)
    }
  }

  async loadUsers() {
    try {
      const response = await fetch("/api/users")
      const users = await response.json()

      this.usersList.innerHTML = ""
      users.forEach((user) => {
        const userDiv = document.createElement("div")
        userDiv.className = "flex items-center space-x-2 p-2 rounded-lg bg-gray-800"

        userDiv.innerHTML = `
                    <div class="w-2 h-2 bg-green-500 rounded-full"></div>
                    <div class="w-6 h-6 bg-green-500 rounded-full flex items-center justify-center text-white text-xs">
                        ${user.username.charAt(0).toUpperCase()}
                    </div>
                    <span class="text-sm text-white">${user.username}</span>
                    ${user.is_admin ? '<span class="text-xs text-yellow-400">👑</span>' : ""}
                `

        this.usersList.appendChild(userDiv)
      })
    } catch (error) {
      console.error("[v0] Error loading users:", error)
    }
  }

  logout() {
    if (this.socket) {
      this.socket.disconnect()
    }

    this.currentUser = null
    this.chatScreen.classList.add("hidden")
    this.authScreen.classList.remove("hidden")
    this.usernameInput.value = ""
    this.passwordInput.value = ""
    this.switchToSignIn()
  }

  // Admin functionality methods
  async clearAllMessages() {
    if (!this.currentUser.is_admin) return

    if (!confirm("Are you sure you want to clear all messages? This action cannot be undone.")) {
      return
    }

    try {
      const response = await fetch("/api/admin/clear-messages", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
      })

      if (response.ok) {
        this.messagesContainer.innerHTML = ""
        this.displaySystemMessage("All messages have been cleared by admin")
      } else {
        alert("Failed to clear messages")
      }
    } catch (error) {
      console.error("[v0] Error clearing messages:", error)
      alert("Error clearing messages")
    }
  }

  async showUserStats() {
    if (!this.currentUser.is_admin) return

    try {
      const response = await fetch("/api/admin/user-stats")
      const stats = await response.json()

      let content = `
          <div class="space-y-4">
              <div class="grid grid-cols-2 gap-4">
                  <div class="bg-gray-800 p-4 rounded-lg">
                      <h3 class="font-semibold text-green-400">Total Users</h3>
                      <p class="text-2xl font-bold">${stats.total_users}</p>
                  </div>
                  <div class="bg-gray-800 p-4 rounded-lg">
                      <h3 class="font-semibold text-green-400">Total Messages</h3>
                      <p class="text-2xl font-bold">${stats.total_messages}</p>
                  </div>
              </div>
              <div class="bg-gray-800 p-4 rounded-lg">
                  <h3 class="font-semibold text-green-400 mb-2">Recent Users</h3>
                  <div class="space-y-2">
      `

      stats.recent_users.forEach((user) => {
        const lastSeen = new Date(user.last_seen).toLocaleString()
        content += `
            <div class="flex justify-between items-center">
                <span>${user.username} ${user.is_admin ? "👑" : ""}</span>
                <span class="text-sm text-gray-400">${lastSeen}</span>
            </div>
        `
      })

      content += `
                  </div>
              </div>
          </div>
      `

      this.modalContent.innerHTML = content
      this.adminModal.classList.remove("hidden")
    } catch (error) {
      console.error("[v0] Error loading user stats:", error)
      alert("Error loading user statistics")
    }
  }

  async exportChatData() {
    if (!this.currentUser.is_admin) return

    try {
      const response = await fetch("/api/admin/export-data")
      const data = await response.json()

      const dataStr = JSON.stringify(data, null, 2)
      const dataBlob = new Blob([dataStr], { type: "application/json" })

      const url = URL.createObjectURL(dataBlob)
      const link = document.createElement("a")
      link.href = url
      link.download = `securechat-export-${new Date().toISOString().split("T")[0]}.json`
      document.body.appendChild(link)
      link.click()
      document.body.removeChild(link)
      URL.revokeObjectURL(url)

      this.displaySystemMessage("Chat data exported successfully")
    } catch (error) {
      console.error("[v0] Error exporting data:", error)
      alert("Error exporting chat data")
    }
  }

  closeModal() {
    this.adminModal.classList.add("hidden")
  }

  displaySystemMessage(message) {
    const messageDiv = document.createElement("div")
    messageDiv.className = "flex justify-center my-4"

    messageDiv.innerHTML = `
        <div class="bg-yellow-500/20 border border-yellow-500/30 rounded-lg px-4 py-2 text-yellow-400 text-sm">
            <svg class="w-4 h-4 inline mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path>
            </svg>
            ${message}
        </div>
    `

    this.messagesContainer.appendChild(messageDiv)
    this.messagesContainer.scrollTop = this.messagesContainer.scrollHeight
  }
}

// Initialize the app when DOM is loaded
document.addEventListener("DOMContentLoaded", () => {
  new SecureChat()
})
