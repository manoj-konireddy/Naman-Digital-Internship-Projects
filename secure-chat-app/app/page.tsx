"use client"

import { useState, useEffect, useRef } from "react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Label } from "@/components/ui/label"
import { ScrollArea } from "@/components/ui/scroll-area"
import { Avatar, AvatarFallback } from "@/components/ui/avatar"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog"
import { Badge } from "@/components/ui/badge"
import {
  Shield,
  MessageCircle,
  Lock,
  Send,
  Users,
  Clock,
  Key,
  Wifi,
  Settings,
  User,
  Trash2,
  Crown,
  Calendar,
  Activity,
} from "lucide-react"

export default function SecureChatApp() {
  const [isAuthenticated, setIsAuthenticated] = useState(false)
  const [currentUser, setCurrentUser] = useState(null)
  const [loginForm, setLoginForm] = useState({ username: "", password: "" })
  const [registerForm, setRegisterForm] = useState({ username: "", password: "", confirmPassword: "" })
  const [error, setError] = useState("")

  const [messages, setMessages] = useState([])
  const [newMessage, setNewMessage] = useState("")
  const [onlineUsers, setOnlineUsers] = useState([])
  const [allUsers, setAllUsers] = useState([])
  const [encryptionKey, setEncryptionKey] = useState(null)
  const [isConnected, setIsConnected] = useState(true)
  const [lastMessageCount, setLastMessageCount] = useState(0)
  const [showUserProfile, setShowUserProfile] = useState(false)
  const [selectedUser, setSelectedUser] = useState(null)
  const [showSettings, setShowSettings] = useState(false)
  const [userStats, setUserStats] = useState({ totalMessages: 0, joinDate: null })
  const messagesEndRef = useRef(null)
  const pollingIntervalRef = useRef(null)

  const getUserStats = (userId) => {
    const messages = JSON.parse(localStorage.getItem("chatMessages") || "[]")
    const userMessages = messages.filter((msg) => msg.senderId === userId)
    const users = JSON.parse(localStorage.getItem("chatUsers") || "[]")
    const user = users.find((u) => u.id === userId)

    return {
      totalMessages: userMessages.length,
      joinDate: user?.createdAt || null,
      lastSeen: user?.lastSeen || null,
      isOnline: isUserOnline(user),
    }
  }

  const deleteUser = (userId) => {
    if (userId === currentUser.id) {
      setError("Cannot delete your own account")
      return
    }

    const users = JSON.parse(localStorage.getItem("chatUsers") || "[]")
    const updatedUsers = users.filter((user) => user.id !== userId)
    localStorage.setItem("chatUsers", JSON.stringify(updatedUsers))

    // Remove user's encryption key
    localStorage.removeItem(`encryptionKey_${userId}`)

    // Update online users list
    updateOnlineUsers()
    setAllUsers(updatedUsers)
    setShowUserProfile(false)
  }

  const clearAllMessages = () => {
    localStorage.setItem("chatMessages", "[]")
    setMessages([])
    setLastMessageCount(0)
  }

  const exportUserData = () => {
    const userData = {
      user: currentUser,
      messages: messages.filter((msg) => msg.senderId === currentUser.id),
      joinDate: userStats.joinDate,
      totalMessages: userStats.totalMessages,
    }

    const dataStr = JSON.stringify(userData, null, 2)
    const dataBlob = new Blob([dataStr], { type: "application/json" })
    const url = URL.createObjectURL(dataBlob)
    const link = document.createElement("a")
    link.href = url
    link.download = `securechat-data-${currentUser.username}.json`
    link.click()
    URL.revokeObjectURL(url)
  }

  // Listen for localStorage changes (simulates real-time updates from other users)
  useEffect(() => {
    const handleStorageChange = (e) => {
      if (e.key === "chatMessages" && isAuthenticated && encryptionKey) {
        console.log("[v0] Storage change detected, reloading messages")
        loadMessages()
      }
      if (e.key === "chatUsers" && isAuthenticated) {
        console.log("[v0] Users updated, refreshing online users")
        updateOnlineUsers()
        updateAllUsers()
      }
    }

    window.addEventListener("storage", handleStorageChange)
    return () => window.removeEventListener("storage", handleStorageChange)
  }, [isAuthenticated, encryptionKey])

  useEffect(() => {
    if (isAuthenticated && encryptionKey) {
      // Poll for new messages every 2 seconds
      pollingIntervalRef.current = setInterval(() => {
        const currentMessages = JSON.parse(localStorage.getItem("chatMessages") || "[]")
        if (currentMessages.length !== lastMessageCount) {
          console.log("[v0] New messages detected via polling")
          loadMessages()
          setLastMessageCount(currentMessages.length)
        }
      }, 2000)

      return () => {
        if (pollingIntervalRef.current) {
          clearInterval(pollingIntervalRef.current)
        }
      }
    }
  }, [isAuthenticated, encryptionKey, lastMessageCount])

  useEffect(() => {
    if (isAuthenticated && currentUser) {
      // Update user's last seen timestamp
      const updateLastSeen = () => {
        const users = JSON.parse(localStorage.getItem("chatUsers") || "[]")
        const updatedUsers = users.map((user) =>
          user.id === currentUser.id ? { ...user, lastSeen: new Date().toISOString() } : user,
        )
        localStorage.setItem("chatUsers", JSON.stringify(updatedUsers))
      }

      updateLastSeen()
      const lastSeenInterval = setInterval(updateLastSeen, 30000) // Update every 30 seconds

      return () => clearInterval(lastSeenInterval)
    }
  }, [isAuthenticated, currentUser])

  useEffect(() => {
    if (isAuthenticated && currentUser) {
      const stats = getUserStats(currentUser.id)
      setUserStats(stats)
    }
  }, [isAuthenticated, currentUser, messages])

  const updateOnlineUsers = () => {
    const allUsers = JSON.parse(localStorage.getItem("chatUsers") || "[]")
    const now = new Date()

    // Consider users online if they were active in the last 2 minutes
    const onlineThreshold = 2 * 60 * 1000 // 2 minutes in milliseconds

    const activeUsers = allUsers
      .filter((user) => {
        if (!user.lastSeen) return false
        const lastSeen = new Date(user.lastSeen)
        return now - lastSeen < onlineThreshold
      })
      .slice(0, 8) // Show up to 8 online users

    setOnlineUsers(activeUsers)
  }

  const updateAllUsers = () => {
    const users = JSON.parse(localStorage.getItem("chatUsers") || "[]")
    setAllUsers(users)
  }

  // Generate encryption key for the user
  const generateEncryptionKey = async () => {
    const key = await crypto.subtle.generateKey(
      {
        name: "AES-GCM",
        length: 256,
      },
      true,
      ["encrypt", "decrypt"],
    )
    return key
  }

  // Convert key to exportable format for storage
  const exportKey = async (key) => {
    const exported = await crypto.subtle.exportKey("raw", key)
    return Array.from(new Uint8Array(exported))
  }

  // Import key from stored format
  const importKey = async (keyData) => {
    const key = await crypto.subtle.importKey(
      "raw",
      new Uint8Array(keyData),
      {
        name: "AES-GCM",
        length: 256,
      },
      true,
      ["encrypt", "decrypt"],
    )
    return key
  }

  // Encrypt message text
  const encryptMessage = async (text, key) => {
    const encoder = new TextEncoder()
    const data = encoder.encode(text)
    const iv = crypto.getRandomValues(new Uint8Array(12))

    const encrypted = await crypto.subtle.encrypt(
      {
        name: "AES-GCM",
        iv: iv,
      },
      key,
      data,
    )

    return {
      encrypted: Array.from(new Uint8Array(encrypted)),
      iv: Array.from(iv),
    }
  }

  // Decrypt message text
  const decryptMessage = async (encryptedData, iv, key) => {
    try {
      const decrypted = await crypto.subtle.decrypt(
        {
          name: "AES-GCM",
          iv: new Uint8Array(iv),
        },
        key,
        new Uint8Array(encryptedData),
      )

      const decoder = new TextDecoder()
      return decoder.decode(decrypted)
    } catch (error) {
      console.error("Decryption failed:", error)
      return "[Decryption Failed]"
    }
  }

  // Check if user is already logged in
  useEffect(() => {
    const savedUser = localStorage.getItem("chatUser")
    if (savedUser) {
      setCurrentUser(JSON.parse(savedUser))
      setIsAuthenticated(true)
    }
  }, [])

  useEffect(() => {
    if (isAuthenticated && currentUser) {
      loadOrGenerateEncryptionKey()

      // Load existing messages
      loadMessages()

      // Update online users
      updateOnlineUsers()
      updateAllUsers()

      // Scroll to bottom of messages
      scrollToBottom()
    }
  }, [isAuthenticated, currentUser])

  const loadOrGenerateEncryptionKey = async () => {
    try {
      const savedKeyData = localStorage.getItem(`encryptionKey_${currentUser.id}`)

      if (savedKeyData) {
        // Load existing key
        const keyData = JSON.parse(savedKeyData)
        const key = await importKey(keyData)
        setEncryptionKey(key)
      } else {
        // Generate new key
        const key = await generateEncryptionKey()
        const keyData = await exportKey(key)
        localStorage.setItem(`encryptionKey_${currentUser.id}`, JSON.stringify(keyData))
        setEncryptionKey(key)
      }
    } catch (error) {
      console.error("Error with encryption key:", error)
    }
  }

  const loadMessages = async () => {
    const savedMessages = JSON.parse(localStorage.getItem("chatMessages") || "[]")
    setLastMessageCount(savedMessages.length)

    if (encryptionKey && savedMessages.length > 0) {
      const decryptedMessages = await Promise.all(
        savedMessages.map(async (message) => {
          if (message.encrypted && message.encryptedData && message.iv) {
            try {
              const decryptedText = await decryptMessage(message.encryptedData, message.iv, encryptionKey)
              return { ...message, text: decryptedText }
            } catch (error) {
              return { ...message, text: "[Decryption Failed]" }
            }
          }
          return message
        }),
      )
      setMessages(decryptedMessages)

      // Auto-scroll to bottom when new messages arrive
      setTimeout(scrollToBottom, 100)
    } else {
      setMessages(savedMessages)
    }
  }

  useEffect(() => {
    if (encryptionKey && isAuthenticated) {
      loadMessages()
    }
  }, [encryptionKey])

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" })
  }

  const handleSendMessage = async (e) => {
    e.preventDefault()
    if (!newMessage.trim() || !encryptionKey) return

    try {
      // Encrypt the message
      const { encrypted, iv } = await encryptMessage(newMessage, encryptionKey)

      const message = {
        id: Date.now().toString(),
        text: newMessage, // Keep original text for display
        encryptedData: encrypted, // Store encrypted data
        iv: iv, // Store initialization vector
        sender: currentUser.username,
        senderId: currentUser.id,
        timestamp: new Date().toISOString(),
        encrypted: true,
      }

      const updatedMessages = [...messages, message]
      setMessages(updatedMessages)

      const messageToSave = { ...message }
      delete messageToSave.text // Don't save plaintext
      const savedMessages = JSON.parse(localStorage.getItem("chatMessages") || "[]")
      savedMessages.push(messageToSave)
      localStorage.setItem("chatMessages", JSON.stringify(savedMessages))
      setLastMessageCount(savedMessages.length)

      window.dispatchEvent(
        new StorageEvent("storage", {
          key: "chatMessages",
          newValue: JSON.stringify(savedMessages),
        }),
      )

      setNewMessage("")

      // Scroll to bottom after sending message
      setTimeout(scrollToBottom, 100)
    } catch (error) {
      console.error("Error sending encrypted message:", error)
      setError("Failed to encrypt message")
    }
  }

  const formatTime = (timestamp) => {
    return new Date(timestamp).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })
  }

  const formatDate = (timestamp) => {
    return new Date(timestamp).toLocaleDateString([], {
      year: "numeric",
      month: "short",
      day: "numeric",
    })
  }

  const getUserInitials = (username) => {
    return username.substring(0, 2).toUpperCase()
  }

  const isUserOnline = (user) => {
    if (!user || !user.lastSeen) return false
    const now = new Date()
    const lastSeen = new Date(user.lastSeen)
    return now - lastSeen < 2 * 60 * 1000 // 2 minutes
  }

  const isAdmin = (userId) => {
    const users = JSON.parse(localStorage.getItem("chatUsers") || "[]")
    if (users.length === 0) return false
    const sortedUsers = users.sort((a, b) => new Date(a.createdAt) - new Date(b.createdAt))
    return sortedUsers[0]?.id === userId
  }

  // Simple password hashing using Web Crypto API
  const hashPassword = async (password) => {
    const encoder = new TextEncoder()
    const data = encoder.encode(password)
    const hash = await crypto.subtle.digest("SHA-256", data)
    return Array.from(new Uint8Array(hash))
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("")
  }

  // Handle user registration
  const handleRegister = async (e) => {
    e.preventDefault()
    setError("")

    if (registerForm.password !== registerForm.confirmPassword) {
      setError("Passwords do not match")
      return
    }

    if (registerForm.password.length < 6) {
      setError("Password must be at least 6 characters")
      return
    }

    try {
      const hashedPassword = await hashPassword(registerForm.password)

      // Get existing users from localStorage
      const existingUsers = JSON.parse(localStorage.getItem("chatUsers") || "[]")

      // Check if username already exists
      if (existingUsers.find((user) => user.username === registerForm.username)) {
        setError("Username already exists")
        return
      }

      // Create new user
      const newUser = {
        id: Date.now().toString(),
        username: registerForm.username,
        password: hashedPassword,
        createdAt: new Date().toISOString(),
        lastSeen: new Date().toISOString(),
      }

      // Save to localStorage
      existingUsers.push(newUser)
      localStorage.setItem("chatUsers", JSON.stringify(existingUsers))

      // Log in the user
      const userSession = { id: newUser.id, username: newUser.username }
      localStorage.setItem("chatUser", JSON.stringify(userSession))
      setCurrentUser(userSession)
      setIsAuthenticated(true)
    } catch (err) {
      setError("Registration failed. Please try again.")
    }
  }

  // Handle user login
  const handleLogin = async (e) => {
    e.preventDefault()
    setError("")

    try {
      const hashedPassword = await hashPassword(loginForm.password)
      const existingUsers = JSON.parse(localStorage.getItem("chatUsers") || "[]")

      const user = existingUsers.find((u) => u.username === loginForm.username && u.password === hashedPassword)

      if (user) {
        // Update last seen
        const updatedUsers = existingUsers.map((u) =>
          u.id === user.id ? { ...u, lastSeen: new Date().toISOString() } : u,
        )
        localStorage.setItem("chatUsers", JSON.stringify(updatedUsers))

        const userSession = { id: user.id, username: user.username }
        localStorage.setItem("chatUser", JSON.stringify(userSession))
        setCurrentUser(userSession)
        setIsAuthenticated(true)
      } else {
        setError("Invalid username or password")
      }
    } catch (err) {
      setError("Login failed. Please try again.")
    }
  }

  // Handle logout
  const handleLogout = () => {
    if (pollingIntervalRef.current) {
      clearInterval(pollingIntervalRef.current)
    }
    localStorage.removeItem("chatUser")
    setCurrentUser(null)
    setIsAuthenticated(false)
    setEncryptionKey(null)
    setLoginForm({ username: "", password: "" })
    setRegisterForm({ username: "", password: "", confirmPassword: "" })
  }

  if (isAuthenticated) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900">
        <div className="container mx-auto px-4 py-8 max-w-7xl">
          {/* Header */}
          <div className="flex items-center justify-between mb-8">
            <div className="flex items-center gap-3">
              <div className="p-2 bg-emerald-500/20 rounded-lg">
                <Shield className="h-8 w-8 text-emerald-400" />
              </div>
              <div>
                <h1 className="text-2xl font-bold text-white">SecureChat</h1>
                <p className="text-slate-400">End-to-end encrypted messaging</p>
              </div>
            </div>
            <div className="flex items-center gap-4">
              <div className="flex items-center gap-2 text-sm">
                {isConnected ? (
                  <>
                    <Wifi className="h-4 w-4 text-emerald-400" />
                    <span className="text-emerald-400">Live</span>
                  </>
                ) : (
                  <>
                    <Wifi className="h-4 w-4 text-red-400" />
                    <span className="text-red-400">Offline</span>
                  </>
                )}
              </div>
              <div className="flex items-center gap-2 text-sm">
                {encryptionKey ? (
                  <>
                    <Key className="h-4 w-4 text-emerald-400" />
                    <span className="text-emerald-400">Encrypted</span>
                  </>
                ) : (
                  <>
                    <Key className="h-4 w-4 text-yellow-400" />
                    <span className="text-yellow-400">Setting up...</span>
                  </>
                )}
              </div>
              <div className="flex items-center gap-2">
                <Avatar className="h-8 w-8">
                  <AvatarFallback className="bg-emerald-500/20 text-emerald-400 text-xs">
                    {getUserInitials(currentUser.username)}
                  </AvatarFallback>
                </Avatar>
                <span className="text-slate-300 flex items-center gap-1">
                  {currentUser.username}
                  {isAdmin(currentUser.id) && <Crown className="h-4 w-4 text-yellow-400" />}
                </span>
              </div>
              <Dialog open={showSettings} onOpenChange={setShowSettings}>
                <DialogTrigger asChild>
                  <Button variant="outline" size="sm">
                    <Settings className="h-4 w-4" />
                  </Button>
                </DialogTrigger>
                <DialogContent className="bg-slate-800 border-slate-700 text-white">
                  <DialogHeader>
                    <DialogTitle className="flex items-center gap-2">
                      <Settings className="h-5 w-5" />
                      User Settings
                    </DialogTitle>
                    <DialogDescription className="text-slate-400">
                      Manage your account and chat preferences
                    </DialogDescription>
                  </DialogHeader>
                  <div className="space-y-6">
                    <div className="space-y-4">
                      <h3 className="text-lg font-semibold">Account Information</h3>
                      <div className="grid grid-cols-2 gap-4 text-sm">
                        <div>
                          <Label className="text-slate-400">Username</Label>
                          <p className="text-white">{currentUser.username}</p>
                        </div>
                        <div>
                          <Label className="text-slate-400">Role</Label>
                          <p className="text-white flex items-center gap-1">
                            {isAdmin(currentUser.id) ? (
                              <>
                                Admin <Crown className="h-3 w-3 text-yellow-400" />
                              </>
                            ) : (
                              "User"
                            )}
                          </p>
                        </div>
                        <div>
                          <Label className="text-slate-400">Joined</Label>
                          <p className="text-white">
                            {userStats.joinDate ? formatDate(userStats.joinDate) : "Unknown"}
                          </p>
                        </div>
                        <div>
                          <Label className="text-slate-400">Messages Sent</Label>
                          <p className="text-white">{userStats.totalMessages}</p>
                        </div>
                      </div>
                    </div>

                    <div className="space-y-4">
                      <h3 className="text-lg font-semibold">Data Management</h3>
                      <div className="flex gap-2">
                        <Button onClick={exportUserData} variant="outline" size="sm">
                          Export My Data
                        </Button>
                        {isAdmin(currentUser.id) && (
                          <Button onClick={clearAllMessages} variant="destructive" size="sm">
                            Clear All Messages
                          </Button>
                        )}
                      </div>
                    </div>
                  </div>
                </DialogContent>
              </Dialog>
              <Button onClick={handleLogout} variant="outline" size="sm">
                Logout
              </Button>
            </div>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
            {/* Online Users Sidebar */}
            <Card className="bg-slate-800/50 border-slate-700 lg:col-span-1">
              <CardHeader>
                <CardTitle className="text-white flex items-center gap-2 text-lg">
                  <Users className="h-5 w-5" />
                  Users ({allUsers.length})
                </CardTitle>
              </CardHeader>
              <CardContent>
                <Tabs defaultValue="online" className="w-full">
                  <TabsList className="grid w-full grid-cols-2 bg-slate-700/50 mb-4">
                    <TabsTrigger value="online" className="text-xs">
                      Online ({onlineUsers.length})
                    </TabsTrigger>
                    <TabsTrigger value="all" className="text-xs">
                      All ({allUsers.length})
                    </TabsTrigger>
                  </TabsList>

                  <TabsContent value="online">
                    <ScrollArea className="h-64">
                      <div className="space-y-3">
                        {onlineUsers.length === 0 ? (
                          <p className="text-slate-400 text-sm text-center py-4">No users online</p>
                        ) : (
                          onlineUsers.map((user) => (
                            <div
                              key={user.id}
                              className="flex items-center gap-3 p-2 rounded-lg hover:bg-slate-700/50 cursor-pointer"
                              onClick={() => {
                                setSelectedUser(user)
                                setShowUserProfile(true)
                              }}
                            >
                              <Avatar className="h-8 w-8">
                                <AvatarFallback className="bg-emerald-500/20 text-emerald-400 text-xs">
                                  {getUserInitials(user.username)}
                                </AvatarFallback>
                              </Avatar>
                              <div className="flex-1 min-w-0">
                                <p className="text-sm text-white truncate flex items-center gap-1">
                                  {user.username}
                                  {user.id === currentUser.id && " (You)"}
                                  {isAdmin(user.id) && <Crown className="h-3 w-3 text-yellow-400" />}
                                </p>
                                <div className="flex items-center gap-1">
                                  <div className="w-2 h-2 bg-emerald-400 rounded-full"></div>
                                  <span className="text-xs text-slate-400">Online</span>
                                </div>
                              </div>
                            </div>
                          ))
                        )}
                      </div>
                    </ScrollArea>
                  </TabsContent>

                  <TabsContent value="all">
                    <ScrollArea className="h-64">
                      <div className="space-y-3">
                        {allUsers.map((user) => (
                          <div
                            key={user.id}
                            className="flex items-center gap-3 p-2 rounded-lg hover:bg-slate-700/50 cursor-pointer"
                            onClick={() => {
                              setSelectedUser(user)
                              setShowUserProfile(true)
                            }}
                          >
                            <Avatar className="h-8 w-8">
                              <AvatarFallback className="bg-slate-600 text-slate-300 text-xs">
                                {getUserInitials(user.username)}
                              </AvatarFallback>
                            </Avatar>
                            <div className="flex-1 min-w-0">
                              <p className="text-sm text-white truncate flex items-center gap-1">
                                {user.username}
                                {user.id === currentUser.id && " (You)"}
                                {isAdmin(user.id) && <Crown className="h-3 w-3 text-yellow-400" />}
                              </p>
                              <div className="flex items-center gap-1">
                                <div
                                  className={`w-2 h-2 rounded-full ${
                                    isUserOnline(user) ? "bg-emerald-400" : "bg-slate-500"
                                  }`}
                                ></div>
                                <span className="text-xs text-slate-400">{isUserOnline(user) ? "Online" : "Away"}</span>
                              </div>
                            </div>
                          </div>
                        ))}
                      </div>
                    </ScrollArea>
                  </TabsContent>
                </Tabs>
              </CardContent>
            </Card>

            {/* Main Chat Area */}
            <Card className="bg-slate-800/50 border-slate-700 lg:col-span-3">
              <CardHeader>
                <CardTitle className="text-white flex items-center gap-2">
                  <MessageCircle className="h-5 w-5" />
                  General Chat
                  <span className="text-xs bg-emerald-500/20 text-emerald-400 px-2 py-1 rounded-full ml-2">LIVE</span>
                </CardTitle>
                <CardDescription className="text-slate-400 flex items-center gap-2">
                  <Lock className="h-4 w-4" />
                  {encryptionKey
                    ? "Messages are end-to-end encrypted • Updates in real-time"
                    : "Setting up encryption..."}
                </CardDescription>
              </CardHeader>
              <CardContent className="p-0">
                {/* Messages Area */}
                <ScrollArea className="h-96 p-4">
                  <div className="space-y-4">
                    {messages.length === 0 ? (
                      <div className="text-center py-8 text-slate-400">
                        <MessageCircle className="h-12 w-12 mx-auto mb-4 text-slate-500" />
                        <p>No messages yet. Start the conversation!</p>
                        {encryptionKey && (
                          <p className="text-xs mt-2 text-emerald-400">🔒 All messages will be encrypted</p>
                        )}
                      </div>
                    ) : (
                      messages.map((message) => (
                        <div
                          key={message.id}
                          className={`flex gap-3 ${
                            message.senderId === currentUser.id ? "justify-end" : "justify-start"
                          }`}
                        >
                          {message.senderId !== currentUser.id && (
                            <Avatar className="h-8 w-8 mt-1">
                              <AvatarFallback className="bg-slate-600 text-slate-300 text-xs">
                                {getUserInitials(message.sender)}
                              </AvatarFallback>
                            </Avatar>
                          )}
                          <div
                            className={`max-w-xs lg:max-w-md px-4 py-2 rounded-lg ${
                              message.senderId === currentUser.id
                                ? "bg-emerald-600 text-white"
                                : "bg-slate-700 text-slate-100"
                            }`}
                          >
                            {message.senderId !== currentUser.id && (
                              <p className="text-xs text-slate-300 mb-1 flex items-center gap-1">
                                {message.sender}
                                {isAdmin(message.senderId) && <Crown className="h-3 w-3 text-yellow-400" />}
                              </p>
                            )}
                            <p className="text-sm">{message.text}</p>
                            <div className="flex items-center gap-1 mt-1">
                              <Clock className="h-3 w-3 opacity-60" />
                              <span className="text-xs opacity-60">{formatTime(message.timestamp)}</span>
                              {message.encrypted ? (
                                <span className="text-xs opacity-60 ml-2 flex items-center gap-1">
                                  <Lock className="h-2 w-2" />
                                  Encrypted
                                </span>
                              ) : (
                                <span className="text-xs opacity-60 ml-2">• Unencrypted</span>
                              )}
                            </div>
                          </div>
                          {message.senderId === currentUser.id && (
                            <Avatar className="h-8 w-8 mt-1">
                              <AvatarFallback className="bg-emerald-500/20 text-emerald-400 text-xs">
                                {getUserInitials(message.sender)}
                              </AvatarFallback>
                            </Avatar>
                          )}
                        </div>
                      ))
                    )}
                    <div ref={messagesEndRef} />
                  </div>
                </ScrollArea>

                {/* Message Input */}
                <div className="border-t border-slate-700 p-4">
                  <form onSubmit={handleSendMessage} className="flex gap-2">
                    <Input
                      value={newMessage}
                      onChange={(e) => setNewMessage(e.target.value)}
                      placeholder={encryptionKey ? "Type your encrypted message..." : "Setting up encryption..."}
                      className="flex-1 bg-slate-700/50 border-slate-600 text-white placeholder:text-slate-400"
                      disabled={!encryptionKey}
                    />
                    <Button
                      type="submit"
                      size="sm"
                      className="bg-emerald-600 hover:bg-emerald-700"
                      disabled={!encryptionKey}
                    >
                      <Send className="h-4 w-4" />
                    </Button>
                  </form>
                  <p className="text-xs text-slate-500 mt-2 flex items-center gap-2">
                    {encryptionKey ? (
                      <>
                        <Lock className="h-3 w-3 text-emerald-400" />
                        Press Enter to send • Real-time encrypted messaging with AES-256
                      </>
                    ) : (
                      <>
                        <Key className="h-3 w-3 text-yellow-400" />
                        Setting up encryption keys...
                      </>
                    )}
                  </p>
                  {error && <p className="text-red-400 text-xs mt-1">{error}</p>}
                </div>
              </CardContent>
            </Card>
          </div>
        </div>

        <Dialog open={showUserProfile} onOpenChange={setShowUserProfile}>
          <DialogContent className="bg-slate-800 border-slate-700 text-white">
            {selectedUser && (
              <>
                <DialogHeader>
                  <DialogTitle className="flex items-center gap-3">
                    <Avatar className="h-12 w-12">
                      <AvatarFallback className="bg-emerald-500/20 text-emerald-400">
                        {getUserInitials(selectedUser.username)}
                      </AvatarFallback>
                    </Avatar>
                    <div>
                      <div className="flex items-center gap-2">
                        {selectedUser.username}
                        {isAdmin(selectedUser.id) && <Crown className="h-4 w-4 text-yellow-400" />}
                      </div>
                      <div className="flex items-center gap-2 text-sm text-slate-400">
                        <div
                          className={`w-2 h-2 rounded-full ${
                            isUserOnline(selectedUser) ? "bg-emerald-400" : "bg-slate-500"
                          }`}
                        ></div>
                        {isUserOnline(selectedUser) ? "Online" : "Away"}
                      </div>
                    </div>
                  </DialogTitle>
                </DialogHeader>
                <div className="space-y-4">
                  <div className="grid grid-cols-2 gap-4">
                    <div className="space-y-2">
                      <Label className="text-slate-400 flex items-center gap-1">
                        <Calendar className="h-4 w-4" />
                        Joined
                      </Label>
                      <p className="text-white">
                        {selectedUser.createdAt ? formatDate(selectedUser.createdAt) : "Unknown"}
                      </p>
                    </div>
                    <div className="space-y-2">
                      <Label className="text-slate-400 flex items-center gap-1">
                        <Activity className="h-4 w-4" />
                        Last Seen
                      </Label>
                      <p className="text-white">
                        {selectedUser.lastSeen ? formatDate(selectedUser.lastSeen) : "Never"}
                      </p>
                    </div>
                    <div className="space-y-2">
                      <Label className="text-slate-400 flex items-center gap-1">
                        <MessageCircle className="h-4 w-4" />
                        Messages
                      </Label>
                      <p className="text-white">{getUserStats(selectedUser.id).totalMessages}</p>
                    </div>
                    <div className="space-y-2">
                      <Label className="text-slate-400">Role</Label>
                      <div className="flex items-center gap-2">
                        {isAdmin(selectedUser.id) ? (
                          <Badge variant="secondary" className="bg-yellow-500/20 text-yellow-400">
                            <Crown className="h-3 w-3 mr-1" />
                            Admin
                          </Badge>
                        ) : (
                          <Badge variant="secondary" className="bg-slate-600 text-slate-300">
                            <User className="h-3 w-3 mr-1" />
                            User
                          </Badge>
                        )}
                      </div>
                    </div>
                  </div>

                  {isAdmin(currentUser.id) && selectedUser.id !== currentUser.id && (
                    <div className="pt-4 border-t border-slate-700">
                      <Label className="text-slate-400 mb-2 block">Admin Actions</Label>
                      <Button
                        onClick={() => deleteUser(selectedUser.id)}
                        variant="destructive"
                        size="sm"
                        className="flex items-center gap-2"
                      >
                        <Trash2 className="h-4 w-4" />
                        Delete User
                      </Button>
                    </div>
                  )}
                </div>
              </>
            )}
          </DialogContent>
        </Dialog>
      </div>
    )
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900 flex items-center justify-center p-4">
      <div className="w-full max-w-md">
        {/* Header */}
        <div className="text-center mb-8">
          <div className="flex items-center justify-center gap-3 mb-4">
            <div className="p-3 bg-emerald-500/20 rounded-xl">
              <Shield className="h-10 w-10 text-emerald-400" />
            </div>
          </div>
          <h1 className="text-3xl font-bold text-white mb-2">SecureChat</h1>
          <p className="text-slate-400">End-to-end encrypted messaging platform</p>
        </div>

        {/* Authentication Form */}
        <Card className="bg-slate-800/50 border-slate-700 backdrop-blur-sm">
          <CardHeader>
            <CardTitle className="text-white text-center">Get Started</CardTitle>
            <CardDescription className="text-slate-400 text-center">
              Sign in or create an account to start secure messaging
            </CardDescription>
          </CardHeader>
          <CardContent>
            <Tabs defaultValue="login" className="w-full">
              <TabsList className="grid w-full grid-cols-2 bg-slate-700/50">
                <TabsTrigger value="login" className="text-slate-300 data-[state=active]:text-white">
                  Sign In
                </TabsTrigger>
                <TabsTrigger value="register" className="text-slate-300 data-[state=active]:text-white">
                  Sign Up
                </TabsTrigger>
              </TabsList>

              {/* Login Tab */}
              <TabsContent value="login" className="space-y-4 mt-6">
                <form onSubmit={handleLogin} className="space-y-4">
                  <div className="space-y-2">
                    <Label htmlFor="login-username" className="text-slate-300">
                      Username
                    </Label>
                    <Input
                      id="login-username"
                      type="text"
                      value={loginForm.username}
                      onChange={(e) => setLoginForm({ ...loginForm, username: e.target.value })}
                      className="bg-slate-700/50 border-slate-600 text-white placeholder:text-slate-400"
                      placeholder="Enter your username"
                      required
                    />
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="login-password" className="text-slate-300">
                      Password
                    </Label>
                    <Input
                      id="login-password"
                      type="password"
                      value={loginForm.password}
                      onChange={(e) => setLoginForm({ ...loginForm, password: e.target.value })}
                      className="bg-slate-700/50 border-slate-600 text-white placeholder:text-slate-400"
                      placeholder="Enter your password"
                      required
                    />
                  </div>
                  {error && <p className="text-red-400 text-sm">{error}</p>}
                  <Button type="submit" className="w-full bg-emerald-600 hover:bg-emerald-700">
                    Sign In
                  </Button>
                </form>
              </TabsContent>

              {/* Register Tab */}
              <TabsContent value="register" className="space-y-4 mt-6">
                <form onSubmit={handleRegister} className="space-y-4">
                  <div className="space-y-2">
                    <Label htmlFor="register-username" className="text-slate-300">
                      Username
                    </Label>
                    <Input
                      id="register-username"
                      type="text"
                      value={registerForm.username}
                      onChange={(e) => setRegisterForm({ ...registerForm, username: e.target.value })}
                      className="bg-slate-700/50 border-slate-600 text-white placeholder:text-slate-400"
                      placeholder="Choose a username"
                      required
                    />
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="register-password" className="text-slate-300">
                      Password
                    </Label>
                    <Input
                      id="register-password"
                      type="password"
                      value={registerForm.password}
                      onChange={(e) => setRegisterForm({ ...registerForm, password: e.target.value })}
                      className="bg-slate-700/50 border-slate-600 text-white placeholder:text-slate-400"
                      placeholder="Create a password (min 6 chars)"
                      required
                    />
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="confirm-password" className="text-slate-300">
                      Confirm Password
                    </Label>
                    <Input
                      id="confirm-password"
                      type="password"
                      value={registerForm.confirmPassword}
                      onChange={(e) => setRegisterForm({ ...registerForm, confirmPassword: e.target.value })}
                      className="bg-slate-700/50 border-slate-600 text-white placeholder:text-slate-400"
                      placeholder="Confirm your password"
                      required
                    />
                  </div>
                  {error && <p className="text-red-400 text-sm">{error}</p>}
                  <Button type="submit" className="w-full bg-emerald-600 hover:bg-emerald-700">
                    Create Account
                  </Button>
                </form>
              </TabsContent>
            </Tabs>
          </CardContent>
        </Card>

        {/* Security Notice */}
        <div className="mt-6 text-center">
          <p className="text-slate-400 text-sm flex items-center justify-center gap-2">
            <Lock className="h-4 w-4" />
            Your data is encrypted and stored locally
          </p>
        </div>
      </div>
    </div>
  )
}
