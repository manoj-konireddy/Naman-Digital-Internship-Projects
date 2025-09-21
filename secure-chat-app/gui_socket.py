"""
Enhanced GUI with Socket-based Real-time Messaging
Replaces polling with true real-time communication
"""

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import threading
from datetime import datetime
from database import DatabaseManager
from encryption import EncryptionManager
from client_socket import SocketClient

class SecureChatGUISocket:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Secure Chat - Real-time Socket Version")
        self.root.geometry("1000x700")
        self.root.configure(bg='#1a1a1a')
        
        # Initialize managers
        self.db_manager = DatabaseManager()
        self.encryption_manager = EncryptionManager()
        self.socket_client = SocketClient()
        
        # User session data
        self.current_user = None
        self.is_logged_in = False
        self.server_mode = False
        
        # Configure styles
        self.setup_styles()
        
        # Setup socket callbacks
        self.setup_socket_callbacks()
        
        # Create main container
        self.main_frame = tk.Frame(self.root, bg='#1a1a1a')
        self.main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Show connection screen initially
        self.show_connection_screen()
    
    def setup_styles(self):
        """Configure custom styles for the application"""
        style = ttk.Style()
        style.theme_use('clam')
        
        # Configure custom styles
        style.configure('Title.TLabel', 
                       background='#1a1a1a', 
                       foreground='#00ff88', 
                       font=('Arial', 16, 'bold'))
        
        style.configure('Subtitle.TLabel', 
                       background='#1a1a1a', 
                       foreground='#ffffff', 
                       font=('Arial', 10))
        
        style.configure('Custom.TButton',
                       background='#00ff88',
                       foreground='#000000',
                       font=('Arial', 10, 'bold'),
                       borderwidth=0)
        
        style.map('Custom.TButton',
                 background=[('active', '#00cc66')])
        
        style.configure('Danger.TButton',
                       background='#ff4444',
                       foreground='#ffffff',
                       font=('Arial', 9, 'bold'))
        
        style.configure('Custom.TEntry',
                       fieldbackground='#2d2d2d',
                       foreground='#ffffff',
                       borderwidth=1,
                       insertcolor='#ffffff')
    
    def setup_socket_callbacks(self):
        """Setup callbacks for socket messages"""
        self.socket_client.set_callback('auth_response', self.handle_auth_response)
        self.socket_client.set_callback('new_message', self.handle_new_message)
        self.socket_client.set_callback('users_list', self.handle_users_list)
        self.socket_client.set_callback('messages_history', self.handle_messages_history)
        self.socket_client.set_callback('error', self.handle_server_error)
    
    def clear_frame(self):
        """Clear all widgets from main frame"""
        for widget in self.main_frame.winfo_children():
            widget.destroy()
    
    def show_connection_screen(self):
        """Display connection mode selection"""
        self.clear_frame()
        
        # Title
        title_label = ttk.Label(self.main_frame, text="🔒 SECURE CHAT - SOCKET VERSION", style='Title.TLabel')
        title_label.pack(pady=(50, 10))
        
        subtitle_label = ttk.Label(self.main_frame, text="Real-time Socket-based Communication", style='Subtitle.TLabel')
        subtitle_label.pack(pady=(0, 30))
        
        # Connection mode frame
        mode_frame = tk.Frame(self.main_frame, bg='#2d2d2d', relief=tk.RAISED, bd=2)
        mode_frame.pack(pady=20, padx=200, fill=tk.X)
        
        mode_title = ttk.Label(mode_frame, text="Connection Mode", style='Title.TLabel')
        mode_title.pack(pady=20)
        
        # Server mode button
        server_btn = ttk.Button(mode_frame, text="START AS SERVER", style='Custom.TButton', 
                               command=self.start_server_mode)
        server_btn.pack(pady=10)
        
        # Client mode button
        client_btn = ttk.Button(mode_frame, text="CONNECT AS CLIENT", style='Custom.TButton', 
                               command=self.start_client_mode)
        client_btn.pack(pady=(0, 20))
        
        # Info
        info_label = ttk.Label(self.main_frame, 
                              text="Server Mode: Start a chat server for others to connect\nClient Mode: Connect to an existing chat server", 
                              style='Subtitle.TLabel')
        info_label.pack(pady=20)
    
    def start_server_mode(self):
        """Start in server mode"""
        self.server_mode = True
        
        # Start server in background thread
        server_thread = threading.Thread(target=self.run_server, daemon=True)
        server_thread.start()
        
        # Connect as client to own server
        threading.Timer(1.0, self.connect_to_server).start()
        
        messagebox.showinfo("Server Started", "Chat server started on localhost:12345\nOthers can connect as clients!")
    
    def start_client_mode(self):
        """Start in client mode"""
        self.server_mode = False
        self.connect_to_server()
    
    def run_server(self):
        """Run the chat server"""
        from server import SecureChatServer
        server = SecureChatServer()
        try:
            server.start_server()
        except Exception as e:
            print(f"Server error: {e}")
    
    def connect_to_server(self):
        """Connect to chat server"""
        success, message = self.socket_client.connect()
        
        if success:
            self.show_login_screen()
        else:
            messagebox.showerror("Connection Failed", f"Could not connect to server:\n{message}")
            if not self.server_mode:
                self.show_connection_screen()
    
    def show_login_screen(self):
        """Display login/registration screen"""
        self.clear_frame()
        
        # Connection status
        status_text = "🟢 Connected to Server" if self.socket_client.is_connected() else "🔴 Disconnected"
        status_label = ttk.Label(self.main_frame, text=status_text, style='Subtitle.TLabel')
        status_label.pack(pady=10)
        
        # Title
        title_label = ttk.Label(self.main_frame, text="🔒 SECURE CHAT", style='Title.TLabel')
        title_label.pack(pady=(20, 10))
        
        subtitle_label = ttk.Label(self.main_frame, text="Socket-based Real-time Messaging", style='Subtitle.TLabel')
        subtitle_label.pack(pady=(0, 30))
        
        # Login form frame
        login_frame = tk.Frame(self.main_frame, bg='#2d2d2d', relief=tk.RAISED, bd=2)
        login_frame.pack(pady=20, padx=200, fill=tk.X)
        
        # Form title
        form_title = ttk.Label(login_frame, text="Authentication", style='Title.TLabel')
        form_title.pack(pady=20)
        
        # Username field
        tk.Label(login_frame, text="Username:", bg='#2d2d2d', fg='#ffffff', font=('Arial', 10)).pack(pady=(10, 5))
        self.username_entry = ttk.Entry(login_frame, style='Custom.TEntry', font=('Arial', 12))
        self.username_entry.pack(pady=(0, 10), padx=20, fill=tk.X)
        
        # Password field
        tk.Label(login_frame, text="Password:", bg='#2d2d2d', fg='#ffffff', font=('Arial', 10)).pack(pady=(10, 5))
        self.password_entry = ttk.Entry(login_frame, show="*", style='Custom.TEntry', font=('Arial', 12))
        self.password_entry.pack(pady=(0, 20), padx=20, fill=tk.X)
        
        # Buttons frame
        buttons_frame = tk.Frame(login_frame, bg='#2d2d2d')
        buttons_frame.pack(pady=(0, 20))
        
        login_btn = ttk.Button(buttons_frame, text="LOGIN", style='Custom.TButton', command=self.login)
        login_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        register_btn = ttk.Button(buttons_frame, text="REGISTER", style='Custom.TButton', command=self.register)
        register_btn.pack(side=tk.LEFT)
        
        # Bind Enter key to login
        self.root.bind('<Return>', lambda event: self.login())
    
    def login(self):
        """Handle user login via socket"""
        username = self.username_entry.get().strip()
        password = self.password_entry.get()
        
        if not username or not password:
            messagebox.showerror("Error", "Please enter both username and password")
            return
        
        if not self.socket_client.is_connected():
            messagebox.showerror("Error", "Not connected to server")
            return
        
        # Send authentication request
        self.socket_client.authenticate(username, password)
    
    def register(self):
        """Handle user registration (local database)"""
        username = self.username_entry.get().strip()
        password = self.password_entry.get()
        
        if not username or not password:
            messagebox.showerror("Error", "Please enter both username and password")
            return
        
        if len(password) < 6:
            messagebox.showerror("Error", "Password must be at least 6 characters long")
            return
        
        success, message = self.db_manager.register_user(username, password)
        
        if success:
            messagebox.showinfo("Success", "Account created successfully! You can now login.")
            self.password_entry.delete(0, tk.END)
        else:
            messagebox.showerror("Registration Failed", message)
    
    def handle_auth_response(self, message):
        """Handle authentication response from server"""
        def update_ui():
            if message['success']:
                self.current_user = message['user_data']
                self.is_logged_in = True
                self.encryption_manager.set_key(self.current_user['encryption_key'])
                
                messagebox.showinfo("Success", f"Welcome back, {self.current_user['username']}!")
                self.show_chat_screen()
            else:
                messagebox.showerror("Login Failed", message['message'])
        
        self.root.after(0, update_ui)
    
    def show_chat_screen(self):
        """Display main chat interface"""
        self.clear_frame()
        
        # Header frame
        header_frame = tk.Frame(self.main_frame, bg='#2d2d2d', height=60)
        header_frame.pack(fill=tk.X, pady=(0, 10))
        header_frame.pack_propagate(False)
        
        # User info with real-time status
        user_info = f"🟢 {self.current_user['username']} (REAL-TIME)"
        if self.current_user['is_admin']:
            user_info += " (ADMIN)"
        
        user_label = tk.Label(header_frame, text=user_info, bg='#2d2d2d', fg='#00ff88', 
                             font=('Arial', 12, 'bold'))
        user_label.pack(side=tk.LEFT, padx=20, pady=15)
        
        # Logout button
        logout_btn = ttk.Button(header_frame, text="LOGOUT", style='Danger.TButton', command=self.logout)
        logout_btn.pack(side=tk.RIGHT, padx=20, pady=15)
        
        # Main content frame
        content_frame = tk.Frame(self.main_frame, bg='#1a1a1a')
        content_frame.pack(fill=tk.BOTH, expand=True)
        
        # Chat area (left side)
        chat_frame = tk.Frame(content_frame, bg='#1a1a1a')
        chat_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 10))
        
        # Messages display
        self.messages_text = scrolledtext.ScrolledText(
            chat_frame, 
            bg='#2d2d2d', 
            fg='#ffffff',
            font=('Consolas', 10),
            state=tk.DISABLED,
            wrap=tk.WORD
        )
        self.messages_text.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        # Message input frame
        input_frame = tk.Frame(chat_frame, bg='#1a1a1a')
        input_frame.pack(fill=tk.X)
        
        self.message_entry = tk.Entry(input_frame, bg='#2d2d2d', fg='#ffffff', 
                                     font=('Arial', 11), insertbackground='#ffffff')
        self.message_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10))
        
        send_btn = ttk.Button(input_frame, text="SEND", style='Custom.TButton', command=self.send_message)
        send_btn.pack(side=tk.RIGHT)
        
        # Users panel (right side)
        users_frame = tk.Frame(content_frame, bg='#2d2d2d', width=250)
        users_frame.pack(side=tk.RIGHT, fill=tk.Y)
        users_frame.pack_propagate(False)
        
        users_title = tk.Label(users_frame, text="👥 REAL-TIME USERS", bg='#2d2d2d', fg='#00ff88', 
                              font=('Arial', 11, 'bold'))
        users_title.pack(pady=10)
        
        self.users_listbox = tk.Listbox(users_frame, bg='#1a1a1a', fg='#ffffff', 
                                       font=('Arial', 10), selectbackground='#00ff88')
        self.users_listbox.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))
        
        # Bind Enter key to send message
        self.message_entry.bind('<Return>', lambda event: self.send_message())
        
        # Request initial data
        self.socket_client.request_messages()
        self.socket_client.request_users()
    
    def send_message(self):
        """Send a new message via socket"""
        message_text = self.message_entry.get().strip()
        if not message_text:
            return
        
        try:
            # Encrypt the message
            encrypted_message = self.encryption_manager.encrypt_message(message_text)
            
            # Send via socket
            if self.socket_client.send_chat_message(encrypted_message):
                self.message_entry.delete(0, tk.END)
            else:
                messagebox.showerror("Error", "Failed to send message")
                
        except Exception as e:
            messagebox.showerror("Encryption Error", f"Failed to encrypt message: {str(e)}")
    
    def handle_new_message(self, message):
        """Handle new message from server"""
        def update_ui():
            if hasattr(self, 'messages_text'):
                # Decrypt message
                decrypted_content = self.encryption_manager.decrypt_message(message['encrypted_content'])
                
                # Format timestamp
                timestamp = datetime.fromisoformat(message['timestamp']).strftime("%H:%M:%S")
                
                # Format message
                sender = message['sender_username']
                if message['sender_id'] == self.current_user['id']:
                    sender = "You"
                
                formatted_message = f"[{timestamp}] {sender}: {decrypted_content}\n"
                
                self.messages_text.config(state=tk.NORMAL)
                self.messages_text.insert(tk.END, formatted_message)
                self.messages_text.config(state=tk.DISABLED)
                self.messages_text.see(tk.END)  # Scroll to bottom
        
        self.root.after(0, update_ui)
    
    def handle_messages_history(self, message):
        """Handle message history from server"""
        def update_ui():
            if hasattr(self, 'messages_text'):
                self.messages_text.config(state=tk.NORMAL)
                self.messages_text.delete(1.0, tk.END)
                
                for msg in message['messages']:
                    # Decrypt message
                    decrypted_content = self.encryption_manager.decrypt_message(msg['encrypted_content'])
                    
                    # Format timestamp
                    timestamp = datetime.fromisoformat(msg['timestamp']).strftime("%H:%M:%S")
                    
                    # Format message
                    sender = msg['sender_username']
                    if msg['sender_id'] == self.current_user['id']:
                        sender = "You"
                    
                    formatted_message = f"[{timestamp}] {sender}: {decrypted_content}\n"
                    self.messages_text.insert(tk.END, formatted_message)
                
                self.messages_text.config(state=tk.DISABLED)
                self.messages_text.see(tk.END)
        
        self.root.after(0, update_ui)
    
    def handle_users_list(self, message):
        """Handle users list from server"""
        def update_ui():
            if hasattr(self, 'users_listbox'):
                self.users_listbox.delete(0, tk.END)
                
                for user in message['users']:
                    display_name = user['username']
                    if user['is_admin']:
                        display_name += " 👑"
                    if user['id'] == self.current_user['id']:
                        display_name += " (You)"
                    if user.get('is_online', False):
                        display_name = "🟢 " + display_name
                    else:
                        display_name = "🔴 " + display_name
                    
                    self.users_listbox.insert(tk.END, display_name)
        
        self.root.after(0, update_ui)
    
    def handle_server_error(self, message):
        """Handle error from server"""
        def show_error():
            messagebox.showerror("Server Error", message['message'])
        
        self.root.after(0, show_error)
    
    def logout(self):
        """Handle user logout"""
        self.current_user = None
        self.is_logged_in = False
        self.encryption_manager = EncryptionManager()
        self.socket_client.disconnect()
        self.show_connection_screen()
    
    def run(self):
        """Start the GUI application"""
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.root.mainloop()
    
    def on_closing(self):
        """Handle window closing"""
        self.socket_client.disconnect()
        self.root.destroy()

if __name__ == "__main__":
    app = SecureChatGUISocket()
    app.run()
