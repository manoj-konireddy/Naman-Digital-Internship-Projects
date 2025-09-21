import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import threading
from datetime import datetime
from database import DatabaseManager
from encryption import EncryptionManager

class SecureChatGUI:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Secure Chat - Cybersecurity Project")
        self.root.geometry("1000x700")
        self.root.configure(bg='#1a1a1a')
        
        # Initialize managers
        self.db_manager = DatabaseManager()
        self.encryption_manager = EncryptionManager()
        
        # User session data
        self.current_user = None
        self.is_logged_in = False
        
        # Configure styles
        self.setup_styles()
        
        # Create main container
        self.main_frame = tk.Frame(self.root, bg='#1a1a1a')
        self.main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Show login screen initially
        self.show_login_screen()
        
        # Start message refresh thread
        self.refresh_messages_thread()
    
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
    
    def clear_frame(self):
        """Clear all widgets from main frame"""
        for widget in self.main_frame.winfo_children():
            widget.destroy()
    
    def show_login_screen(self):
        """Display login/registration screen"""
        self.clear_frame()
        
        # Title
        title_label = ttk.Label(self.main_frame, text="🔒 SECURE CHAT", style='Title.TLabel')
        title_label.pack(pady=(50, 10))
        
        subtitle_label = ttk.Label(self.main_frame, text="Cybersecurity Project - End-to-End Encrypted Messaging", style='Subtitle.TLabel')
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
        
        # Security info
        security_frame = tk.Frame(self.main_frame, bg='#1a1a1a')
        security_frame.pack(pady=30)
        
        security_title = ttk.Label(security_frame, text="🛡️ Security Features", style='Title.TLabel')
        security_title.pack()
        
        features = [
            "• AES-256-GCM End-to-End Encryption",
            "• PBKDF2 Password Hashing (100,000 iterations)",
            "• SQLite Database with Secure Storage",
            "• Real-time Socket Communication",
            "• Admin User Management System"
        ]
        
        for feature in features:
            feature_label = ttk.Label(security_frame, text=feature, style='Subtitle.TLabel')
            feature_label.pack(pady=2)
        
        # Bind Enter key to login
        self.root.bind('<Return>', lambda event: self.login())
    
    def login(self):
        """Handle user login"""
        username = self.username_entry.get().strip()
        password = self.password_entry.get()
        
        if not username or not password:
            messagebox.showerror("Error", "Please enter both username and password")
            return
        
        success, user_data, message = self.db_manager.authenticate_user(username, password)
        
        if success:
            self.current_user = user_data
            self.is_logged_in = True
            self.encryption_manager.set_key(user_data['encryption_key'])
            
            # Test encryption
            test_success, test_message = self.encryption_manager.test_encryption()
            if not test_success:
                messagebox.showerror("Encryption Error", f"Encryption test failed: {test_message}")
                return
            
            messagebox.showinfo("Success", f"Welcome back, {username}!")
            self.show_chat_screen()
        else:
            messagebox.showerror("Login Failed", message)
    
    def register(self):
        """Handle user registration"""
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
            messagebox.showinfo("Success", f"Account created successfully! You can now login.")
            self.password_entry.delete(0, tk.END)
        else:
            messagebox.showerror("Registration Failed", message)
    
    def show_chat_screen(self):
        """Display main chat interface"""
        self.clear_frame()
        
        # Header frame
        header_frame = tk.Frame(self.main_frame, bg='#2d2d2d', height=60)
        header_frame.pack(fill=tk.X, pady=(0, 10))
        header_frame.pack_propagate(False)
        
        # User info
        user_info = f"🔒 {self.current_user['username']}"
        if self.current_user['is_admin']:
            user_info += " (ADMIN)"
        
        user_label = tk.Label(header_frame, text=user_info, bg='#2d2d2d', fg='#00ff88', 
                             font=('Arial', 12, 'bold'))
        user_label.pack(side=tk.LEFT, padx=20, pady=15)
        
        # Logout button
        logout_btn = ttk.Button(header_frame, text="LOGOUT", style='Danger.TButton', command=self.logout)
        logout_btn.pack(side=tk.RIGHT, padx=20, pady=15)
        
        # Settings button (admin only)
        if self.current_user['is_admin']:
            settings_btn = ttk.Button(header_frame, text="ADMIN PANEL", style='Custom.TButton', command=self.show_admin_panel)
            settings_btn.pack(side=tk.RIGHT, padx=(0, 10), pady=15)
        
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
        
        users_title = tk.Label(users_frame, text="👥 ONLINE USERS", bg='#2d2d2d', fg='#00ff88', 
                              font=('Arial', 11, 'bold'))
        users_title.pack(pady=10)
        
        self.users_listbox = tk.Listbox(users_frame, bg='#1a1a1a', fg='#ffffff', 
                                       font=('Arial', 10), selectbackground='#00ff88')
        self.users_listbox.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))
        
        # Bind Enter key to send message
        self.message_entry.bind('<Return>', lambda event: self.send_message())
        
        # Load initial data
        self.load_messages()
        self.load_users()
    
    def send_message(self):
        """Send a new message"""
        message_text = self.message_entry.get().strip()
        if not message_text:
            return
        
        try:
            # Encrypt the message
            encrypted_message = self.encryption_manager.encrypt_message(message_text)
            
            # Save to database
            if self.db_manager.save_message(self.current_user['id'], encrypted_message):
                self.message_entry.delete(0, tk.END)
                self.load_messages()  # Refresh messages
            else:
                messagebox.showerror("Error", "Failed to send message")
                
        except Exception as e:
            messagebox.showerror("Encryption Error", f"Failed to encrypt message: {str(e)}")
    
    def load_messages(self):
        """Load and display messages"""
        messages = self.db_manager.get_messages()
        
        self.messages_text.config(state=tk.NORMAL)
        self.messages_text.delete(1.0, tk.END)
        
        for msg in messages:
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
        self.messages_text.see(tk.END)  # Scroll to bottom
    
    def load_users(self):
        """Load and display online users"""
        users = self.db_manager.get_all_users()
        
        self.users_listbox.delete(0, tk.END)
        
        for user in users:
            display_name = user['username']
            if user['is_admin']:
                display_name += " 👑"
            if user['id'] == self.current_user['id']:
                display_name += " (You)"
            
            self.users_listbox.insert(tk.END, display_name)
    
    def show_admin_panel(self):
        """Show admin panel (admin only)"""
        if not self.current_user['is_admin']:
            messagebox.showerror("Access Denied", "Admin privileges required")
            return
        
        admin_window = tk.Toplevel(self.root)
        admin_window.title("Admin Panel")
        admin_window.geometry("400x300")
        admin_window.configure(bg='#1a1a1a')
        
        title_label = tk.Label(admin_window, text="🛡️ ADMIN PANEL", bg='#1a1a1a', fg='#ff4444', 
                              font=('Arial', 14, 'bold'))
        title_label.pack(pady=20)
        
        # Clear messages button
        clear_btn = ttk.Button(admin_window, text="CLEAR ALL MESSAGES", style='Danger.TButton',
                              command=self.clear_all_messages)
        clear_btn.pack(pady=10)
        
        # User management
        users_label = tk.Label(admin_window, text="User Management:", bg='#1a1a1a', fg='#ffffff', 
                              font=('Arial', 11, 'bold'))
        users_label.pack(pady=(20, 10))
        
        users = self.db_manager.get_all_users()
        for user in users:
            if user['id'] != self.current_user['id']:  # Don't show delete button for self
                user_frame = tk.Frame(admin_window, bg='#2d2d2d')
                user_frame.pack(fill=tk.X, padx=20, pady=2)
                
                user_label = tk.Label(user_frame, text=user['username'], bg='#2d2d2d', fg='#ffffff')
                user_label.pack(side=tk.LEFT, padx=10, pady=5)
                
                delete_btn = ttk.Button(user_frame, text="DELETE", style='Danger.TButton',
                                       command=lambda uid=user['id']: self.delete_user(uid, admin_window))
                delete_btn.pack(side=tk.RIGHT, padx=10, pady=5)
    
    def clear_all_messages(self):
        """Clear all messages (admin only)"""
        if messagebox.askyesno("Confirm", "Are you sure you want to delete ALL messages?"):
            if self.db_manager.clear_all_messages():
                messagebox.showinfo("Success", "All messages cleared")
                self.load_messages()
            else:
                messagebox.showerror("Error", "Failed to clear messages")
    
    def delete_user(self, user_id, admin_window):
        """Delete a user (admin only)"""
        if messagebox.askyesno("Confirm", "Are you sure you want to delete this user?"):
            if self.db_manager.delete_user(user_id):
                messagebox.showinfo("Success", "User deleted")
                self.load_users()
                admin_window.destroy()
                self.show_admin_panel()  # Refresh admin panel
            else:
                messagebox.showerror("Error", "Failed to delete user")
    
    def refresh_messages_thread(self):
        """Background thread to refresh messages periodically"""
        def refresh_loop():
            while True:
                if self.is_logged_in:
                    try:
                        self.root.after(0, self.load_messages)
                        self.root.after(0, self.load_users)
                    except:
                        pass  # Window might be closed
                threading.Event().wait(3)  # Wait 3 seconds
        
        thread = threading.Thread(target=refresh_loop, daemon=True)
        thread.start()
    
    def logout(self):
        """Handle user logout"""
        self.current_user = None
        self.is_logged_in = False
        self.encryption_manager = EncryptionManager()  # Reset encryption manager
        self.show_login_screen()
    
    def run(self):
        """Start the GUI application"""
        self.root.mainloop()

if __name__ == "__main__":
    app = SecureChatGUI()
    app.run()
