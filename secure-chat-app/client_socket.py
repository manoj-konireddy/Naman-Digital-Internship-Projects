"""
Socket Client Manager for Real-time Communication
Handles connection to chat server and message exchange
"""

import socket
import threading
import json
import time
from queue import Queue

class SocketClient:
    def __init__(self, host='localhost', port=12345):
        self.host = host
        self.port = port
        self.socket = None
        self.connected = False
        self.message_queue = Queue()
        self.callbacks = {
            'auth_response': None,
            'new_message': None,
            'users_list': None,
            'messages_history': None,
            'error': None
        }
        
    def connect(self):
        """Connect to the chat server"""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.host, self.port))
            self.connected = True
            
            # Start message receiver thread
            receiver_thread = threading.Thread(target=self.receive_messages, daemon=True)
            receiver_thread.start()
            
            return True, "Connected to server"
            
        except socket.error as e:
            return False, f"Connection failed: {e}"
    
    def disconnect(self):
        """Disconnect from the server"""
        self.connected = False
        if self.socket:
            try:
                self.socket.close()
            except:
                pass
            self.socket = None
    
    def send_message(self, message):
        """Send message to server"""
        if not self.connected or not self.socket:
            return False
        
        try:
            data = json.dumps(message).encode('utf-8')
            self.socket.send(data)
            return True
        except socket.error as e:
            print(f"❌ Failed to send message: {e}")
            self.connected = False
            return False
    
    def receive_messages(self):
        """Receive messages from server (runs in background thread)"""
        while self.connected:
            try:
                data = self.socket.recv(4096).decode('utf-8')
                if not data:
                    break
                
                try:
                    message = json.loads(data)
                    self.handle_server_message(message)
                except json.JSONDecodeError as e:
                    print(f"❌ Invalid message from server: {e}")
                    
            except socket.error as e:
                if self.connected:
                    print(f"🔌 Connection lost: {e}")
                break
        
        self.connected = False
    
    def handle_server_message(self, message):
        """Handle different types of messages from server"""
        msg_type = message.get('type')
        
        if msg_type in self.callbacks and self.callbacks[msg_type]:
            try:
                self.callbacks[msg_type](message)
            except Exception as e:
                print(f"❌ Callback error for {msg_type}: {e}")
        else:
            # Store message in queue for polling
            self.message_queue.put(message)
    
    def set_callback(self, message_type, callback_function):
        """Set callback function for specific message types"""
        if message_type in self.callbacks:
            self.callbacks[message_type] = callback_function
    
    def authenticate(self, username, password):
        """Send authentication request"""
        auth_message = {
            'type': 'auth',
            'username': username,
            'password': password
        }
        return self.send_message(auth_message)
    
    def send_chat_message(self, encrypted_content):
        """Send chat message"""
        chat_message = {
            'type': 'chat_message',
            'encrypted_content': encrypted_content
        }
        return self.send_message(chat_message)
    
    def request_users(self):
        """Request user list from server"""
        request = {'type': 'get_users'}
        return self.send_message(request)
    
    def request_messages(self):
        """Request message history from server"""
        request = {'type': 'get_messages'}
        return self.send_message(request)
    
    def get_queued_message(self):
        """Get message from queue (non-blocking)"""
        try:
            return self.message_queue.get_nowait()
        except:
            return None
    
    def is_connected(self):
        """Check if connected to server"""
        return self.connected
