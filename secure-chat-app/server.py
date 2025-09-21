#!/usr/bin/env python3
"""
Secure Chat Server - Socket-based Real-time Messaging
Handles multiple client connections and message broadcasting
"""

import socket
import threading
import json
import time
from datetime import datetime
from database import DatabaseManager
from encryption import EncryptionManager

class SecureChatServer:
    def __init__(self, host='localhost', port=12345):
        self.host = host
        self.port = port
        self.clients = {}  # {socket: {'username': str, 'user_id': int, 'encryption_key': str}}
        self.db_manager = DatabaseManager()
        self.server_socket = None
        self.running = False
        
    def start_server(self):
        """Start the chat server"""
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            self.running = True
            
            print(f"🚀 Secure Chat Server started on {self.host}:{self.port}")
            print("🔒 Waiting for client connections...")
            
            while self.running:
                try:
                    client_socket, address = self.server_socket.accept()
                    print(f"📱 New connection from {address}")
                    
                    # Start client handler thread
                    client_thread = threading.Thread(
                        target=self.handle_client,
                        args=(client_socket, address),
                        daemon=True
                    )
                    client_thread.start()
                    
                except socket.error as e:
                    if self.running:
                        print(f"❌ Socket error: {e}")
                    break
                    
        except Exception as e:
            print(f"❌ Server error: {e}")
        finally:
            self.stop_server()
    
    def handle_client(self, client_socket, address):
        """Handle individual client connection"""
        try:
            while self.running:
                # Receive data from client
                data = client_socket.recv(4096).decode('utf-8')
                if not data:
                    break
                
                try:
                    message = json.loads(data)
                    self.process_message(client_socket, message)
                except json.JSONDecodeError:
                    self.send_error(client_socket, "Invalid message format")
                    
        except socket.error as e:
            print(f"🔌 Client {address} disconnected: {e}")
        finally:
            self.disconnect_client(client_socket)
    
    def process_message(self, client_socket, message):
        """Process different types of messages from clients"""
        msg_type = message.get('type')
        
        if msg_type == 'auth':
            self.handle_authentication(client_socket, message)
        elif msg_type == 'chat_message':
            self.handle_chat_message(client_socket, message)
        elif msg_type == 'get_users':
            self.handle_get_users(client_socket)
        elif msg_type == 'get_messages':
            self.handle_get_messages(client_socket)
        else:
            self.send_error(client_socket, f"Unknown message type: {msg_type}")
    
    def handle_authentication(self, client_socket, message):
        """Handle client authentication"""
        username = message.get('username')
        password = message.get('password')
        
        if not username or not password:
            self.send_error(client_socket, "Username and password required")
            return
        
        success, user_data, auth_message = self.db_manager.authenticate_user(username, password)
        
        if success:
            # Store client info
            self.clients[client_socket] = {
                'username': user_data['username'],
                'user_id': user_data['id'],
                'encryption_key': user_data['encryption_key'],
                'is_admin': user_data['is_admin']
            }
            
            # Send success response
            response = {
                'type': 'auth_response',
                'success': True,
                'user_data': user_data,
                'message': auth_message
            }
            self.send_message(client_socket, response)
            
            # Notify other clients about new user
            self.broadcast_user_list()
            
            print(f"✅ User '{username}' authenticated successfully")
            
        else:
            response = {
                'type': 'auth_response',
                'success': False,
                'message': auth_message
            }
            self.send_message(client_socket, response)
    
    def handle_chat_message(self, client_socket, message):
        """Handle chat message from client"""
        if client_socket not in self.clients:
            self.send_error(client_socket, "Not authenticated")
            return
        
        encrypted_content = message.get('encrypted_content')
        if not encrypted_content:
            self.send_error(client_socket, "Message content required")
            return
        
        client_info = self.clients[client_socket]
        
        # Save message to database
        if self.db_manager.save_message(client_info['user_id'], encrypted_content):
            # Broadcast message to all connected clients
            broadcast_message = {
                'type': 'new_message',
                'sender_id': client_info['user_id'],
                'sender_username': client_info['username'],
                'encrypted_content': encrypted_content,
                'timestamp': datetime.now().isoformat()
            }
            
            self.broadcast_message(broadcast_message)
            print(f"📨 Message from {client_info['username']} broadcasted")
        else:
            self.send_error(client_socket, "Failed to save message")
    
    def handle_get_users(self, client_socket):
        """Send user list to client"""
        users = self.db_manager.get_all_users()
        
        # Add online status
        online_usernames = [info['username'] for info in self.clients.values()]
        for user in users:
            user['is_online'] = user['username'] in online_usernames
        
        response = {
            'type': 'users_list',
            'users': users
        }
        self.send_message(client_socket, response)
    
    def handle_get_messages(self, client_socket):
        """Send message history to client"""
        messages = self.db_manager.get_messages()
        
        response = {
            'type': 'messages_history',
            'messages': messages
        }
        self.send_message(client_socket, response)
    
    def send_message(self, client_socket, message):
        """Send message to specific client"""
        try:
            data = json.dumps(message).encode('utf-8')
            client_socket.send(data)
        except socket.error as e:
            print(f"❌ Failed to send message to client: {e}")
            self.disconnect_client(client_socket)
    
    def send_error(self, client_socket, error_message):
        """Send error message to client"""
        error_response = {
            'type': 'error',
            'message': error_message
        }
        self.send_message(client_socket, error_response)
    
    def broadcast_message(self, message):
        """Broadcast message to all connected clients"""
        disconnected_clients = []
        
        for client_socket in self.clients:
            try:
                self.send_message(client_socket, message)
            except:
                disconnected_clients.append(client_socket)
        
        # Clean up disconnected clients
        for client_socket in disconnected_clients:
            self.disconnect_client(client_socket)
    
    def broadcast_user_list(self):
        """Broadcast updated user list to all clients"""
        for client_socket in list(self.clients.keys()):
            self.handle_get_users(client_socket)
    
    def disconnect_client(self, client_socket):
        """Disconnect and clean up client"""
        if client_socket in self.clients:
            username = self.clients[client_socket]['username']
            del self.clients[client_socket]
            print(f"👋 User '{username}' disconnected")
            
            # Notify remaining clients about user list update
            self.broadcast_user_list()
        
        try:
            client_socket.close()
        except:
            pass
    
    def stop_server(self):
        """Stop the server and disconnect all clients"""
        print("🛑 Stopping server...")
        self.running = False
        
        # Disconnect all clients
        for client_socket in list(self.clients.keys()):
            self.disconnect_client(client_socket)
        
        # Close server socket
        if self.server_socket:
            try:
                self.server_socket.close()
            except:
                pass
        
        print("✅ Server stopped")

def main():
    """Main server entry point"""
    server = SecureChatServer()
    
    try:
        server.start_server()
    except KeyboardInterrupt:
        print("\n🛑 Server interrupted by user")
        server.stop_server()
    except Exception as e:
        print(f"❌ Server error: {e}")
        server.stop_server()

if __name__ == "__main__":
    main()
