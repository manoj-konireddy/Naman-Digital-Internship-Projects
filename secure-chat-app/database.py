import sqlite3
import hashlib
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import base64
from datetime import datetime

class DatabaseManager:
    def __init__(self, db_name="secure_chat.db"):
        self.db_name = db_name
        self.init_database()
    
    def init_database(self):
        """Initialize the database with required tables"""
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        
        # Users table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                salt TEXT NOT NULL,
                encryption_key TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_admin BOOLEAN DEFAULT FALSE
            )
        ''')
        
        # Messages table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender_id INTEGER NOT NULL,
                encrypted_content TEXT NOT NULL,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (sender_id) REFERENCES users (id)
            )
        ''')
        
        # Sessions table for active users
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                session_token TEXT UNIQUE NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def hash_password(self, password, salt=None):
        """Hash password using PBKDF2 with SHA-256"""
        if salt is None:
            salt = os.urandom(32)  # 32 bytes = 256 bits
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,  # OWASP recommended minimum
            backend=default_backend()
        )
        
        password_hash = kdf.derive(password.encode('utf-8'))
        return base64.b64encode(password_hash).decode('utf-8'), base64.b64encode(salt).decode('utf-8')
    
    def verify_password(self, password, stored_hash, stored_salt):
        """Verify password against stored hash"""
        salt = base64.b64decode(stored_salt.encode('utf-8'))
        password_hash, _ = self.hash_password(password, salt)
        return password_hash == stored_hash
    
    def generate_encryption_key(self):
        """Generate a unique encryption key for each user"""
        key = os.urandom(32)  # 256-bit key for AES-256
        return base64.b64encode(key).decode('utf-8')
    
    def register_user(self, username, password):
        """Register a new user"""
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        
        try:
            # Check if username already exists
            cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
            if cursor.fetchone():
                return False, "Username already exists"
            
            # Hash password and generate encryption key
            password_hash, salt = self.hash_password(password)
            encryption_key = self.generate_encryption_key()
            
            # Check if this is the first user (make them admin)
            cursor.execute("SELECT COUNT(*) FROM users")
            user_count = cursor.fetchone()[0]
            is_admin = user_count == 0
            
            # Insert new user
            cursor.execute('''
                INSERT INTO users (username, password_hash, salt, encryption_key, is_admin)
                VALUES (?, ?, ?, ?, ?)
            ''', (username, password_hash, salt, encryption_key, is_admin))
            
            conn.commit()
            return True, "User registered successfully"
            
        except sqlite3.Error as e:
            return False, f"Database error: {str(e)}"
        finally:
            conn.close()
    
    def authenticate_user(self, username, password):
        """Authenticate user login"""
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                SELECT id, password_hash, salt, encryption_key, is_admin 
                FROM users WHERE username = ?
            ''', (username,))
            
            user_data = cursor.fetchone()
            if not user_data:
                return False, None, "Invalid username or password"
            
            user_id, stored_hash, stored_salt, encryption_key, is_admin = user_data
            
            if self.verify_password(password, stored_hash, stored_salt):
                # Update last seen
                cursor.execute('''
                    UPDATE users SET last_seen = CURRENT_TIMESTAMP WHERE id = ?
                ''', (user_id,))
                conn.commit()
                
                return True, {
                    'id': user_id,
                    'username': username,
                    'encryption_key': encryption_key,
                    'is_admin': bool(is_admin)
                }, "Login successful"
            else:
                return False, None, "Invalid username or password"
                
        except sqlite3.Error as e:
            return False, None, f"Database error: {str(e)}"
        finally:
            conn.close()
    
    def get_all_users(self):
        """Get all registered users"""
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                SELECT id, username, created_at, last_seen, is_admin 
                FROM users ORDER BY username
            ''')
            users = cursor.fetchall()
            return [
                {
                    'id': user[0],
                    'username': user[1],
                    'created_at': user[2],
                    'last_seen': user[3],
                    'is_admin': bool(user[4])
                }
                for user in users
            ]
        except sqlite3.Error as e:
            print(f"Database error: {str(e)}")
            return []
        finally:
            conn.close()
    
    def save_message(self, sender_id, encrypted_content):
        """Save encrypted message to database"""
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                INSERT INTO messages (sender_id, encrypted_content)
                VALUES (?, ?)
            ''', (sender_id, encrypted_content))
            conn.commit()
            return True
        except sqlite3.Error as e:
            print(f"Database error: {str(e)}")
            return False
        finally:
            conn.close()
    
    def get_messages(self, limit=50):
        """Get recent messages with sender information"""
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                SELECT m.id, m.sender_id, u.username, m.encrypted_content, m.timestamp
                FROM messages m
                JOIN users u ON m.sender_id = u.id
                ORDER BY m.timestamp DESC
                LIMIT ?
            ''', (limit,))
            
            messages = cursor.fetchall()
            return [
                {
                    'id': msg[0],
                    'sender_id': msg[1],
                    'sender_username': msg[2],
                    'encrypted_content': msg[3],
                    'timestamp': msg[4]
                }
                for msg in reversed(messages)  # Reverse to show oldest first
            ]
        except sqlite3.Error as e:
            print(f"Database error: {str(e)}")
            return []
        finally:
            conn.close()
    
    def delete_user(self, user_id):
        """Delete a user (admin only)"""
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        
        try:
            # Delete user's messages first
            cursor.execute("DELETE FROM messages WHERE sender_id = ?", (user_id,))
            # Delete user's sessions
            cursor.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
            # Delete user
            cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
            conn.commit()
            return True
        except sqlite3.Error as e:
            print(f"Database error: {str(e)}")
            return False
        finally:
            conn.close()
    
    def clear_all_messages(self):
        """Clear all messages (admin only)"""
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        
        try:
            cursor.execute("DELETE FROM messages")
            conn.commit()
            return True
        except sqlite3.Error as e:
            print(f"Database error: {str(e)}")
            return False
        finally:
            conn.close()
