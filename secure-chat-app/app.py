from flask import Flask, render_template, request, jsonify, session
from flask_socketio import SocketIO, emit, join_room, leave_room
import sqlite3
import hashlib
import secrets
import os
from datetime import datetime
import json

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(16)
socketio = SocketIO(app, cors_allowed_origins="*")

# Database setup
def init_db():
    conn = sqlite3.connect('securechat.db')
    c = conn.cursor()
    
    # Users table
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  username TEXT UNIQUE NOT NULL,
                  password_hash TEXT NOT NULL,
                  salt TEXT NOT NULL,
                  is_admin BOOLEAN DEFAULT FALSE,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    
    # Messages table
    c.execute('''CREATE TABLE IF NOT EXISTS messages
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  sender_id INTEGER NOT NULL,
                  content TEXT NOT NULL,
                  encrypted BOOLEAN DEFAULT TRUE,
                  timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  FOREIGN KEY (sender_id) REFERENCES users (id))''')
    
    conn.commit()
    conn.close()

def hash_password(password, salt=None):
    if salt is None:
        salt = secrets.token_hex(32)
    
    # PBKDF2 with 100,000 iterations
    password_hash = hashlib.pbkdf2_hmac('sha256', 
                                       password.encode('utf-8'), 
                                       salt.encode('utf-8'), 
                                       100000)
    return password_hash.hex(), salt

def verify_password(password, stored_hash, salt):
    password_hash, _ = hash_password(password, salt)
    return password_hash == stored_hash

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    if not username or not password:
        return jsonify({'error': 'Username and password required'}), 400
    
    conn = sqlite3.connect('securechat.db')
    c = conn.cursor()
    
    # Check if username exists
    c.execute('SELECT id FROM users WHERE username = ?', (username,))
    if c.fetchone():
        conn.close()
        return jsonify({'error': 'Username already exists'}), 400
    
    # Hash password
    password_hash, salt = hash_password(password)
    
    # Check if this is the first user (make them admin)
    c.execute('SELECT COUNT(*) FROM users')
    user_count = c.fetchone()[0]
    is_admin = user_count == 0
    
    # Insert user
    c.execute('INSERT INTO users (username, password_hash, salt, is_admin) VALUES (?, ?, ?, ?)',
              (username, password_hash, salt, is_admin))
    
    user_id = c.lastrowid
    conn.commit()
    conn.close()
    
    session['user_id'] = user_id
    session['username'] = username
    session['is_admin'] = is_admin
    
    return jsonify({'success': True, 'user_id': user_id, 'username': username, 'is_admin': is_admin})

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    if not username or not password:
        return jsonify({'error': 'Username and password required'}), 400
    
    conn = sqlite3.connect('securechat.db')
    c = conn.cursor()
    
    c.execute('SELECT id, password_hash, salt, is_admin FROM users WHERE username = ?', (username,))
    user = c.fetchone()
    
    if not user or not verify_password(password, user[1], user[2]):
        conn.close()
        return jsonify({'error': 'Invalid credentials'}), 401
    
    # Update last seen
    c.execute('UPDATE users SET last_seen = CURRENT_TIMESTAMP WHERE id = ?', (user[0],))
    conn.commit()
    conn.close()
    
    session['user_id'] = user[0]
    session['username'] = username
    session['is_admin'] = user[3]
    
    return jsonify({'success': True, 'user_id': user[0], 'username': username, 'is_admin': user[3]})

@app.route('/api/messages', methods=['GET'])
def get_messages():
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    conn = sqlite3.connect('securechat.db')
    c = conn.cursor()
    
    c.execute('''SELECT m.id, m.content, m.timestamp, u.username, u.id as user_id
                 FROM messages m
                 JOIN users u ON m.sender_id = u.id
                 ORDER BY m.timestamp DESC LIMIT 50''')
    
    messages = []
    for row in c.fetchall():
        messages.append({
            'id': row[0],
            'content': row[1],
            'timestamp': row[2],
            'username': row[3],
            'user_id': row[4]
        })
    
    conn.close()
    return jsonify(messages[::-1])  # Reverse to show oldest first

@app.route('/api/users', methods=['GET'])
def get_users():
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    conn = sqlite3.connect('securechat.db')
    c = conn.cursor()
    
    c.execute('SELECT id, username, is_admin, last_seen FROM users ORDER BY username')
    users = []
    for row in c.fetchall():
        users.append({
            'id': row[0],
            'username': row[1],
            'is_admin': row[2],
            'last_seen': row[3]
        })
    
    conn.close()
    return jsonify(users)

@app.route('/api/admin/clear-messages', methods=['POST'])
def clear_messages():
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    conn = sqlite3.connect('securechat.db')
    c = conn.cursor()
    
    # Check if user is admin
    c.execute('SELECT is_admin FROM users WHERE id = ?', (session['user_id'],))
    user = c.fetchone()
    
    if not user or not user[0]:
        conn.close()
        return jsonify({'error': 'Admin access required'}), 403
    
    # Clear all messages
    c.execute('DELETE FROM messages')
    conn.commit()
    conn.close()
    
    return jsonify({'success': True})

@app.route('/api/admin/user-stats', methods=['GET'])
def get_user_stats():
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    conn = sqlite3.connect('securechat.db')
    c = conn.cursor()
    
    # Check if user is admin
    c.execute('SELECT is_admin FROM users WHERE id = ?', (session['user_id'],))
    user = c.fetchone()
    
    if not user or not user[0]:
        conn.close()
        return jsonify({'error': 'Admin access required'}), 403
    
    # Get statistics
    c.execute('SELECT COUNT(*) FROM users')
    total_users = c.fetchone()[0]
    
    c.execute('SELECT COUNT(*) FROM messages')
    total_messages = c.fetchone()[0]
    
    c.execute('SELECT username, is_admin, last_seen FROM users ORDER BY last_seen DESC LIMIT 10')
    recent_users = []
    for row in c.fetchall():
        recent_users.append({
            'username': row[0],
            'is_admin': row[1],
            'last_seen': row[2]
        })
    
    conn.close()
    
    return jsonify({
        'total_users': total_users,
        'total_messages': total_messages,
        'recent_users': recent_users
    })

@app.route('/api/admin/export-data', methods=['GET'])
def export_data():
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    conn = sqlite3.connect('securechat.db')
    c = conn.cursor()
    
    # Check if user is admin
    c.execute('SELECT is_admin FROM users WHERE id = ?', (session['user_id'],))
    user = c.fetchone()
    
    if not user or not user[0]:
        conn.close()
        return jsonify({'error': 'Admin access required'}), 403
    
    # Export all data
    c.execute('SELECT id, username, is_admin, created_at, last_seen FROM users')
    users = []
    for row in c.fetchall():
        users.append({
            'id': row[0],
            'username': row[1],
            'is_admin': row[2],
            'created_at': row[3],
            'last_seen': row[4]
        })
    
    c.execute('''SELECT m.id, m.content, m.timestamp, u.username
                 FROM messages m
                 JOIN users u ON m.sender_id = u.id
                 ORDER BY m.timestamp''')
    messages = []
    for row in c.fetchall():
        messages.append({
            'id': row[0],
            'content': row[1],
            'timestamp': row[2],
            'username': row[3]
        })
    
    conn.close()
    
    return jsonify({
        'export_date': datetime.now().isoformat(),
        'users': users,
        'messages': messages
    })

# WebSocket events
@socketio.on('connect')
def on_connect():
    if 'user_id' in session:
        join_room('chat')
        emit('user_connected', {
            'username': session['username'],
            'user_id': session['user_id']
        }, room='chat')

@socketio.on('disconnect')
def on_disconnect():
    if 'user_id' in session:
        leave_room('chat')
        emit('user_disconnected', {
            'username': session['username'],
            'user_id': session['user_id']
        }, room='chat')

@socketio.on('send_message')
def handle_message(data):
    if 'user_id' not in session:
        return
    
    content = data.get('content', '').strip()
    if not content:
        return
    
    # Store message in database
    conn = sqlite3.connect('securechat.db')
    c = conn.cursor()
    c.execute('INSERT INTO messages (sender_id, content) VALUES (?, ?)',
              (session['user_id'], content))
    message_id = c.lastrowid
    conn.commit()
    conn.close()
    
    # Broadcast message
    emit('new_message', {
        'id': message_id,
        'content': content,
        'username': session['username'],
        'user_id': session['user_id'],
        'timestamp': datetime.now().isoformat()
    }, room='chat')

if __name__ == '__main__':
    init_db()
    
    cert_path = 'certs/cert.pem'
    key_path = 'certs/key.pem'
    
    if os.path.exists(cert_path) and os.path.exists(key_path):
        print("🔒 Starting SecureChat with HTTPS on https://localhost:5000")
        print("📋 SSL Certificate found - secure connection enabled!")
        socketio.run(app, 
                    debug=True, 
                    host='0.0.0.0', 
                    port=5000,
                    certfile=cert_path,
                    keyfile=key_path)
    else:
        print("⚠️  Starting SecureChat with HTTP on http://localhost:5000")
        print("🔧 To enable HTTPS, run: python generate_cert.py")
        socketio.run(app, debug=True, host='0.0.0.0', port=5000)
