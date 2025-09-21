#!/usr/bin/env python3
"""
Secure Chat Application - Cybersecurity Project
End-to-End Encrypted Desktop Chat Application

Features:
- AES-256-GCM Encryption
- PBKDF2 Password Hashing
- SQLite Database
- Real-time Messaging
- Admin User Management

Author: Cybersecurity Student
"""

import sys
import os

# Add current directory to path for imports
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from gui import SecureChatGUI

def main():
    """Main entry point for the Secure Chat Application"""
    print("🔒 Starting Secure Chat Application...")
    print("📋 Cybersecurity Project - End-to-End Encrypted Messaging")
    print("🛡️ Features: AES-256-GCM, PBKDF2, SQLite, Real-time Messaging")
    print("-" * 60)
    
    try:
        # Create and run the GUI application
        app = SecureChatGUI()
        app.run()
        
    except KeyboardInterrupt:
        print("\n🛑 Application interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"❌ Fatal error: {str(e)}")
        sys.exit(1)
    
    print("👋 Secure Chat Application closed")

if __name__ == "__main__":
    main()
