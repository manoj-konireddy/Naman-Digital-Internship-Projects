# 🔐 Password-Strength-Checker (Flask Web App)
📌 Project Overview

This is a cybersecurity project that helps users test the strength of their passwords in real-time.
The app evaluates passwords based on length, use of uppercase/lowercase letters, digits, and special characters.
It provides an instant Weak / Medium / Strong rating, helping users create secure passwords.

✅ Built as part of my Internship Cybersecurity Projects.
✅ Includes show/hide password toggle, real-time strength check, and a modern UI.

🚀 Features

>🖥️ Web-based application (Flask backend + HTML/CSS/JS frontend)

>👁️ Show/Hide password toggle with FontAwesome icons

>⚡ Real-time password strength check (AJAX, no page reload)

>🎨 Responsive & modern design with gradient background

✅ Strength detection rules:

   > Minimum length: 8 characters

   > At least 1 uppercase letter

   > At least 1 lowercase letter

   > At least 1 digit

   > At least 1 special character

🛠️ Tech Stack

Backend: Python (Flask)

Frontend: HTML, CSS, JavaScript (fetch API, FontAwesome)

Libraries: flask, re (regex for validation)

📂 Project Structure
password_strength_checker/
│── app.py              # Flask backend
│── requirements.txt    # Python dependencies
│── static/
│   └── style.css       # CSS styles
│── templates/
│   └── index.html      # Frontend HTML
