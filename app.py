from flask import Flask, render_template, request, redirect, url_for
import sqlite3
import hashlib
from datetime import datetime, timedelta

app = Flask(__name__)

# Database initialization
conn = sqlite3.connect('passwords.db', check_same_thread=False)
cursor = conn.cursor()

cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        password_hash BLOB NOT NULL
    )
''')

cursor.execute('''
    CREATE TABLE IF NOT EXISTS reset_tokens (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        token TEXT NOT NULL,
        expiration TIMESTAMP NOT NULL
    )
''')

conn.commit()
conn.close()

# Function to hash passwords
def hash_password(password):
    hashed_password = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), b'', 100000)
    return hashed_password.hex()

# Function to create a user in the database
def create_user(username, password):
    conn = sqlite3.connect('passwords.db')
    cursor = conn.cursor()

    try:
        # Check if the username already exists
        cursor.execute('SELECT * FROM users WHERE username=?', (username,))
        existing_user = cursor.fetchone()

        if existing_user:
            return "Username already exists. Please choose a different username."
        else:
            # Hash the password
            hashed_password = hash_password(password)

            # Insert user into the database
            cursor.execute('INSERT INTO users (username, password_hash) VALUES (?, ?)',
                           (username, hashed_password))
            conn.commit()
            return "User created successfully."
    except Exception as e:
        return f"Error creating user: {e}"
    finally:
        conn.close()

# Function to verify login credentials
def login_user(username, password):
    conn = sqlite3.connect('passwords.db')
    cursor = conn.cursor()

    try:
        cursor.execute('SELECT * FROM users WHERE username=? AND password_hash=?',
                       (username, hash_password(password)))
        user = cursor.fetchone()

        if user:
            return True
        else:
            return False
    except Exception as e:
        print(f"Error logging in: {e}")
    finally:
        conn.close()

# Function to display users from the database
def display_users():
    conn = sqlite3.connect('passwords.db')
    cursor = conn.cursor()
    cursor.execute('SELECT username, password_hash FROM users')
    users_info = cursor.fetchall()
    conn.close()
    return users_info


# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/logout')
def logout():
    return redirect(url_for('index'))

@app.route('/display_users')
def display_users_route():
    users_info = display_users()
    return render_template('display_users.html', users_info=users_info)

@app.route('/create_user', methods=['POST'])
def create_user_route():
    username = request.form.get('username')
    password = request.form.get('password')
    result = create_user(username, password)
    
    if result == "User created successfully.":
        return render_template('user_created.html', username=username)
    else:
        return render_template('result.html', result=result)
    
@app.route('/login')
def login():
    return render_template('login.html')

@app.route('/login', methods=['POST'])
def login_route():
    username = request.form.get('username')
    password = request.form.get('password')

    if login_user(username, password):
        return render_template('dashboard.html', username=username)
    else:
        return render_template('result.html', result="Incorrect username or password. Please try again.")

if __name__ == '__main__':
    app.run()
