import sqlite3
import hashlib
import os
import secrets
from datetime import datetime, timedelta

def hash_password(password):
    hashed_password = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), b'', 100000)
    return hashed_password.hex()

def generate_reset_token():
    return secrets.token_hex(32)

def create_user(username, password):
    # Open the database connection
    conn = sqlite3.connect('passwords.db')
    cursor = conn.cursor()

    try:
        # Check if the username already exists
        cursor.execute('SELECT * FROM users WHERE username=?', (username,))
        existing_user = cursor.fetchone()

        if existing_user:
            print("Username already exists. Please choose a different username.")
        else:
            # Hash the password using PBKDF2
            hashed_password = hash_password(password)

            # Insert user into the database
            cursor.execute('INSERT INTO users (username, password_hash) VALUES (?, ?)',
                           (username, hashed_password))
            conn.commit()
            print("User created successfully.")
    except Exception as e:
        print(f"Error creating user: {e}")
    finally:
        # Close the database connection
        conn.close()

def reset_password(username):
    # Open the database connection
    conn = sqlite3.connect('passwords.db')
    cursor = conn.cursor()

    try:
        # Check if the username exists
        cursor.execute('SELECT * FROM users WHERE username=?', (username,))
        existing_user = cursor.fetchone()

        if existing_user:
            new_password = input("Enter your new password: ")
            # Hash the new password using PBKDF2
            hashed_password = hash_password(new_password)
            # Update user's password in the database
            cursor.execute('UPDATE users SET password_hash=? WHERE username=?',
                           (hashed_password, username))
            conn.commit()
            print("Password reset successfully.")
        else:
            print("Username does not exist. Please enter a valid username.")
    except Exception as e:
        print(f"Error resetting password: {e}")
    finally:
        # Close the database connection
        conn.close()


def reset_password_with_token(token, new_password):
    # Open the database connection
    conn = sqlite3.connect('passwords.db')
    cursor = conn.cursor()

    try:
        # Retrieve username associated with the reset token
        cursor.execute('SELECT username FROM reset_tokens WHERE token=? AND expiration > ?',
                       (token, datetime.now()))
        result = cursor.fetchone()

        if result:
            username = result[0]
            # Hash the new password using PBKDF2
            hashed_password = hash_password(new_password)
            # Update user's password in the database
            cursor.execute('UPDATE users SET password_hash=? WHERE username=?',
                           (hashed_password, username))
            # Delete the used reset token
            cursor.execute('DELETE FROM reset_tokens WHERE token=?', (token,))
            conn.commit()
            print("Password reset successfully.")
        else:
            print("Invalid or expired reset token.")
    except Exception as e:
        print(f"Error resetting password with token: {e}")
    finally:
        # Close the database connection
        conn.close()


# Create SQLite database and tables if not exists
conn = sqlite3.connect('passwords.db')
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

# Example of usage
username = input("Enter your username: ")
password = input("Enter your password: ")

create_user(username, password)

# Display users and hashed passwords from the database
conn = sqlite3.connect('passwords.db')
cursor = conn.cursor()
cursor.execute('SELECT username, password_hash FROM users')
users_info = cursor.fetchall()

print("\nUsers and Hashed Passwords:")
for user_info in users_info:
    print(f"Username: {user_info[0]}, Hashed Password: {user_info[1]}")

# Reset password options
reset_choice = input("Do you want to reset your password? (yes/no): ").lower()
if reset_choice == "yes":
    reset_username = input("Enter your username: ")
    reset_password(reset_username)

# Display users and hashed passwords from the database after password reset
cursor.execute('SELECT username, password_hash FROM users')
users_info_after_reset = cursor.fetchall()

print("\nUsers and Hashed Passwords after reset:")
for user_info in users_info_after_reset:
    print(f"Username: {user_info[0]}, Hashed Password: {user_info[1]}")

# Close the database connection
conn.close()
