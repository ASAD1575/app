import sqlite3
from passlib.hash import bcrypt
import datetime

DB_NAME = "users.db"

# Create tables if they don't exist
def init_db():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    # Create users table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        email TEXT UNIQUE,
        password TEXT
    )
    """)
    # Create password_reset_tokens table (kept for compatibility, but not used in new direct reset flow)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS password_reset_tokens (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT NOT NULL,
        token TEXT UNIQUE NOT NULL,
        expires_at TIMESTAMP NOT NULL,
        used BOOLEAN DEFAULT 0
    )
    """)
    conn.commit()
    conn.close()

# Create a new user
def create_user(username: str, email: str, password: str) -> bool:
    init_db() # Ensure tables are created
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    try:
        hashed_password = bcrypt.hash(password)
        cursor.execute("INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
                       (username, email, hashed_password))
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        # This error occurs if username or email is not unique
        return False
    finally:
        conn.close()

# Verify existing user credentials
def verify_user(username: str, password: str) -> bool:
    init_db() # Ensure tables are created
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT password FROM users WHERE username = ?", (username,))
    row = cursor.fetchone()
    conn.close()
    if row and bcrypt.verify(password, row[0]):
        return True
    return False

def get_user_by_email(email: str):
    """
    Retrieves user data by email.
    Returns a dictionary with user info if found, None otherwise.
    """
    init_db() # Ensure tables are created
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, email FROM users WHERE email = ?", (email,))
    row = cursor.fetchone()
    conn.close()
    if row:
        return {"id": row[0], "username": row[1], "email": row[2]}
    return None

def get_user_by_username(username: str):
    """
    Retrieves user data by username.
    Returns a dictionary with user info if found, None otherwise.
    """
    init_db() # Ensure tables are created
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, email FROM users WHERE username = ?", (username,))
    row = cursor.fetchone()
    conn.close()
    if row:
        return {"id": row[0], "username": row[1], "email": row[2]}
    return None

def update_user_password(email: str, new_password: str) -> bool:
    """
    Updates a user's password in the database.
    Returns True on success, False on failure (e.g., user not found).
    """
    init_db() # Ensure tables are created
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    hashed_password = bcrypt.hash(new_password)
    cursor.execute("UPDATE users SET password = ? WHERE email = ?", (hashed_password, email))
    conn.commit()
    success = cursor.rowcount > 0
    conn.close()
    return success

# --- Password Reset Token Management Functions (These are no longer actively used for direct reset) ---

def save_password_reset_token(email: str, token: str, expires_at: datetime.datetime) -> bool:
    """
    Saves a password reset token to the database.
    If a token already exists for the email, it will be updated (or replaced).
    """
    init_db() # Ensure tables are created
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    try:
        # First, invalidate any existing tokens for this email
        cursor.execute("UPDATE password_reset_tokens SET used = 1 WHERE email = ? AND used = 0", (email,))

        # Insert the new token
        cursor.execute("INSERT INTO password_reset_tokens (email, token, expires_at) VALUES (?, ?, ?)",
                       (email, token, expires_at))
        conn.commit()
        return True
    except Exception as e:
        print(f"Error saving password reset token: {e}")
        return False
    finally:
        conn.close()

def verify_password_reset_token(token: str) -> str | None:
    """
    Verifies a password reset token.
    Returns the user's email if the token is valid and not expired, None otherwise.
    Should also check if the token has already been used.
    """
    init_db() # Ensure tables are created
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT email, expires_at, used FROM password_reset_tokens WHERE token = ?", (token,))
    row = cursor.fetchone()
    conn.close()

    if row:
        email, expires_at_str, used = row
        expires_at = datetime.datetime.fromisoformat(expires_at_str) # Convert string back to datetime

        if not used and datetime.datetime.now() < expires_at:
            return email
    return None

def invalidate_token(token: str) -> bool:
    """
    Invalidates a password reset token after it has been used.
    """
    init_db() # Ensure tables are created
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("UPDATE password_reset_tokens SET used = 1 WHERE token = ?", (token,))
    conn.commit()
    success = cursor.rowcount > 0
    conn.close()
    return success

# Initialize the database when the script starts
init_db()
