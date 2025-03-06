import sqlite3
import bcrypt  # Import bcrypt for password hashing
from flask import Flask, render_template, request, redirect, url_for, session

app = Flask(__name__)
app.secret_key = "supersecretkey123"  # REQUIRED for session handling


# Database Initialization
def init_db():
    conn = sqlite3.connect('jewelry_store.db')
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            jewelry_type TEXT,
            metal TEXT,
            gemstone TEXT
        )
    ''')
    conn.commit()
    conn.close()

# Initialize the database when the app starts
init_db()

# Homepage Route
@app.route('/')
def home():
    return render_template('index.html')

# Customization Route
@app.route('/customize', methods=['GET', 'POST'])
def customize():
    user = session.get('user')  # Check if user is logged in

    if request.method == 'POST':
        if not user:
            return "You must be logged in to save an order. <a href='/login'>Login here</a>"

        jewelry_type = request.form.get('jewelry_type')
        metal = request.form.get('metal')
        gemstone = request.form.get('gemstone') if jewelry_type != "Watch" else "None"

        conn = sqlite3.connect('jewelry_store.db')
        c = conn.cursor()
        c.execute("SELECT id FROM users WHERE username = ?", (user,))
        user_id = c.fetchone()[0]

        c.execute("INSERT INTO orders (jewelry_type, metal, gemstone, user_id) VALUES (?, ?, ?, ?)", 
                  (jewelry_type, metal, gemstone, user_id))
        conn.commit()
        conn.close()

        return render_template('result.html', jewelry_type=jewelry_type, metal=metal, gemstone=gemstone, user=user)

    return render_template('customize.html', user=user)

# Orders Route (View all saved orders)
@app.route('/orders')
def view_orders():
    if 'user' not in session:
        return redirect(url_for('login'))

    user = session['user']
    conn = sqlite3.connect('jewelry_store.db')
    c = conn.cursor()
    c.execute("SELECT id FROM users WHERE username = ?", (user,))
    user_id = c.fetchone()[0]

    c.execute("SELECT jewelry_type, metal, gemstone FROM orders WHERE user_id = ?", (user_id,))
    orders = c.fetchall()
    conn.close()
    return render_template('orders.html', orders=orders, user=user)

# Run Flask App
if __name__ == '__main__':
    app.run(debug=True)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Hash the password before saving
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        conn = sqlite3.connect('jewelry_store.db')
        c = conn.cursor()
        try:
            c.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_password))
            conn.commit()
            session['user'] = username  # Log in the user immediately after signup
            return redirect(url_for('customize'))
        except sqlite3.IntegrityError:
            return "Username already exists. Try a different one."
        finally:
            conn.close()

    return render_template('register.html')


import time  # Import time module for handling timeout

# Dictionary to track failed login attempts
failed_attempts = {}

import time  # Import time module for handling timeout

# Dictionary to track failed login attempts
failed_attempts = {}

import time  # Import time module for handling timeout

# Dictionary to track failed login attempts
failed_attempts = {}

import time  # Import time module for handling timeout

# Dictionary to track failed login attempts
failed_attempts = {}

import time  # Import time module for handling timeout

# Dictionary to track failed login attempts
failed_attempts = {}

@app.route('/login', methods=['GET', 'POST'])
def login():
    global failed_attempts  # Use the global dictionary for tracking attempts
    remaining_time = 0  # Default value for countdown

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Check if the user has exceeded login attempts
        if username in failed_attempts and failed_attempts[username]['count'] >= 3:
            remaining_time = 60 - (time.time() - failed_attempts[username]['time'])
            if remaining_time > 0:
                return render_template('login.html', error=f"Too many failed attempts. Try again in {int(remaining_time)} seconds.", remaining_time=int(remaining_time))

        conn = sqlite3.connect('jewelry_store.db')
        c = conn.cursor()
        c.execute("SELECT password FROM users WHERE username = ?", (username,))
        user = c.fetchone()
        conn.close()

        if user:
            stored_password = user[0].encode('utf-8')  # Convert stored password to bytes
            if bcrypt.checkpw(password.encode('utf-8'), stored_password):
                session['user'] = username
                failed_attempts.pop(username, None)  # Reset failed attempts on successful login
                return redirect(url_for('customize'))

        # Handle failed login attempt
        if username not in failed_attempts:
            failed_attempts[username] = {'count': 1, 'time': time.time()}
        else:
            failed_attempts[username]['count'] += 1
            failed_attempts[username]['time'] = time.time()

        remaining_attempts = 3 - failed_attempts[username]['count']
        if remaining_attempts > 0:
            return render_template('login.html', error=f"Invalid login. {remaining_attempts} attempts remaining.", remaining_time=0)
        else:
            remaining_time = 60
            return render_template('login.html', error="Too many failed attempts.", remaining_time=int(remaining_time))

    return render_template('login.html', remaining_time=0)


@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('login'))

@app.route('/delete_order/<int:order_id>', methods=['POST'])
def delete_order(order_id):
    if 'user' not in session:
        return redirect(url_for('login'))

    conn = sqlite3.connect('jewelry_store.db')
    c = conn.cursor()
    c.execute("DELETE FROM orders WHERE id = ?", (order_id,))
    conn.commit()
    conn.close()

    return redirect(url_for('view_orders'))

@app.route('/change_password', methods=['GET', 'POST'])
def change_password():
    if 'user' not in session:
        return redirect(url_for('login'))

    user = session['user']

    if request.method == 'POST':
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        conn = sqlite3.connect('jewelry_store.db')
        c = conn.cursor()
        c.execute("SELECT password FROM users WHERE username = ?", (user,))
        stored_password = c.fetchone()[0]

        # Verify the current password
        if not bcrypt.checkpw(current_password.encode('utf-8'), stored_password):
            return render_template('change_password.html', error="Current password is incorrect.")

        # Check if new passwords match
        if new_password != confirm_password:
            return render_template('change_password.html', error="New passwords do not match.")

        # Hash the new password before saving
        hashed_new_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
        c.execute("UPDATE users SET password = ? WHERE username = ?", (hashed_new_password, user))
        conn.commit()
        conn.close()

        return render_template('change_password.html', message="Password successfully changed!")

    return render_template('change_password.html')
