import sqlite3
import bcrypt  # Import bcrypt for password hashing
from flask import Flask, render_template, request, redirect, url_for, session
from flask import Flask, render_template, request, redirect, url_for

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


# Customization Route
@app.route('/customize', methods=['GET', 'POST'])
def customize():
    user = session.get('user')  # Get logged-in user if available

    # Convert guest param to a proper boolean
    is_guest = request.args.get('guest', 'false').lower() == 'true'

    if not user and not is_guest:
        return redirect(url_for('login'))  # Redirect ONLY if neither user nor guest

    if request.method == 'POST':
        jewelry_type = request.form.get('jewelry_type', "").strip()
        metal = request.form.get('metal', "").strip()
        gemstone = request.form.get('gemstone', "").strip() if jewelry_type != "Watch" else "None"

        # Assign prices based on jewelry type
        price_dict = {
            "Ring": 150.0,
            "Necklace": 200.0,
            "Watch": 300.0,
        }
        price = price_dict.get(jewelry_type, 0.0)

        if user:  # Only store data if user is logged in
            conn = sqlite3.connect('jewelry_store.db')
            c = conn.cursor()

            c.execute("SELECT id FROM users WHERE username = ?", (user,))
            user_id = c.fetchone()[0]

            # Check if the item already exists
            c.execute("""
                SELECT id, quantity FROM orders 
                WHERE user_id = ? AND jewelry_type = ? AND metal = ? AND gemstone = ?
            """, (user_id, jewelry_type, metal, gemstone))

            existing_order = c.fetchone()

            if existing_order:
                new_quantity = existing_order[1] + 1
                c.execute("UPDATE orders SET quantity = ? WHERE id = ?", (new_quantity, existing_order[0]))
            else:
                c.execute("INSERT INTO orders (jewelry_type, metal, gemstone, user_id, quantity, price) VALUES (?, ?, ?, ?, ?, ?)", 
                        (jewelry_type, metal, gemstone, user_id, 1, price))

            conn.commit()
            conn.close()

        return redirect(url_for('view_orders'))

    return render_template('customize.html', user=user, is_guest=is_guest)

# Orders Route (View all saved orders)
@app.route('/orders')
def view_orders():
    if 'user' not in session:
        return redirect(url_for('login'))

    user = session['user']

    conn = sqlite3.connect('jewelry_store.db')
    c = conn.cursor()

    # Fetch all orders for the user
    c.execute('''
        SELECT id, jewelry_type, metal, gemstone, quantity, price
        FROM orders
        WHERE user_id = (SELECT id FROM users WHERE username = ?)
    ''', (user,))
    orders = c.fetchall()

    # Calculate totals
    c.execute("SELECT SUM(quantity) FROM orders WHERE user_id = (SELECT id FROM users WHERE username = ?)", (user,))
    total_quantity = c.fetchone()[0] or 0

    c.execute("SELECT SUM(quantity * price) FROM orders WHERE user_id = (SELECT id FROM users WHERE username = ?)", (user,))
    total_price = c.fetchone()[0] or 0.0

    conn.close()

    #  Ensure user, orders, totals are passed to the template
    return render_template('orders.html', user=user, orders=orders, total_quantity=total_quantity, total_price=total_price)


# Run Flask App
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80, debug=True)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Hash and decode the password before storing
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

        conn = sqlite3.connect('jewelry_store.db')
        c = conn.cursor()
        try:
            c.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_password))
            conn.commit()
            session['user'] = username
            return redirect(url_for('customize'))
        except sqlite3.IntegrityError:
            error = "Username already exists. Please choose a different one."
            return render_template('register.html', error=error, username=username)
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

        # Get the stored password
        c.execute("SELECT password FROM users WHERE username = ?", (user,))
        user_data = c.fetchone()

        # Check if user exists
        if user_data is None:
            return render_template('change_password.html', error="User not found in database.")

        stored_password = user_data[0]

        # Verify the current password
        if not bcrypt.checkpw(current_password.encode('utf-8'), stored_password.encode('utf-8')):
            return render_template('change_password.html', error="Current password is incorrect.")

        # Check if new passwords match
        if new_password != confirm_password:
            return render_template('change_password.html', error="New passwords do not match.")

        # Hash and store the new password
        hashed_new_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        c.execute("UPDATE users SET password = ? WHERE username = ?", (hashed_new_password, user))
        conn.commit()
        conn.close()

        return render_template('change_password.html', message="Password successfully changed!")

    return render_template('change_password.html')

@app.route('/remove_order/<int:order_id>', methods=['POST'])
def remove_order(order_id):
    if 'user' not in session:
        return redirect(url_for('login'))

    user = session['user']

    conn = sqlite3.connect('jewelry_store.db')
    c = conn.cursor()

    # Ensure the order belongs to the logged-in user
    c.execute("DELETE FROM orders WHERE id = ? AND user_id = (SELECT id FROM users WHERE username = ?)", 
              (order_id, user))

    conn.commit()
    conn.close()

    return redirect(url_for('view_orders'))

@app.route('/update_quantity/<int:order_id>', methods=['POST'])
def update_quantity(order_id):
    if 'user' not in session:
        return redirect(url_for('login'))

    action = request.form.get('action')

    conn = sqlite3.connect('jewelry_store.db')
    c = conn.cursor()

    # Get current quantity
    c.execute("SELECT quantity FROM orders WHERE id = ?", (order_id,))
    order = c.fetchone()

    if order:
        current_quantity = order[0]

        if action == "increase":
            new_quantity = current_quantity + 1
            c.execute("UPDATE orders SET quantity = ? WHERE id = ?", (new_quantity, order_id))

        elif action == "decrease" and current_quantity > 1:
            new_quantity = current_quantity - 1
            c.execute("UPDATE orders SET quantity = ? WHERE id = ?", (new_quantity, order_id))

    conn.commit()
    conn.close()

    return redirect(url_for('view_orders'))

@app.route('/')
def home():
    user = session.get('user')  # Get the user from session
    return render_template('index.html', user=user)


@app.route('/checkout', methods=['GET', 'POST'])
def checkout():
    if request.method == 'POST':
        name = request.form.get('name')
        address = request.form.get('address')
        payment = request.form.get('payment')

        user = session.get('user')
        orders = []

        if user:
            conn = sqlite3.connect('jewelry_store.db')
            c = conn.cursor()

            # Get user ID
            c.execute("SELECT id FROM users WHERE username = ?", (user,))
            user_id = c.fetchone()[0]

            # Fetch user's current orders before deleting
            c.execute("""
                SELECT jewelry_type, metal, gemstone, quantity, price 
                FROM orders 
                WHERE user_id = ?
            """, (user_id,))
            orders = c.fetchall()

            # Delete all orders for this user (simulate emptying the cart)
            c.execute("DELETE FROM orders WHERE user_id = ?", (user_id,))
            conn.commit()
            conn.close()

        return render_template('confirmation.html', name=name, orders=orders)

    return render_template('checkout.html')



@app.route('/delete_account', methods=['GET', 'POST'])
def delete_account():
    if 'user' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        username = session['user']

        conn = sqlite3.connect('jewelry_store.db')
        c = conn.cursor()

        # Delete orders first (foreign key constraint if added later)
        c.execute("DELETE FROM orders WHERE user_id = (SELECT id FROM users WHERE username = ?)", (username,))

        # Then delete the user
        c.execute("DELETE FROM users WHERE username = ?", (username,))
        conn.commit()
        conn.close()

        # Log the user out
        session.pop('user', None)

        return redirect(url_for('home'))

    return render_template('delete_account.html')
