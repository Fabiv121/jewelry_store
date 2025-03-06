import sqlite3
import bcrypt

conn = sqlite3.connect('jewelry_store.db')
c = conn.cursor()

# Fetch all users and update passwords if they are not already hashed
c.execute("SELECT username, password FROM users")
users = c.fetchall()

for user in users:
    username, plain_password = user

    # Check if the password is already hashed (bcrypt hashed passwords start with $2b$ or $2a$)
    if plain_password.startswith("$2b$") or plain_password.startswith("$2a$"):
        print(f"Skipping {username}, already hashed.")
        continue

    # Hash the plain text password
    hashed_password = bcrypt.hashpw(plain_password.encode('utf-8'), bcrypt.gensalt())

    # Update the password in the database
    c.execute("UPDATE users SET password = ? WHERE username = ?", (hashed_password.decode('utf-8'), username))

conn.commit()
conn.close()

print("✅ Passwords updated successfully.")
