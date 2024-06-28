from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
def init_db():

    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS ips(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        IP TEXT NOT NULL
    )''')
    
    # Insert sample users
    # sample_users = [
    #     ('user1', generate_password_hash('password1')),
    #     ('user2', generate_password_hash('password2'))
    # ]
    # c.executemany('INSERT OR IGNORE INTO users (username, password) VALUES (?, ?)', sample_users)
    conn.commit()
    conn.close()
init_db()

