from flask import Flask, render_template, request, redirect, url_for, session, flash
import sqlite3
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'your-secret-key-here'  # Change this to a secure, random key

# Database connection function


def get_db_connection():
    conn = sqlite3.connect('society_management.db')
    conn.row_factory = sqlite3.Row
    return conn

# Initialize database


def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS entries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            role TEXT NOT NULL,
            check_in TEXT NOT NULL,
            check_out TEXT,
            status TEXT DEFAULT 'Inside'
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL
        )
    ''')

    conn.commit()
    conn.close()

# Function to check registered users (from previous request)


def check_registered_users():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, username FROM users")
    users = cursor.fetchall()
    conn.close()

    if users:
        print("Registered Users in Database:")
        print("ID | Username")
        print("-- | --------")
        for user in users:
            print(f"{user['id']}  | {user['username']}")
    else:
        print("No users registered in the database.")

# Check if user is logged in


def login_required(f):
    def wrap(*args, **kwargs):
        if 'logged_in' not in session:
            flash('Please log in first.')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    wrap.__name__ = f.__name__
    return wrap


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
        user = cursor.fetchone()
        conn.close()

        if user and check_password_hash(user['password'], password):
            session['logged_in'] = True
            session['username'] = username
            flash('Login successful!')
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password.')

    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if not username or not password or not confirm_password:
            flash('All fields are required.')
            return render_template('register.html')

        if password != confirm_password:
            flash('Passwords do not match.')
            return render_template('register.html')

        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
        if cursor.fetchone():
            flash('Username already taken.')
            conn.close()
            return render_template('register.html')

        hashed_password = generate_password_hash(password)
        cursor.execute('INSERT INTO users (username, password) VALUES (?, ?)',
                       (username, hashed_password))
        conn.commit()
        conn.close()

        flash('Registration successful! Please log in.')
        return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    session.pop('username', None)
    flash('You have been logged out.')
    return redirect(url_for('login'))


@app.route('/check_in', methods=['GET', 'POST'])
@login_required
def check_in():
    if request.method == 'POST':
        name = request.form['name']
        role = request.form['role']
        check_in_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO entries (name, role, check_in) 
            VALUES (?, ?, ?)
        ''', (name, role, check_in_time))
        conn.commit()
        conn.close()
        flash(f"{name} checked in successfully.")
        return redirect(url_for('index'))

    return render_template('check_in.html')


@app.route('/check_out', methods=['GET', 'POST'])
@login_required
def check_out():
    if request.method == 'POST':
        name = request.form['name']
        check_out_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('''
            UPDATE entries 
            SET check_out = ?, status = 'Left'
            WHERE name = ? AND status = 'Inside'
        ''', (check_out_time, name))
        if cursor.rowcount > 0:
            conn.commit()
            flash(f"{name} checked out successfully.")
        else:
            flash(f"No active entry found for {name}.")
        conn.close()
        return redirect(url_for('index'))

    return render_template('check_out.html')

# Updated /current route with search functionality


@app.route('/current', methods=['GET'])
@login_required
def current():
    # Get search term from query string
    search_query = request.args.get('search', '').strip()

    conn = get_db_connection()
    cursor = conn.cursor()

    if search_query:
        # Filter by name or role (case-insensitive)
        query = """
            SELECT name, role, check_in 
            FROM entries 
            WHERE status = 'Inside' 
            AND (LOWER(name) LIKE ? OR LOWER(role) LIKE ?)
        """
        search_term = f"%{search_query.lower()}%"
        cursor.execute(query, (search_term, search_term))
    else:
        # Show all if no search query
        cursor.execute(
            "SELECT name, role, check_in FROM entries WHERE status = 'Inside'")

    entries = cursor.fetchall()
    conn.close()

    return render_template('current.html', entries=entries, search_query=search_query)


# Run the app
if __name__ == '__main__':
    init_db()
    check_registered_users()
    app.run(debug=True)
