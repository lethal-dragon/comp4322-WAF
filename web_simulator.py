import threading
from collections import defaultdict
from flask import Flask, request, flash, render_template, g, redirect, url_for
from functools import wraps
from bleach import clean
import sqlite3
import os
import re

# create the Flask app
app = Flask(__name__)
app.secret_key = 'comp4322'

# set the path to the database
DATABASE = 'database.db'

# WAF State: Initially deactivated
app.config['WAF_ENABLED'] = False

# Rate limiting: send error meesage when too many requests
connection_counts = defaultdict(int)
connection_lock = threading.Lock()


@app.before_request
def count_connections():
    if app.config['WAF_ENABLED']:
        ip = request.remote_addr
        with connection_lock:
            connection_counts[ip] += 1
            if connection_counts[ip] > 100:  # Set your threshold here
                return "Too many connections", 429  # HTTP 429 Too Many Requests


# decorator to check if the file access is allowed when WAF is enabled
def check_file_access(func):
    @wraps(func)
    def decorated_function(*args, **kwargs):
        if app.config['WAF_ENABLED']:
            filename = request.args.get('file')
            if filename:
                allowed_path = os.path.abspath('demo_files/common_files')
                full_path = os.path.abspath(os.path.join('demo_files', filename))
                if not full_path.startswith(allowed_path):
                    return "Access denied. This file is not accessible when WAF is enabled.", 403
        return func(*args, **kwargs)

    return decorated_function


# define a decorator to check for SQL injection when the WAF is enabled
def check_sql_injection(func):
    @wraps(func)
    def decorated_function(*args, **kwargs):
        if app.config['WAF_ENABLED']:
            sql_injection_patterns = ["'", '"', "--", "/*", "*/", "xp_", "UNION", "SELECT", "DROP", ";", "INSERT",
                                      "DELETE", "UPDATE", "%25", '%']
            for value in list(request.args.values()) + list(request.form.values()):
                for pattern in sql_injection_patterns:
                    if re.search(pattern, value):
                        return "Request blocked by WAF due to SQL Injection attempt", 403
        return func(*args, **kwargs)

    return decorated_function


# toggle the state of the WAF (enable/disable)
@app.route('/toggle_waf')
def toggle_waf():
    app.config['WAF_ENABLED'] = not app.config['WAF_ENABLED']
    if app.config['WAF_ENABLED']:
        state = "enabled"
    else:
        state = "disabled"
    return redirect(url_for('home', message=f"WAF is now {state}"))


# connect to the database
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
    return db


# close the database connection
@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()


# route to home page
@app.route('/')
def home():
    message = request.args.get('message')
    if app.config['WAF_ENABLED']:
        waf_status = "enabled"
    else:
        waf_status = "disabled"
    return render_template('main.html', message=message, waf_status=waf_status)


# simulate a simple login page and check for SQL injection
@app.route('/login', methods=['GET', 'POST'])
@check_sql_injection
def login():
    if request.method == 'POST':
        username = request.form['uname']
        password = request.form['psw']
        db = get_db()
        cur = db.cursor()
        # Directly inserting user input into the SQL query
        query = f"SELECT * FROM users WHERE name = '{username}' AND password = '{password}'"
        cur.execute(query)
        user = cur.fetchone()
        # use 'OR'1'='1 to bypass the login
        if user is None:
            return redirect(url_for('home', login=False))
        else:
            return render_template('login_successful.html', login=True)
    else:
        return render_template('main.html')


@app.route('/logout')
def logout():
    return redirect(url_for('home'))


# simulate a simple search page and check for SQL injection
@app.route('/search', methods=['GET'])
@check_sql_injection
def search():
    query = request.args.get('q')
    db = get_db()
    cur = db.cursor()
    if not query:
        return render_template('search.html', search_fail=True, results=[])
    else:
        # Vulnerable to SQL Injection '%'
        cur.execute(f"SELECT * FROM users WHERE name LIKE '%{query}%'")
        results = cur.fetchall()
        return render_template('search.html', results=results)


# simulate a simple search page and check for file inclusion
@app.route('/load', methods=['GET'])
@check_file_access
def load_file():
    # use http://127.0.0.1:5000/load?file=confidential_files/confidential_1.txt to attack
    filename = request.args.get('file')
    # confidential files are vulnerable to File Inclusion
    base_directory = os.path.abspath('demo_files')  # White-Listing directory for Safety in Demonstrations
    file_path = os.path.abspath(os.path.join(base_directory, filename))

    if file_path.startswith(base_directory) and os.path.isfile(file_path):
        with open(file_path, 'r') as file:
            content = file.read()
        return content


# Simulate a simple comment page and check for XSS
@app.route('/comment', methods=['GET', 'POST'])
def comment():
    if request.method == 'POST':
        comment = request.form.get('comment')
        # When the WAF is enabled, the comment is cleaned before being displayed
        if app.config['WAF_ENABLED']:
            safe_comment = clean(comment)
            # Check if the comment has been modified
            if safe_comment != comment:
                # If the comment has been modified, it is likely that the user has attempted an XSS attack
                flash("Error: Your action could not be completed")
            else:
                # If the comment has not been modified, it is safe to display
                flash("Comment successfully submitted!")
        else:
            # When the WAF is disabled, the comment is submitted no matter what the comment is
            flash("Comment successfully submitted!")
    return render_template('comment.html')


if __name__ == "__main__":
    app.run(debug=True, threaded=True, processes=1)
