import threading
from collections import defaultdict
from flask import Flask, request, flash, render_template, g, redirect, url_for, session
from functools import wraps
from bleach import clean
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import sqlite3
import os

app = Flask(__name__)
app.secret_key = 'comp4322'


# to set the rate limit dynamically
def dynamic_limit():
    if app.config['WAF_ENABLED']:
        return "10/minute"


# Get the remote address of the user as the parameter for rate limiting
limiter = Limiter(key_func=get_remote_address)
# Initialize the limiter with the app
limiter.init_app(app)

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


def check_sql_injection(func):
    @wraps(func)
    def decorated_function(*args, **kwargs):
        if app.config['WAF_ENABLED']:
            sql_injection_patterns = ["'", '"', "--", "/*", "*/", "xp_", "UNION", "SELECT", "DROP", ";", "INSERT",
                                      "DELETE", "UPDATE", "%25", '%']
            for value in list(request.args.values()) + list(request.form.values()):
                if any(pattern in value for pattern in sql_injection_patterns):
                    return "Request blocked by WAF due to SQL Injection attempt", 403
        return func(*args, **kwargs)

    return decorated_function


@app.route('/toggle_waf')
def toggle_waf():
    app.config['WAF_ENABLED'] = not app.config['WAF_ENABLED']
    state = "enabled" if app.config['WAF_ENABLED'] else "disabled"
    return redirect(url_for('home', message=f"WAF is now {state}"))


def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
    return db


@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()


@app.route('/')
def home():
    message = request.args.get('message')
    waf_status = "enabled" if app.config['WAF_ENABLED'] else "disabled"
    return render_template('main.html', message=message, waf_status=waf_status)


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
        if user is None:
            return redirect(url_for('home', login=False))
        else:
            return render_template('login_successful.html', login=True)
    else:
        return render_template('main.html')


@app.route('/logout')
def logout():
    # Here you would add code to log the user out
    return redirect(url_for('home'))


@app.route('/search', methods=['GET'])
@check_sql_injection
def search():
    query = request.args.get('q')
    db = get_db()
    cur = db.cursor()
    if not query:
        return render_template('search.html', search_fail=True, results=[])
    else:
        # Vulnerable to SQL Injection
        cur.execute(f"SELECT * FROM users WHERE name LIKE '%{query}%'")
        results = cur.fetchall()
        return render_template('search.html', results=results)


@app.route('/load', methods=['GET'])
@check_file_access
def load_file():
    # use http://127.0.0.1:5000/load?file=confidential_files/confidential_1.txt to attack
    filename = request.args.get('file')
    # confidential files are vulnerable to File Inclusion
    base_directory = os.path.abspath('demo_files')  # White-Listing directory for Safety in Demonstrations
    file_path = os.path.abspath(os.path.join(base_directory, filename))

    if file_path.startswith(base_directory) and os.path.isfile(file_path):
        try:
            with open(file_path, 'r') as file:
                content = file.read()
            return content
        except Exception as e:
            return f"Error: {str(e)}"
    else:
        return "File not found or access denied"


# To simulate a XSS protection
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
