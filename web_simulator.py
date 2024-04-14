from flask import Flask, request, render_template, g, redirect, url_for
import sqlite3
import os

app = Flask(__name__)

DATABASE = 'database.db'
from flask import Flask, request, render_template, redirect, url_for, session
from functools import wraps

app = Flask(__name__)

# WAF State: Initially deactivated
app.config['WAF_ENABLED'] = False

def check_waf(func):
    """Decorator to check requests if WAF is enabled."""
    @wraps(func)
    def decorated_function(*args, **kwargs):
        if app.config['WAF_ENABLED']:
            # Check for SQL Injection patterns in query parameters and form data
            sql_injection_patterns = ["'", '"', "--", "/*", "*/", "xp_", "UNION", "SELECT", "DROP", ";", "INSERT", "DELETE", "UPDATE","%25",'%']
            for value in list(request.args.values()) + list(request.form.values()):
                if any(pattern in value for pattern in sql_injection_patterns):
                    return "Request blocked by WAF due to SQL Injection attempt", 403
        return func(*args, **kwargs)
    return decorated_function

@app.route('/toggle_waf')
def toggle_waf():
    """Route to toggle WAF on and off."""
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


@app.route('/login', methods=['POST'])
@check_waf
def login():
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

@app.route('/logout')
def logout():
    # Here you would add code to log the user out
    return redirect(url_for('home'))

@app.route('/search', methods=['GET'])
@check_waf
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
def load_file():
    filename = request.args.get('file')
    # Vulnerable to File Inclusion
    if os.path.isfile(filename):
        with open(filename, 'r') as file:
            content = file.read()
        return content
    else:
        return "File not found"

@app.route('/comment', methods=['POST'])
def comment():
    comment = request.form.get('comment')
    # Vulnerable to XSS
    return render_template('comment.html', comment=comment)

if __name__ == "__main__":
    app.run(debug=True)