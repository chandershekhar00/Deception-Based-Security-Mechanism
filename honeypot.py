from flask import Flask, request, render_template_string, jsonify
import datetime
import os

app = Flask(__name__)

LOG_FILE = "alerts.log"
BLOCKED_IPS_FILE = "blocked_ips.txt"

# Utility Functions

def get_timestamp():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def log_alert(ip, action, details=""):
    entry = f"{get_timestamp()} | {ip} | {action} | {details}\n"
    with open(LOG_FILE, "a") as f:
        f.write(entry)
    print(entry.strip())

def is_blocked(ip):
    if not os.path.exists(BLOCKED_IPS_FILE):
        return False
    with open(BLOCKED_IPS_FILE, "r") as f:
        return ip in f.read()

def block_ip(ip):
    with open(BLOCKED_IPS_FILE, "a") as f:
        f.write(ip + "\n")

# Fake Login Trap (Honeypot)

fake_login_page = """
<!DOCTYPE html>
<html>
<head><title>Admin Login</title></head>
<body>
<h2>Admin Login Panel</h2>
<form method="POST">
  Username: <input name="username"><br><br>
  Password: <input name="password" type="password"><br><br>
  <input type="submit" value="Login">
</form>
</body>
</html>
"""

# Track attempts per IP
attempt_counter = {}

@app.route('/admin-login', methods=['GET', 'POST'])
def fake_admin():
    ip = request.remote_addr

    if is_blocked(ip):
        return "<h3>Access Denied</h3>"

    # Log visit
    log_alert(ip, "Visited Trap")

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        # Log credential attempt
        log_alert(ip, "Credential Attempt", f"{username}/{password}")

        # Count attempts
        attempt_counter[ip] = attempt_counter.get(ip, 0) + 1

        # Block after 3 attempts
        if attempt_counter[ip] >= 3:
            block_ip(ip)
            log_alert(ip, "IP Blocked", "Too many attempts")
            return "<h3>Too many attempts. You are blocked.</h3>"

        return "<h3>Login Failed</h3>"

    return render_template_string(fake_login_page)

# Dummy API Trap

@app.route('/api/secure-data')
def fake_api():
    ip = request.remote_addr

    if is_blocked(ip):
        return jsonify({"error": "Blocked"}), 403

    log_alert(ip, "Accessed Fake API")
    return jsonify({"error": "Unauthorized access detected"}), 401

# Hidden File Trap

@app.route('/secret-config.txt')
def fake_file():
    ip = request.remote_addr

    if is_blocked(ip):
        return "Blocked", 403

    log_alert(ip, "Accessed Hidden File")
    return "ACCESS DENIED"

# Dashboard (View Logs)

@app.route('/dashboard')
def dashboard():
    if not os.path.exists(LOG_FILE):
        return "<h3>No logs yet</h3>"

    with open(LOG_FILE, "r") as f:
        logs = f.readlines()

    logs_html = "<br>".join(logs[::-1])  # newest first
    return f"<h2>Security Logs</h2><p>{logs_html}</p>"

# Normal Application Route

@app.route('/')
def home():
    return """
    <h1>Welcome to Secure System</h1>
    <p>This is the normal user interface.</p>
    """

# Run App

if __name__ == '__main__':
    app.run(debug=True)