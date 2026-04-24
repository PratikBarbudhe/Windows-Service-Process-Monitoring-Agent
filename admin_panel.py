"""
Admin Panel for Windows Service Process Monitoring Agent

Web-based dashboard for:
- User authentication
- Real-time log viewing
- Alert management
- Configuration (thresholds, notification settings)
- Whitelist/blacklist management
- Process control history
- System statistics

Run:
    python admin_panel.py
    
Then visit: http://localhost:5000

Default credentials:
    Username: admin
    Password: admin123

Change these immediately in production!
"""

import json
import logging
import os
from datetime import datetime, timedelta
from functools import wraps
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from flask import Flask, render_template_string, request, session, redirect, url_for, jsonify
from werkzeug.security import generate_password_hash, check_password_hash

import config
from process_control import ProcessControlManager

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Flask app setup
app = Flask(__name__)
app.secret_key = os.environ.get("ADMIN_SECRET_KEY", "change-this-in-production-secret-key")

# Admin credentials (should be stored securely in production)
ADMIN_USERS = {
    "admin": generate_password_hash("admin123")
}

# Process control manager
process_control_manager = ProcessControlManager()

# ============================================================================
# Authentication & Session Management
# ============================================================================

def login_required(f):
    """Decorator to require login for routes."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login page and authentication."""
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        
        if username in ADMIN_USERS and check_password_hash(ADMIN_USERS[username], password):
            session['user'] = username
            session['login_time'] = datetime.now().isoformat()
            logger.info(f"User {username} logged in")
            return redirect(url_for('dashboard'))
        else:
            logger.warning(f"Failed login attempt for user {username}")
            return render_template_string(LOGIN_TEMPLATE, error="Invalid credentials")
    
    return render_template_string(LOGIN_TEMPLATE)


@app.route('/logout')
def logout():
    """Logout user."""
    username = session.get('user', 'unknown')
    session.clear()
    logger.info(f"User {username} logged out")
    return redirect(url_for('login'))


# ============================================================================
# Dashboard & Main Routes
# ============================================================================

@app.route('/')
@login_required
def dashboard():
    """Main dashboard with statistics and status."""
    try:
        # Get statistics
        stats = process_control_manager.get_statistics()
        
        # Get recent alerts
        alerts = _get_recent_alerts(limit=10)
        
        # Get service status
        service_status = _get_service_status()
        
        # System info
        system_info = {
            'timestamp': datetime.now().isoformat(),
            'config_version': '1.0',
            'process_control_enabled': config.PROCESS_CONTROL_ENABLED,
            'email_enabled': config.EMAIL_NOTIFICATIONS_ENABLED,
        }
        
        return render_template_string(
            DASHBOARD_TEMPLATE,
            user=session.get('user'),
            stats=stats,
            alerts=alerts,
            service_status=service_status,
            system_info=system_info
        )
    except Exception as e:
        logger.error(f"Dashboard error: {e}", exc_info=True)
        return render_template_string(ERROR_TEMPLATE, error=str(e))


@app.route('/logs')
@login_required
def view_logs():
    """View alert logs with filtering and search."""
    try:
        # Get log file path
        log_dir = os.environ.get("WSPMA_LOG_DIR", "logs")
        
        # Get all alert files
        alert_files = []
        if os.path.exists(log_dir):
            for f in os.listdir(log_dir):
                if f.startswith("alerts_") and f.endswith(".json"):
                    filepath = os.path.join(log_dir, f)
                    alert_files.append({
                        'name': f,
                        'path': filepath,
                        'size': os.path.getsize(filepath),
                        'modified': datetime.fromtimestamp(os.path.getmtime(filepath)).isoformat()
                    })
        
        alert_files.sort(key=lambda x: x['modified'], reverse=True)
        
        # Get selected file and its contents
        selected_file = request.args.get('file')
        alerts = []
        
        if selected_file and len(alert_files) > 0:
            # Validate file path for security
            file_path = next((f['path'] for f in alert_files if f['name'] == selected_file), None)
            if file_path:
                try:
                    with open(file_path, 'r') as f:
                        alerts = json.load(f)
                        if not isinstance(alerts, list):
                            alerts = [alerts]
                except Exception as e:
                    logger.error(f"Error reading log file: {e}")
        
        # Apply filters
        severity_filter = request.args.get('severity', 'all')
        alert_type_filter = request.args.get('type', 'all')
        search_term = request.args.get('search', '')
        
        if alerts:
            if severity_filter != 'all':
                alerts = [a for a in alerts if a.get('severity') == severity_filter]
            
            if alert_type_filter != 'all':
                alerts = [a for a in alerts if alert_type_filter.lower() in a.get('type', '').lower()]
            
            if search_term:
                search_lower = search_term.lower()
                alerts = [
                    a for a in alerts
                    if search_lower in str(a).lower()
                ]
        
        # Paginate
        page = int(request.args.get('page', 1))
        per_page = 50
        total = len(alerts)
        alerts = alerts[(page - 1) * per_page:page * per_page]
        
        return render_template_string(
            LOGS_TEMPLATE,
            user=session.get('user'),
            alert_files=alert_files,
            selected_file=selected_file,
            alerts=alerts,
            total=total,
            page=page,
            per_page=per_page,
            severity_filter=severity_filter,
            alert_type_filter=alert_type_filter,
            search_term=search_term
        )
    except Exception as e:
        logger.error(f"Logs error: {e}", exc_info=True)
        return render_template_string(ERROR_TEMPLATE, error=str(e))


@app.route('/config')
@login_required
def configuration():
    """Configure system thresholds and settings."""
    try:
        # Get current configuration
        current_config = {
            'cpu_threshold': config.CPU_THRESHOLD_PERCENT,
            'memory_threshold': config.MEMORY_THRESHOLD_PERCENT,
            'disk_threshold': config.DISK_THRESHOLD_PERCENT,
            'email_enabled': config.EMAIL_NOTIFICATIONS_ENABLED,
            'email_severity': config.EMAIL_ALERT_SEVERITY_THRESHOLD,
            'desktop_enabled': config.NOTIFICATIONS_ENABLED,
            'desktop_severity': config.NOTIFICATION_SEVERITY_THRESHOLD,
            'rate_limit_enabled': config.RATE_LIMIT_ENABLED,
            'rate_limit_seconds': config.RATE_LIMIT_SECONDS,
            'process_control_enabled': config.PROCESS_CONTROL_ENABLED,
            'auto_kill_enabled': config.AUTO_KILL_BLACKLISTED,
            'auto_block_enabled': config.AUTO_BLOCK_SUSPICIOUS,
            'kill_on_critical': config.KILL_ON_CRITICAL_ALERT,
        }
        
        return render_template_string(
            CONFIG_TEMPLATE,
            user=session.get('user'),
            config=current_config
        )
    except Exception as e:
        logger.error(f"Config error: {e}", exc_info=True)
        return render_template_string(ERROR_TEMPLATE, error=str(e))


@app.route('/api/config', methods=['POST'])
@login_required
def update_configuration():
    """Update configuration via API."""
    try:
        data = request.get_json()
        
        # Validate and set environment variables
        updates = {}
        
        if 'cpu_threshold' in data:
            try:
                val = float(data['cpu_threshold'])
                if 0 <= val <= 100:
                    os.environ['WSPMA_CPU_THRESHOLD'] = str(val)
                    updates['cpu_threshold'] = val
            except ValueError:
                return jsonify({'error': 'Invalid CPU threshold'}), 400
        
        if 'memory_threshold' in data:
            try:
                val = float(data['memory_threshold'])
                if 0 <= val <= 100:
                    os.environ['WSPMA_MEMORY_THRESHOLD'] = str(val)
                    updates['memory_threshold'] = val
            except ValueError:
                return jsonify({'error': 'Invalid memory threshold'}), 400
        
        if 'disk_threshold' in data:
            try:
                val = float(data['disk_threshold'])
                if 0 <= val <= 100:
                    os.environ['WSPMA_DISK_THRESHOLD'] = str(val)
                    updates['disk_threshold'] = val
            except ValueError:
                return jsonify({'error': 'Invalid disk threshold'}), 400
        
        if 'email_enabled' in data:
            os.environ['WSPMA_EMAIL_ENABLED'] = 'true' if data['email_enabled'] else 'false'
        
        if 'process_control_enabled' in data:
            os.environ['WSPMA_PROCESS_CONTROL_ENABLED'] = 'true' if data['process_control_enabled'] else 'false'
        
        if 'auto_kill_enabled' in data:
            os.environ['WSPMA_AUTO_KILL_BLACKLISTED'] = 'true' if data['auto_kill_enabled'] else 'false'
        
        logger.info(f"Configuration updated by {session.get('user')}: {updates}")
        
        return jsonify({
            'success': True,
            'message': 'Configuration updated',
            'updates': updates
        })
    except Exception as e:
        logger.error(f"Config update error: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500


@app.route('/processes')
@login_required
def manage_processes():
    """Manage whitelisted and blacklisted processes."""
    try:
        whitelist = process_control_manager.get_whitelist()
        blacklist = process_control_manager.get_blacklist()
        
        # Convert to sorted lists
        whitelist_list = sorted(whitelist.values(), key=lambda x: x['name'])
        blacklist_list = sorted(blacklist.values(), key=lambda x: x['name'])
        
        return render_template_string(
            PROCESSES_TEMPLATE,
            user=session.get('user'),
            whitelist=whitelist_list,
            blacklist=blacklist_list
        )
    except Exception as e:
        logger.error(f"Processes error: {e}", exc_info=True)
        return render_template_string(ERROR_TEMPLATE, error=str(e))


@app.route('/api/whitelist', methods=['POST'])
@login_required
def add_to_whitelist():
    """Add process to whitelist via API."""
    try:
        data = request.get_json()
        process_name = data.get('process_name', '').strip()
        reason = data.get('reason', 'Added via admin panel')
        
        if not process_name:
            return jsonify({'error': 'Process name required'}), 400
        
        success = process_control_manager.whitelist_process(
            process_name,
            reason=reason,
            added_by=f"admin:{session.get('user')}"
        )
        
        if success:
            logger.info(f"{session.get('user')} whitelisted {process_name}")
            return jsonify({'success': True, 'message': f'{process_name} whitelisted'})
        else:
            return jsonify({'error': 'Failed to whitelist process'}), 400
    except Exception as e:
        logger.error(f"Whitelist error: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500


@app.route('/api/whitelist/<process_name>', methods=['DELETE'])
@login_required
def remove_from_whitelist(process_name):
    """Remove process from whitelist via API."""
    try:
        success = process_control_manager.remove_from_whitelist(process_name)
        
        if success:
            logger.info(f"{session.get('user')} removed {process_name} from whitelist")
            return jsonify({'success': True, 'message': f'{process_name} removed from whitelist'})
        else:
            return jsonify({'error': 'Process not found in whitelist'}), 404
    except Exception as e:
        logger.error(f"Remove whitelist error: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500


@app.route('/api/blacklist', methods=['POST'])
@login_required
def add_to_blacklist():
    """Add process to blacklist via API."""
    try:
        data = request.get_json()
        process_name = data.get('process_name', '').strip()
        reason = data.get('reason', 'Added via admin panel')
        auto_block = data.get('auto_block', False)
        
        if not process_name:
            return jsonify({'error': 'Process name required'}), 400
        
        success = process_control_manager.blacklist_process(
            process_name,
            reason=reason,
            auto_block=auto_block,
            added_by=f"admin:{session.get('user')}"
        )
        
        if success:
            logger.info(f"{session.get('user')} blacklisted {process_name} (auto_block={auto_block})")
            return jsonify({'success': True, 'message': f'{process_name} blacklisted'})
        else:
            return jsonify({'error': 'Failed to blacklist process'}), 400
    except Exception as e:
        logger.error(f"Blacklist error: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500


@app.route('/api/blacklist/<process_name>', methods=['DELETE'])
@login_required
def remove_from_blacklist(process_name):
    """Remove process from blacklist via API."""
    try:
        success = process_control_manager.remove_from_blacklist(process_name)
        
        if success:
            logger.info(f"{session.get('user')} removed {process_name} from blacklist")
            return jsonify({'success': True, 'message': f'{process_name} removed from blacklist'})
        else:
            return jsonify({'error': 'Process not found in blacklist'}), 404
    except Exception as e:
        logger.error(f"Remove blacklist error: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500


@app.route('/history')
@login_required
def process_history():
    """View process termination history."""
    try:
        history = process_control_manager.get_kill_history(limit=200)
        history = list(reversed(history))  # Most recent first
        
        # Paginate
        page = int(request.args.get('page', 1))
        per_page = 50
        total = len(history)
        history = history[(page - 1) * per_page:page * per_page]
        
        # Statistics
        stats = process_control_manager.get_statistics()
        
        return render_template_string(
            HISTORY_TEMPLATE,
            user=session.get('user'),
            history=history,
            stats=stats,
            total=total,
            page=page,
            per_page=per_page
        )
    except Exception as e:
        logger.error(f"History error: {e}", exc_info=True)
        return render_template_string(ERROR_TEMPLATE, error=str(e))


# ============================================================================
# Helper Functions
# ============================================================================

def _get_recent_alerts(limit: int = 10) -> List[Dict]:
    """Get recent alerts from log files."""
    try:
        log_dir = os.environ.get("WSPMA_LOG_DIR", "logs")
        if not os.path.exists(log_dir):
            return []
        
        alerts = []
        for f in sorted(os.listdir(log_dir), reverse=True):
            if f.startswith("alerts_") and f.endswith(".json"):
                try:
                    with open(os.path.join(log_dir, f), 'r') as fp:
                        file_alerts = json.load(fp)
                        if isinstance(file_alerts, list):
                            alerts.extend(file_alerts)
                        else:
                            alerts.append(file_alerts)
                        
                        if len(alerts) >= limit:
                            break
                except Exception as e:
                    logger.warning(f"Error reading {f}: {e}")
        
        return sorted(alerts, key=lambda x: x.get('timestamp', ''), reverse=True)[:limit]
    except Exception as e:
        logger.warning(f"Error getting recent alerts: {e}")
        return []


def _get_service_status() -> Dict:
    """Get Windows Service status."""
    try:
        import subprocess
        result = subprocess.run(
            ['powershell', '-Command', 
             'Get-Service -Name "Windows Service Process Monitoring Agent" -ErrorAction SilentlyContinue | Select-Object Status, StartType'],
            capture_output=True,
            text=True,
            timeout=5
        )
        
        if result.returncode == 0:
            return {
                'installed': True,
                'running': 'Running' in result.stdout,
                'status': result.stdout.strip()
            }
        else:
            return {'installed': False}
    except Exception as e:
        logger.warning(f"Error getting service status: {e}")
        return {'installed': False, 'error': str(e)}


# ============================================================================
# HTML Templates
# ============================================================================

LOGIN_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>WSPMA Admin Panel - Login</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .login-container {
            background: white;
            border-radius: 8px;
            box-shadow: 0 10px 40px rgba(0, 0, 0, 0.2);
            padding: 40px;
            width: 100%;
            max-width: 400px;
        }
        .login-header {
            text-align: center;
            margin-bottom: 30px;
        }
        .login-header h1 {
            font-size: 28px;
            color: #333;
            margin-bottom: 10px;
        }
        .login-header p {
            color: #666;
            font-size: 14px;
        }
        .form-group {
            margin-bottom: 20px;
        }
        label {
            display: block;
            margin-bottom: 8px;
            color: #333;
            font-weight: 500;
        }
        input[type="text"],
        input[type="password"] {
            width: 100%;
            padding: 12px;
            border: 1px solid #ddd;
            border-radius: 4px;
            font-size: 14px;
            transition: border-color 0.2s;
        }
        input[type="text"]:focus,
        input[type="password"]:focus {
            outline: none;
            border-color: #667eea;
            box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
        }
        button {
            width: 100%;
            padding: 12px;
            background: #667eea;
            color: white;
            border: none;
            border-radius: 4px;
            font-size: 14px;
            font-weight: 600;
            cursor: pointer;
            transition: background 0.2s;
        }
        button:hover {
            background: #5568d3;
        }
        .error {
            background: #fee;
            color: #c33;
            padding: 12px;
            border-radius: 4px;
            margin-bottom: 20px;
            font-size: 14px;
        }
        .default-creds {
            background: #eff6ff;
            border: 1px solid #bfdbfe;
            padding: 12px;
            border-radius: 4px;
            margin-top: 20px;
            font-size: 13px;
            color: #1e40af;
        }
        .default-creds strong {
            display: block;
            margin-bottom: 5px;
        }
    </style>
</head>
<body>
    <div class="login-container">
        <div class="login-header">
            <h1>WSPMA Admin</h1>
            <p>Windows Service Process Monitoring Agent</p>
        </div>
        
        {% if error %}
        <div class="error">{{ error }}</div>
        {% endif %}
        
        <form method="POST">
            <div class="form-group">
                <label for="username">Username</label>
                <input type="text" id="username" name="username" required autofocus>
            </div>
            
            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" id="password" name="password" required>
            </div>
            
            <button type="submit">Sign In</button>
        </form>
        
        <div class="default-creds">
            <strong>Default Credentials:</strong>
            Username: admin<br>
            Password: admin123
        </div>
    </div>
</body>
</html>
'''

DASHBOARD_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>WSPMA Admin - Dashboard</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            background: #f5f7fa;
            color: #333;
        }
        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 20px;
        }
        header {
            background: white;
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }
        header h1 { font-size: 24px; }
        .user-menu { display: flex; gap: 20px; align-items: center; }
        .user-menu a { color: #667eea; text-decoration: none; }
        .user-menu a:hover { text-decoration: underline; }
        nav {
            display: flex;
            gap: 10px;
            margin-bottom: 20px;
        }
        nav a {
            display: inline-block;
            padding: 10px 20px;
            background: white;
            border-radius: 4px;
            text-decoration: none;
            color: #333;
            font-weight: 500;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            transition: background 0.2s;
        }
        nav a:hover { background: #667eea; color: white; }
        .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; margin-bottom: 20px; }
        .card {
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }
        .card h2 { font-size: 18px; margin-bottom: 15px; color: #667eea; }
        .stat { display: flex; justify-content: space-between; padding: 8px 0; border-bottom: 1px solid #eee; }
        .stat:last-child { border-bottom: none; }
        .stat-label { color: #666; }
        .stat-value { font-weight: 600; color: #333; }
        .status { padding: 8px 12px; border-radius: 4px; font-size: 13px; font-weight: 600; }
        .status.running { background: #d1fae5; color: #065f46; }
        .status.stopped { background: #fee2e2; color: #991b1b; }
        .alerts { max-height: 400px; overflow-y: auto; }
        .alert-item {
            padding: 10px;
            margin-bottom: 8px;
            border-left: 4px solid #667eea;
            background: #f9fafb;
            border-radius: 2px;
        }
        .alert-item.critical { border-left-color: #dc2626; }
        .alert-item.high { border-left-color: #ea580c; }
        .alert-item.medium { border-left-color: #f59e0b; }
        .alert-item.low { border-left-color: #3b82f6; }
        .alert-severity {
            display: inline-block;
            padding: 2px 8px;
            border-radius: 3px;
            font-size: 11px;
            font-weight: 600;
            margin-right: 8px;
        }
        .alert-severity.critical { background: #fecaca; color: #7f1d1d; }
        .alert-severity.high { background: #fed7aa; color: #7c2d12; }
        .alert-severity.medium { background: #fcd34d; color: #78350f; }
        .alert-severity.low { background: #bfdbfe; color: #1e3a8a; }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>WSPMA Admin Panel</h1>
            <div class="user-menu">
                <span>{{ user }}</span>
                <a href="{{ url_for('logout') }}">Logout</a>
            </div>
        </header>
        
        <nav>
            <a href="{{ url_for('dashboard') }}">Dashboard</a>
            <a href="{{ url_for('view_logs') }}">Logs</a>
            <a href="{{ url_for('manage_processes') }}">Processes</a>
            <a href="{{ url_for('configuration') }}">Configuration</a>
            <a href="{{ url_for('process_history') }}">History</a>
        </nav>
        
        <div class="grid">
            <div class="card">
                <h2>Process Control</h2>
                <div class="stat">
                    <span class="stat-label">Whitelisted</span>
                    <span class="stat-value">{{ stats.whitelist_count }}</span>
                </div>
                <div class="stat">
                    <span class="stat-label">Blacklisted</span>
                    <span class="stat-value">{{ stats.blacklist_count }}</span>
                </div>
                <div class="stat">
                    <span class="stat-label">Auto-block Enabled</span>
                    <span class="stat-value">{{ stats.auto_block_enabled }}</span>
                </div>
                <div class="stat">
                    <span class="stat-label">Total Kills</span>
                    <span class="stat-value">{{ stats.kill_history_count }}</span>
                </div>
            </div>
            
            <div class="card">
                <h2>Service Status</h2>
                {% if service_status.installed %}
                    <div class="stat">
                        <span class="stat-label">Status</span>
                        <span class="status {% if service_status.running %}running{% else %}stopped{% endif %}">
                            {% if service_status.running %}Running{% else %}Stopped{% endif %}
                        </span>
                    </div>
                {% else %}
                    <div class="stat">
                        <span class="stat-label">Service</span>
                        <span class="status stopped">Not Installed</span>
                    </div>
                {% endif %}
            </div>
            
            <div class="card">
                <h2>System Configuration</h2>
                <div class="stat">
                    <span class="stat-label">Process Control</span>
                    <span class="stat-value">{% if system_info.process_control_enabled %}Enabled{% else %}Disabled{% endif %}</span>
                </div>
                <div class="stat">
                    <span class="stat-label">Email Alerts</span>
                    <span class="stat-value">{% if system_info.email_enabled %}Enabled{% else %}Disabled{% endif %}</span>
                </div>
            </div>
        </div>
        
        <div class="card">
            <h2>Recent Alerts</h2>
            {% if alerts %}
            <div class="alerts">
                {% for alert in alerts %}
                <div class="alert-item {{ alert.get('severity', 'info')|lower }}">
                    <span class="alert-severity {{ alert.get('severity', 'info')|lower }}">
                        {{ alert.get('severity', 'INFO') }}
                    </span>
                    <strong>{{ alert.get('type', 'Unknown') }}</strong>
                    <br>
                    <small>{{ alert.get('process_name', 'N/A') }} - {{ alert.get('timestamp', 'N/A') }}</small>
                </div>
                {% endfor %}
            </div>
            {% else %}
            <p style="color: #999;">No alerts</p>
            {% endif %}
        </div>
    </div>
</body>
</html>
'''

LOGS_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>WSPMA Admin - Logs</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            background: #f5f7fa;
            color: #333;
        }
        .container { max-width: 1400px; margin: 0 auto; padding: 20px; }
        header { background: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; display: flex; justify-content: space-between; align-items: center; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }
        header h1 { font-size: 24px; }
        .user-menu { display: flex; gap: 20px; }
        .user-menu a { color: #667eea; text-decoration: none; }
        nav { display: flex; gap: 10px; margin-bottom: 20px; }
        nav a { display: inline-block; padding: 10px 20px; background: white; border-radius: 4px; text-decoration: none; color: #333; font-weight: 500; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }
        nav a:hover { background: #667eea; color: white; }
        .card { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); margin-bottom: 20px; }
        .filters { display: flex; gap: 10px; margin-bottom: 20px; flex-wrap: wrap; }
        select, input { padding: 8px 12px; border: 1px solid #ddd; border-radius: 4px; font-size: 13px; }
        table { width: 100%; border-collapse: collapse; font-size: 13px; }
        th { background: #f9fafb; padding: 12px; text-align: left; font-weight: 600; border-bottom: 2px solid #e5e7eb; }
        td { padding: 12px; border-bottom: 1px solid #e5e7eb; }
        tr:hover { background: #f9fafb; }
        .severity { display: inline-block; padding: 2px 8px; border-radius: 3px; font-size: 11px; font-weight: 600; }
        .severity.critical { background: #fecaca; color: #7f1d1d; }
        .severity.high { background: #fed7aa; color: #7c2d12; }
        .severity.medium { background: #fcd34d; color: #78350f; }
        .severity.low { background: #bfdbfe; color: #1e3a8a; }
        .pagination { display: flex; gap: 5px; justify-content: center; margin-top: 20px; }
        .pagination a, .pagination span { padding: 6px 10px; border: 1px solid #ddd; border-radius: 4px; text-decoration: none; color: #667eea; }
        .pagination a:hover { background: #667eea; color: white; }
        .pagination .current { background: #667eea; color: white; border-color: #667eea; }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>Alert Logs</h1>
            <div class="user-menu">
                <span>{{ user }}</span>
                <a href="{{ url_for('logout') }}">Logout</a>
            </div>
        </header>
        
        <nav>
            <a href="{{ url_for('dashboard') }}">Dashboard</a>
            <a href="{{ url_for('view_logs') }}">Logs</a>
            <a href="{{ url_for('manage_processes') }}">Processes</a>
            <a href="{{ url_for('configuration') }}">Configuration</a>
            <a href="{{ url_for('process_history') }}">History</a>
        </nav>
        
        <div class="card">
            <div class="filters">
                <form method="GET" style="display: flex; gap: 10px; width: 100%;">
                    <select name="file" onchange="this.form.submit()">
                        <option value="">Select Log File</option>
                        {% for f in alert_files %}
                        <option value="{{ f.name }}" {% if selected_file == f.name %}selected{% endif %}>{{ f.name }}</option>
                        {% endfor %}
                    </select>
                    
                    <select name="severity" onchange="this.form.submit()">
                        <option value="all">All Severities</option>
                        <option value="CRITICAL" {% if severity_filter == 'CRITICAL' %}selected{% endif %}>Critical</option>
                        <option value="HIGH" {% if severity_filter == 'HIGH' %}selected{% endif %}>High</option>
                        <option value="MEDIUM" {% if severity_filter == 'MEDIUM' %}selected{% endif %}>Medium</option>
                        <option value="LOW" {% if severity_filter == 'LOW' %}selected{% endif %}>Low</option>
                    </select>
                    
                    <input type="text" name="search" placeholder="Search..." value="{{ search_term }}" onchange="this.form.submit()">
                </form>
            </div>
            
            {% if alerts %}
            <table>
                <thead>
                    <tr>
                        <th>Timestamp</th>
                        <th>Severity</th>
                        <th>Type</th>
                        <th>Process</th>
                        <th>Description</th>
                    </tr>
                </thead>
                <tbody>
                    {% for alert in alerts %}
                    <tr>
                        <td>{{ alert.get('timestamp', 'N/A')[:19] }}</td>
                        <td><span class="severity {{ alert.get('severity', 'INFO')|lower }}">{{ alert.get('severity', 'INFO') }}</span></td>
                        <td>{{ alert.get('type', 'Unknown') }}</td>
                        <td>{{ alert.get('process_name', 'N/A') }}</td>
                        <td>{{ alert.get('description', '')[:60] }}</td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
            
            <div class="pagination">
                {% if page > 1 %}
                <a href="?page=1">First</a>
                <a href="?page={{ page - 1 }}">Previous</a>
                {% endif %}
                <span class="current">Page {{ page }}</span>
                {% if total > (page * per_page) %}
                <a href="?page={{ page + 1 }}">Next</a>
                <a href="?page={{ (total // per_page) + 1 }}">Last</a>
                {% endif %}
            </div>
            {% else %}
            <p style="color: #999;">No alerts found</p>
            {% endif %}
        </div>
    </div>
</body>
</html>
'''

PROCESSES_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>WSPMA Admin - Processes</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            background: #f5f7fa;
            color: #333;
        }
        .container { max-width: 1400px; margin: 0 auto; padding: 20px; }
        header { background: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; display: flex; justify-content: space-between; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }
        nav { display: flex; gap: 10px; margin-bottom: 20px; }
        nav a { padding: 10px 20px; background: white; border-radius: 4px; text-decoration: none; color: #333; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }
        nav a:hover { background: #667eea; color: white; }
        .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(500px, 1fr)); gap: 20px; }
        .card { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }
        .card h2 { margin-bottom: 15px; color: #667eea; }
        .add-form { display: flex; gap: 10px; margin-bottom: 15px; }
        .add-form input { flex: 1; padding: 8px 12px; border: 1px solid #ddd; border-radius: 4px; }
        .add-form button { padding: 8px 16px; background: #667eea; color: white; border: none; border-radius: 4px; cursor: pointer; }
        .add-form button:hover { background: #5568d3; }
        .process-item { padding: 12px; border: 1px solid #e5e7eb; border-radius: 4px; margin-bottom: 8px; display: flex; justify-content: space-between; align-items: center; }
        .process-name { font-weight: 600; }
        .process-reason { font-size: 13px; color: #666; }
        .btn-remove { padding: 4px 8px; background: #ef4444; color: white; border: none; border-radius: 3px; cursor: pointer; font-size: 12px; }
        .btn-remove:hover { background: #dc2626; }
        table { width: 100%; border-collapse: collapse; font-size: 13px; }
        th { background: #f9fafb; padding: 12px; text-align: left; font-weight: 600; border-bottom: 2px solid #e5e7eb; }
        td { padding: 12px; border-bottom: 1px solid #e5e7eb; }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>Manage Processes</h1>
            <span>{{ user }}</span>
        </header>
        
        <nav>
            <a href="{{ url_for('dashboard') }}">Dashboard</a>
            <a href="{{ url_for('view_logs') }}">Logs</a>
            <a href="{{ url_for('manage_processes') }}">Processes</a>
            <a href="{{ url_for('configuration') }}">Configuration</a>
            <a href="{{ url_for('process_history') }}">History</a>
        </nav>
        
        <div class="grid">
            <div class="card">
                <h2>Whitelisted Processes</h2>
                <div class="add-form">
                    <input type="text" id="whitelist-name" placeholder="Process name (e.g., explorer.exe)">
                    <button onclick="addWhitelist()">Add</button>
                </div>
                {% for p in whitelist %}
                <div class="process-item">
                    <div>
                        <div class="process-name">{{ p.name }}</div>
                        <div class="process-reason">{{ p.reason }}</div>
                    </div>
                    <button class="btn-remove" onclick="removeWhitelist('{{ p.name }}')">Remove</button>
                </div>
                {% endfor %}
            </div>
            
            <div class="card">
                <h2>Blacklisted Processes</h2>
                <div class="add-form">
                    <input type="text" id="blacklist-name" placeholder="Process name">
                    <input type="checkbox" id="blacklist-auto" title="Auto-kill when detected">
                    <button onclick="addBlacklist()">Add</button>
                </div>
                {% for p in blacklist %}
                <div class="process-item">
                    <div>
                        <div class="process-name">{{ p.name }} {% if p.auto_block %}<span style="font-size: 11px; background: #fee2e2; color: #991b1b; padding: 2px 6px; border-radius: 2px; margin-left: 8px;">AUTO-KILL</span>{% endif %}</div>
                        <div class="process-reason">{{ p.reason }}</div>
                    </div>
                    <button class="btn-remove" onclick="removeBlacklist('{{ p.name }}')">Remove</button>
                </div>
                {% endfor %}
            </div>
        </div>
    </div>
    
    <script>
        function addWhitelist() {
            const name = document.getElementById('whitelist-name').value;
            if (!name) return alert('Enter process name');
            
            fetch('{{ url_for("add_to_whitelist") }}', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({process_name: name, reason: 'Added via admin panel'})
            }).then(r => r.json()).then(d => {
                if (d.success) location.reload();
                else alert(d.error);
            });
        }
        
        function removeWhitelist(name) {
            if (!confirm('Remove ' + name + '?')) return;
            fetch('{{ url_for("remove_from_whitelist", process_name="") }}' + name, {method: 'DELETE'})
                .then(r => r.json()).then(d => {
                    if (d.success) location.reload();
                    else alert(d.error);
                });
        }
        
        function addBlacklist() {
            const name = document.getElementById('blacklist-name').value;
            const autoBlock = document.getElementById('blacklist-auto').checked;
            if (!name) return alert('Enter process name');
            
            fetch('{{ url_for("add_to_blacklist") }}', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({process_name: name, reason: 'Added via admin panel', auto_block: autoBlock})
            }).then(r => r.json()).then(d => {
                if (d.success) location.reload();
                else alert(d.error);
            });
        }
        
        function removeBlacklist(name) {
            if (!confirm('Remove ' + name + '?')) return;
            fetch('{{ url_for("remove_from_blacklist", process_name="") }}' + name, {method: 'DELETE'})
                .then(r => r.json()).then(d => {
                    if (d.success) location.reload();
                    else alert(d.error);
                });
        }
    </script>
</body>
</html>
'''

CONFIG_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>WSPMA Admin - Configuration</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            background: #f5f7fa;
            color: #333;
        }
        .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
        header { background: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; display: flex; justify-content: space-between; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }
        nav { display: flex; gap: 10px; margin-bottom: 20px; }
        nav a { padding: 10px 20px; background: white; border-radius: 4px; text-decoration: none; color: #333; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }
        nav a:hover { background: #667eea; color: white; }
        .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(400px, 1fr)); gap: 20px; }
        .card { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }
        .card h2 { margin-bottom: 15px; color: #667eea; font-size: 18px; }
        .form-group { margin-bottom: 15px; }
        label { display: block; margin-bottom: 5px; font-weight: 600; font-size: 14px; }
        input[type="number"], input[type="text"] { width: 100%; padding: 8px 12px; border: 1px solid #ddd; border-radius: 4px; }
        .checkbox-group { display: flex; align-items: center; gap: 10px; }
        input[type="checkbox"] { cursor: pointer; }
        .help-text { font-size: 12px; color: #666; margin-top: 5px; }
        button { padding: 10px 20px; background: #667eea; color: white; border: none; border-radius: 4px; cursor: pointer; font-weight: 600; }
        button:hover { background: #5568d3; }
        .success { background: #d1fae5; color: #065f46; padding: 12px; border-radius: 4px; margin-bottom: 15px; }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>Configuration</h1>
            <span>{{ user }}</span>
        </header>
        
        <nav>
            <a href="{{ url_for('dashboard') }}">Dashboard</a>
            <a href="{{ url_for('view_logs') }}">Logs</a>
            <a href="{{ url_for('manage_processes') }}">Processes</a>
            <a href="{{ url_for('configuration') }}">Configuration</a>
            <a href="{{ url_for('process_history') }}">History</a>
        </nav>
        
        <div class="grid">
            <div class="card">
                <h2>System Thresholds</h2>
                <form id="config-form">
                    <div class="form-group">
                        <label for="cpu">CPU Threshold (%)</label>
                        <input type="number" id="cpu" min="0" max="100" value="{{ config.cpu_threshold }}" step="0.1">
                        <div class="help-text">Alert when CPU exceeds this value</div>
                    </div>
                    
                    <div class="form-group">
                        <label for="mem">Memory Threshold (%)</label>
                        <input type="number" id="mem" min="0" max="100" value="{{ config.memory_threshold }}" step="0.1">
                        <div class="help-text">Alert when memory exceeds this value</div>
                    </div>
                    
                    <div class="form-group">
                        <label for="disk">Disk Threshold (%)</label>
                        <input type="number" id="disk" min="0" max="100" value="{{ config.disk_threshold }}" step="0.1">
                        <div class="help-text">Alert when disk usage exceeds this value</div>
                    </div>
                    
                    <button type="button" onclick="saveConfig()">Save Thresholds</button>
                </form>
            </div>
            
            <div class="card">
                <h2>Notifications</h2>
                <form id="notify-form">
                    <div class="form-group">
                        <label class="checkbox-group">
                            <input type="checkbox" id="email" {% if config.email_enabled %}checked{% endif %}>
                            <span>Email Alerts</span>
                        </label>
                        <div class="help-text">Send alerts via email</div>
                    </div>
                    
                    <button type="button" onclick="saveConfig()">Save Notifications</button>
                </form>
            </div>
            
            <div class="card">
                <h2>Process Control</h2>
                <form id="process-form">
                    <div class="form-group">
                        <label class="checkbox-group">
                            <input type="checkbox" id="pc-enabled" {% if config.process_control_enabled %}checked{% endif %}>
                            <span>Enable Process Control</span>
                        </label>
                    </div>
                    
                    <div class="form-group">
                        <label class="checkbox-group">
                            <input type="checkbox" id="auto-kill" {% if config.auto_kill_enabled %}checked{% endif %}>
                            <span>Auto-kill Blacklisted Processes</span>
                        </label>
                        <div class="help-text">Automatically terminate blacklisted processes</div>
                    </div>
                    
                    <div class="form-group">
                        <label class="checkbox-group">
                            <input type="checkbox" id="auto-block" {% if config.auto_block_enabled %}checked{% endif %}>
                            <span>Auto-block Suspicious</span>
                        </label>
                        <div class="help-text">Block process execution for suspicious processes</div>
                    </div>
                    
                    <div class="form-group">
                        <label class="checkbox-group">
                            <input type="checkbox" id="kill-critical" {% if config.kill_on_critical %}checked{% endif %}>
                            <span>Kill on Critical Alert</span>
                        </label>
                        <div class="help-text" style="color: #dc2626;">⚠️ Dangerous: Requires careful configuration</div>
                    </div>
                    
                    <button type="button" onclick="saveConfig()">Save Settings</button>
                </form>
            </div>
        </div>
    </div>
    
    <script>
        function saveConfig() {
            const data = {
                cpu_threshold: parseFloat(document.getElementById('cpu').value),
                memory_threshold: parseFloat(document.getElementById('mem').value),
                disk_threshold: parseFloat(document.getElementById('disk').value),
                email_enabled: document.getElementById('email').checked,
                process_control_enabled: document.getElementById('pc-enabled').checked,
                auto_kill_enabled: document.getElementById('auto-kill').checked,
                auto_block_enabled: document.getElementById('auto-block').checked,
                kill_on_critical: document.getElementById('kill-critical').checked
            };
            
            fetch('{{ url_for("update_configuration") }}', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify(data)
            }).then(r => r.json()).then(d => {
                if (d.success) {
                    alert('Configuration saved successfully');
                    location.reload();
                } else {
                    alert('Error: ' + d.error);
                }
            });
        }
    </script>
</body>
</html>
'''

HISTORY_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>WSPMA Admin - Kill History</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            background: #f5f7fa;
            color: #333;
        }
        .container { max-width: 1400px; margin: 0 auto; padding: 20px; }
        header { background: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; display: flex; justify-content: space-between; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }
        nav { display: flex; gap: 10px; margin-bottom: 20px; }
        nav a { padding: 10px 20px; background: white; border-radius: 4px; text-decoration: none; color: #333; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }
        nav a:hover { background: #667eea; color: white; }
        .card { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); margin-bottom: 20px; }
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-bottom: 20px; }
        .stat { background: #f9fafb; padding: 15px; border-radius: 4px; border-left: 4px solid #667eea; }
        .stat-label { font-size: 13px; color: #666; }
        .stat-value { font-size: 24px; font-weight: 700; color: #333; }
        table { width: 100%; border-collapse: collapse; font-size: 13px; }
        th { background: #f9fafb; padding: 12px; text-align: left; font-weight: 600; border-bottom: 2px solid #e5e7eb; }
        td { padding: 12px; border-bottom: 1px solid #e5e7eb; }
        tr:hover { background: #f9fafb; }
        .success { color: #059669; font-weight: 600; }
        .failed { color: #dc2626; font-weight: 600; }
        .pagination { display: flex; gap: 5px; justify-content: center; margin-top: 20px; }
        .pagination a, .pagination span { padding: 6px 10px; border: 1px solid #ddd; border-radius: 4px; text-decoration: none; color: #667eea; }
        .pagination a:hover { background: #667eea; color: white; }
        .pagination .current { background: #667eea; color: white; border-color: #667eea; }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>Process Kill History</h1>
            <span>{{ user }}</span>
        </header>
        
        <nav>
            <a href="{{ url_for('dashboard') }}">Dashboard</a>
            <a href="{{ url_for('view_logs') }}">Logs</a>
            <a href="{{ url_for('manage_processes') }}">Processes</a>
            <a href="{{ url_for('configuration') }}">Configuration</a>
            <a href="{{ url_for('process_history') }}">History</a>
        </nav>
        
        <div class="card">
            <div class="stats-grid">
                <div class="stat">
                    <div class="stat-label">Total Kills</div>
                    <div class="stat-value">{{ stats.kill_history_count }}</div>
                </div>
                <div class="stat">
                    <div class="stat-label">Successful</div>
                    <div class="stat-value" style="color: #059669;">{{ stats.successful_kills }}</div>
                </div>
                <div class="stat">
                    <div class="stat-label">Failed</div>
                    <div class="stat-value" style="color: #dc2626;">{{ stats.failed_kills }}</div>
                </div>
            </div>
        </div>
        
        <div class="card">
            {% if history %}
            <table>
                <thead>
                    <tr>
                        <th>Timestamp</th>
                        <th>Process</th>
                        <th>PID</th>
                        <th>Method</th>
                        <th>Status</th>
                        <th>Reason</th>
                    </tr>
                </thead>
                <tbody>
                    {% for h in history %}
                    <tr>
                        <td>{{ h.timestamp[:19] }}</td>
                        <td>{{ h.name }}</td>
                        <td>{{ h.pid }}</td>
                        <td>{{ h.kill_method }}</td>
                        <td><span class="{% if h.success %}success{% else %}failed{% endif %}">{% if h.success %}Success{% else %}Failed{% endif %}</span></td>
                        <td>{{ h.reason[:50] }}</td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
            
            <div class="pagination">
                {% if page > 1 %}
                <a href="?page=1">First</a>
                <a href="?page={{ page - 1 }}">Previous</a>
                {% endif %}
                <span class="current">Page {{ page }}</span>
                {% if total > (page * per_page) %}
                <a href="?page={{ page + 1 }}">Next</a>
                <a href="?page={{ (total // per_page) + 1 }}">Last</a>
                {% endif %}
            </div>
            {% else %}
            <p style="color: #999;">No kill history</p>
            {% endif %}
        </div>
    </div>
</body>
</html>
'''

ERROR_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>Error</title>
    <style>
        body { font-family: sans-serif; background: #f5f7fa; padding: 40px; }
        .error { background: white; padding: 40px; border-radius: 8px; color: #dc2626; }
        .error h1 { margin-bottom: 20px; }
    </style>
</head>
<body>
    <div class="error">
        <h1>Error</h1>
        <p>{{ error }}</p>
        <a href="{{ url_for('dashboard') }}">Back to Dashboard</a>
    </div>
</body>
</html>
'''


# ============================================================================
# Main Entry Point
# ============================================================================

if __name__ == '__main__':
    logger.info("Starting WSPMA Admin Panel")
    logger.info("Access at: http://localhost:5000")
    logger.info("Default login: admin / admin123")
    
    app.run(
        host='0.0.0.0',
        port=5000,
        debug=False,  # Set to True for development
        threaded=True
    )
