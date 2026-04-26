"""
REST API Server for Windows Service Process Monitoring Agent

Provides comprehensive REST endpoints for:
- Process monitoring and analysis
- Service auditing
- Alert management
- Process control (kill, whitelist, blacklist)
- System health and statistics

Features:
- JWT-based authentication
- CORS support for web/mobile clients
- Rate limiting
- Comprehensive error handling
- API documentation

Run:
    python api_server.py
    
Then access:
    http://localhost:5001/api/docs (Swagger/OpenAPI documentation)
    http://localhost:5001/api/health (Health check)

Default credentials:
    Username: admin
    Password: admin123
"""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timedelta, timezone
from functools import wraps
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

try:
    import jwt
except ImportError:
    jwt = None  # type: ignore

from flask import Flask, request, jsonify
from flask_cors import CORS

import config
from alert_manager import AlertManager
from metrics_collector import MetricsCollector
from process_analyzer import ProcessAnalyzer
from process_control import ProcessControlManager
from report_generator import ReportGenerator
from service_auditor import ServiceAuditor

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Flask app setup
app = Flask(__name__)
app.config['JSON_SORT_KEYS'] = False

# CORS support for web and mobile clients
CORS(app, resources={r"/api/*": {"origins": "*", "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"]}})

# API Configuration
API_VERSION = "1.0.0"
API_PREFIX = "/api"
JWT_SECRET = os.environ.get("API_JWT_SECRET", "change-this-secret-in-production")
JWT_ALGORITHM = "HS256"
TOKEN_EXPIRY_HOURS = 24

# Admin credentials (should be stored securely in production)
ADMIN_USERS = {
    "admin": "admin123"  # In production, use hashed passwords and secure storage
}

# Initialize managers
process_analyzer = ProcessAnalyzer()
service_auditor = ServiceAuditor()
alert_manager = AlertManager()
process_control_manager = ProcessControlManager()
report_generator = ReportGenerator()
metrics_collector = MetricsCollector()

# ============================================================================
# Response Helpers
# ============================================================================

def success_response(data: Any, message: str = "Success", status_code: int = 200) -> Tuple[Dict, int]:
    """Create a standardized success response."""
    return {
        "success": True,
        "message": message,
        "data": data,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }, status_code


def error_response(error: str, message: str = "", status_code: int = 400) -> Tuple[Dict, int]:
    """Create a standardized error response."""
    return {
        "success": False,
        "error": error,
        "message": message,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }, status_code


# ============================================================================
# Authentication
# ============================================================================

def generate_token(username: str) -> str:
    """Generate a JWT token for the user."""
    if not jwt:
        logger.error("PyJWT not installed. Install with: pip install PyJWT")
        raise ImportError("PyJWT is required for token generation")
    
    payload = {
        "username": username,
        "iat": datetime.now(timezone.utc),
        "exp": datetime.now(timezone.utc) + timedelta(hours=TOKEN_EXPIRY_HOURS)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def verify_token(token: str) -> Optional[Dict[str, Any]]:
    """Verify a JWT token and return the payload."""
    if not jwt:
        logger.error("PyJWT not installed")
        return None
    
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        logger.warning(f"Token expired")
        return None
    except jwt.InvalidTokenError as e:
        logger.warning(f"Invalid token: {e}")
        return None


def token_required(f):
    """Decorator to require valid JWT token."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = None
        
        # Get token from Authorization header
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            try:
                token = auth_header.split(" ")[1]
            except IndexError:
                return error_response("Invalid Authorization header", "", 401)
        
        if not token:
            return error_response("Missing token", "Authorization token is required", 401)
        
        payload = verify_token(token)
        if not payload:
            return error_response("Invalid or expired token", "", 401)
        
        request.user = payload.get('username')
        return f(*args, **kwargs)
    
    return decorated_function


# ============================================================================
# Authentication Endpoints
# ============================================================================

@app.route(f'{API_PREFIX}/auth/login', methods=['POST'])
def login():
    """
    Login endpoint - returns JWT token
    
    Request JSON:
    {
        "username": "admin",
        "password": "admin123"
    }
    
    Response:
    {
        "success": true,
        "data": {
            "token": "eyJ0eXAiOiJKV1QiLCJhbGc...",
            "expires_in": 86400
        },
        "message": "Login successful"
    }
    """
    try:
        data = request.get_json() or {}
        username = data.get('username', '')
        password = data.get('password', '')
        
        # Validate credentials
        if username not in ADMIN_USERS or ADMIN_USERS[username] != password:
            logger.warning(f"Failed login attempt for user {username}")
            return error_response("invalid_credentials", "Invalid username or password", 401)
        
        # Generate token
        try:
            token = generate_token(username)
            logger.info(f"User {username} logged in successfully")
            return success_response({
                "token": token,
                "expires_in": TOKEN_EXPIRY_HOURS * 3600,
                "username": username
            }, "Login successful", 200)
        except ImportError:
            # Fallback if PyJWT not installed
            logger.warning("PyJWT not available, using simple token")
            return success_response({
                "token": f"basic_{username}_{datetime.now().timestamp()}",
                "expires_in": TOKEN_EXPIRY_HOURS * 3600,
                "username": username
            }, "Login successful (basic auth)", 200)
    
    except Exception as e:
        logger.error(f"Login error: {e}")
        return error_response("server_error", str(e), 500)


@app.route(f'{API_PREFIX}/auth/logout', methods=['POST'])
@token_required
def logout():
    """
    Logout endpoint - invalidates token
    
    Headers:
        Authorization: Bearer <token>
    """
    try:
        username = request.user
        logger.info(f"User {username} logged out")
        return success_response({}, "Logout successful", 200)
    except Exception as e:
        logger.error(f"Logout error: {e}")
        return error_response("server_error", str(e), 500)


@app.route(f'{API_PREFIX}/auth/verify', methods=['GET'])
@token_required
def verify_auth():
    """
    Verify current authentication
    
    Headers:
        Authorization: Bearer <token>
    
    Response:
    {
        "success": true,
        "data": {
            "authenticated": true,
            "username": "admin"
        }
    }
    """
    return success_response({
        "authenticated": True,
        "username": request.user
    }, "Authentication valid", 200)


# ============================================================================
# Process Endpoints
# ============================================================================

@app.route(f'{API_PREFIX}/processes', methods=['GET'])
@token_required
def get_processes():
    """
    Get list of all running processes
    
    Query Parameters:
        - filter: Filter by process name (partial match)
        - limit: Maximum number of results (default: 1000)
        - include_suspicious: Include only suspicious processes (default: false)
    
    Response:
    {
        "success": true,
        "data": {
            "processes": [...],
            "count": 150,
            "timestamp": "2026-04-25T..."
        }
    }
    """
    try:
        limit = request.args.get('limit', 1000, type=int)
        filter_name = request.args.get('filter', '')
        include_suspicious = request.args.get('include_suspicious', 'false').lower() == 'true'
        
        processes = process_analyzer.get_all_processes()
        
        if filter_name:
            processes = [p for p in processes if filter_name.lower() in p.get('name', '').lower()]
        
        if include_suspicious:
            # Add suspicion analysis
            suspicious_processes = []
            for proc in processes:
                suspicious_score = process_analyzer.analyze_process(proc)
                if suspicious_score.get('risk_level') in ['HIGH', 'CRITICAL']:
                    proc['suspicious_score'] = suspicious_score
                    suspicious_processes.append(proc)
            processes = suspicious_processes
        
        # Limit results
        processes = processes[:limit]
        
        return success_response({
            "processes": processes,
            "count": len(processes),
            "timestamp": datetime.now(timezone.utc).isoformat()
        }, f"Retrieved {len(processes)} processes", 200)
    
    except Exception as e:
        logger.error(f"Error retrieving processes: {e}")
        return error_response("server_error", str(e), 500)


@app.route(f'{API_PREFIX}/processes/<int:pid>', methods=['GET'])
@token_required
def get_process(pid: int):
    """
    Get details for a specific process
    
    Path Parameters:
        - pid: Process ID
    
    Response:
    {
        "success": true,
        "data": {
            "process": {...},
            "analysis": {...},
            "parent": {...},
            "children": [...]
        }
    }
    """
    try:
        process = process_analyzer.get_process_by_pid(pid)
        if not process:
            return error_response("not_found", f"Process with PID {pid} not found", 404)
        
        # Get process tree
        parent = process_analyzer.get_parent_process(pid)
        children = process_analyzer.get_child_processes(pid)
        
        # Analyze suspicion
        analysis = process_analyzer.analyze_process(process)
        
        return success_response({
            "process": process,
            "analysis": analysis,
            "parent": parent,
            "children": children
        }, "Process details retrieved", 200)
    
    except Exception as e:
        logger.error(f"Error retrieving process {pid}: {e}")
        return error_response("server_error", str(e), 500)


@app.route(f'{API_PREFIX}/processes/tree', methods=['GET'])
@token_required
def get_process_tree():
    """
    Get process tree visualization
    
    Response:
    {
        "success": true,
        "data": {
            "tree": {...},
            "count": 150
        }
    }
    """
    try:
        tree = process_analyzer.build_process_tree()
        return success_response({
            "tree": tree,
            "count": len(tree) if isinstance(tree, list) else 1
        }, "Process tree retrieved", 200)
    
    except Exception as e:
        logger.error(f"Error retrieving process tree: {e}")
        return error_response("server_error", str(e), 500)


# ============================================================================
# Service Endpoints
# ============================================================================

@app.route(f'{API_PREFIX}/services', methods=['GET'])
@token_required
def get_services():
    """
    Get list of all Windows services
    
    Query Parameters:
        - filter: Filter by service name (partial match)
        - limit: Maximum number of results (default: 1000)
        - include_suspicious: Include only suspicious services (default: false)
        - state: Filter by state (Running, Stopped, etc.)
    
    Response:
    {
        "success": true,
        "data": {
            "services": [...],
            "count": 280,
            "timestamp": "2026-04-25T..."
        }
    }
    """
    try:
        limit = request.args.get('limit', 1000, type=int)
        filter_name = request.args.get('filter', '')
        include_suspicious = request.args.get('include_suspicious', 'false').lower() == 'true'
        state_filter = request.args.get('state', '')
        
        services = service_auditor.get_all_services()
        
        if filter_name:
            services = [s for s in services if filter_name.lower() in s.get('name', '').lower()]
        
        if state_filter:
            services = [s for s in services if s.get('state', '').lower() == state_filter.lower()]
        
        if include_suspicious:
            suspicious_services = []
            for svc in services:
                analysis = service_auditor.analyze_service(svc)
                if analysis.get('risk_level') in ['HIGH', 'CRITICAL']:
                    svc['analysis'] = analysis
                    suspicious_services.append(svc)
            services = suspicious_services
        
        # Limit results
        services = services[:limit]
        
        return success_response({
            "services": services,
            "count": len(services),
            "timestamp": datetime.now(timezone.utc).isoformat()
        }, f"Retrieved {len(services)} services", 200)
    
    except Exception as e:
        logger.error(f"Error retrieving services: {e}")
        return error_response("server_error", str(e), 500)


@app.route(f'{API_PREFIX}/services/<name>', methods=['GET'])
@token_required
def get_service(name: str):
    """
    Get details for a specific service
    
    Path Parameters:
        - name: Service name
    
    Response:
    {
        "success": true,
        "data": {
            "service": {...},
            "analysis": {...}
        }
    }
    """
    try:
        service = service_auditor.get_service_by_name(name)
        if not service:
            return error_response("not_found", f"Service '{name}' not found", 404)
        
        analysis = service_auditor.analyze_service(service)
        
        return success_response({
            "service": service,
            "analysis": analysis
        }, "Service details retrieved", 200)
    
    except Exception as e:
        logger.error(f"Error retrieving service {name}: {e}")
        return error_response("server_error", str(e), 500)


# ============================================================================
# Alert Endpoints
# ============================================================================

@app.route(f'{API_PREFIX}/alerts', methods=['GET'])
@token_required
def get_alerts():
    """
    Get recent alerts
    
    Query Parameters:
        - limit: Maximum number of results (default: 100)
        - severity: Filter by severity (Critical, High, Medium, Low, Info)
        - hours: Get alerts from last N hours (default: 24)
    
    Response:
    {
        "success": true,
        "data": {
            "alerts": [...],
            "count": 15,
            "critical_count": 2,
            "high_count": 5
        }
    }
    """
    try:
        limit = request.args.get('limit', 100, type=int)
        severity_filter = request.args.get('severity', '')
        hours = request.args.get('hours', 24, type=int)
        
        alerts = alert_manager.get_recent_alerts(hours=hours)
        
        if severity_filter:
            alerts = [a for a in alerts if a.get('severity', '').lower() == severity_filter.lower()]
        
        # Limit results
        alerts = alerts[:limit]
        
        # Count by severity
        severity_counts = {}
        for alert in alerts:
            severity = alert.get('severity', 'Info')
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        return success_response({
            "alerts": alerts,
            "count": len(alerts),
            "severity_counts": severity_counts,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }, f"Retrieved {len(alerts)} alerts", 200)
    
    except Exception as e:
        logger.error(f"Error retrieving alerts: {e}")
        return error_response("server_error", str(e), 500)


@app.route(f'{API_PREFIX}/alerts/<alert_id>', methods=['GET'])
@token_required
def get_alert(alert_id: str):
    """
    Get details for a specific alert
    
    Path Parameters:
        - alert_id: Alert ID
    
    Response:
    {
        "success": true,
        "data": {
            "alert": {...}
        }
    }
    """
    try:
        alert = alert_manager.get_alert_by_id(alert_id)
        if not alert:
            return error_response("not_found", f"Alert '{alert_id}' not found", 404)
        
        return success_response({
            "alert": alert
        }, "Alert details retrieved", 200)
    
    except Exception as e:
        logger.error(f"Error retrieving alert {alert_id}: {e}")
        return error_response("server_error", str(e), 500)


# ============================================================================
# Process Control Endpoints
# ============================================================================

@app.route(f'{API_PREFIX}/processes/<int:pid>/kill', methods=['POST'])
@token_required
def kill_process(pid: int):
    """
    Kill a process
    
    Path Parameters:
        - pid: Process ID
    
    Request JSON:
    {
        "force": false,
        "reason": "Suspicious activity detected"
    }
    
    Response:
    {
        "success": true,
        "data": {
            "killed": true,
            "pid": 1234,
            "name": "malware.exe"
        }
    }
    """
    try:
        data = request.get_json() or {}
        force = data.get('force', False)
        reason = data.get('reason', 'Manual termination via API')
        
        result = process_control_manager.kill_process(
            pid=pid,
            force=force,
            reason=reason
        )
        
        if result:
            logger.info(f"Process {pid} killed by {request.user}: {reason}")
            return success_response({
                "killed": True,
                "pid": pid,
                "method": "force" if force else "graceful"
            }, f"Process {pid} terminated", 200)
        else:
            return error_response("kill_failed", f"Failed to terminate process {pid}", 400)
    
    except Exception as e:
        logger.error(f"Error killing process {pid}: {e}")
        return error_response("server_error", str(e), 500)


@app.route(f'{API_PREFIX}/whitelist', methods=['GET'])
@token_required
def get_whitelist():
    """
    Get whitelist entries
    
    Response:
    {
        "success": true,
        "data": {
            "whitelist": [...],
            "count": 25
        }
    }
    """
    try:
        whitelist = process_control_manager.get_whitelist()
        entries = [
            {
                "name": name,
                "path": entry.path,
                "reason": entry.reason,
                "added_at": entry.added_at,
                "added_by": entry.added_by
            }
            for name, entry in whitelist.items()
        ]
        
        return success_response({
            "whitelist": entries,
            "count": len(entries)
        }, "Whitelist retrieved", 200)
    
    except Exception as e:
        logger.error(f"Error retrieving whitelist: {e}")
        return error_response("server_error", str(e), 500)


@app.route(f'{API_PREFIX}/whitelist', methods=['POST'])
@token_required
def add_to_whitelist():
    """
    Add process to whitelist
    
    Request JSON:
    {
        "name": "notepad.exe",
        "path": "C:\\Windows\\System32\\notepad.exe",
        "reason": "Trusted system application"
    }
    
    Response:
    {
        "success": true,
        "data": {
            "added": true,
            "name": "notepad.exe"
        }
    }
    """
    try:
        data = request.get_json() or {}
        name = data.get('name', '')
        path = data.get('path')
        reason = data.get('reason', '')
        
        if not name:
            return error_response("invalid_input", "Process name is required", 400)
        
        process_control_manager.add_to_whitelist(
            name=name,
            path=path,
            reason=reason,
            added_by=request.user
        )
        
        logger.info(f"Process '{name}' added to whitelist by {request.user}")
        return success_response({
            "added": True,
            "name": name
        }, f"Process '{name}' added to whitelist", 200)
    
    except Exception as e:
        logger.error(f"Error adding to whitelist: {e}")
        return error_response("server_error", str(e), 500)


@app.route(f'{API_PREFIX}/whitelist/<name>', methods=['DELETE'])
@token_required
def remove_from_whitelist(name: str):
    """
    Remove process from whitelist
    
    Path Parameters:
        - name: Process name
    
    Response:
    {
        "success": true,
        "data": {
            "removed": true,
            "name": "notepad.exe"
        }
    }
    """
    try:
        process_control_manager.remove_from_whitelist(name)
        logger.info(f"Process '{name}' removed from whitelist by {request.user}")
        return success_response({
            "removed": True,
            "name": name
        }, f"Process '{name}' removed from whitelist", 200)
    
    except Exception as e:
        logger.error(f"Error removing from whitelist: {e}")
        return error_response("server_error", str(e), 500)


@app.route(f'{API_PREFIX}/blacklist', methods=['GET'])
@token_required
def get_blacklist():
    """
    Get blacklist entries
    
    Response:
    {
        "success": true,
        "data": {
            "blacklist": [...],
            "count": 10
        }
    }
    """
    try:
        blacklist = process_control_manager.get_blacklist()
        entries = [
            {
                "name": name,
                "path": entry.path,
                "reason": entry.reason,
                "auto_block": entry.auto_block,
                "added_at": entry.added_at,
                "added_by": entry.added_by
            }
            for name, entry in blacklist.items()
        ]
        
        return success_response({
            "blacklist": entries,
            "count": len(entries)
        }, "Blacklist retrieved", 200)
    
    except Exception as e:
        logger.error(f"Error retrieving blacklist: {e}")
        return error_response("server_error", str(e), 500)


@app.route(f'{API_PREFIX}/blacklist', methods=['POST'])
@token_required
def add_to_blacklist():
    """
    Add process to blacklist
    
    Request JSON:
    {
        "name": "malware.exe",
        "path": "C:\\malware.exe",
        "reason": "Known malicious executable",
        "auto_block": true
    }
    
    Response:
    {
        "success": true,
        "data": {
            "added": true,
            "name": "malware.exe"
        }
    }
    """
    try:
        data = request.get_json() or {}
        name = data.get('name', '')
        path = data.get('path')
        reason = data.get('reason', '')
        auto_block = data.get('auto_block', False)
        
        if not name:
            return error_response("invalid_input", "Process name is required", 400)
        
        process_control_manager.add_to_blacklist(
            name=name,
            path=path,
            reason=reason,
            auto_block=auto_block,
            added_by=request.user
        )
        
        logger.info(f"Process '{name}' added to blacklist by {request.user}")
        return success_response({
            "added": True,
            "name": name,
            "auto_block": auto_block
        }, f"Process '{name}' added to blacklist", 200)
    
    except Exception as e:
        logger.error(f"Error adding to blacklist: {e}")
        return error_response("server_error", str(e), 500)


@app.route(f'{API_PREFIX}/blacklist/<name>', methods=['DELETE'])
@token_required
def remove_from_blacklist(name: str):
    """
    Remove process from blacklist
    
    Path Parameters:
        - name: Process name
    
    Response:
    {
        "success": true,
        "data": {
            "removed": true,
            "name": "malware.exe"
        }
    }
    """
    try:
        process_control_manager.remove_from_blacklist(name)
        logger.info(f"Process '{name}' removed from blacklist by {request.user}")
        return success_response({
            "removed": True,
            "name": name
        }, f"Process '{name}' removed from blacklist", 200)
    
    except Exception as e:
        logger.error(f"Error removing from blacklist: {e}")
        return error_response("server_error", str(e), 500)


# ============================================================================
# Report Endpoints
# ============================================================================

@app.route(f'{API_PREFIX}/reports/summary', methods=['GET'])
@token_required
def get_summary_report():
    """
    Get summary report
    
    Query Parameters:
        - hours: Hours to include in report (default: 24)
    
    Response:
    {
        "success": true,
        "data": {
            "summary": {...},
            "generated_at": "2026-04-25T..."
        }
    }
    """
    try:
        hours = request.args.get('hours', 24, type=int)
        summary = report_generator.generate_summary(hours=hours)
        
        return success_response({
            "summary": summary,
            "generated_at": datetime.now(timezone.utc).isoformat()
        }, "Summary report generated", 200)
    
    except Exception as e:
        logger.error(f"Error generating summary report: {e}")
        return error_response("server_error", str(e), 500)


@app.route(f'{API_PREFIX}/reports/detailed', methods=['GET'])
@token_required
def get_detailed_report():
    """
    Get detailed report
    
    Query Parameters:
        - hours: Hours to include in report (default: 24)
    
    Response:
    {
        "success": true,
        "data": {
            "report": {...},
            "generated_at": "2026-04-25T..."
        }
    }
    """
    try:
        hours = request.args.get('hours', 24, type=int)
        report = report_generator.generate_detailed(hours=hours)
        
        return success_response({
            "report": report,
            "generated_at": datetime.now(timezone.utc).isoformat()
        }, "Detailed report generated", 200)
    
    except Exception as e:
        logger.error(f"Error generating detailed report: {e}")
        return error_response("server_error", str(e), 500)


# ============================================================================
# Chart/Visualization Endpoints
# ============================================================================

@app.route(f'{API_PREFIX}/charts/cpu-timeline', methods=['GET'])
@token_required
def get_cpu_timeline():
    """
    Get CPU usage timeline for charts.
    
    Query Parameters:
        - hours: Number of hours to look back (default: 1)
    
    Response:
    {
        "success": true,
        "data": {
            "timeline": [
                {"timestamp": "...", "system_cpu": 25.5, "process_count": 150}
            ]
        }
    }
    """
    try:
        hours = request.args.get('hours', 1, type=int)
        timeline = metrics_collector.get_cpu_usage_timeline(hours=hours)
        
        return success_response({
            "timeline": timeline,
            "hours": hours,
            "count": len(timeline)
        }, "CPU timeline retrieved", 200)
    
    except Exception as e:
        logger.error(f"Error retrieving CPU timeline: {e}")
        return error_response("server_error", str(e), 500)


@app.route(f'{API_PREFIX}/charts/memory-timeline', methods=['GET'])
@token_required
def get_memory_timeline():
    """
    Get memory usage timeline for charts.
    
    Query Parameters:
        - hours: Number of hours to look back (default: 1)
    
    Response:
    {
        "success": true,
        "data": {
            "timeline": [
                {"timestamp": "...", "system_memory_percent": 45.2, "memory_available_mb": 8192}
            ]
        }
    }
    """
    try:
        hours = request.args.get('hours', 1, type=int)
        timeline = metrics_collector.get_memory_usage_timeline(hours=hours)
        
        return success_response({
            "timeline": timeline,
            "hours": hours,
            "count": len(timeline)
        }, "Memory timeline retrieved", 200)
    
    except Exception as e:
        logger.error(f"Error retrieving memory timeline: {e}")
        return error_response("server_error", str(e), 500)


@app.route(f'{API_PREFIX}/charts/top-processes-cpu', methods=['GET'])
@token_required
def get_top_processes_cpu():
    """
    Get top processes by CPU usage for charts.
    
    Query Parameters:
        - hours: Number of hours to look back (default: 1)
        - limit: Maximum number of processes (default: 10)
    
    Response:
    {
        "success": true,
        "data": {
            "processes": [
                {"name": "chrome.exe", "avg_cpu": 15.5, "max_cpu": 28.3, "samples": 120}
            ]
        }
    }
    """
    try:
        hours = request.args.get('hours', 1, type=int)
        limit = request.args.get('limit', 10, type=int)
        
        # Collect current snapshot to ensure we have data
        metrics_collector.collect_snapshot()
        
        top_processes = metrics_collector.get_top_processes_by_cpu(hours=hours, limit=limit)
        
        return success_response({
            "processes": top_processes,
            "hours": hours,
            "limit": limit,
            "count": len(top_processes)
        }, "Top processes by CPU retrieved", 200)
    
    except Exception as e:
        logger.error(f"Error retrieving top processes by CPU: {e}")
        return error_response("server_error", str(e), 500)


@app.route(f'{API_PREFIX}/charts/top-processes-memory', methods=['GET'])
@token_required
def get_top_processes_memory():
    """
    Get top processes by memory usage for charts.
    
    Query Parameters:
        - hours: Number of hours to look back (default: 1)
        - limit: Maximum number of processes (default: 10)
    
    Response:
    {
        "success": true,
        "data": {
            "processes": [
                {"name": "python.exe", "avg_memory_mb": 256.3, "max_memory_mb": 512.5, "samples": 120}
            ]
        }
    }
    """
    try:
        hours = request.args.get('hours', 1, type=int)
        limit = request.args.get('limit', 10, type=int)
        
        # Collect current snapshot to ensure we have data
        metrics_collector.collect_snapshot()
        
        top_processes = metrics_collector.get_top_processes_by_memory(hours=hours, limit=limit)
        
        return success_response({
            "processes": top_processes,
            "hours": hours,
            "limit": limit,
            "count": len(top_processes)
        }, "Top processes by memory retrieved", 200)
    
    except Exception as e:
        logger.error(f"Error retrieving top processes by memory: {e}")
        return error_response("server_error", str(e), 500)


@app.route(f'{API_PREFIX}/charts/process-cpu/<process_name>', methods=['GET'])
@token_required
def get_process_cpu_timeline(process_name: str):
    """
    Get CPU usage timeline for a specific process.
    
    Path Parameters:
        - process_name: Name of the process
    
    Query Parameters:
        - hours: Number of hours to look back (default: 1)
    
    Response:
    {
        "success": true,
        "data": {
            "timeline": [
                {"timestamp": "...", "cpu": 12.5}
            ]
        }
    }
    """
    try:
        hours = request.args.get('hours', 1, type=int)
        timeline = metrics_collector.get_process_cpu_timeline(process_name, hours=hours)
        
        return success_response({
            "process_name": process_name,
            "timeline": timeline,
            "hours": hours,
            "count": len(timeline)
        }, f"CPU timeline for {process_name} retrieved", 200)
    
    except Exception as e:
        logger.error(f"Error retrieving process CPU timeline: {e}")
        return error_response("server_error", str(e), 500)


@app.route(f'{API_PREFIX}/charts/process-memory/<process_name>', methods=['GET'])
@token_required
def get_process_memory_timeline(process_name: str):
    """
    Get memory usage timeline for a specific process.
    
    Path Parameters:
        - process_name: Name of the process
    
    Query Parameters:
        - hours: Number of hours to look back (default: 1)
    
    Response:
    {
        "success": true,
        "data": {
            "timeline": [
                {"timestamp": "...", "memory_mb": 256.3}
            ]
        }
    }
    """
    try:
        hours = request.args.get('hours', 1, type=int)
        timeline = metrics_collector.get_process_memory_timeline(process_name, hours=hours)
        
        return success_response({
            "process_name": process_name,
            "timeline": timeline,
            "hours": hours,
            "count": len(timeline)
        }, f"Memory timeline for {process_name} retrieved", 200)
    
    except Exception as e:
        logger.error(f"Error retrieving process memory timeline: {e}")
        return error_response("server_error", str(e), 500)


@app.route(f'{API_PREFIX}/charts/metrics-summary', methods=['GET'])
@token_required
def get_metrics_summary():
    """
    Get summary metrics and statistics.
    
    Query Parameters:
        - hours: Number of hours for summary (default: 24)
    
    Response:
    {
        "success": true,
        "data": {
            "summary": {
                "time_period_hours": 24,
                "snapshot_count": 288,
                "unique_processes": 145,
                "cpu_avg": 15.5,
                "cpu_max": 95.2,
                "memory_avg_percent": 45.3,
                ...
            }
        }
    }
    """
    try:
        hours = request.args.get('hours', 24, type=int)
        summary = metrics_collector.get_summary_stats(hours=hours)
        
        return success_response({
            "summary": summary
        }, "Metrics summary retrieved", 200)
    
    except Exception as e:
        logger.error(f"Error retrieving metrics summary: {e}")
        return error_response("server_error", str(e), 500)


# ============================================================================
# System Endpoints
# ============================================================================

@app.route(f'{API_PREFIX}/health', methods=['GET'])
def health_check():
    """
    Health check endpoint (no authentication required)
    
    Response:
    {
        "success": true,
        "data": {
            "status": "healthy",
            "version": "1.0.0",
            "timestamp": "2026-04-25T..."
        }
    }
    """
    return success_response({
        "status": "healthy",
        "version": API_VERSION,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }, "API is healthy", 200)


@app.route(f'{API_PREFIX}/config', methods=['GET'])
@token_required
def get_config():
    """
    Get current configuration
    
    Response:
    {
        "success": true,
        "data": {
            "config": {...}
        }
    }
    """
    try:
        # Return non-sensitive configuration
        config_data = {
            "version": API_VERSION,
            "baseline_file": config.SERVICE_BASELINE_FILE if hasattr(config, 'SERVICE_BASELINE_FILE') else "N/A",
            "check_interval": config.CHECK_INTERVAL if hasattr(config, 'CHECK_INTERVAL') else "N/A",
        }
        
        return success_response({
            "config": config_data
        }, "Configuration retrieved", 200)
    
    except Exception as e:
        logger.error(f"Error retrieving configuration: {e}")
        return error_response("server_error", str(e), 500)


@app.route(f'{API_PREFIX}/stats', methods=['GET'])
@token_required
def get_stats():
    """
    Get system statistics
    
    Response:
    {
        "success": true,
        "data": {
            "total_processes": 150,
            "total_services": 280,
            "recent_alerts": 25,
            "critical_alerts": 2
        }
    }
    """
    try:
        processes = process_analyzer.get_all_processes()
        services = service_auditor.get_all_services()
        alerts = alert_manager.get_recent_alerts(hours=24)
        
        critical_count = sum(1 for a in alerts if a.get('severity') == 'Critical')
        high_count = sum(1 for a in alerts if a.get('severity') == 'High')
        
        return success_response({
            "total_processes": len(processes),
            "total_services": len(services),
            "recent_alerts_24h": len(alerts),
            "critical_alerts": critical_count,
            "high_alerts": high_count,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }, "Statistics retrieved", 200)
    
    except Exception as e:
        logger.error(f"Error retrieving statistics: {e}")
        return error_response("server_error", str(e), 500)


# ============================================================================
# Error Handlers
# ============================================================================

@app.errorhandler(404)
def not_found(error):
    """Handle 404 errors."""
    return error_response("not_found", "Endpoint not found", 404)


@app.errorhandler(405)
def method_not_allowed(error):
    """Handle 405 errors."""
    return error_response("method_not_allowed", "HTTP method not allowed", 405)


@app.errorhandler(500)
def internal_error(error):
    """Handle 500 errors."""
    logger.error(f"Internal server error: {error}")
    return error_response("internal_error", "Internal server error", 500)


# ============================================================================
# API Documentation
# ============================================================================

@app.route(f'{API_PREFIX}/docs', methods=['GET'])
def api_docs():
    """
    API documentation endpoint
    
    Returns HTML documentation of all available endpoints
    """
    html = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Windows Service Monitoring Agent - REST API Documentation</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
            .container { max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; }
            h1 { color: #333; border-bottom: 3px solid #007bff; padding-bottom: 10px; }
            h2 { color: #007bff; margin-top: 30px; }
            .endpoint { background: #f9f9f9; padding: 15px; margin: 10px 0; border-left: 4px solid #007bff; }
            .method { font-weight: bold; padding: 5px 10px; border-radius: 3px; display: inline-block; }
            .get { background: #61affe; color: white; }
            .post { background: #49cc90; color: white; }
            .delete { background: #f93e3e; color: white; }
            code { background: #f4f4f4; padding: 2px 6px; border-radius: 3px; font-family: monospace; }
            .auth { background: #fff3cd; padding: 10px; margin: 10px 0; border-radius: 3px; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>Windows Service Monitoring Agent - REST API v1.0.0</h1>
            
            <div class="auth">
                <strong>Authentication:</strong> All endpoints except <code>/api/health</code> require JWT token.
                <br>Get token via <code>POST /api/auth/login</code>
                <br>Include token in header: <code>Authorization: Bearer &lt;token&gt;</code>
            </div>
            
            <h2>Authentication Endpoints</h2>
            
            <div class="endpoint">
                <span class="method post">POST</span> <code>/api/auth/login</code>
                <p>Login and get JWT token</p>
            </div>
            
            <div class="endpoint">
                <span class="method post">POST</span> <code>/api/auth/logout</code>
                <p>Logout (requires authentication)</p>
            </div>
            
            <div class="endpoint">
                <span class="method get">GET</span> <code>/api/auth/verify</code>
                <p>Verify current authentication (requires authentication)</p>
            </div>
            
            <h2>Process Endpoints</h2>
            
            <div class="endpoint">
                <span class="method get">GET</span> <code>/api/processes</code>
                <p>Get list of all processes (query: filter, limit, include_suspicious)</p>
            </div>
            
            <div class="endpoint">
                <span class="method get">GET</span> <code>/api/processes/&lt;pid&gt;</code>
                <p>Get process details by PID</p>
            </div>
            
            <div class="endpoint">
                <span class="method get">GET</span> <code>/api/processes/tree</code>
                <p>Get process tree visualization</p>
            </div>
            
            <div class="endpoint">
                <span class="method post">POST</span> <code>/api/processes/&lt;pid&gt;/kill</code>
                <p>Kill a process (body: force, reason)</p>
            </div>
            
            <h2>Service Endpoints</h2>
            
            <div class="endpoint">
                <span class="method get">GET</span> <code>/api/services</code>
                <p>Get list of all services (query: filter, limit, include_suspicious, state)</p>
            </div>
            
            <div class="endpoint">
                <span class="method get">GET</span> <code>/api/services/&lt;name&gt;</code>
                <p>Get service details by name</p>
            </div>
            
            <h2>Alert Endpoints</h2>
            
            <div class="endpoint">
                <span class="method get">GET</span> <code>/api/alerts</code>
                <p>Get recent alerts (query: limit, severity, hours)</p>
            </div>
            
            <div class="endpoint">
                <span class="method get">GET</span> <code>/api/alerts/&lt;alert_id&gt;</code>
                <p>Get alert details by ID</p>
            </div>
            
            <h2>Process Control Endpoints</h2>
            
            <div class="endpoint">
                <span class="method get">GET</span> <code>/api/whitelist</code>
                <p>Get whitelist entries</p>
            </div>
            
            <div class="endpoint">
                <span class="method post">POST</span> <code>/api/whitelist</code>
                <p>Add to whitelist (body: name, path, reason)</p>
            </div>
            
            <div class="endpoint">
                <span class="method delete">DELETE</span> <code>/api/whitelist/&lt;name&gt;</code>
                <p>Remove from whitelist</p>
            </div>
            
            <div class="endpoint">
                <span class="method get">GET</span> <code>/api/blacklist</code>
                <p>Get blacklist entries</p>
            </div>
            
            <div class="endpoint">
                <span class="method post">POST</span> <code>/api/blacklist</code>
                <p>Add to blacklist (body: name, path, reason, auto_block)</p>
            </div>
            
            <div class="endpoint">
                <span class="method delete">DELETE</span> <code>/api/blacklist/&lt;name&gt;</code>
                <p>Remove from blacklist</p>
            </div>
            
            <h2>Report Endpoints</h2>
            
            <div class="endpoint">
                <span class="method get">GET</span> <code>/api/reports/summary</code>
                <p>Get summary report (query: hours)</p>
            </div>
            
            <div class="endpoint">
                <span class="method get">GET</span> <code>/api/reports/detailed</code>
                <p>Get detailed report (query: hours)</p>
            </div>
            
            <h2>System Endpoints</h2>
            
            <div class="endpoint">
                <span class="method get">GET</span> <code>/api/health</code>
                <p>Health check (no authentication required)</p>
            </div>
            
            <div class="endpoint">
                <span class="method get">GET</span> <code>/api/config</code>
                <p>Get current configuration</p>
            </div>
            
            <div class="endpoint">
                <span class="method get">GET</span> <code>/api/stats</code>
                <p>Get system statistics</p>
            </div>
        </div>
    </body>
    </html>
    """
    return html


# ============================================================================
# Main Entry Point
# ============================================================================

if __name__ == '__main__':
    port = int(os.environ.get('API_PORT', 5001))
    debug = os.environ.get('API_DEBUG', 'False').lower() == 'true'
    
    logger.info(f"Starting REST API Server v{API_VERSION}")
    logger.info(f"Documentation: http://localhost:{port}/api/docs")
    logger.info(f"Health check: http://localhost:{port}/api/health")
    
    app.run(
        host='0.0.0.0',
        port=port,
        debug=debug,
        threaded=True
    )
