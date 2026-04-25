"""
REST API Client SDK for Windows Service Process Monitoring Agent

Provides a Python client library for interacting with the monitoring API.
Useful for mobile apps, external integrations, and remote monitoring.

Usage:
    from api_client import MonitoringAPIClient
    
    client = MonitoringAPIClient("http://localhost:5001")
    token = client.login("admin", "admin123")
    
    # Get processes
    processes = client.get_processes(include_suspicious=True)
    
    # Kill a process
    client.kill_process(1234, force=False, reason="Suspicious activity")
    
    # Get alerts
    alerts = client.get_alerts(severity="Critical")
    
    # Add to blacklist
    client.add_to_blacklist("malware.exe", reason="Known malware")
"""

from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Optional

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False
    requests = None  # type: ignore

logger = logging.getLogger(__name__)


class APIClientError(Exception):
    """Base exception for API client errors."""
    pass


class APIAuthenticationError(APIClientError):
    """Authentication error."""
    pass


class APINotFoundError(APIClientError):
    """Resource not found error."""
    pass


class APIServerError(APIClientError):
    """Server error."""
    pass


class MonitoringAPIClient:
    """
    REST API client for Windows Service Process Monitoring Agent.
    
    Provides convenient methods for all API operations.
    """
    
    def __init__(self, api_url: str, timeout: int = 30):
        """
        Initialize API client.
        
        Args:
            api_url: Base URL of the API (e.g., http://localhost:5001)
            timeout: Request timeout in seconds
        """
        if not HAS_REQUESTS:
            raise ImportError("requests library is required. Install with: pip install requests")
        
        self.api_url = api_url.rstrip('/')
        self.timeout = timeout
        self.token: Optional[str] = None
        self.username: Optional[str] = None
        self.session = requests.Session()
    
    def _make_request(
        self,
        method: str,
        endpoint: str,
        data: Optional[Dict[str, Any]] = None,
        params: Optional[Dict[str, Any]] = None,
        require_auth: bool = True
    ) -> Dict[str, Any]:
        """
        Make HTTP request to API.
        
        Args:
            method: HTTP method (GET, POST, DELETE, etc.)
            endpoint: API endpoint path (e.g., /api/processes)
            data: Request body as dictionary
            params: Query parameters
            require_auth: Whether authentication token is required
        
        Returns:
            Response JSON data
            
        Raises:
            APIClientError: On API errors
        """
        url = f"{self.api_url}{endpoint}"
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "MonitoringAPIClient/1.0"
        }
        
        if require_auth:
            if not self.token:
                raise APIAuthenticationError("Not authenticated. Call login() first.")
            headers["Authorization"] = f"Bearer {self.token}"
        
        try:
            response = self.session.request(
                method=method,
                url=url,
                json=data,
                params=params,
                headers=headers,
                timeout=self.timeout
            )
            
            # Handle different status codes
            if response.status_code == 401:
                raise APIAuthenticationError("Authentication failed. Token may be expired.")
            elif response.status_code == 404:
                raise APINotFoundError(f"Resource not found: {endpoint}")
            elif response.status_code >= 500:
                raise APIServerError(f"Server error: {response.status_code}")
            
            response.raise_for_status()
            return response.json()
        
        except requests.RequestException as e:
            raise APIClientError(f"Request failed: {e}")
    
    # ========================================================================
    # Authentication Methods
    # ========================================================================
    
    def login(self, username: str, password: str) -> str:
        """
        Login and obtain authentication token.
        
        Args:
            username: Username
            password: Password
            
        Returns:
            Authentication token
            
        Raises:
            APIAuthenticationError: If login fails
        """
        try:
            response = self._make_request(
                method="POST",
                endpoint="/api/auth/login",
                data={"username": username, "password": password},
                require_auth=False
            )
            
            if response.get('success'):
                self.token = response['data']['token']
                self.username = username
                logger.info(f"Successfully logged in as {username}")
                return self.token
            else:
                raise APIAuthenticationError(response.get('error', 'Login failed'))
        
        except APIClientError:
            raise
        except Exception as e:
            raise APIAuthenticationError(f"Login failed: {e}")
    
    def logout(self) -> None:
        """Logout and clear authentication token."""
        try:
            self._make_request(method="POST", endpoint="/api/auth/logout")
            self.token = None
            self.username = None
            logger.info("Logged out successfully")
        except Exception as e:
            logger.warning(f"Logout failed: {e}")
    
    def verify_auth(self) -> bool:
        """
        Verify current authentication.
        
        Returns:
            True if authenticated and token is valid
        """
        try:
            response = self._make_request(method="GET", endpoint="/api/auth/verify")
            return response.get('success', False)
        except APIClientError:
            return False
    
    # ========================================================================
    # Process Methods
    # ========================================================================
    
    def get_processes(
        self,
        filter: Optional[str] = None,
        limit: int = 1000,
        include_suspicious: bool = False
    ) -> List[Dict[str, Any]]:
        """
        Get list of running processes.
        
        Args:
            filter: Filter by process name (partial match)
            limit: Maximum number of results
            include_suspicious: Include only suspicious processes
            
        Returns:
            List of processes
        """
        params = {
            "limit": limit,
            "include_suspicious": str(include_suspicious).lower()
        }
        if filter:
            params["filter"] = filter
        
        response = self._make_request(
            method="GET",
            endpoint="/api/processes",
            params=params
        )
        return response.get('data', {}).get('processes', [])
    
    def get_process(self, pid: int) -> Dict[str, Any]:
        """
        Get details for a specific process.
        
        Args:
            pid: Process ID
            
        Returns:
            Process details including analysis and process tree
        """
        response = self._make_request(
            method="GET",
            endpoint=f"/api/processes/{pid}"
        )
        return response.get('data', {})
    
    def get_process_tree(self) -> Dict[str, Any]:
        """
        Get process tree visualization.
        
        Returns:
            Process tree structure
        """
        response = self._make_request(
            method="GET",
            endpoint="/api/processes/tree"
        )
        return response.get('data', {})
    
    def kill_process(
        self,
        pid: int,
        force: bool = False,
        reason: str = "Manual termination"
    ) -> bool:
        """
        Kill a process.
        
        Args:
            pid: Process ID
            force: Force kill if True, graceful termination if False
            reason: Reason for killing
            
        Returns:
            True if process was killed successfully
        """
        try:
            response = self._make_request(
                method="POST",
                endpoint=f"/api/processes/{pid}/kill",
                data={"force": force, "reason": reason}
            )
            return response.get('data', {}).get('killed', False)
        except APIClientError:
            return False
    
    # ========================================================================
    # Service Methods
    # ========================================================================
    
    def get_services(
        self,
        filter: Optional[str] = None,
        limit: int = 1000,
        include_suspicious: bool = False,
        state: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Get list of Windows services.
        
        Args:
            filter: Filter by service name (partial match)
            limit: Maximum number of results
            include_suspicious: Include only suspicious services
            state: Filter by state (Running, Stopped, etc.)
            
        Returns:
            List of services
        """
        params = {
            "limit": limit,
            "include_suspicious": str(include_suspicious).lower()
        }
        if filter:
            params["filter"] = filter
        if state:
            params["state"] = state
        
        response = self._make_request(
            method="GET",
            endpoint="/api/services",
            params=params
        )
        return response.get('data', {}).get('services', [])
    
    def get_service(self, name: str) -> Dict[str, Any]:
        """
        Get details for a specific service.
        
        Args:
            name: Service name
            
        Returns:
            Service details including analysis
        """
        response = self._make_request(
            method="GET",
            endpoint=f"/api/services/{name}"
        )
        return response.get('data', {})
    
    # ========================================================================
    # Alert Methods
    # ========================================================================
    
    def get_alerts(
        self,
        limit: int = 100,
        severity: Optional[str] = None,
        hours: int = 24
    ) -> List[Dict[str, Any]]:
        """
        Get recent alerts.
        
        Args:
            limit: Maximum number of results
            severity: Filter by severity (Critical, High, Medium, Low, Info)
            hours: Get alerts from last N hours
            
        Returns:
            List of alerts
        """
        params = {
            "limit": limit,
            "hours": hours
        }
        if severity:
            params["severity"] = severity
        
        response = self._make_request(
            method="GET",
            endpoint="/api/alerts",
            params=params
        )
        return response.get('data', {}).get('alerts', [])
    
    def get_alert(self, alert_id: str) -> Dict[str, Any]:
        """
        Get details for a specific alert.
        
        Args:
            alert_id: Alert ID
            
        Returns:
            Alert details
        """
        response = self._make_request(
            method="GET",
            endpoint=f"/api/alerts/{alert_id}"
        )
        return response.get('data', {})
    
    # ========================================================================
    # Whitelist Methods
    # ========================================================================
    
    def get_whitelist(self) -> List[Dict[str, Any]]:
        """
        Get whitelist entries.
        
        Returns:
            List of whitelisted processes
        """
        response = self._make_request(
            method="GET",
            endpoint="/api/whitelist"
        )
        return response.get('data', {}).get('whitelist', [])
    
    def add_to_whitelist(
        self,
        name: str,
        path: Optional[str] = None,
        reason: str = ""
    ) -> bool:
        """
        Add process to whitelist.
        
        Args:
            name: Process name
            path: Process path (optional)
            reason: Reason for whitelisting
            
        Returns:
            True if added successfully
        """
        try:
            response = self._make_request(
                method="POST",
                endpoint="/api/whitelist",
                data={"name": name, "path": path, "reason": reason}
            )
            return response.get('data', {}).get('added', False)
        except APIClientError:
            return False
    
    def remove_from_whitelist(self, name: str) -> bool:
        """
        Remove process from whitelist.
        
        Args:
            name: Process name
            
        Returns:
            True if removed successfully
        """
        try:
            response = self._make_request(
                method="DELETE",
                endpoint=f"/api/whitelist/{name}"
            )
            return response.get('data', {}).get('removed', False)
        except APIClientError:
            return False
    
    # ========================================================================
    # Blacklist Methods
    # ========================================================================
    
    def get_blacklist(self) -> List[Dict[str, Any]]:
        """
        Get blacklist entries.
        
        Returns:
            List of blacklisted processes
        """
        response = self._make_request(
            method="GET",
            endpoint="/api/blacklist"
        )
        return response.get('data', {}).get('blacklist', [])
    
    def add_to_blacklist(
        self,
        name: str,
        path: Optional[str] = None,
        reason: str = "",
        auto_block: bool = False
    ) -> bool:
        """
        Add process to blacklist.
        
        Args:
            name: Process name
            path: Process path (optional)
            reason: Reason for blacklisting
            auto_block: Automatically block/kill if detected
            
        Returns:
            True if added successfully
        """
        try:
            response = self._make_request(
                method="POST",
                endpoint="/api/blacklist",
                data={
                    "name": name,
                    "path": path,
                    "reason": reason,
                    "auto_block": auto_block
                }
            )
            return response.get('data', {}).get('added', False)
        except APIClientError:
            return False
    
    def remove_from_blacklist(self, name: str) -> bool:
        """
        Remove process from blacklist.
        
        Args:
            name: Process name
            
        Returns:
            True if removed successfully
        """
        try:
            response = self._make_request(
                method="DELETE",
                endpoint=f"/api/blacklist/{name}"
            )
            return response.get('data', {}).get('removed', False)
        except APIClientError:
            return False
    
    # ========================================================================
    # Report Methods
    # ========================================================================
    
    def get_summary_report(self, hours: int = 24) -> Dict[str, Any]:
        """
        Get summary report.
        
        Args:
            hours: Hours to include in report
            
        Returns:
            Summary report data
        """
        response = self._make_request(
            method="GET",
            endpoint="/api/reports/summary",
            params={"hours": hours}
        )
        return response.get('data', {})
    
    def get_detailed_report(self, hours: int = 24) -> Dict[str, Any]:
        """
        Get detailed report.
        
        Args:
            hours: Hours to include in report
            
        Returns:
            Detailed report data
        """
        response = self._make_request(
            method="GET",
            endpoint="/api/reports/detailed",
            params={"hours": hours}
        )
        return response.get('data', {})
    
    # ========================================================================
    # System Methods
    # ========================================================================
    
    def health_check(self) -> bool:
        """
        Check API health.
        
        Returns:
            True if API is healthy
        """
        try:
            response = self._make_request(
                method="GET",
                endpoint="/api/health",
                require_auth=False
            )
            return response.get('success', False)
        except APIClientError:
            return False
    
    def get_config(self) -> Dict[str, Any]:
        """
        Get current configuration.
        
        Returns:
            Configuration data
        """
        response = self._make_request(
            method="GET",
            endpoint="/api/config"
        )
        return response.get('data', {})
    
    def get_stats(self) -> Dict[str, Any]:
        """
        Get system statistics.
        
        Returns:
            Statistics including process count, alert counts, etc.
        """
        response = self._make_request(
            method="GET",
            endpoint="/api/stats"
        )
        return response.get('data', {})


# ============================================================================
# Convenience Functions
# ============================================================================

def create_client(api_url: str) -> MonitoringAPIClient:
    """
    Create and return an API client.
    
    Args:
        api_url: Base URL of the API
        
    Returns:
        MonitoringAPIClient instance
    """
    return MonitoringAPIClient(api_url)


if __name__ == '__main__':
    # Example usage
    logging.basicConfig(level=logging.INFO)
    
    client = MonitoringAPIClient("http://localhost:5001")
    
    # Check health
    if client.health_check():
        print("✓ API is healthy")
        
        # Login
        try:
            token = client.login("admin", "admin123")
            print(f"✓ Logged in. Token: {token[:20]}...")
            
            # Get stats
            stats = client.get_stats()
            print(f"✓ System stats: {stats}")
            
            # Get processes
            processes = client.get_processes(limit=5)
            print(f"✓ Found {len(processes)} processes")
            
            # Get alerts
            alerts = client.get_alerts(limit=5)
            print(f"✓ Found {len(alerts)} recent alerts")
            
            # Logout
            client.logout()
            print("✓ Logged out")
        
        except Exception as e:
            print(f"✗ Error: {e}")
    else:
        print("✗ API is not available")
