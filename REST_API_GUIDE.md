REST API Layer - Complete Guide

# Windows Service Monitoring Agent - REST API Documentation

## Overview

The REST API layer provides comprehensive access to all monitoring and control features, enabling:
- **Remote Monitoring** - Monitor systems from anywhere
- **Mobile App Integration** - Build iOS/Android apps for process monitoring
- **External Integration** - Connect with other tools and dashboards
- **Programmatic Control** - Automate process management and alerts

## Quick Start

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

Required packages:
- Flask>=2.3.0
- Flask-CORS>=4.0.0
- PyJWT>=2.8.0
- requests>=2.31.0 (for API client)

### 2. Start the API Server

```bash
python api_server.py
```

The API will start on `http://localhost:5001` by default.

Configuration via environment variables:
```bash
export API_PORT=5001
export API_DEBUG=False
export API_JWT_SECRET=your-secret-key-here
python api_server.py
```

### 3. Access API Documentation

Open in your browser:
```
http://localhost:5001/api/docs
```

### 4. Health Check

```bash
curl http://localhost:5001/api/health
```

Response:
```json
{
  "success": true,
  "data": {
    "status": "healthy",
    "version": "1.0.0",
    "timestamp": "2026-04-25T10:30:00+00:00"
  },
  "message": "API is healthy"
}
```

## Authentication

### JWT Token Authentication

All endpoints except `/api/health` require JWT authentication.

#### Login Endpoint

**Request:**
```bash
curl -X POST http://localhost:5001/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "admin123"}'
```

**Response:**
```json
{
  "success": true,
  "data": {
    "token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
    "expires_in": 86400,
    "username": "admin"
  },
  "message": "Login successful"
}
```

#### Using the Token

Include the token in the Authorization header:

```bash
curl http://localhost:5001/api/processes \
  -H "Authorization: Bearer <your-token-here>"
```

#### Token Expiry

Tokens expire after 24 hours by default. Get a new token before expiry by calling login again.

## API Endpoints Reference

### Authentication Endpoints

#### POST /api/auth/login
Login and obtain JWT token.

**Request Body:**
```json
{
  "username": "admin",
  "password": "admin123"
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "token": "eyJ0eXAiOiJKV1QiLCJhbGc...",
    "expires_in": 86400,
    "username": "admin"
  }
}
```

#### POST /api/auth/logout
Logout and invalidate token. (Requires authentication)

#### GET /api/auth/verify
Verify current authentication is valid. (Requires authentication)

### Process Endpoints

#### GET /api/processes
Get list of all running processes.

**Query Parameters:**
- `filter` (string): Filter by process name (partial match)
- `limit` (integer): Max results, default 1000
- `include_suspicious` (boolean): Only suspicious processes, default false

**Example:**
```bash
curl "http://localhost:5001/api/processes?include_suspicious=true&limit=50" \
  -H "Authorization: Bearer <token>"
```

**Response:**
```json
{
  "success": true,
  "data": {
    "processes": [
      {
        "pid": 1234,
        "name": "explorer.exe",
        "path": "C:\\Windows\\explorer.exe",
        "parent_pid": 900,
        "cpu_percent": 2.5,
        "memory_mb": 150.2
      }
    ],
    "count": 145,
    "timestamp": "2026-04-25T10:30:00+00:00"
  }
}
```

#### GET /api/processes/<pid>
Get details for a specific process including analysis.

**Example:**
```bash
curl http://localhost:5001/api/processes/1234 \
  -H "Authorization: Bearer <token>"
```

**Response:**
```json
{
  "success": true,
  "data": {
    "process": {
      "pid": 1234,
      "name": "explorer.exe",
      "path": "C:\\Windows\\explorer.exe"
    },
    "analysis": {
      "risk_level": "LOW",
      "suspicious_indicators": []
    },
    "parent": { "pid": 900, "name": "svchost.exe" },
    "children": [
      { "pid": 5678, "name": "notepad.exe" }
    ]
  }
}
```

#### GET /api/processes/tree
Get complete process tree visualization.

**Example:**
```bash
curl http://localhost:5001/api/processes/tree \
  -H "Authorization: Bearer <token>"
```

#### POST /api/processes/<pid>/kill
Kill a process.

**Request Body:**
```json
{
  "force": false,
  "reason": "Suspicious behavior detected"
}
```

**Example:**
```bash
curl -X POST http://localhost:5001/api/processes/1234/kill \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"force": false, "reason": "Malicious process"}'
```

**Response:**
```json
{
  "success": true,
  "data": {
    "killed": true,
    "pid": 1234,
    "method": "graceful"
  }
}
```

### Service Endpoints

#### GET /api/services
Get list of all Windows services.

**Query Parameters:**
- `filter` (string): Filter by service name
- `limit` (integer): Max results, default 1000
- `include_suspicious` (boolean): Only suspicious services
- `state` (string): Filter by state (Running, Stopped, etc.)

**Example:**
```bash
curl "http://localhost:5001/api/services?state=Running&include_suspicious=true" \
  -H "Authorization: Bearer <token>"
```

**Response:**
```json
{
  "success": true,
  "data": {
    "services": [
      {
        "name": "WinDefend",
        "display_name": "Windows Defender",
        "state": "Running",
        "startup_type": "Automatic",
        "path": "C:\\ProgramFiles\\...\\MsMpEng.exe"
      }
    ],
    "count": 280
  }
}
```

#### GET /api/services/<name>
Get details for a specific service.

### Alert Endpoints

#### GET /api/alerts
Get recent alerts.

**Query Parameters:**
- `limit` (integer): Max results, default 100
- `severity` (string): Filter by severity (Critical, High, Medium, Low, Info)
- `hours` (integer): Get alerts from last N hours, default 24

**Example - Get critical alerts from last 6 hours:**
```bash
curl "http://localhost:5001/api/alerts?severity=Critical&hours=6" \
  -H "Authorization: Bearer <token>"
```

**Response:**
```json
{
  "success": true,
  "data": {
    "alerts": [
      {
        "id": "alert_20260425_001",
        "type": "suspicious_process",
        "severity": "Critical",
        "timestamp": "2026-04-25T10:15:00+00:00",
        "process_name": "malware.exe",
        "description": "Unauthorized process detected"
      }
    ],
    "count": 2,
    "severity_counts": {
      "Critical": 2,
      "High": 5
    }
  }
}
```

#### GET /api/alerts/<alert_id>
Get details for a specific alert.

### Process Control - Whitelist

#### GET /api/whitelist
Get all whitelisted processes.

#### POST /api/whitelist
Add process to whitelist.

**Request Body:**
```json
{
  "name": "notepad.exe",
  "path": "C:\\Windows\\System32\\notepad.exe",
  "reason": "Trusted system application"
}
```

**Example:**
```bash
curl -X POST http://localhost:5001/api/whitelist \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "notepad.exe",
    "reason": "Trusted application"
  }'
```

#### DELETE /api/whitelist/<name>
Remove process from whitelist.

**Example:**
```bash
curl -X DELETE http://localhost:5001/api/whitelist/notepad.exe \
  -H "Authorization: Bearer <token>"
```

### Process Control - Blacklist

#### GET /api/blacklist
Get all blacklisted processes.

#### POST /api/blacklist
Add process to blacklist.

**Request Body:**
```json
{
  "name": "malware.exe",
  "path": "C:\\malware.exe",
  "reason": "Known malicious executable",
  "auto_block": true
}
```

**Example:**
```bash
curl -X POST http://localhost:5001/api/blacklist \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "malware.exe",
    "reason": "Detected malware",
    "auto_block": true
  }'
```

#### DELETE /api/blacklist/<name>
Remove process from blacklist.

### Report Endpoints

#### GET /api/reports/summary
Get summary report.

**Query Parameters:**
- `hours` (integer): Hours to include in report, default 24

**Example:**
```bash
curl "http://localhost:5001/api/reports/summary?hours=24" \
  -H "Authorization: Bearer <token>"
```

#### GET /api/reports/detailed
Get detailed report.

### Chart & Visualization Endpoints

These endpoints provide data optimized for visualization and charting.

#### GET /api/charts/cpu-timeline
Get CPU usage timeline data for charts.

**Query Parameters:**
- `hours` (integer): Number of hours to look back, default 1

**Response:**
```json
{
  "success": true,
  "data": {
    "timeline": [
      {
        "timestamp": "2026-04-25T10:00:00+00:00",
        "system_cpu": 25.5,
        "process_count": 145
      }
    ],
    "hours": 24,
    "count": 144
  }
}
```

**Usage Examples:**

Chart.js:
```javascript
fetch('http://localhost:5001/api/charts/cpu-timeline?hours=24', {
  headers: { 'Authorization': 'Bearer <token>' }
})
.then(r => r.json())
.then(data => {
  const labels = data.data.timeline.map(d => d.timestamp);
  const values = data.data.timeline.map(d => d.system_cpu);
  // Create Chart.js line chart
})
```

Python:
```python
client.session.get(
  'http://localhost:5001/api/charts/cpu-timeline?hours=24',
  headers={'Authorization': f'Bearer {token}'}
).json()
```

Curl:
```bash
curl "http://localhost:5001/api/charts/cpu-timeline?hours=24" \
  -H "Authorization: Bearer <token>"
```

#### GET /api/charts/memory-timeline
Get memory usage timeline data for charts.

**Query Parameters:**
- `hours` (integer): Number of hours to look back, default 1

**Response:**
```json
{
  "success": true,
  "data": {
    "timeline": [
      {
        "timestamp": "2026-04-25T10:00:00+00:00",
        "system_memory_percent": 45.2,
        "memory_available_mb": 8192
      }
    ],
    "hours": 24,
    "count": 144
  }
}
```

#### GET /api/charts/top-processes-cpu
Get top processes ranked by CPU usage.

**Query Parameters:**
- `hours` (integer): Number of hours to look back, default 1
- `limit` (integer): Maximum processes to return, default 10

**Response:**
```json
{
  "success": true,
  "data": {
    "processes": [
      {
        "name": "chrome.exe",
        "avg_cpu": 15.5,
        "max_cpu": 28.3,
        "samples": 120
      }
    ],
    "hours": 1,
    "limit": 10,
    "count": 8
  }
}
```

**Usage - React/Recharts:**
```jsx
const [data, setData] = useState([]);

useEffect(() => {
  fetch('http://localhost:5001/api/charts/top-processes-cpu?limit=10', {
    headers: { 'Authorization': `Bearer ${token}` }
  })
  .then(r => r.json())
  .then(d => {
    const formatted = d.data.processes.map(p => ({
      name: p.name,
      cpu: p.avg_cpu
    }));
    setData(formatted);
  });
}, []);

return (
  <BarChart data={data}>
    <Bar dataKey="cpu" />
  </BarChart>
);
```

#### GET /api/charts/top-processes-memory
Get top processes ranked by memory usage.

**Query Parameters:**
- `hours` (integer): Number of hours to look back, default 1
- `limit` (integer): Maximum processes to return, default 10

**Response:**
```json
{
  "success": true,
  "data": {
    "processes": [
      {
        "name": "python.exe",
        "avg_memory_mb": 256.3,
        "max_memory_mb": 512.5,
        "samples": 120
      }
    ],
    "hours": 1,
    "limit": 10,
    "count": 7
  }
}
```

#### GET /api/charts/process-cpu/{process_name}
Get CPU timeline for a specific process.

**Path Parameters:**
- `process_name` (string): Name of the process

**Query Parameters:**
- `hours` (integer): Number of hours to look back, default 1

**Response:**
```json
{
  "success": true,
  "data": {
    "process_name": "chrome.exe",
    "timeline": [
      {
        "timestamp": "2026-04-25T10:00:00+00:00",
        "cpu": 12.5
      }
    ],
    "hours": 1,
    "count": 12
  }
}
```

**Example:**
```bash
curl "http://localhost:5001/api/charts/process-cpu/chrome.exe?hours=1" \
  -H "Authorization: Bearer <token>"
```

#### GET /api/charts/process-memory/{process_name}
Get memory timeline for a specific process.

**Path Parameters:**
- `process_name` (string): Name of the process

**Query Parameters:**
- `hours` (integer): Number of hours to look back, default 1

**Response:**
```json
{
  "success": true,
  "data": {
    "process_name": "python.exe",
    "timeline": [
      {
        "timestamp": "2026-04-25T10:00:00+00:00",
        "memory_mb": 256.3
      }
    ],
    "hours": 1,
    "count": 12
  }
}
```

#### GET /api/charts/metrics-summary
Get aggregated summary statistics for a time period.

**Query Parameters:**
- `hours` (integer): Time period for summary, default 24

**Response:**
```json
{
  "success": true,
  "data": {
    "summary": {
      "time_period_hours": 24,
      "snapshot_count": 288,
      "unique_processes": 145,
      "cpu_avg": 15.5,
      "cpu_max": 95.2,
      "cpu_min": 5.1,
      "memory_avg_percent": 45.3,
      "memory_max_percent": 78.5,
      "memory_min_percent": 38.2,
      "total_threads": 2500,
      "total_handles": 15000
    }
  }
}
```

### System Endpoints

#### GET /api/health
Health check (no authentication required).

#### GET /api/config
Get current configuration.

#### GET /api/stats
Get system statistics.

**Response:**
```json
{
  "success": true,
  "data": {
    "total_processes": 145,
    "total_services": 280,
    "recent_alerts_24h": 15,
    "critical_alerts": 2,
    "high_alerts": 5,
    "timestamp": "2026-04-25T10:30:00+00:00"
  }
}
```

## Python Client SDK Usage

The `api_client.py` module provides a convenient Python SDK for interacting with the API.

### Installation

```bash
pip install requests
```

### Basic Usage

```python
from api_client import MonitoringAPIClient

# Create client
client = MonitoringAPIClient("http://localhost:5001")

# Login
token = client.login("admin", "admin123")
print(f"Token: {token}")

# Check health
is_healthy = client.health_check()
print(f"API Health: {is_healthy}")

# Get system stats
stats = client.get_stats()
print(f"Stats: {stats}")

# Get processes
processes = client.get_processes(include_suspicious=True, limit=50)
for proc in processes:
    print(f"Process: {proc['name']} (PID: {proc['pid']})")

# Get alerts
alerts = client.get_alerts(severity="Critical")
for alert in alerts:
    print(f"ALERT: {alert['description']}")

# Kill a malicious process
if client.kill_process(1234, force=True, reason="Malware detected"):
    print("Process killed successfully")

# Add to blacklist
client.add_to_blacklist(
    "malware.exe",
    reason="Known malware",
    auto_block=True
)

# Get whitelist
whitelist = client.get_whitelist()
print(f"Whitelisted processes: {len(whitelist)}")

# Add to whitelist
client.add_to_whitelist(
    "notepad.exe",
    reason="Trusted application"
)

# Get reports
summary = client.get_summary_report(hours=24)
detailed = client.get_detailed_report(hours=24)

# Logout
client.logout()
```

### Error Handling

```python
from api_client import (
    MonitoringAPIClient,
    APIClientError,
    APIAuthenticationError,
    APINotFoundError,
    APIServerError
)

client = MonitoringAPIClient("http://localhost:5001")

try:
    client.login("admin", "wrong_password")
except APIAuthenticationError as e:
    print(f"Authentication failed: {e}")

try:
    process = client.get_process(999999)
except APINotFoundError as e:
    print(f"Process not found: {e}")

try:
    processes = client.get_processes()
except APIServerError as e:
    print(f"Server error: {e}")
except APIClientError as e:
    print(f"Request failed: {e}")
```

## Mobile App Integration

### iOS/Swift Example

```swift
import Foundation

class MonitoringAPIClient {
    let apiURL: String
    var token: String?
    
    init(apiURL: String) {
        self.apiURL = apiURL
    }
    
    func login(username: String, password: String) async throws -> String {
        let url = URL(string: "\(apiURL)/api/auth/login")!
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        
        let body: [String: String] = [
            "username": username,
            "password": password
        ]
        request.httpBody = try JSONEncoder().encode(body)
        
        let (data, response) = try await URLSession.shared.data(for: request)
        let decoder = JSONDecoder()
        let result = try decoder.decode([String: Any].self, from: data)
        
        if let token = result["data"] as? [String: String]?["token"] {
            self.token = token
            return token
        }
        throw NSError(domain: "LoginFailed", code: -1)
    }
    
    func getProcesses() async throws -> [[String: Any]] {
        guard let token = token else { throw NSError(domain: "NotAuthenticated", code: -1) }
        
        let url = URL(string: "\(apiURL)/api/processes")!
        var request = URLRequest(url: url)
        request.httpMethod = "GET"
        request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        
        let (data, _) = try await URLSession.shared.data(for: request)
        let decoder = JSONDecoder()
        let result = try decoder.decode([String: Any].self, from: data)
        
        if let processes = result["data"] as? [String: Any]?["processes"] {
            return processes as? [[String: Any]] ?? []
        }
        return []
    }
}
```

### Android/Kotlin Example

```kotlin
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONObject

class MonitoringAPIClient(private val apiUrl: String) {
    private val client = OkHttpClient()
    private var token: String? = null
    
    fun login(username: String, password: String): String? {
        val json = JSONObject().apply {
            put("username", username)
            put("password", password)
        }
        
        val body = json.toString()
            .toRequestBody("application/json".toMediaType())
        
        val request = Request.Builder()
            .url("$apiUrl/api/auth/login")
            .post(body)
            .build()
        
        val response = client.newCall(request).execute()
        
        response.body?.string()?.let { responseBody ->
            val jsonResponse = JSONObject(responseBody)
            token = jsonResponse.getJSONObject("data").getString("token")
            return token
        }
        
        return null
    }
    
    fun getProcesses(): List<Map<String, Any>> {
        val request = Request.Builder()
            .url("$apiUrl/api/processes")
            .header("Authorization", "Bearer $token")
            .get()
            .build()
        
        val response = client.newCall(request).execute()
        val processes = mutableListOf<Map<String, Any>>()
        
        response.body?.string()?.let { responseBody ->
            val jsonResponse = JSONObject(responseBody)
            // Parse processes array
        }
        
        return processes
    }
}
```

### React Native Example

```javascript
import axios from 'axios';

class MonitoringAPIClient {
  constructor(apiUrl) {
    this.apiUrl = apiUrl;
    this.token = null;
    this.client = axios.create({
      baseURL: apiUrl,
      timeout: 30000
    });
  }

  async login(username, password) {
    try {
      const response = await this.client.post('/api/auth/login', {
        username,
        password
      });
      
      this.token = response.data.data.token;
      this.client.defaults.headers.common['Authorization'] = `Bearer ${this.token}`;
      return this.token;
    } catch (error) {
      throw new Error(`Login failed: ${error.message}`);
    }
  }

  async getProcesses(options = {}) {
    try {
      const response = await this.client.get('/api/processes', {
        params: {
          include_suspicious: options.suspicious || false,
          limit: options.limit || 1000
        }
      });
      return response.data.data.processes;
    } catch (error) {
      throw new Error(`Failed to get processes: ${error.message}`);
    }
  }

  async getAlerts(severity = null) {
    try {
      const response = await this.client.get('/api/alerts', {
        params: {
          severity: severity || null,
          hours: 24
        }
      });
      return response.data.data.alerts;
    } catch (error) {
      throw new Error(`Failed to get alerts: ${error.message}`);
    }
  }

  async killProcess(pid, force = false) {
    try {
      const response = await this.client.post(
        `/api/processes/${pid}/kill`,
        { force }
      );
      return response.data.data.killed;
    } catch (error) {
      throw new Error(`Failed to kill process: ${error.message}`);
    }
  }
}

export default MonitoringAPIClient;
```

## Error Handling

### Common HTTP Status Codes

| Status | Meaning | Example |
|--------|---------|---------|
| 200 | Success | Operation completed successfully |
| 400 | Bad Request | Invalid input parameters |
| 401 | Unauthorized | Missing or invalid token |
| 404 | Not Found | Resource doesn't exist |
| 500 | Server Error | Internal server error |

### Error Response Format

```json
{
  "success": false,
  "error": "invalid_credentials",
  "message": "Invalid username or password",
  "timestamp": "2026-04-25T10:30:00+00:00"
}
```

## Security Best Practices

1. **Token Management**
   - Store tokens securely (use platform-specific secure storage)
   - Don't log or expose tokens
   - Refresh tokens before expiry (24 hours default)
   - Clear tokens on logout

2. **HTTPS in Production**
   - Always use HTTPS in production environments
   - Use valid SSL/TLS certificates
   - Consider certificate pinning for mobile apps

3. **Credentials**
   - Never hardcode credentials in code
   - Use environment variables or secure configuration
   - Change default admin credentials immediately
   - Implement password hashing in production

4. **API Security**
   - Implement rate limiting for production
   - Add request validation
   - Use API keys in addition to JWT for extra security
   - Monitor API access logs

5. **Data Privacy**
   - Encrypt sensitive data in transit
   - Don't expose sensitive paths or hashes in responses
   - Implement proper access controls
   - Audit all sensitive operations

## Deployment

### Docker Deployment

```dockerfile
FROM python:3.10-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENV API_PORT=5001
ENV API_DEBUG=False

EXPOSE 5001

CMD ["python", "api_server.py"]
```

Build and run:
```bash
docker build -t monitoring-api .
docker run -p 5001:5001 monitoring-api
```

### Kubernetes Deployment

See `kubernetes-deployment.yaml` for example Kubernetes manifests.

### Reverse Proxy Configuration

#### Nginx

```nginx
server {
    listen 443 ssl http2;
    server_name monitoring.example.com;
    
    ssl_certificate /etc/ssl/certs/cert.pem;
    ssl_certificate_key /etc/ssl/private/key.pem;
    
    location /api/ {
        proxy_pass http://localhost:5001/api/;
        proxy_set_header Authorization $http_authorization;
        proxy_pass_header Authorization;
        proxy_read_timeout 30s;
    }
}
```

## Performance Optimization

1. **Caching**
   - Cache process/service lists (refresh every 30 seconds)
   - Cache static configuration data
   - Use ETags for conditional requests

2. **Pagination**
   - Use limit parameter to reduce response size
   - Implement offset-based pagination for large datasets

3. **Monitoring**
   - Add request logging and metrics
   - Monitor API response times
   - Alert on high error rates

## Troubleshooting

### API won't start
- Check if port 5001 is already in use
- Verify all dependencies are installed
- Check logs for detailed error messages

### Authentication errors
- Verify username and password
- Check if token has expired
- Ensure Authorization header is correctly formatted

### Slow responses
- Check system resources (CPU, memory)
- Review database query performance
- Enable request caching

### CORS errors
- Verify Flask-CORS is installed
- Check CORS configuration in api_server.py
- Ensure client is making valid preflight requests

## Related Documentation

- [REST API Server Code](api_server.py)
- [Python Client SDK Code](api_client.py)
- [Admin Panel Guide](ADMIN_PANEL_GUIDE.md)
- [Process Control Guide](PROCESS_CONTROL_GUIDE.md)
- [Windows Service Features](WINDOWS_SERVICE_FEATURES.md)
