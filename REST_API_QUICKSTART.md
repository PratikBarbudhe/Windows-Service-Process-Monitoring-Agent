# REST API - Quick Start Guide

## 5-Minute Setup

### 1. Install Dependencies (1 minute)

```bash
pip install -r requirements.txt
```

Key packages:
- `Flask>=2.3.0` - Web framework
- `Flask-CORS>=4.0.0` - CORS support for web/mobile clients
- `PyJWT>=2.8.0` - JWT token authentication
- `requests>=2.31.0` - HTTP client (for SDK)

### 2. Start API Server (30 seconds)

```bash
python api_server.py
```

Expected output:
```
Starting REST API Server v1.0.0
Documentation: http://localhost:5001/api/docs
Health check: http://localhost:5001/api/health
 * Running on http://0.0.0.0:5001
```

### 3. Test API Health (30 seconds)

```bash
curl http://localhost:5001/api/health
```

Response (should show success: true):
```json
{
  "success": true,
  "data": {
    "status": "healthy",
    "version": "1.0.0"
  }
}
```

### 4. Login & Get Token (1 minute)

```bash
curl -X POST http://localhost:5001/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "admin123"}'
```

Save the token from response:
```json
{
  "success": true,
  "data": {
    "token": "eyJ0eXAiOiJKV1QiLCJhbGc..."
  }
}
```

### 5. Use API (1 minute)

Example - Get system stats:
```bash
curl http://localhost:5001/api/stats \
  -H "Authorization: Bearer <your-token-here>"
```

## Common Commands

### Get running processes
```bash
curl "http://localhost:5001/api/processes?limit=10" \
  -H "Authorization: Bearer <token>"
```

### Get suspicious processes
```bash
curl "http://localhost:5001/api/processes?include_suspicious=true" \
  -H "Authorization: Bearer <token>"
```

### Get recent alerts
```bash
curl "http://localhost:5001/api/alerts?hours=24" \
  -H "Authorization: Bearer <token>"
```

### Get critical alerts
```bash
curl "http://localhost:5001/api/alerts?severity=Critical" \
  -H "Authorization: Bearer <token>"
```

### Get Windows services
```bash
curl "http://localhost:5001/api/services?limit=20" \
  -H "Authorization: Bearer <token>"
```

### Add process to whitelist
```bash
curl -X POST http://localhost:5001/api/whitelist \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"name": "trusted.exe", "reason": "Trusted app"}'
```

### Add process to blacklist
```bash
curl -X POST http://localhost:5001/api/blacklist \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"name": "malware.exe", "reason": "Malicious", "auto_block": true}'
```

### Kill a process
```bash
curl -X POST http://localhost:5001/api/processes/1234/kill \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"force": false, "reason": "Threat detected"}'
```

## Python SDK Examples

### Installation
```bash
pip install requests
```

### Basic Usage
```python
from api_client import MonitoringAPIClient

# Create client and login
client = MonitoringAPIClient("http://localhost:5001")
token = client.login("admin", "admin123")

# Get processes
processes = client.get_processes(limit=10)
print(f"Found {len(processes)} processes")

# Get alerts
alerts = client.get_alerts(severity="Critical")
print(f"Critical alerts: {len(alerts)}")

# Kill a process
client.kill_process(1234, force=False, reason="Suspicious")

# Add to blacklist
client.add_to_blacklist("malware.exe", auto_block=True)

# Logout
client.logout()
```

## Web Dashboard

Access the interactive API documentation:
```
http://localhost:5001/api/docs
```

This shows all available endpoints and allows testing them directly.

## Environment Configuration

### Custom Port
```bash
export API_PORT=8080
python api_server.py
```

### Debug Mode
```bash
export API_DEBUG=True
python api_server.py
```

### Custom JWT Secret
```bash
export API_JWT_SECRET=your-secret-key
python api_server.py
```

## Running Test Examples

### Python Examples
```bash
python api_examples.py login      # Test authentication
python api_examples.py monitor    # Test process monitoring
python api_examples.py alerts     # Test alert monitoring
python api_examples.py control    # Test process control
python api_examples.py dashboard  # Test dashboard stats
python api_examples.py threat     # Test threat response
python api_examples.py all        # Run all examples
```

### Bash Examples (Linux/Mac)
```bash
bash api_test_examples.sh
```

## Next Steps

### For Web Apps
1. Use the Python SDK (`api_client.py`) or similar libraries
2. Store JWT token in localStorage/sessionStorage
3. Refresh token before expiry (24 hours)
4. Implement error handling for expired tokens

### For Mobile Apps
1. Review mobile-specific examples in [REST API Guide](REST_API_GUIDE.md)
2. iOS: Use URLSession with Bearer token auth
3. Android: Use Retrofit/OkHttp with JWT interceptor
4. React Native: Use axios or fetch API

### For External Integration
1. Create API key if implementing key-based auth
2. Implement webhook callbacks for alerts
3. Set up automated threat responses
4. Monitor API usage and performance

## Troubleshooting

### Port Already in Use
```bash
# Windows
netstat -ano | findstr :5001

# Linux/Mac
lsof -i :5001
```

Kill the process and try again, or use a different port:
```bash
export API_PORT=5002
python api_server.py
```

### Authentication Errors
- Verify username/password: `admin` / `admin123`
- Check token is included in Authorization header
- Check token hasn't expired (24 hour expiry)
- Get a new token if needed

### CORS Errors
Ensure Flask-CORS is installed:
```bash
pip install Flask-CORS
```

### Process Not Found
Some processes may require elevated permissions to access. Run with administrator privileges if needed.

## Security Recommendations

1. **Change Default Credentials**
   - Update admin password in production
   - Use environment variables for credentials

2. **Use HTTPS**
   - Set up reverse proxy (Nginx/Apache)
   - Use valid SSL certificates
   - Enable HSTS header

3. **Token Security**
   - Store tokens in secure storage
   - Use HTTPS for all requests
   - Implement token refresh logic
   - Clear tokens on logout

4. **API Security**
   - Implement rate limiting
   - Add request validation
   - Use API keys in addition to JWT
   - Monitor access logs

## Performance Tips

1. **Use Limit Parameter**
   ```bash
   curl "http://localhost:5001/api/processes?limit=100"
   ```

2. **Filter Results**
   ```bash
   curl "http://localhost:5001/api/processes?filter=chrome"
   ```

3. **Query Specific Resource**
   ```bash
   curl "http://localhost:5001/api/processes/1234"
   ```

4. **Cache Responses**
   - Cache process/service lists (30-60 seconds)
   - Cache configuration data
   - Use ETags for conditional requests

## Related Documentation

- [REST API Complete Guide](REST_API_GUIDE.md) - Comprehensive API documentation
- [API Server Code](api_server.py) - Full implementation
- [API Client SDK](api_client.py) - Python client library
- [API Examples](api_examples.py) - Usage examples

## Support

For issues or questions:
1. Check API logs: Look for error messages in terminal output
2. Review documentation: See REST_API_GUIDE.md
3. Test health endpoint: `curl http://localhost:5001/api/health`
4. Run examples: `python api_examples.py all`
