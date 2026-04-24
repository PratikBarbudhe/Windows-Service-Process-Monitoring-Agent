# Admin Panel Quick Start

## Installation (One-time)

```bash
# Install Flask dependency
pip install Flask>=2.3.0 Werkzeug>=2.3.0

# Or install all dependencies
pip install -r requirements.txt
```

## Running the Admin Panel

```bash
# Start the web server
python admin_panel.py

# Output will show:
# Starting WSPMA Admin Panel
# Access at: http://localhost:5000
# Default login: admin / admin123
```

## Login

1. Open browser: **http://localhost:5000**
2. Username: **admin**
3. Password: **admin1234**

⚠️ **Change these credentials immediately in production!**

## Main Features

### Dashboard (Home Page)
- Process control statistics
- Service status
- Recent alerts (last 10)
- System configuration summary

### Logs Tab
- View alert files
- Filter by severity (CRITICAL, HIGH, MEDIUM, LOW)
- Search alerts
- Pagination (50 per page)

### Processes Tab
- **Whitelisted Processes** - Add/remove trusted processes
- **Blacklisted Processes** - Add/remove malicious processes with auto-kill option

### Configuration Tab
- **System Thresholds** - CPU, Memory, Disk alerts
- **Notifications** - Enable/disable email alerts
- **Process Control** - Enable/disable process killing, auto-block, etc.

### History Tab
- Process kill audit trail
- Kill statistics (total, successful, failed)
- Timestamp, process name, kill method, reason

## Common Tasks

### Add Process to Whitelist

```
1. Go to Processes tab
2. Enter process name: "explorer.exe"
3. Click "Add" button
4. Process added to whitelist.json
```

### Blacklist Malicious Process

```
1. Go to Processes tab
2. Enter process name: "malware.exe"
3. Check "AUTO-KILL" checkbox
4. Click "Add" button
5. Process will be auto-killed on detection
```

### View Recent Alerts

```
1. Go to Logs tab
2. Select alert file from dropdown
3. Filter by severity if needed
4. Click alert row for details
```

### Change Thresholds

```
1. Go to Configuration tab
2. Adjust CPU/Memory/Disk sliders
3. Click "Save Thresholds"
4. Changes take effect after service restart
```

### Check Kill History

```
1. Go to History tab
2. View statistics (total, successful, failed)
3. Browse kill records with pagination
4. Each record shows: timestamp, process, PID, method, status, reason
```

## Security

### Default Credentials Must Be Changed

Edit `admin_panel.py`:

```python
from werkzeug.security import generate_password_hash

# Change this section:
ADMIN_USERS = {
    "admin": generate_password_hash("your_new_password")  # Use strong password!
}
```

Restart admin panel.

### Network Access

In production, restrict access:

```powershell
# Allow only local network
netsh advfirewall firewall add rule name="WSPMA Admin" dir=in action=allow protocol=tcp localport=5000 remoteip=192.168.1.0/24
```

### HTTPS for Production

Use reverse proxy (nginx):

```nginx
server {
    listen 443 ssl;
    server_name admin.example.com;
    
    ssl_certificate /path/to/cert.crt;
    ssl_certificate_key /path/to/key.key;
    
    location / {
        proxy_pass http://127.0.0.1:5000;
    }
}
```

## API Endpoints (Programmatic Access)

The admin panel provides REST APIs:

```bash
# Get configuration
curl http://localhost:5000/config

# Add to whitelist
curl -X POST http://localhost:5000/api/whitelist \
  -H "Content-Type: application/json" \
  -d '{"process_name":"explorer.exe", "reason":"System"}'

# Add to blacklist
curl -X POST http://localhost:5000/api/blacklist \
  -H "Content-Type: application/json" \
  -d '{"process_name":"malware.exe", "reason":"Malware", "auto_block":true}'

# Remove from whitelist
curl -X DELETE http://localhost:5000/api/whitelist/explorer.exe

# View logs
curl http://localhost:5000/logs
```

## Troubleshooting

### Admin Panel Won't Start

```bash
# Check port 5000 is available
netstat -ano | findstr :5000

# If in use, change port in admin_panel.py:
# app.run(port=8000)
```

### Flask Not Found Error

```bash
# Install Flask
pip install Flask Werkzeug
```

### Login Not Working

```bash
# Check ADMIN_USERS in admin_panel.py
# Default: admin / admin123

# Reset if needed:
# Edit admin_panel.py, update ADMIN_USERS
# Restart admin panel
```

### Whitelist/Blacklist Changes Not Appearing

```bash
# Changes should be immediate
# If not:
1. Refresh browser (F5)
2. Check config/whitelist.json and config/blacklist.json exist
3. Check file permissions
```

## Production Deployment

### Checklist

- [ ] Change default credentials
- [ ] Configure HTTPS/reverse proxy
- [ ] Set up network access controls
- [ ] Enable logging/monitoring
- [ ] Test backup/recovery
- [ ] Document access procedures
- [ ] Schedule security reviews

### Systemd Service (Linux)

Create `/etc/systemd/system/wspma-admin.service`:

```ini
[Unit]
Description=WSPMA Admin Panel
After=network.target

[Service]
Type=simple
User=wspma
WorkingDirectory=/opt/wspma
ExecStart=/usr/bin/python3 /opt/wspma/admin_panel.py
Restart=always

[Install]
WantedBy=multi-user.target
```

## Related Documentation

- [ADMIN_PANEL_GUIDE.md](ADMIN_PANEL_GUIDE.md) - Complete feature guide
- [PROCESS_CONTROL_GUIDE.md](PROCESS_CONTROL_GUIDE.md) - Process control details
- [SERVICE_INSTALLATION_GUIDE.md](SERVICE_INSTALLATION_GUIDE.md) - Service setup
- [QUICK_REFERENCE.md](QUICK_REFERENCE.md) - Command reference

## Summary

The Admin Panel provides a complete web-based management interface for the Windows Service Process Monitoring Agent with:

✅ Secure authentication  
✅ Real-time dashboard  
✅ Log viewer with search  
✅ Configuration management  
✅ Whitelist/blacklist control  
✅ Audit trail  
✅ Responsive UI  
✅ REST API backend  

Perfect for security operations teams to manage threat detection and response from a web browser!
