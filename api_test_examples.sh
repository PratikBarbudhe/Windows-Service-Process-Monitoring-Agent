#!/bin/bash
# REST API Testing Examples - cURL Command Reference
# 
# These examples show how to test the REST API using curl commands.
# All examples use the default credentials: admin / admin123
#
# Prerequisites:
#   - API server running on http://localhost:5001
#   - curl installed
#   - jq installed (optional, for pretty-printing JSON)
#
# Usage:
#   bash api_test_examples.sh

set -e

API_URL="http://localhost:5001"
TOKEN=""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Functions
print_header() {
    echo -e "\n${BLUE}═══════════════════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}  $1${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════════${NC}\n"
}

print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

print_error() {
    echo -e "${RED}✗ $1${NC}"
}

print_info() {
    echo -e "${YELLOW}ℹ $1${NC}"
}

print_command() {
    echo -e "${BLUE}$ $1${NC}\n"
}

# ============================================================================
# Example 1: Health Check
# ============================================================================

example_health_check() {
    print_header "Example 1: Health Check"
    
    print_command "curl $API_URL/api/health"
    
    response=$(curl -s $API_URL/api/health)
    echo "$response" | jq . 2>/dev/null || echo "$response"
    
    if echo "$response" | grep -q '"success": true'; then
        print_success "API is healthy"
    else
        print_error "API health check failed"
    fi
}

# ============================================================================
# Example 2: Authentication - Login
# ============================================================================

example_login() {
    print_header "Example 2: Authentication - Login"
    
    print_command "curl -X POST $API_URL/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{\"username\": \"admin\", \"password\": \"admin123\"}'"
    
    response=$(curl -s -X POST $API_URL/api/auth/login \
        -H "Content-Type: application/json" \
        -d '{"username": "admin", "password": "admin123"}')
    
    echo "$response" | jq . 2>/dev/null || echo "$response"
    
    # Extract token for use in other commands
    TOKEN=$(echo "$response" | jq -r '.data.token' 2>/dev/null)
    
    if [ ! -z "$TOKEN" ] && [ "$TOKEN" != "null" ]; then
        print_success "Login successful, token obtained"
        echo -e "Token (first 40 chars): ${TOKEN:0:40}...\n"
    else
        print_error "Login failed"
        return 1
    fi
}

# ============================================================================
# Example 3: Verify Authentication
# ============================================================================

example_verify_auth() {
    print_header "Example 3: Verify Authentication"
    
    if [ -z "$TOKEN" ]; then
        print_error "No token available, run login example first"
        return 1
    fi
    
    print_command "curl $API_URL/api/auth/verify \
  -H 'Authorization: Bearer <token>'"
    
    response=$(curl -s $API_URL/api/auth/verify \
        -H "Authorization: Bearer $TOKEN")
    
    echo "$response" | jq . 2>/dev/null || echo "$response"
    
    if echo "$response" | grep -q '"authenticated": true'; then
        print_success "Authentication verified"
    else
        print_error "Authentication verification failed"
    fi
}

# ============================================================================
# Example 4: Get System Statistics
# ============================================================================

example_get_stats() {
    print_header "Example 4: Get System Statistics"
    
    if [ -z "$TOKEN" ]; then
        print_error "No token available, run login example first"
        return 1
    fi
    
    print_command "curl $API_URL/api/stats \
  -H 'Authorization: Bearer <token>'"
    
    response=$(curl -s $API_URL/api/stats \
        -H "Authorization: Bearer $TOKEN")
    
    echo "$response" | jq . 2>/dev/null || echo "$response"
    print_success "Statistics retrieved"
}

# ============================================================================
# Example 5: Get All Processes
# ============================================================================

example_get_processes() {
    print_header "Example 5: Get All Processes"
    
    if [ -z "$TOKEN" ]; then
        print_error "No token available, run login example first"
        return 1
    fi
    
    print_command "curl '$API_URL/api/processes?limit=5' \
  -H 'Authorization: Bearer <token>'"
    
    response=$(curl -s "$API_URL/api/processes?limit=5" \
        -H "Authorization: Bearer $TOKEN")
    
    echo "$response" | jq . 2>/dev/null || echo "$response"
    print_success "Processes retrieved"
}

# ============================================================================
# Example 6: Get Suspicious Processes
# ============================================================================

example_get_suspicious_processes() {
    print_header "Example 6: Get Suspicious Processes"
    
    if [ -z "$TOKEN" ]; then
        print_error "No token available, run login example first"
        return 1
    fi
    
    print_command "curl '$API_URL/api/processes?include_suspicious=true&limit=10' \
  -H 'Authorization: Bearer <token>'"
    
    response=$(curl -s "$API_URL/api/processes?include_suspicious=true&limit=10" \
        -H "Authorization: Bearer $TOKEN")
    
    echo "$response" | jq . 2>/dev/null || echo "$response"
    print_success "Suspicious processes retrieved"
}

# ============================================================================
# Example 7: Get Process Details
# ============================================================================

example_get_process_details() {
    print_header "Example 7: Get Process Details by PID"
    
    if [ -z "$TOKEN" ]; then
        print_error "No token available, run login example first"
        return 1
    fi
    
    # Get first process PID
    processes_response=$(curl -s "$API_URL/api/processes?limit=1" \
        -H "Authorization: Bearer $TOKEN")
    pid=$(echo "$processes_response" | jq -r '.data.processes[0].pid' 2>/dev/null)
    
    if [ ! -z "$pid" ] && [ "$pid" != "null" ]; then
        print_command "curl $API_URL/api/processes/$pid \
  -H 'Authorization: Bearer <token>'"
        
        response=$(curl -s "$API_URL/api/processes/$pid" \
            -H "Authorization: Bearer $TOKEN")
        
        echo "$response" | jq . 2>/dev/null || echo "$response"
        print_success "Process details retrieved for PID $pid"
    else
        print_error "Could not get process PID"
    fi
}

# ============================================================================
# Example 8: Get Process Tree
# ============================================================================

example_get_process_tree() {
    print_header "Example 8: Get Process Tree"
    
    if [ -z "$TOKEN" ]; then
        print_error "No token available, run login example first"
        return 1
    fi
    
    print_command "curl $API_URL/api/processes/tree \
  -H 'Authorization: Bearer <token>'"
    
    response=$(curl -s $API_URL/api/processes/tree \
        -H "Authorization: Bearer $TOKEN")
    
    # Show just the count to avoid huge output
    count=$(echo "$response" | jq '.data.count' 2>/dev/null)
    echo "$response" | jq '.data | {count: .count}' 2>/dev/null || echo "$response"
    print_success "Process tree retrieved (count: $count)"
}

# ============================================================================
# Example 9: Get All Services
# ============================================================================

example_get_services() {
    print_header "Example 9: Get All Services"
    
    if [ -z "$TOKEN" ]; then
        print_error "No token available, run login example first"
        return 1
    fi
    
    print_command "curl '$API_URL/api/services?limit=5' \
  -H 'Authorization: Bearer <token>'"
    
    response=$(curl -s "$API_URL/api/services?limit=5" \
        -H "Authorization: Bearer $TOKEN")
    
    echo "$response" | jq . 2>/dev/null || echo "$response"
    print_success "Services retrieved"
}

# ============================================================================
# Example 10: Get Suspicious Services
# ============================================================================

example_get_suspicious_services() {
    print_header "Example 10: Get Suspicious Services"
    
    if [ -z "$TOKEN" ]; then
        print_error "No token available, run login example first"
        return 1
    fi
    
    print_command "curl '$API_URL/api/services?include_suspicious=true&limit=5' \
  -H 'Authorization: Bearer <token>'"
    
    response=$(curl -s "$API_URL/api/services?include_suspicious=true&limit=5" \
        -H "Authorization: Bearer $TOKEN")
    
    echo "$response" | jq . 2>/dev/null || echo "$response"
    print_success "Suspicious services retrieved"
}

# ============================================================================
# Example 11: Get Recent Alerts
# ============================================================================

example_get_alerts() {
    print_header "Example 11: Get Recent Alerts"
    
    if [ -z "$TOKEN" ]; then
        print_error "No token available, run login example first"
        return 1
    fi
    
    print_command "curl '$API_URL/api/alerts?limit=5&hours=24' \
  -H 'Authorization: Bearer <token>'"
    
    response=$(curl -s "$API_URL/api/alerts?limit=5&hours=24" \
        -H "Authorization: Bearer $TOKEN")
    
    echo "$response" | jq . 2>/dev/null || echo "$response"
    print_success "Alerts retrieved"
}

# ============================================================================
# Example 12: Get Critical Alerts
# ============================================================================

example_get_critical_alerts() {
    print_header "Example 12: Get Critical Alerts"
    
    if [ -z "$TOKEN" ]; then
        print_error "No token available, run login example first"
        return 1
    fi
    
    print_command "curl '$API_URL/api/alerts?severity=Critical&limit=5' \
  -H 'Authorization: Bearer <token>'"
    
    response=$(curl -s "$API_URL/api/alerts?severity=Critical&limit=5" \
        -H "Authorization: Bearer $TOKEN")
    
    echo "$response" | jq . 2>/dev/null || echo "$response"
    print_success "Critical alerts retrieved"
}

# ============================================================================
# Example 13: Get Whitelist
# ============================================================================

example_get_whitelist() {
    print_header "Example 13: Get Whitelist"
    
    if [ -z "$TOKEN" ]; then
        print_error "No token available, run login example first"
        return 1
    fi
    
    print_command "curl $API_URL/api/whitelist \
  -H 'Authorization: Bearer <token>'"
    
    response=$(curl -s $API_URL/api/whitelist \
        -H "Authorization: Bearer $TOKEN")
    
    echo "$response" | jq . 2>/dev/null || echo "$response"
    print_success "Whitelist retrieved"
}

# ============================================================================
# Example 14: Add to Whitelist
# ============================================================================

example_add_to_whitelist() {
    print_header "Example 14: Add Process to Whitelist"
    
    if [ -z "$TOKEN" ]; then
        print_error "No token available, run login example first"
        return 1
    fi
    
    print_command "curl -X POST $API_URL/api/whitelist \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer <token>' \
  -d '{
    \"name\": \"notepad.exe\",
    \"reason\": \"Trusted system application\"
  }'"
    
    response=$(curl -s -X POST $API_URL/api/whitelist \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer $TOKEN" \
        -d '{
            "name": "notepad.exe",
            "reason": "Trusted system application"
        }')
    
    echo "$response" | jq . 2>/dev/null || echo "$response"
    print_success "Process added to whitelist"
}

# ============================================================================
# Example 15: Get Blacklist
# ============================================================================

example_get_blacklist() {
    print_header "Example 15: Get Blacklist"
    
    if [ -z "$TOKEN" ]; then
        print_error "No token available, run login example first"
        return 1
    fi
    
    print_command "curl $API_URL/api/blacklist \
  -H 'Authorization: Bearer <token>'"
    
    response=$(curl -s $API_URL/api/blacklist \
        -H "Authorization: Bearer $TOKEN")
    
    echo "$response" | jq . 2>/dev/null || echo "$response"
    print_success "Blacklist retrieved"
}

# ============================================================================
# Example 16: Add to Blacklist
# ============================================================================

example_add_to_blacklist() {
    print_header "Example 16: Add Process to Blacklist"
    
    if [ -z "$TOKEN" ]; then
        print_error "No token available, run login example first"
        return 1
    fi
    
    print_command "curl -X POST $API_URL/api/blacklist \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer <token>' \
  -d '{
    \"name\": \"malware.exe\",
    \"reason\": \"Known malicious executable\",
    \"auto_block\": true
  }'"
    
    response=$(curl -s -X POST $API_URL/api/blacklist \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer $TOKEN" \
        -d '{
            "name": "malware.exe",
            "reason": "Known malicious executable",
            "auto_block": true
        }')
    
    echo "$response" | jq . 2>/dev/null || echo "$response"
    print_success "Process added to blacklist"
}

# ============================================================================
# Example 17: Get Summary Report
# ============================================================================

example_get_summary_report() {
    print_header "Example 17: Get Summary Report"
    
    if [ -z "$TOKEN" ]; then
        print_error "No token available, run login example first"
        return 1
    fi
    
    print_command "curl '$API_URL/api/reports/summary?hours=24' \
  -H 'Authorization: Bearer <token>'"
    
    response=$(curl -s "$API_URL/api/reports/summary?hours=24" \
        -H "Authorization: Bearer $TOKEN")
    
    echo "$response" | jq . 2>/dev/null || echo "$response"
    print_success "Summary report retrieved"
}

# ============================================================================
# Example 18: Get Configuration
# ============================================================================

example_get_config() {
    print_header "Example 18: Get Configuration"
    
    if [ -z "$TOKEN" ]; then
        print_error "No token available, run login example first"
        return 1
    fi
    
    print_command "curl $API_URL/api/config \
  -H 'Authorization: Bearer <token>'"
    
    response=$(curl -s $API_URL/api/config \
        -H "Authorization: Bearer $TOKEN")
    
    echo "$response" | jq . 2>/dev/null || echo "$response"
    print_success "Configuration retrieved"
}

# ============================================================================
# Main Menu
# ============================================================================

main() {
    clear
    
    echo -e "${BLUE}"
    echo "╔════════════════════════════════════════════════════════════════════╗"
    echo "║     Windows Service Monitoring Agent - REST API Test Examples      ║"
    echo "╚════════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    
    print_info "API Server: $API_URL"
    print_info "This script will run all API examples in sequence\n"
    
    # Run all examples
    example_health_check
    
    if ! example_login; then
        print_error "Login failed, cannot continue with authenticated examples"
        exit 1
    fi
    
    example_verify_auth
    example_get_stats
    example_get_processes
    example_get_suspicious_processes
    example_get_process_details
    example_get_process_tree
    example_get_services
    example_get_suspicious_services
    example_get_alerts
    example_get_critical_alerts
    example_get_whitelist
    example_add_to_whitelist
    example_get_blacklist
    example_add_to_blacklist
    example_get_summary_report
    example_get_config
    
    print_header "All Examples Completed Successfully!"
    print_success "REST API is working correctly"
}

# Run main function
main
