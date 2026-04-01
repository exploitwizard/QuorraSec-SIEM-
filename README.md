# Quorra SIEM Tool

Quorra is a Security Information and Event Management (SIEM) tool designed specifically for monitoring the Block Fortress application. It provides real-time security monitoring, attack detection, and alerting.

## Features

- **Real-time Monitoring**: Connects to Block Fortress via WebSocket
- **Attack Detection**: Detects brute force, command injection, privilege escalation
- **Geo-velocity Analysis**: Identifies impossible travel scenarios
- **IP Blocking**: Automatic and manual IP blocking
- **Real-time Alerts**: Web-based dashboard with live updates
- **Visual Analytics**: Charts and graphs of attack patterns

## Installation

### Method 1: Quick Install
```bash
# 1. Clone or extract Quorra
git clone <quorra-repo>
cd quorra

# 2. Install dependencies
pip install -r requirements.txt

# 3. Make executable
chmod +x quorra.py

# 4. Install globally
pip install -e .