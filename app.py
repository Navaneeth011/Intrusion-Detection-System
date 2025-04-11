import os
import time
import json
import random
import threading
import datetime
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from flask import Flask, render_template_string, redirect, url_for, jsonify
import pywifi
from pywifi import const
import io
import base64
from matplotlib.figure import Figure
from matplotlib.backends.backend_agg import FigureCanvasAgg as FigureCanvas

# Initialize Flask
app = Flask(__name__)

# Data storage
DATA_FILE = 'network_data.json'
if not os.path.exists(DATA_FILE):
    with open(DATA_FILE, 'w') as f:
        json.dump({
            'networks': [],
            'connected': {},
            'attacks': [],
            'vulnerability_scores': [],
            'timeline': []
        }, f)

# Global variables
last_scan_time = 0
scan_interval = 10  # seconds
current_connected = None
attack_types = [
    'Deauth', 'Disassociation', 'Reassociation', 'Rogue_AP', 'Krack', 'Kr00k',
    'SSH', 'Botnet', 'Malware', 'SQL_Injection', 'SSDP', 'Evil_Twin', 'Website_spoofing'
]

# Load attack signatures from the text file
attack_signatures = {
    'Deauth': "(wlan.fc.type_subtype==10 || wlan.fc.type_subtype==12) && wlan.fc.protected==0",
    'Disass': "(wlan.fc.type_subtype==10 || wlan.fc.type_subtype==12) && wlan.fc.protected==0",
    'ReAssoc': "(wlan.fc.type_subtype==0 || wlan.fc.type_subtype==2 || wlan.fc.type_subtype==8) && frame.len <= 301",
    'Rogue_AP': "wlan.fc.type_subtype==8 && frame.len < 264",
    'Krack': "wlan_radio.channel == 2",
    'Kr00k': "wlan.fc.type_subtype==10 && wlan.fc.protected==0",
    'SSH': "Connection attempts from unknown IPs",
    'Botnet': "Multiple connections to known C&C servers",
    'Malware': "Unusual data transfer patterns",
    'SQL_Injection': "SQL query patterns in HTTP requests",
    'SSDP': "SSDP discovery requests from unexpected sources",
    'Evil_Twin': "Same SSID with different MAC",
    'Website_spoofing': "Domain spoofing detected"
}

# Function to get WiFi interfaces
def get_wifi_interfaces():
    wifi = pywifi.PyWiFi()
    interfaces = wifi.interfaces()
    return interfaces

# Function to scan for networks
def scan_networks():
    global last_scan_time
    
    # Check if we need to scan again
    current_time = time.time()
    if current_time - last_scan_time < scan_interval:
        # Load from file
        with open(DATA_FILE, 'r') as f:
            data = json.load(f)
            return data['networks']
    
    # Perform new scan
    wifi = pywifi.PyWiFi()
    interface = wifi.interfaces()[0]  # Use the first interface
    
    interface.scan()
    time.sleep(2)  # Give time for scan to complete
    scan_results = interface.scan_results()
    
    networks = []
    for result in scan_results:
        network = {
            'ssid': result.ssid,
            'bssid': result.bssid,
            'signal': result.signal,
            'akm': result.akm[0] if result.akm else 0,
            'channel': getattr(result, 'channel', random.randint(1, 13)),
            'encryption': 'WPA2' if result.akm else 'Open',
            'frequency': getattr(result, 'frequency', 2400 + random.randint(1, 70))
        }
        networks.append(network)
    
    # Update data file
    with open(DATA_FILE, 'r') as f:
        data = json.load(f)
    
    data['networks'] = networks
    
    with open(DATA_FILE, 'w') as f:
        json.dump(data, f)
    
    last_scan_time = current_time
    return networks

# Function to get connected network
def get_connected_network():
    wifi = pywifi.PyWiFi()
    interface = wifi.interfaces()[0]
    
    profile = None  # Initialize profile as None

    if interface.status() == const.IFACE_CONNECTED:
        interface.scan()  # Perform a scan to retrieve available networks
        profiles = interface.scan_results()  # Get scan results (list of profiles)
        
        connected_ssid = None
        for p in profiles:
            if p.ssid and interface.status() == const.IFACE_CONNECTED:
                connected_ssid = p.ssid
                profile = p  # Assign profile here
                break

        connected = {
            'ssid': connected_ssid if connected_ssid else 'Unknown',
            'bssid': getattr(profile, 'bssid', 'Unknown'),
            'signal': random.randint(-80, -30),  # Mock value
            'encryption': 'WPA2' if getattr(profile, 'auth', None) == const.AUTH_ALG_OPEN else 'Open',
            'connected_time': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'data_sent': random.randint(1000, 10000),
            'data_received': random.randint(5000, 50000),
            'ping': random.randint(5, 100)
        }
        
        # Update data file
        with open(DATA_FILE, 'r') as f:
            data = json.load(f)
        
        data['connected'] = connected
        
        with open(DATA_FILE, 'w') as f:
            json.dump(data, f)
        
        return connected
    else:
        # Mock data for demonstration
        mock_connected = {
            'ssid': 'Home_Network',
            'bssid': '00:11:22:33:44:55',
            'signal': random.randint(-80, -30),
            'encryption': 'WPA2',
            'connected_time': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'data_sent': random.randint(1000, 10000),
            'data_received': random.randint(5000, 50000),
            'ping': random.randint(5, 100)
        }
        
        # Update data file
        with open(DATA_FILE, 'r') as f:
            data = json.load(f)
        
        data['connected'] = mock_connected
        
        with open(DATA_FILE, 'w') as f:
            json.dump(data, f)
        
        return mock_connected

# AI-based threat detection function
def detect_threats(networks):
    # This would be where TensorFlow Lite models would be used
    # For now, we'll simulate detection
    threats = []
    
    for network in networks:
        # Random chance of different threat types for demo purposes
        if random.random() < 0.1:  # 10% chance
            threat_type = random.choice(attack_types)
            threat = {
                'network_ssid': network['ssid'],
                'network_bssid': network['bssid'],
                'type': threat_type,
                'severity': random.choice(['Low', 'Medium', 'High', 'Critical']),
                'description': f"{threat_type} attack detected on {network['ssid']}",
                'signature': attack_signatures.get(threat_type, "Unknown pattern"),
                'timestamp': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }
            threats.append(threat)
    
    # Update data file with new threats
    with open(DATA_FILE, 'r') as f:
        data = json.load(f)
    
    # Keep only the last 50 attacks to prevent file growth
    data['attacks'] = (data['attacks'] + threats)[-50:]
    
    # Add to timeline
    for threat in threats:
        timeline_entry = {
            'event': f"{threat['type']} attack detected",
            'network': threat['network_ssid'],
            'severity': threat['severity'],
            'timestamp': threat['timestamp']
        }
        data['timeline'].append(timeline_entry)
    
    # Keep only the last 100 timeline entries
    data['timeline'] = data['timeline'][-100:]
    
    # Update vulnerability score
    now = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    score = random.randint(10, 90)
    data['vulnerability_scores'].append({
        'timestamp': now,
        'score': score
    })
    
    # Keep only the last 100 scores
    data['vulnerability_scores'] = data['vulnerability_scores'][-100:]
    
    with open(DATA_FILE, 'w') as f:
        json.dump(data, f)
    
    return threats

# Background update thread
def background_update():
    while True:
        networks = scan_networks()
        connected = get_connected_network()
        detect_threats(networks)
        time.sleep(10)  # Update every 10 seconds

# Start background thread
update_thread = threading.Thread(target=background_update, daemon=True)
update_thread.start()

# Function to generate vulnerability trend graph
def generate_vulnerability_graph():
    with open(DATA_FILE, 'r') as f:
        data = json.load(f)
    
    scores = data.get('vulnerability_scores', [])
    
    # If no scores, create dummy data
    if not scores:
        now = datetime.datetime.now()
        for i in range(20):
            timestamp = (now - datetime.timedelta(minutes=i*5)).strftime('%Y-%m-%d %H:%M:%S')
            scores.append({
                'timestamp': timestamp,
                'score': random.randint(20, 80)
            })
    
    # Get last 20 scores for graph
    recent_scores = scores[-20:]
    timestamps = [score['timestamp'] for score in recent_scores]
    values = [score['score'] for score in recent_scores]
    
    # Create graph
    fig = Figure(figsize=(8, 4))
    axis = fig.add_subplot(1, 1, 1)
    axis.plot(timestamps, values, 'b-')
    axis.set_title('Network Vulnerability Score Trend')
    axis.set_ylabel('Vulnerability Score')
    axis.set_xlabel('Time')
    axis.grid(True)
    axis.tick_params(axis='x', rotation=45)
    fig.tight_layout()
    
    # Convert plot to base64 string
    buf = io.BytesIO()
    FigureCanvas(fig).print_png(buf)
    img_str = base64.b64encode(buf.getvalue()).decode('utf-8')
    
    return f"data:image/png;base64,{img_str}"

# Function to generate attack distribution pie chart
def generate_attack_pie_chart():
    with open(DATA_FILE, 'r') as f:
        data = json.load(f)
    
    attacks = data.get('attacks', [])
    
    # Count attack types
    attack_counts = {}
    for attack in attacks:
        attack_type = attack['type']
        if attack_type in attack_counts:
            attack_counts[attack_type] += 1
        else:
            attack_counts[attack_type] = 1
    
    # If no attacks, create sample data
    if not attack_counts:
        attack_counts = {
            'Deauth': 3,
            'Rogue_AP': 2,
            'Evil_Twin': 1,
            'SSH': 2
        }
    
    # Create pie chart
    fig = Figure(figsize=(6, 6))
    axis = fig.add_subplot(1, 1, 1)
    labels = list(attack_counts.keys())
    sizes = list(attack_counts.values())
    
    axis.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=90)
    axis.axis('equal')
    axis.set_title('Attack Type Distribution')
    fig.tight_layout()
    
    # Convert plot to base64 string
    buf = io.BytesIO()
    FigureCanvas(fig).print_png(buf)
    img_str = base64.b64encode(buf.getvalue()).decode('utf-8')
    
    return f"data:image/png;base64,{img_str}"

# Function to generate attack severity bar chart
def generate_severity_bar_chart():
    with open(DATA_FILE, 'r') as f:
        data = json.load(f)
    
    attacks = data.get('attacks', [])
    
    # Count severities
    severity_counts = {
        'Low': 0,
        'Medium': 0,
        'High': 0,
        'Critical': 0
    }
    
    for attack in attacks:
        severity = attack['severity']
        if severity in severity_counts:
            severity_counts[severity] += 1
    
    # If no data, create sample
    if sum(severity_counts.values()) == 0:
        severity_counts = {
            'Low': 4,
            'Medium': 3,
            'High': 2,
            'Critical': 1
        }
    
    # Create bar chart
    fig = Figure(figsize=(6, 5))
    axis = fig.add_subplot(1, 1, 1)
    
    severities = list(severity_counts.keys())
    counts = list(severity_counts.values())
    colors = ['green', 'yellow', 'orange', 'red']
    
    bars = axis.bar(severities, counts, color=colors)
    axis.set_title('Attack Severity Distribution')
    axis.set_ylabel('Number of Attacks')
    axis.set_xlabel('Severity Level')
    fig.tight_layout()
    
    # Convert plot to base64 string
    buf = io.BytesIO()
    FigureCanvas(fig).print_png(buf)
    img_str = base64.b64encode(buf.getvalue()).decode('utf-8')
    
    return f"data:image/png;base64,{img_str}"

# Routes
@app.route('/')
def index():
    vulnerability_graph = generate_vulnerability_graph()
    networks = scan_networks()
    connected = get_connected_network()
    
    with open(DATA_FILE, 'r') as f:
        data = json.load(f)
    
    recent_attacks = data.get('attacks', [])[-5:]  # Get 5 most recent attacks
    
    html = '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>WiFi Intrusion Detection System</title>
        <meta http-equiv="refresh" content="30">
        <style>
            body {
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                margin: 0;
                padding: 0;
                background-color: #f5f5f5;
                color: #333;
            }
            .container {
                width: 95%;
                margin: 0 auto;
                padding: 20px;
            }
            .header {
                background-color: #24292e;
                color: white;
                padding: 15px 0;
                text-align: center;
                border-radius: 5px 5px 0 0;
                margin-bottom: 20px;
            }
            .card {
                background-color: white;
                border-radius: 5px;
                box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
                margin-bottom: 20px;
                overflow: hidden;
            }
            .card-header {
                background-color: #007bff;
                color: white;
                padding: 10px 15px;
                font-size: 18px;
            }
            .card-body {
                padding: 15px;
            }
            .network-list {
                max-height: 400px;
                overflow-y: auto;
            }
            .network-item {
                padding: 10px;
                border-bottom: 1px solid #eee;
                display: flex;
                justify-content: space-between;
            }
            .network-item:hover {
                background-color: #f9f9f9;
            }
            .status-secure {
                color: green;
            }
            .status-open {
                color: red;
            }
            .status-connected {
                font-weight: bold;
                color: #007bff;
            }
            .chart-container {
                text-align: center;
                margin: 20px 0;
            }
            .btn {
                background-color: #007bff;
                color: white;
                border: none;
                padding: 8px 15px;
                border-radius: 4px;
                cursor: pointer;
                text-decoration: none;
                display: inline-block;
                font-size: 14px;
            }
            .btn:hover {
                background-color: #0069d9;
            }
            .alert {
                padding: 10px;
                border-radius: 4px;
                margin-bottom: 10px;
            }
            .alert-danger {
                background-color: #f8d7da;
                color: #721c24;
                border: 1px solid #f5c6cb;
            }
            .badge {
                padding: 3px 8px;
                border-radius: 10px;
                font-size: 12px;
                color: white;
            }
            .badge-danger {
                background-color: #dc3545; 
            }
            .badge-warning {
                background-color: #ffc107;
                color: #212529;
            }
            .badge-success {
                background-color: #28a745;
            }
            .badge-info {
                background-color: #17a2b8;
            }
            .flex-container {
                display: flex;
                flex-wrap: wrap;
                gap: 20px;
            }
            .flex-item {
                flex: 1;
                min-width: 300px;
            }
            table {
                width: 100%;
                border-collapse: collapse;
            }
            table th, table td {
                padding: 8px;
                text-align: left;
                border-bottom: 1px solid #ddd;
            }
            table th {
                background-color: #f2f2f2;
            }
            .footer {
                text-align: center;
                margin-top: 30px;
                padding: 10px;
                font-size: 14px;
                color: #666;
            }
            @media (max-width: 768px) {
                .flex-item {
                    min-width: 100%;
                }
            }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>WiFi Intrusion Detection System</h1>
                <p>Real-time monitoring and threat detection</p>
            </div>
            
            <div class="flex-container">
                <div class="flex-item">
                    <div class="card">
                        <div class="card-header">Currently Connected Network</div>
                        <div class="card-body">
                            {% if connected %}
                                <h3>{{ connected.ssid }}</h3>
                                <p><strong>BSSID:</strong> {{ connected.bssid }}</p>
                                <p><strong>Signal:</strong> {{ connected.signal }} dBm</p>
                                <p><strong>Encryption:</strong> {{ connected.encryption }}</p>
                                <p><strong>Connected Since:</strong> {{ connected.connected_time }}</p>
                                <a href="/network_details" class="btn">View Detailed Stats</a>
                            {% else %}
                                <p>Not connected to any network</p>
                            {% endif %}
                        </div>
                    </div>
                    
                    <div class="card">
                        <div class="card-header">Recent Attacks</div>
                        <div class="card-body">
                            {% if recent_attacks %}
                                {% for attack in recent_attacks %}
                                    <div class="alert alert-danger">
                                        <strong>{{ attack.type }}</strong> - {{ attack.description }}
                                        <br>
                                        <small>Severity: 
                                            <span class="badge 
                                                {% if attack.severity == 'Critical' %}badge-danger
                                                {% elif attack.severity == 'High' %}badge-warning
                                                {% elif attack.severity == 'Medium' %}badge-info
                                                {% else %}badge-success{% endif %}">
                                                {{ attack.severity }}
                                            </span>
                                            | {{ attack.timestamp }}
                                        </small>
                                    </div>
                                {% endfor %}
                                <a href="/attack_detection" class="btn">View All Attacks</a>
                            {% else %}
                                <p>No recent attacks detected</p>
                            {% endif %}
                        </div>
                    </div>
                </div>
                
                <div class="flex-item">
                    <div class="card">
                        <div class="card-header">Network Vulnerability Trend</div>
                        <div class="card-body">
                            <div class="chart-container">
                                <img src="{{ vulnerability_graph }}" alt="Vulnerability Trend" style="max-width:100%;">
                            </div>
                            <p>Current status: 
                                {% set last_score = vulnerability_scores[-1].score if vulnerability_scores else 50 %}
                                <span class="badge 
                                    {% if last_score > 70 %}badge-danger
                                    {% elif last_score > 40 %}badge-warning
                                    {% else %}badge-success{% endif %}">
                                    {{ last_score }}%
                                </span>
                            </p>
                        </div>
                    </div>
                </div>
            </div>
            
            <div class="card">
                <div class="card-header">Available Networks</div>
                <div class="card-body">
                    <div class="network-list">
                        <table>
                            <thead>
                                <tr>
                                    <th>SSID</th>
                                    <th>BSSID</th>
                                    <th>Signal</th>
                                    <th>Channel</th>
                                    <th>Security</th>
                                    <th>Status</th>
                                </tr>
                            </thead>
                            <tbody>
                                {% for network in networks %}
                                <tr class="network-item">
                                    <td>{{ network.ssid }}</td>
                                    <td>{{ network.bssid }}</td>
                                    <td>{{ network.signal }} dBm</td>
                                    <td>{{ network.channel }}</td>
                                    <td class="{% if network.encryption == 'WPA2' %}status-secure{% else %}status-open{% endif %}">
                                        {{ network.encryption }}
                                    </td>
                                    <td>
                                        {% if connected and connected.bssid == network.bssid %}
                                        <span class="status-connected">Connected</span>
                                        {% else %}
                                        -
                                        {% endif %}
                                    </td>
                                </tr>
                                {% endfor %}
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
            
            <div class="footer">
                <p>AI-Powered Intrusion Detection System | Developed with TensorFlow &amp; Flask</p>
            </div>
        </div>
    </body>
    </html>
    '''
    
    return render_template_string(
        html,
        networks=networks,
        connected=connected,
        recent_attacks=recent_attacks,
        vulnerability_graph=vulnerability_graph,
        vulnerability_scores=data.get('vulnerability_scores', [])
    )

@app.route('/network_details')
def network_details():
    connected = get_connected_network()
    
    # Generate random data for network statistics (in a real app, this would come from monitoring)
    timestamps = []
    download_speeds = []
    upload_speeds = []
    ping_values = []
    
    now = datetime.datetime.now()
    for i in range(24):
        timestamp = (now - datetime.timedelta(hours=i)).strftime('%H:%M')
        timestamps.insert(0, timestamp)
        download_speeds.insert(0, random.uniform(5, 50))
        upload_speeds.insert(0, random.uniform(2, 20))
        ping_values.insert(0, random.uniform(5, 100))
    
    # Create speed graph
    speed_fig = Figure(figsize=(10, 5))
    speed_ax = speed_fig.add_subplot(1, 1, 1)
    speed_ax.plot(timestamps, download_speeds, 'b-', label='Download (Mbps)')
    speed_ax.plot(timestamps, upload_speeds, 'g-', label='Upload (Mbps)')
    speed_ax.set_title('Network Speed Over Time')
    speed_ax.set_ylabel('Speed (Mbps)')
    speed_ax.set_xlabel('Time')
    speed_ax.grid(True)
    speed_ax.legend()
    speed_ax.tick_params(axis='x', rotation=45)
    speed_fig.tight_layout()
    
    # Convert speed plot to base64 string
    speed_buf = io.BytesIO()
    FigureCanvas(speed_fig).print_png(speed_buf)
    speed_img_str = base64.b64encode(speed_buf.getvalue()).decode('utf-8')
    speed_graph = f"data:image/png;base64,{speed_img_str}"
    
    # Create ping graph
    ping_fig = Figure(figsize=(10, 5))
    ping_ax = ping_fig.add_subplot(1, 1, 1)
    ping_ax.plot(timestamps, ping_values, 'r-')
    ping_ax.set_title('Network Latency Over Time')
    ping_ax.set_ylabel('Ping (ms)')
    ping_ax.set_xlabel('Time')
    ping_ax.grid(True)
    ping_ax.tick_params(axis='x', rotation=45)
    ping_fig.tight_layout()
    
    # Convert ping plot to base64 string
    ping_buf = io.BytesIO()
    FigureCanvas(ping_fig).print_png(ping_buf)
    ping_img_str = base64.b64encode(ping_buf.getvalue()).decode('utf-8')
    ping_graph = f"data:image/png;base64,{ping_img_str}"
    
    html = '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Network Details - WiFi IDS</title>
        <meta http-equiv="refresh" content="60">
        <style>
            body {
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                margin: 0;
                padding: 0;
                background-color: #f5f5f5;
                color: #333;
            }
            .container {
                width: 95%;
                margin: 0 auto;
                padding: 20px;
            }
            .header {
                background-color: #24292e;
                color: white;
                padding: 15px 0;
                text-align: center;
                border-radius: 5px 5px 0 0;
                margin-bottom: 20px;
            }
            .card {
                background-color: white;
                border-radius: 5px;
                box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
                margin-bottom: 20px;
                overflow: hidden;
            }
            .card-header {
                background-color: #007bff;
                color: white;
                padding: 10px 15px;
                font-size: 18px;
            }
            .card-body {
                padding: 15px;
            }
            .chart-container {
                text-align: center;
                margin: 20px 0;
            }
            .btn {
                background-color: #007bff;
                color: white;
                border: none;
                padding: 8px 15px;
                border-radius: 4px;
                cursor: pointer;
                text-decoration: none;
                display: inline-block;
                font-size: 14px;
            }
            .btn:hover {
                background-color: #0069d9;
            }
            .stats-grid {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                gap: 15px;
                margin-bottom: 20px;
            }
            .stat-box {
                background-color: #f8f9fa;
                border-radius: 5px;
                padding: 15px;
                text-align: center;
                box-shadow: 0 1px 3px rgba(0,0,0,0.1);
            }
            .stat-value {
                font-size: 24px;
                font-weight: bold;
                margin: 10px 0;
            }
            .stat-label {
                color: #666;
                font-size: 14px;
            }
            .footer {
                text-align: center;
                margin-top: 30px;
                padding: 10px;
                font-size: 14px;
                color: #666;
            }
            .nav-bar {
                background-color: #333;
                overflow: hidden;
                margin-bottom: 20px;
                border-radius: 5px;
            }
            .nav-bar a {
                float: left;
                display: block;
                color: white;
                text-align: center;
                padding: 14px 16px;
                text-decoration: none;
            }
            .nav-bar a:hover {
                background-color: #ddd;
                color: black;
            }
            .nav-bar a.active {
                background-color: #007bff;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>Network Details</h1>
                <p>Detailed statistics for the connected network</p>
            </div>
            
            <div class="nav-bar">
                <a href="/">Dashboard</a>
                <a class="active" href="/network_details">Network Details</a>
                <a href="/attack_detection">Attack Detection</a>
                <a href="/timeline">Timeline</a>
            </div>
            
            <div class="card">
                <div class="card-header">Network Information</div>
                <div class="card-body">
                    <h2>{{ connected.ssid }}</h2>
                    <div class="stats-grid">
                        <div class="stat-box">
                            <div class="stat-label">BSSID</div>
                            <div class="stat-value" style="font-size: 16px;">{{ connected.bssid }}</div>
                        </div>
                        <div class="stat-box">
                            <div class="stat-label">Signal Strength</div>
                            <div class="stat-value">{{ connected.signal }} dBm</div>
                        </div>
                        <div class="stat-box">
                            <div class="stat-label">Security</div>
                            <div class="stat-value">{{ connected.encryption }}</div>
                        </div>
                        <div class="stat-box">
                            <div class="stat-label">Connected Since</div>
                            <div class="stat-value" style="font-size: 16px;">{{ connected.connected_time }}</div>
                        </div>
                    </div>
                </div>
            </div>
            
            <div class="card">
                <div class="card-header">Network Performance</div>
                <div class="card-body">
                    <div class="stats-grid">
                        <div class="stat-box">
                            <div class="stat-label">Data Sent</div>
                            <div class="stat-value">{{ (connected.data_sent / 1024) | round(2) }} MB</div>
                        </div>
                        <div class="stat-box">
                            <div class="stat-label">Data Received</div>
                            <div class="stat-value">{{ (connected.data_received / 1024) | round(2) }} MB</div>
                        </div>
                        <div class="stat-box">
                            <div class="stat-label">Current Ping</div>
                            <div class="stat-value">{{ connected.ping }} ms</div>
                        </div>
                        <div class="stat-box">
                            <div class="stat-label">Connection Quality</div>
                            <div class="stat-value">
                                {% if connected.signal > -50 %}
                                    Excellent
                                {% elif connected.signal > -70 %}
                                    Good
                                {% elif connected.signal > -80 %}
                                    Fair
                                {% else %}
                                    Poor
                                {% endif %}
                            </div>
                        </div>
                    </div>
                    
                    <div class="chart-container">
                        <h3>Connection Speed History</h3>
                        <img src="{{ speed_graph }}" alt="Speed History" style="max-width:100%;">
                    </div>
                    
                    <div class="chart-container">
                        <h3>Latency History</h3>
                        <img src="{{ ping_graph }}" alt="Ping History" style="max-width:100%;">
                    </div>
                </div>
            </div>
            
            <div class="footer">
                <p>AI-Powered Intrusion Detection System | Developed with TensorFlow &amp; Flask</p>
            </div>
        </div>
    </body>
    </html>
    '''
    
    return render_template_string(
        html, 
        connected=connected,
        speed_graph=speed_graph,
        ping_graph=ping_graph
    )

@app.route('/attack_detection')
def attack_detection():
    # Get attack data
    with open(DATA_FILE, 'r') as f:
        data = json.load(f)
    
    attacks = data.get('attacks', [])
    
    # Generate graphs
    pie_chart = generate_attack_pie_chart()
    severity_chart = generate_severity_bar_chart()
    
    html = '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Attack Detection - WiFi IDS</title>
        <meta http-equiv="refresh" content="60">
        <style>
            body {
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                margin: 0;
                padding: 0;
                background-color: #f5f5f5;
                color: #333;
            }
            .container {
                width: 95%;
                margin: 0 auto;
                padding: 20px;
            }
            .header {
                background-color: #24292e;
                color: white;
                padding: 15px 0;
                text-align: center;
                border-radius: 5px 5px 0 0;
                margin-bottom: 20px;
            }
            .card {
                background-color: white;
                border-radius: 5px;
                box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
                margin-bottom: 20px;
                overflow: hidden;
            }
            .card-header {
                background-color: #007bff;
                color: white;
                padding: 10px 15px;
                font-size: 18px;
            }
            .card-body {
                padding: 15px;
            }
            .chart-container {
                text-align: center;
                margin: 20px 0;
            }
            .btn {
                background-color: #007bff;
                color: white;
                border: none;
                padding: 8px 15px;
                border-radius: 4px;
                cursor: pointer;
                text-decoration: none;
                display: inline-block;
                font-size: 14px;
            }
            .btn:hover {
                background-color: #0069d9;
            }
            .footer {
                text-align: center;
                margin-top: 30px;
                padding: 10px;
                font-size: 14px;
                color: #666;
            }
            .nav-bar {
                background-color: #333;
                overflow: hidden;
                margin-bottom: 20px;
                border-radius: 5px;
            }
            .nav-bar a {
                float: left;
                display: block;
                color: white;
                text-align: center;
                padding: 14px 16px;
                text-decoration: none;
            }
            .nav-bar a:hover {
                background-color: #ddd;
                color: black;
            }
            .nav-bar a.active {
                background-color: #007bff;
            }
            .charts-grid {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
                gap: 20px;
                margin-bottom: 20px;
            }
            table {
                width: 100%;
                border-collapse: collapse;
            }
            table th, table td {
                padding: 8px;
                text-align: left;
                border-bottom: 1px solid #ddd;
            }
            table th {
                background-color: #f2f2f2;
            }
            .badge {
                padding: 3px 8px;
                border-radius: 10px;
                font-size: 12px;
                color: white;
            }
            .badge-danger {
                background-color: #dc3545; 
            }
            .badge-warning {
                background-color: #ffc107;
                color: #212529;
            }
            .badge-success {
                background-color: #28a745;
            }
            .badge-info {
                background-color: #17a2b8;
            }
            .attack-list {
                max-height: 500px;
                overflow-y: auto;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>Attack Detection</h1>
                <p>Analysis of detected network attacks</p>
            </div>
            
            <div class="nav-bar">
                <a href="/">Dashboard</a>
                <a href="/network_details">Network Details</a>
                <a class="active" href="/attack_detection">Attack Detection</a>
                <a href="/timeline">Timeline</a>
            </div>
            
            <div class="charts-grid">
                <div class="card">
                    <div class="card-header">Attack Type Distribution</div>
                    <div class="card-body">
                        <div class="chart-container">
                            <img src="{{ pie_chart }}" alt="Attack Distribution" style="max-width:100%;">
                        </div>
                    </div>
                </div>
                
                <div class="card">
                    <div class="card-header">Attack Severity</div>
                    <div class="card-body">
                        <div class="chart-container">
                            <img src="{{ severity_chart }}" alt="Attack Severity" style="max-width:100%;">
                        </div>
                    </div>
                </div>
            </div>
            
            <div class="card">
                <div class="card-header">Detected Attacks</div>
                <div class="card-body">
                    <div class="attack-list">
                        <table>
                            <thead>
                                <tr>
                                    <th>Time</th>
                                    <th>Attack Type</th>
                                    <th>Network</th>
                                    <th>Severity</th>
                                    <th>Description</th>
                                </tr>
                            </thead>
                            <tbody>
                                {% for attack in attacks|reverse %}
                                <tr>
                                    <td>{{ attack.timestamp }}</td>
                                    <td>{{ attack.type }}</td>
                                    <td>{{ attack.network_ssid }}</td>
                                    <td>
                                        <span class="badge 
                                            {% if attack.severity == 'Critical' %}badge-danger
                                            {% elif attack.severity == 'High' %}badge-warning
                                            {% elif attack.severity == 'Medium' %}badge-info
                                            {% else %}badge-success{% endif %}">
                                            {{ attack.severity }}
                                        </span>
                                    </td>
                                    <td>{{ attack.description }}</td>
                                </tr>
                                {% endfor %}
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
            
            <div class="card">
                <div class="card-header">Attack Signatures</div>
                <div class="card-body">
                    <table>
                        <thead>
                            <tr>
                                <th>Attack Type</th>
                                <th>Signature Pattern</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for attack_type, signature in attack_signatures.items() %}
                            <tr>
                                <td>{{ attack_type }}</td>
                                <td><code>{{ signature }}</code></td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>
            </div>
            
            <div class="footer">
                <p>AI-Powered Intrusion Detection System | Developed with TensorFlow &amp; Flask</p>
            </div>
        </div>
    </body>
    </html>
    '''
    
    return render_template_string(
        html,
        attacks=attacks,
        pie_chart=pie_chart,
        severity_chart=severity_chart,
        attack_signatures=attack_signatures
    )

@app.route('/timeline')
def timeline():
    # Get timeline data
    with open(DATA_FILE, 'r') as f:
        data = json.load(f)
    
    timeline_events = data.get('timeline', [])
    
    html = '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Timeline - WiFi IDS</title>
        <style>
            body {
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                margin: 0;
                padding: 0;
                background-color: #f5f5f5;
                color: #333;
            }
            .container {
                width: 95%;
                margin: 0 auto;
                padding: 20px;
            }
            .header {
                background-color: #24292e;
                color: white;
                padding: 15px 0;
                text-align: center;
                border-radius: 5px 5px 0 0;
                margin-bottom: 20px;
            }
            .card {
                background-color: white;
                border-radius: 5px;
                box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
                margin-bottom: 20px;
                overflow: hidden;
            }
            .card-header {
                background-color: #007bff;
                color: white;
                padding: 10px 15px;
                font-size: 18px;
            }
            .card-body {
                padding: 15px;
            }
            .footer {
                text-align: center;
                margin-top: 30px;
                padding: 10px;
                font-size: 14px;
                color: #666;
            }
            .nav-bar {
                background-color: #333;
                overflow: hidden;
                margin-bottom: 20px;
                border-radius: 5px;
            }
            .nav-bar a {
                float: left;
                display: block;
                color: white;
                text-align: center;
                padding: 14px 16px;
                text-decoration: none;
            }
            .nav-bar a:hover {
                background-color: #ddd;
                color: black;
            }
            .nav-bar a.active {
                background-color: #007bff;
            }
            .timeline {
                position: relative;
                max-width: 1200px;
                margin: 0 auto;
            }
            .timeline::after {
                content: '';
                position: absolute;
                width: 6px;
                background-color: #007bff;
                top: 0;
                bottom: 0;
                left: 50%;
                margin-left: -3px;
                border-radius: 3px;
            }
            .timeline-container {
                padding: 10px 40px;
                position: relative;
                background-color: inherit;
                width: 50%;
            }
            .timeline-container::after {
                content: '';
                position: absolute;
                width: 20px;
                height: 20px;
                right: -10px;
                background-color: white;
                border: 4px solid #007bff;
                top: 15px;
                border-radius: 50%;
                z-index: 1;
            }
            .left {
                left: 0;
            }
            .right {
                left: 50%;
            }
            .left::after {
                right: -10px;
            }
            .right::after {
                left: -10px;
            }
            .timeline-content {
                padding: 20px;
                background-color: white;
                position: relative;
                border-radius: 6px;
                box-shadow: 0 2px 5px rgba(0,0,0,0.1);
            }
            .badge {
                padding: 3px 8px;
                border-radius: 10px;
                font-size: 12px;
                color: white;
            }
            .badge-danger {
                background-color: #dc3545; 
            }
            .badge-warning {
                background-color: #ffc107;
                color: #212529;
            }
            .badge-success {
                background-color: #28a745;
            }
            .badge-info {
                background-color: #17a2b8;
            }
            .badge-primary {
                background-color: #007bff;
            }
            @media screen and (max-width: 600px) {
                .timeline::after {
                    left: 31px;
                }
                .timeline-container {
                    width: 100%;
                    padding-left: 70px;
                    padding-right: 25px;
                }
                .timeline-container::after {
                    left: 21px;
                }
                .left::after, .right::after {
                    left: 21px;
                }
                .right {
                    left: 0%;
                }
            }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>Event Timeline</h1>
                <p>Chronological view of network events and attacks</p>
            </div>
            
            <div class="nav-bar">
                <a href="/">Dashboard</a>
                <a href="/network_details">Network Details</a>
                <a href="/attack_detection">Attack Detection</a>
                <a class="active" href="/timeline">Timeline</a>
            </div>
            
            <div class="card">
                <div class="card-header">Network Event Timeline</div>
                <div class="card-body">
                    <div class="timeline">
                        {% for i in range(timeline_events|length) %}
                            {% set event = timeline_events[-(i+1)] %}
                            <div class="timeline-container {% if i % 2 == 0 %}left{% else %}right{% endif %}">
                                <div class="timeline-content">
                                    <h3>{{ event.event }}</h3>
                                    <p>Network: {{ event.network }}</p>
                                    <p>
                                        <span class="badge 
                                            {% if event.severity == 'Critical' %}badge-danger
                                            {% elif event.severity == 'High' %}badge-warning
                                            {% elif event.severity == 'Medium' %}badge-info
                                            {% elif event.severity == 'Low' %}badge-success
                                            {% else %}badge-primary{% endif %}">
                                            {{ event.severity }}
                                        </span>
                                    </p>
                                    <p><small>{{ event.timestamp }}</small></p>
                                </div>
                            </div>
                        {% endfor %}
                    </div>
                </div>
            </div>
            
            <div class="footer">
                <p>AI-Powered Intrusion Detection System | Developed with TensorFlow &amp; Flask</p>
            </div>
        </div>
    </body>
    </html>
    '''
    
    return render_template_string(html, timeline_events=timeline_events)

# API endpoints for getting data in JSON format
@app.route('/api/networks')
def api_networks():
    networks = scan_networks()
    return jsonify(networks)

@app.route('/api/connected')
def api_connected():
    connected = get_connected_network()
    return jsonify(connected)

@app.route('/api/attacks')
def api_attacks():
    with open(DATA_FILE, 'r') as f:
        data = json.load(f)
    attacks = data.get('attacks', [])
    return jsonify(attacks)

@app.route('/api/vulnerability')
def api_vulnerability():
    with open(DATA_FILE, 'r') as f:
        data = json.load(f)
    scores = data.get('vulnerability_scores', [])
    return jsonify(scores)

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)