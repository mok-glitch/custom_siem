from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from flask_session import Session
import json
import os
from pathlib import Path
from datetime import datetime, timedelta
import pandas as pd
from collections import defaultdict, Counter
import re
import hashlib

app = Flask(__name__)
app.config['SECRET_KEY'] = 'siem_secret_key_change_this_in_production'
app.config['SESSION_TYPE'] = 'filesystem'
Session(app)

# Define paths
BASE_DIR = Path(__file__).parent.parent
LOGS_DIR = BASE_DIR / 'Logs'
TELEMETRY_FILE = LOGS_DIR / 'telemetry.json'
NETWORK_FILE = LOGS_DIR / 'network.json'
AUTH_FILE = LOGS_DIR / 'auth.json'
ALERTS_FILE = LOGS_DIR / 'alerts.json'

# Ensure alerts.json exists
if not ALERTS_FILE.exists():
    with open(ALERTS_FILE, 'w') as f:
        json.dump([], f)

# Default credentials (in production, use proper password hashing)
USERS = {
    'admin': hashlib.sha256('admin123'.encode()).hexdigest()
}

def load_json_file(file_path):
    """Load JSON file safely"""
    try:
        if file_path.exists():
            with open(file_path, 'r') as f:
                return json.load(f)
        return []
    except (json.JSONDecodeError, FileNotFoundError):
        return []

def save_json_file(file_path, data):
    """Save data to JSON file"""
    with open(file_path, 'w') as f:
        json.dump(data, f, indent=2)

@app.route('/')
def index():
    """Redirect to login or dashboard"""
    if 'username' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login page"""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if username in USERS and USERS[username] == hashlib.sha256(password.encode()).hexdigest():
            session['username'] = username
            return redirect(url_for('dashboard'))
        else:
            return render_template('login.html', error='Invalid credentials')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    """Logout user"""
    session.pop('username', None)
    return redirect(url_for('login'))

@app.route('/dashboard')
def dashboard():
    """Main dashboard page"""
    if 'username' not in session:
        return redirect(url_for('login'))
    return render_template('dashboard.html')

@app.route('/logs')
def logs():
    """System logs page"""
    if 'username' not in session:
        return redirect(url_for('login'))
    return render_template('logs.html')

@app.route('/network_logs')
def network_logs():
    """Network logs page"""
    if 'username' not in session:
        return redirect(url_for('login'))
    return render_template('network_logs.html')

@app.route('/auth_logs')
def auth_logs():
    """Authentication logs page"""
    if 'username' not in session:
        return redirect(url_for('login'))
    return render_template('auth_logs.html')

@app.route('/alerts')
def alerts():
    """Alerts page"""
    if 'username' not in session:
        return redirect(url_for('login'))
    return render_template('alerts.html')

@app.route('/event/<int:event_id>')
def event_details(event_id):
    """Event details page"""
    if 'username' not in session:
        return redirect(url_for('login'))
    return render_template('event.html', event_id=event_id)

@app.route('/network_event/<int:event_id>')
def network_event_details(event_id):
    """Network event details page"""
    if 'username' not in session:
        return redirect(url_for('login'))
    return render_template('network_event.html', event_id=event_id)

@app.route('/investigate/<alert_id>')
def investigate(alert_id):
    """Investigation page for alerts"""
    if 'username' not in session:
        return redirect(url_for('login'))
    return render_template('investigate.html', alert_id=alert_id)

# API Endpoints for real-time data
@app.route('/api/dashboard/stats')
def api_dashboard_stats():
    """Get dashboard statistics"""
    telemetry = load_json_file(TELEMETRY_FILE)
    alerts = load_json_file(ALERTS_FILE)
    
    # Total events (last 24 hours)
    last_24h = datetime.now() - timedelta(hours=24)
    recent_events = [e for e in telemetry if datetime.fromisoformat(e['timestamp']) > last_24h]
    total_events = len(recent_events)
    
    # Open alerts
    open_alerts = len([a for a in alerts if a.get('status') == 'Open'])
    
    # Critical/High alerts
    critical_high = len([a for a in alerts if a.get('severity') in ['Critical', 'High']])
    
    # Active hosts (unique source IPs from network logs)
    network = load_json_file(NETWORK_FILE)
    active_hosts = len(set([n.get('source_ip') for n in network]))
    
    return jsonify({
        'total_events': total_events,
        'open_alerts': open_alerts,
        'critical_high': critical_high,
        'active_hosts': active_hosts
    })

@app.route('/api/dashboard/timeline')
def api_dashboard_timeline():
    """Get event timeline for last 24 hours"""
    telemetry = load_json_file(TELEMETRY_FILE)
    
    # Group by hour
    hours = defaultdict(int)
    for event in telemetry:
        try:
            timestamp = datetime.fromisoformat(event['timestamp'])
            if timestamp > datetime.now() - timedelta(hours=24):
                hour_key = timestamp.strftime('%Y-%m-%d %H:00')
                hours[hour_key] += 1
        except:
            pass
    
    # Sort by time
    sorted_hours = sorted(hours.items())
    labels = [h[0].split()[1] for h in sorted_hours]
    values = [h[1] for h in sorted_hours]
    
    return jsonify({'labels': labels, 'values': values})

@app.route('/api/dashboard/severity')
def api_dashboard_severity():
    """Get alert severity distribution"""
    alerts = load_json_file(ALERTS_FILE)
    
    severity_counts = Counter([a.get('severity', 'Low') for a in alerts])
    
    return jsonify({
        'labels': list(severity_counts.keys()),
        'values': list(severity_counts.values())
    })

@app.route('/api/dashboard/top_processes')
def api_dashboard_top_processes():
    """Get top processes by CPU usage"""
    telemetry = load_json_file(TELEMETRY_FILE)
    
    # Get latest 1000 events
    recent = telemetry[:1000]
    
    # Aggregate CPU by process
    process_cpu = defaultdict(float)
    for event in recent:
        process_cpu[event['process_name']] += event['cpu_percent']
    
    # Get top 10
    top_processes = sorted(process_cpu.items(), key=lambda x: x[1], reverse=True)[:10]
    
    return jsonify({
        'labels': [p[0] for p in top_processes],
        'values': [p[1] for p in top_processes]
    })

@app.route('/api/dashboard/recent_alerts')
def api_dashboard_recent_alerts():
    """Get recent alerts"""
    alerts = load_json_file(ALERTS_FILE)
    recent_alerts = alerts[:10]  # Get 10 most recent
    
    return jsonify(recent_alerts)

@app.route('/api/dashboard/active_threats')
def api_dashboard_active_threats():
    """Get active threats (brute force attempts)"""
    alerts = load_json_file(ALERTS_FILE)
    
    # Find brute force alerts from last hour
    brute_force_alerts = [
        a for a in alerts 
        if 'Brute Force' in a.get('title', '') and 
        datetime.fromisoformat(a['timestamp']) > datetime.now() - timedelta(hours=1)
    ]
    
    threats = []
    for alert in brute_force_alerts[:5]:
        threats.append({
            'title': alert.get('title'),
            'severity': alert.get('severity'),
            'source_ip': alert.get('details', {}).get('source_ip', 'Unknown'),
            'attempts': alert.get('details', {}).get('attempts', 0),
            'timestamp': alert.get('timestamp')
        })
    
    return jsonify(threats)

@app.route('/api/logs')
def api_logs():
    """Get system logs with filtering and pagination"""
    telemetry = load_json_file(TELEMETRY_FILE)
    
    # Get parameters
    search = request.args.get('search', '')
    date_from = request.args.get('date_from', '')
    date_to = request.args.get('date_to', '')
    limit = int(request.args.get('limit', 50))
    page = int(request.args.get('page', 1))
    sort_by = request.args.get('sort_by', 'id')
    sort_order = request.args.get('sort_order', 'desc')
    
    # Apply filters
    filtered = telemetry
    
    if search:
        filtered = [e for e in filtered if search.lower() in e.get('process_name', '').lower()]
    
    if date_from:
        try:
            from_date = datetime.fromisoformat(date_from)
            filtered = [e for e in filtered if datetime.fromisoformat(e['timestamp']) >= from_date]
        except:
            pass
    
    if date_to:
        try:
            to_date = datetime.fromisoformat(date_to)
            filtered = [e for e in filtered if datetime.fromisoformat(e['timestamp']) <= to_date]
        except:
            pass
    
    # Sort
    reverse = sort_order == 'desc'
    filtered.sort(key=lambda x: x.get(sort_by, 0), reverse=reverse)
    
    # Pagination
    total = len(filtered)
    start = (page - 1) * limit
    end = start + limit
    paginated = filtered[start:end]
    
    # Add sequential IDs
    for idx, event in enumerate(paginated):
        event['seq_id'] = total - (start + idx)
    
    return jsonify({
        'data': paginated,
        'total': total,
        'page': page,
        'limit': limit,
        'total_pages': (total + limit - 1) // limit if total > 0 else 1
    })

@app.route('/api/network_logs')
def api_network_logs():
    """Get network logs with filtering"""
    network = load_json_file(NETWORK_FILE)
    
    # Get parameters
    src_ip = request.args.get('src_ip', '')
    dst_ip = request.args.get('dst_ip', '')
    port = request.args.get('port', '')
    protocol = request.args.get('protocol', '')
    date_from = request.args.get('date_from', '')
    date_to = request.args.get('date_to', '')
    limit = int(request.args.get('limit', 50))
    page = int(request.args.get('page', 1))
    
    # Apply filters
    filtered = network
    
    if src_ip:
        filtered = [e for e in filtered if src_ip.lower() in e.get('source_ip', '').lower()]
    
    if dst_ip:
        filtered = [e for e in filtered if dst_ip.lower() in e.get('destination_ip', '').lower()]
    
    if port:
        try:
            port_int = int(port)
            filtered = [e for e in filtered if e.get('destination_port') == port_int or e.get('source_port') == port_int]
        except:
            pass
    
    if protocol:
        filtered = [e for e in filtered if e.get('protocol', '').upper() == protocol.upper()]
    
    if date_from:
        try:
            from_date = datetime.fromisoformat(date_from)
            filtered = [e for e in filtered if datetime.fromisoformat(e['timestamp']) >= from_date]
        except:
            pass
    
    if date_to:
        try:
            to_date = datetime.fromisoformat(date_to)
            filtered = [e for e in filtered if datetime.fromisoformat(e['timestamp']) <= to_date]
        except:
            pass
    
    # Sort by timestamp descending
    filtered.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
    
    # Pagination
    total = len(filtered)
    start = (page - 1) * limit
    end = start + limit
    paginated = filtered[start:end]
    
    # Add sequential IDs
    for idx, event in enumerate(paginated):
        event['seq_id'] = total - (start + idx)
    
    return jsonify({
        'data': paginated,
        'total': total,
        'page': page,
        'limit': limit,
        'total_pages': (total + limit - 1) // limit if total > 0 else 1
    })

@app.route('/api/auth_logs')
def api_auth_logs():
    """Get authentication logs with filtering"""
    auth_logs = load_json_file(AUTH_FILE)
    
    # Get parameters
    ip = request.args.get('ip', '')
    username = request.args.get('username', '')
    status = request.args.get('status', '')
    date_from = request.args.get('date_from', '')
    date_to = request.args.get('date_to', '')
    limit = int(request.args.get('limit', 100))
    page = int(request.args.get('page', 1))
    sort_by = request.args.get('sort_by', 'timestamp')
    sort_order = request.args.get('sort_order', 'desc')
    
    # Apply filters
    filtered = auth_logs
    
    if ip:
        filtered = [e for e in filtered if ip.lower() in e.get('source_ip', '').lower()]
    
    if username:
        filtered = [e for e in filtered if username.lower() in e.get('username', '').lower()]
    
    if status and status != 'all':
        filtered = [e for e in filtered if e.get('status') == status]
    
    if date_from:
        try:
            from_date = datetime.fromisoformat(date_from)
            filtered = [e for e in filtered if datetime.fromisoformat(e['timestamp']) >= from_date]
        except:
            pass
    
    if date_to:
        try:
            to_date = datetime.fromisoformat(date_to)
            filtered = [e for e in filtered if datetime.fromisoformat(e['timestamp']) <= to_date]
        except:
            pass
    
    # Sort
    reverse = sort_order == 'desc'
    filtered.sort(key=lambda x: x.get(sort_by, ''), reverse=reverse)
    
    # Pagination
    total = len(filtered)
    start = (page - 1) * limit
    end = start + limit
    paginated = filtered[start:end]
    
    # Get statistics
    total_success = len([e for e in filtered if e.get('status') == 'Success'])
    total_failure = len([e for e in filtered if e.get('status') == 'Failure'])
    unique_ips = len(set([e.get('source_ip') for e in filtered if e.get('source_ip')]))
    
    # Get suspicious IPs (IPs with 5+ failures)
    ip_failures = defaultdict(int)
    for e in filtered:
        if e.get('status') == 'Failure' and e.get('source_ip'):
            ip_failures[e['source_ip']] += 1
    
    suspicious_ips = [
        {'ip': ip, 'count': count}
        for ip, count in ip_failures.items()
        if count >= 5
    ]
    suspicious_ips.sort(key=lambda x: x['count'], reverse=True)
    
    # Get most targeted usernames
    username_targets = defaultdict(int)
    for e in filtered:
        if e.get('status') == 'Failure' and e.get('username'):
            username_targets[e['username']] += 1
    
    top_targeted = [
        {'username': user, 'count': count}
        for user, count in sorted(username_targets.items(), key=lambda x: x[1], reverse=True)[:10]
    ]
    
    return jsonify({
        'data': paginated,
        'total': total,
        'page': page,
        'limit': limit,
        'total_pages': (total + limit - 1) // limit if total > 0 else 1,
        'stats': {
            'total': total,
            'success': total_success,
            'failure': total_failure,
            'unique_ips': unique_ips
        },
        'insights': {
            'suspicious_ips': suspicious_ips,
            'top_targeted_usernames': top_targeted
        }
    })

@app.route('/api/alerts')
def api_alerts():
    """Get alerts with filtering"""
    alerts = load_json_file(ALERTS_FILE)
    
    # Get parameters
    severity = request.args.get('severity', 'All')
    status = request.args.get('status', 'All')
    date_from = request.args.get('date_from', '')
    date_to = request.args.get('date_to', '')
    
    # Apply filters
    filtered = alerts
    
    if severity != 'All':
        filtered = [a for a in filtered if a.get('severity') == severity]
    
    if status != 'All':
        filtered = [a for a in filtered if a.get('status') == status]
    
    if date_from:
        try:
            from_date = datetime.fromisoformat(date_from)
            filtered = [a for a in filtered if datetime.fromisoformat(a['timestamp']) >= from_date]
        except:
            pass
    
    if date_to:
        try:
            to_date = datetime.fromisoformat(date_to)
            filtered = [a for a in filtered if datetime.fromisoformat(a['timestamp']) <= to_date]
        except:
            pass
    
    # Sort by timestamp descending
    filtered.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
    
    # Get statistics
    total_alerts = len(alerts)
    open_alerts = len([a for a in alerts if a.get('status') == 'Open'])
    confirmed_alerts = len([a for a in alerts if a.get('status') == 'Confirmed'])
    false_positives = len([a for a in alerts if a.get('status') == 'False Positive'])
    
    return jsonify({
        'data': filtered,
        'stats': {
            'total': total_alerts,
            'open': open_alerts,
            'confirmed': confirmed_alerts,
            'false_positive': false_positives
        }
    })

@app.route('/api/alert/<alert_id>/update', methods=['POST'])
def api_update_alert(alert_id):
    """Update alert status"""
    alerts = load_json_file(ALERTS_FILE)
    data = request.json
    new_status = data.get('status')
    
    for alert in alerts:
        if alert.get('id') == alert_id:
            alert['status'] = new_status
            break
    
    save_json_file(ALERTS_FILE, alerts)
    return jsonify({'success': True})

@app.route('/api/event/<int:event_id>')
def api_event_details(event_id):
    """Get specific event details"""
    telemetry = load_json_file(TELEMETRY_FILE)
    
    # Find the event
    event = next((e for e in telemetry if e.get('id') == event_id), None)
    
    if not event:
        return jsonify({'error': 'Event not found'}), 404
    
    # Find related events (same process within ±1 hour)
    event_time = datetime.fromisoformat(event['timestamp'])
    related = []
    
    for e in telemetry:
        if e['id'] != event_id and e.get('process_name') == event.get('process_name'):
            try:
                e_time = datetime.fromisoformat(e['timestamp'])
                if abs((e_time - event_time).total_seconds()) <= 3600:  # Within 1 hour
                    related.append(e)
            except:
                pass
    
    return jsonify({
        'event': event,
        'related_events': related[:10]  # Limit to 10 related events
    })

@app.route('/api/network_event/<int:event_id>')
def api_network_event_details(event_id):
    """Get specific network event details"""
    network = load_json_file(NETWORK_FILE)
    
    # Find the event
    event = next((e for e in network if e.get('id') == event_id), None)
    
    if not event:
        return jsonify({'error': 'Event not found'}), 404
    
    # Find related events (same IP within ±1 hour)
    event_time = datetime.fromisoformat(event['timestamp'])
    related = []
    
    for e in network:
        if e['id'] != event_id and e.get('source_ip') == event.get('source_ip'):
            try:
                e_time = datetime.fromisoformat(e['timestamp'])
                if abs((e_time - event_time).total_seconds()) <= 3600:  # Within 1 hour
                    related.append(e)
            except:
                pass
    
    return jsonify({
        'event': event,
        'related_events': related[:10]  # Limit to 10 related events
    })

@app.route('/api/investigate/<alert_id>')
def api_investigate(alert_id):
    """Get investigation data for an alert"""
    alerts = load_json_file(ALERTS_FILE)
    
    # Find the alert
    alert = next((a for a in alerts if a.get('id') == alert_id), None)
    
    if not alert:
        return jsonify({'error': 'Alert not found'}), 404
    
    # Get related events based on alert details
    related_events = []
    similar_alerts = []
    
    # Get events from auth logs if it's a brute force alert
    if 'Brute Force' in alert.get('title', ''):
        source_ip = alert.get('details', {}).get('source_ip')
        if source_ip:
            auth_logs = load_json_file(AUTH_FILE)
            # Get auth events from this IP
            related_events = [e for e in auth_logs if e.get('source_ip') == source_ip][:20]
    
    # Get similar alerts (same title)
    similar_alerts = [a for a in alerts if a.get('title') == alert.get('title') and a.get('id') != alert_id][:5]
    
    # Get timeline of related events
    timeline = []
    for event in related_events[:10]:
        timeline.append({
            'timestamp': event.get('timestamp'),
            'type': 'Authentication',
            'details': f"Username: {event.get('username')}, Status: {event.get('status')}"
        })
    
    return jsonify({
        'alert': alert,
        'related_events': related_events,
        'similar_alerts': similar_alerts,
        'timeline': timeline
    })

@app.route('/api/logs/clear', methods=['POST'])
def api_clear_logs():
    """Clear all logs"""
    data = request.json
    log_type = data.get('type')
    
    if log_type == 'system':
        save_json_file(TELEMETRY_FILE, [])
    elif log_type == 'network':
        save_json_file(NETWORK_FILE, [])
    elif log_type == 'auth':
        save_json_file(AUTH_FILE, [])
    
    return jsonify({'success': True})

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)