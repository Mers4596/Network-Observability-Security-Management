import sqlite3
import os
import threading
import time
import random
import collections
import json
from datetime import datetime
from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO, emit
from functools import wraps

app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*")
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH   = os.path.join(BASE_DIR, 'observability.db')

if os.path.exists(DB_PATH):
    if not os.access(DB_PATH, os.W_OK):
        print(f"Warning: {DB_PATH} is not writable. Attempting to fix permissions...")
        try:
            os.chmod(DB_PATH, 0o666)
        except Exception as e:
            print(f"Error changing permissions: {e}")

def get_db_connection():
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    # High-Performance Concurrency Settings
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    conn.execute("PRAGMA foreign_keys=ON;")
    return conn

# Threading sync for DB Initialization
DB_READY = threading.Event()

def init_db():
    print(f"DB INIT: {DB_PATH}")
    conn   = get_db_connection()
    cursor = conn.cursor()

    # ── 1. Core tables (CREATE IF NOT EXISTS) ────────────────────────────────

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS devices (
            id                   TEXT    PRIMARY KEY,
            hostname             TEXT    NOT NULL,
            ip_address           TEXT,
            mac_address          TEXT    UNIQUE,
            mac_vendor           TEXT,
            type                 TEXT,
            os                   TEXT,
            status               TEXT,
            risk_level           INTEGER DEFAULT 0,
            last_seen            TEXT,
            discovery_date       TEXT,
            location             TEXT,
            parent_id            TEXT,
            active_hours_start   TEXT,
            active_hours_end     TEXT,
            unusual_activity_flag BOOLEAN DEFAULT 0,
            uptime_seconds       INTEGER DEFAULT 0,
            firmware_version     TEXT,
            vlan_id              INTEGER,
            open_ports_cached    TEXT,
            first_seen           TEXT,
            deleted_at           TEXT,
            notes                TEXT
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS traffic_logs (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id     TEXT,
            dest_ip       TEXT,
            dest_port     INTEGER,
            bytes_sent    INTEGER DEFAULT 0,
            bytes_recv    INTEGER DEFAULT 0,
            packets_sent  INTEGER DEFAULT 0,
            protocol      TEXT    DEFAULT 'TCP',
            direction     TEXT    DEFAULT 'out',
            flagged       BOOLEAN DEFAULT 0,
            timestamp     TEXT,
            FOREIGN KEY (device_id) REFERENCES devices(id)
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS vulnerability_reports (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id     TEXT,
            finding_type  TEXT,
            severity      TEXT,
            description   TEXT,
            timestamp     TEXT,
            FOREIGN KEY (device_id) REFERENCES devices(id)
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS network_health_history (
            id                    INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp_minute      TEXT    UNIQUE,
            total_bytes_out       INTEGER DEFAULT 0,
            total_bytes_in        INTEGER DEFAULT 0,
            active_devices_count  INTEGER DEFAULT 0,
            critical_alerts_count INTEGER DEFAULT 0,
            avg_risk_level        INTEGER DEFAULT 0
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS security_alerts (
            id               INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id        TEXT,
            type             TEXT,
            severity         TEXT,
            message          TEXT,
            timestamp        TEXT,
            status           TEXT    DEFAULT 'new',
            cve_id           TEXT,
            attack_vector    TEXT,
            source_ip        TEXT,
            dest_port        INTEGER,
            acknowledged_at  TEXT,
            acknowledged_by  TEXT,
            resolved_at      TEXT,
            false_positive   BOOLEAN DEFAULT 0,
            FOREIGN KEY (device_id) REFERENCES devices(id)
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS safe_zones (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_range    TEXT,
            description TEXT,
            zone_type   TEXT    DEFAULT 'internal',
            vlan_tag    INTEGER,
            created_by  TEXT    DEFAULT 'system'
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS security_scans (
            id                   INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id            TEXT,
            scan_date            TEXT,
            open_ports           TEXT,
            vulnerabilities_found TEXT,
            risk_level_detected  INTEGER,
            triggered_by         TEXT    DEFAULT 'auto',
            operator             TEXT,
            scan_duration_ms     INTEGER,
            status               TEXT    DEFAULT 'complete',
            cve_ids_found        TEXT,
            FOREIGN KEY (device_id) REFERENCES devices(id)
        )
    ''')

    # ── 2. New tables ─────────────────────────────────────────────────────────

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS topology_links (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            source_id  TEXT    NOT NULL,
            target_id  TEXT    NOT NULL,
            link_type  TEXT    DEFAULT 'ethernet',
            bandwidth  TEXT,
            latency_ms INTEGER,
            status     TEXT    DEFAULT 'up',
            created_at TEXT    DEFAULT (datetime(\'now\')),
            FOREIGN KEY (source_id) REFERENCES devices(id),
            FOREIGN KEY (target_id) REFERENCES devices(id),
            UNIQUE(source_id, target_id)
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS user_action_logs (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            operator    TEXT    NOT NULL DEFAULT \'system\',
            action      TEXT    NOT NULL,
            target_type TEXT    NOT NULL,
            target_id   TEXT    NOT NULL,
            detail      TEXT,
            ip_address  TEXT,
            timestamp   TEXT    DEFAULT (datetime(\'now\'))
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS device_uptime_log (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id    TEXT    NOT NULL,
            event        TEXT    NOT NULL,
            timestamp    TEXT    NOT NULL,
            duration_s   INTEGER,
            triggered_by TEXT    DEFAULT \'auto\',
            FOREIGN KEY (device_id) REFERENCES devices(id)
        )
    ''')
    cursor.execute(
        'CREATE INDEX IF NOT EXISTS idx_uptime_device ON device_uptime_log(device_id)'
    )

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS traffic_stats_hourly (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            hour_bucket     TEXT    NOT NULL,
            total_bytes_out INTEGER DEFAULT 0,
            total_bytes_in  INTEGER DEFAULT 0,
            peak_mbps       REAL    DEFAULT 0,
            alert_count     INTEGER DEFAULT 0,
            top_talker_id   TEXT,
            FOREIGN KEY (top_talker_id) REFERENCES devices(id)
        )
    ''')
    cursor.execute(
        'CREATE INDEX IF NOT EXISTS idx_stats_hour ON traffic_stats_hourly(hour_bucket)'
    )
    
    # ── Time-Series Indexing ────────────────────────────────────────────────
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_traffic_timestamp ON traffic_logs(timestamp)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON security_alerts(timestamp)')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS access_rules (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            title       TEXT    NOT NULL,
            action      TEXT    NOT NULL CHECK(action IN (\'allow\',\'deny\')),
            source_cidr TEXT,
            dest_cidr   TEXT,
            dest_port   TEXT,
            protocol    TEXT    DEFAULT \'TCP\',
            priority    INTEGER NOT NULL DEFAULT 99,
            enabled     BOOLEAN DEFAULT 1,
            created_by  TEXT    DEFAULT \'system\',
            created_at  TEXT    DEFAULT (datetime(\'now\')),
            updated_at  TEXT    DEFAULT (datetime(\'now\'))
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS alert_severity_history (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id   TEXT    NOT NULL,
            risk_level  INTEGER NOT NULL,
            recorded_at TEXT    DEFAULT (datetime(\'now\')),
            FOREIGN KEY (device_id) REFERENCES devices(id)
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS settings (
            key   TEXT PRIMARY KEY,
            value TEXT
        )
    ''')

    # ── 3. Seed initial data (only if tables are empty) ───────────────────────

    cursor.execute('SELECT COUNT(*) FROM devices')
    if cursor.fetchone()[0] == 0:
        print("Seeding database with mock devices...")
        mock_devices = [
            ('dev-001', 'CORE-RT-01',    '192.168.1.1',   '00:11:22:33:44:55', 'Cisco',    'network', 'IOS-XE',      'online',  15, '2024-03-07 10:00', '2024-01-01', 'Server Room',   None,      '00:00', '23:59', 0),
            ('dev-002', 'WEB-SRV-01',   '192.168.1.10',  '00:1A:2B:3C:4D:5E', 'Dell',     'server',  'Ubuntu 22.04','online',  10, '2024-03-07 10:10', '2024-01-15', 'Server Room',   'dev-001', '00:00', '23:59', 0),
            ('dev-003', 'PC-ADMIN-01',  '192.168.1.120', 'AA:BB:CC:DD:EE:01', 'HP',       'pc',      'Windows 11',  'online',   5, '2024-03-07 10:15', '2024-02-01', 'Office 101',    'dev-001', '08:00', '18:00', 0),
            ('dev-004', 'SEC-CAM-01',   '192.168.1.200', '11:22:33:44:55:66', 'Hikvision','iot',     'Embedded',    'warning', 85, '2024-03-07 09:30', '2024-01-20', 'Main Entrance', 'dev-001', '00:00', '23:59', 1),
            ('dev-005', 'SMART-HUB-01', '192.168.1.50',  '55:44:33:22:11:00', 'Samsung',  'iot',     'Embedded',    'online',  30, '2024-03-07 11:00', '2024-02-10', 'Lobby',         'dev-001', '00:00', '23:59', 0),
        ]
        cursor.executemany('''
            INSERT INTO devices
                (id, hostname, ip_address, mac_address, mac_vendor, type, os, status,
                 risk_level, last_seen, discovery_date, location, parent_id,
                 active_hours_start, active_hours_end, unusual_activity_flag)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        ''', mock_devices)

    cursor.execute('SELECT COUNT(*) FROM safe_zones')
    if cursor.fetchone()[0] == 0:
        cursor.execute(
            "INSERT INTO safe_zones (ip_range, description) VALUES (?, ?)",
            ('192.168.1.0/24', 'Internal Management Network')
        )
        cursor.execute(
            "INSERT INTO safe_zones (ip_range, description) VALUES (?, ?)",
            ('10.0.0.0/8', 'Cloud VPC Bridge')
        )

    cursor.execute('SELECT COUNT(*) FROM access_rules')
    if cursor.fetchone()[0] == 0:
        print("Seeding access rules...")
        mock_rules = [
            ('Accounting Dept',  'allow', '192.168.10.0/24', None,         '443',    'TCP', 1, 1, 'system'),
            ('IT Administrators', 'allow', '192.168.5.0/24',  None,         '22,3389','TCP', 2, 1, 'system'),
            ('Interns',          'deny',  '192.168.20.0/24', '0.0.0.0/0',  None,     'ANY', 3, 1, 'system'),
            ('File Server',      'allow', None,               '10.0.1.10',  '445',    'TCP', 4, 1, 'system'),
            ('Mail Server',      'allow', None,               '10.0.1.11',  '25,587', 'TCP', 5, 1, 'system'),
        ]
        cursor.executemany('''
            INSERT INTO access_rules (title, action, source_cidr, dest_cidr, dest_port, protocol, priority, enabled, created_by)
            VALUES (?,?,?,?,?,?,?,?,?)
        ''', mock_rules)

    cursor.execute('SELECT COUNT(*) FROM settings')
    if cursor.fetchone()[0] == 0:
        cursor.execute("INSERT INTO settings (key, value) VALUES (?, ?)", ('guest_wifi_enabled', '0'))
        cursor.execute("INSERT INTO settings (key, value) VALUES (?, ?)", ('access_schedule', '[]'))

    conn.commit()
    conn.close()

    DB_READY.set()
    print("Database Initialized / Verified. Lock released.")

def audit_logger(action_type, target_type):
    """Decorator to automatically log admin actions."""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Validation for mutation methods
            if request.method in ['POST', 'PATCH', 'PUT']:
                if request.content_length and request.content_length > 0 and not request.is_json:
                    return jsonify({"error": "JSON payload required"}), 400
            
            response = f(*args, **kwargs)
            
            # Log only if successful
            status_code = response[1] if isinstance(response, tuple) else (response.status_code if hasattr(response, 'status_code') else 200)
            if 200 <= status_code < 300:
                t_id = next(iter(kwargs.values())) if kwargs else 'global'
                detail = json.dumps(request.json) if (request.is_json and request.method != 'GET') else None
                log_user_action(
                    action=action_type,
                    target_type=target_type,
                    target_id=str(t_id),
                    detail=detail,
                    operator='Admin'
                )
            return response
        return decorated_function
    return decorator

from flask import has_request_context

def log_user_action(action, target_type, target_id, detail=None, operator='system'):
    """Write every operator write-action to the audit trail."""
    remote_ip = request.remote_addr if has_request_context() else 'internal'
    
    max_retries = 3
    for attempt in range(max_retries):
        try:
            conn = get_db_connection()
            conn.execute(
                '''
                INSERT INTO user_action_logs (operator, action, target_type, target_id, detail, ip_address)
                VALUES (?, ?, ?, ?, ?, ?)
                ''',
                (operator, action, target_type, target_id, detail, remote_ip)
            )
            conn.commit()
            conn.close()
            break
        except Exception as e:
            if attempt < max_retries - 1:
                time.sleep(0.5)
            else:
                # Audit logging must never crash the main request
                print(f"[AUDIT LOG ERROR] Failed after retries: {e}")


def reset_device_status(device_id):
    """Timer callback to revert device status after auto-scan and log results."""
    try:
        conn = get_db_connection()
        # 1. Revert status
        conn.execute("UPDATE devices SET status = 'online' WHERE id = ?", (device_id,))
        
        # 2. Log dummy scan results
        scan_date = datetime.now().strftime('%Y-%m-%d %H:%M')
        open_ports = random.choice(["80, 443, 22", "80, 445, 139", "53, 3000, 8080", "443, 8443"])
        vulns = random.choice(["None detected", "Minor CVE-2023-1234 (Patch available)", "Outdated TLS Version", "SSH Password Auth Enabled"])
        risk = random.randint(10, 60)
        
        conn.execute('''
            INSERT INTO security_scans (device_id, scan_date, open_ports, vulnerabilities_found, risk_level_detected)
            VALUES (?, ?, ?, ?, ?)
        ''', (device_id, scan_date, open_ports, vulns, risk))
        
        conn.commit()
        conn.close()
        print(f"Auto-Scan completed for {device_id}. Results logged and reverted to online.")
    except Exception as e:
        print(f"Error in scan completion logic: {e}")

# ── Global In-Memory Buffer Layer ───────────────────────────────────────────
TRAFFIC_BUFFER = collections.deque()
TRAFFIC_LOCK = threading.Lock()
MEMORY_ALERTS = [] # Cache for low-risk alerts

def flush_traffic_buffer():
    """Background worker to perform batch inserts every 30 records or every 5 seconds."""
    DB_READY.wait()
    last_flush = time.time()
    while True:
        try:
            batch = []
            now = time.time()
            with TRAFFIC_LOCK:
                # Flush if buffer hits 30 records OR if it's been 5 seconds and there's SOMETHING to flush
                if len(TRAFFIC_BUFFER) >= 30 or (len(TRAFFIC_BUFFER) > 0 and (now - last_flush) >= 5):
                    # Take up to 100 at a time to keep DB transactions reasonable
                    while TRAFFIC_BUFFER and len(batch) < 100:
                        batch.append(TRAFFIC_BUFFER.popleft())
                    last_flush = now
            
            if batch:
                max_retries = 3
                success = False
                for attempt in range(max_retries):
                    try:
                        conn = get_db_connection()
                        conn.executemany('''
                            INSERT INTO traffic_logs (device_id, dest_ip, dest_port, bytes_sent, bytes_recv, protocol, flagged, timestamp)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                        ''', batch)
                        conn.commit()
                        conn.close()
                        print(f"[PIPELINE] Flushed {len(batch)} records to DB on attempt {attempt+1}.")
                        success = True
                        break
                    except Exception as e:
                        print(f"[FLUSHER Retry {attempt+1}] {e}")
                        time.sleep(1)
                
                if not success:
                    print(f"[FLUSHER CRITICAL] Dropped {len(batch)} logs due to persistent DB locks.")
            
            time.sleep(1) # Faster check to reduce latency
        except Exception as e:
            print(f"[FLUSHER ERROR] {e}")
            time.sleep(5)

def simulate_traffic():
    """Refactored Simulator: Buffers logs and uses Adaptive Logging."""
    DB_READY.wait()
    print("Traffic Simulator & Security Engine started (Buffered Mode)...")
    while True:
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            
            cursor.execute("SELECT id, hostname FROM devices WHERE status NOT IN ('offline', 'Under Scan', 'Isolated')")
            devices = cursor.fetchall()
            conn.close() # Close connection as we only read once
            
            if devices:
                device = random.choice(devices)
                source_id = device['id']
                hostname = device['hostname']
                dest_ip = f"192.168.{random.randint(1, 255)}.{random.randint(1, 255)}"
                
                roll = random.random()
                protocol = random.choice(['TCP', 'UDP', 'ICMP'])
                flagged = 0
                
                if roll < 0.05: # Suspicious SMB
                    dest_port = 445
                    bytes_sent = random.randint(1000, 5000)
                    bytes_recv = random.randint(100, 500)
                    flagged = 1
                elif roll < 0.10: # Exfiltration
                    dest_port = 443
                    bytes_sent = random.randint(60000, 100000)
                    bytes_recv = random.randint(1000, 5000)
                else:
                    dest_port = random.choice([80, 443, 8080, 22, 53, 3000])
                    bytes_sent = random.randint(500000, 2000000)
                    bytes_recv = random.randint(100000, 500000)

                timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                
                # 1. Pipeline: Push to Buffer
                with TRAFFIC_LOCK:
                    TRAFFIC_BUFFER.append((source_id, dest_ip, dest_port, bytes_sent, bytes_recv, protocol, flagged, timestamp))
                
                # 2. Heuristic Check (Adaptive Logging)
                if dest_port == 445 or bytes_sent > 50000:
                    alert_type = "Potential Exploit" if dest_port == 445 else "Exfiltration Detected"
                    severity = "critical" if dest_port == 445 else "warning"
                    message = f"Suspicious activity on {hostname} (Port {dest_port}, {bytes_sent} bytes)."
                    
                    # High-Risk: SQL Persistent
                    conn = get_db_connection()
                    conn.execute('''
                        INSERT INTO security_alerts (device_id, type, severity, message, timestamp)
                        VALUES (?, ?, ?, ?, ?)
                    ''', (source_id, alert_type, severity, message, timestamp))
                    alert_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
                    
                    # Real-time WebSocket Emission
                    socketio.emit('new_critical_alert', {
                        "id": alert_id,
                        "device_id": source_id,
                        "type": alert_type,
                        "severity": severity,
                        "message": message,
                        "timestamp": timestamp,
                        "status": "new"
                    })

                    # Risk Analytics Persistence
                    risk_val = 100 if severity == "critical" else (70 if severity == "warning" else 30)
                    conn.execute('''
                        INSERT INTO alert_severity_history (device_id, risk_level, recorded_at)
                        VALUES (?, ?, ?)
                    ''', (source_id, risk_val, timestamp))
                    
                    conn.commit()
                    conn.close()
                else:
                    # Low-Risk: In-Memory Only
                    MEMORY_ALERTS.append({
                        "id": "mem-" + str(random.randint(1000, 9999)),
                        "device_id": source_id,
                        "type": "Noise Filtered",
                        "severity": "info",
                        "message": "Routine background traffic log.",
                        "timestamp": timestamp
                    })
                    if len(MEMORY_ALERTS) > 50: MEMORY_ALERTS.pop(0)

        except Exception as e:
            print(f"Simulator Error: {e}")
            
        time.sleep(1) # Faster simulation, buffer handles it

from datetime import timedelta

def summarize_network_health():
    """Background worker to aggregate traffic & alerts into minute-by-minute history."""
    DB_READY.wait()
    last_summarized_minute = None
    while True:
        try:
            now_minute = datetime.now().strftime('%Y-%m-%d %H:%M')
            if last_summarized_minute != now_minute:
                conn = get_db_connection()
                prev_minute_dt = datetime.now() - timedelta(minutes=1)
                prev_minute_str = prev_minute_dt.strftime('%Y-%m-%d %H:%M')
                
                existing = conn.execute('SELECT id FROM network_health_history WHERE timestamp_minute = ?', (prev_minute_str,)).fetchone()
                if not existing:
                    stats = conn.execute('''
                        SELECT 
                            COALESCE(SUM(bytes_sent), 0) as out_bytes,
                            COALESCE(SUM(bytes_recv), 0) as in_bytes
                        FROM traffic_logs 
                        WHERE timestamp LIKE ?
                    ''', (f'{prev_minute_str}%',)).fetchone()
                    
                    active_devices = conn.execute("SELECT COUNT(*) FROM devices WHERE status = 'online'").fetchone()[0]
                    critical_alerts = conn.execute("SELECT COUNT(*) FROM security_alerts WHERE severity = 'critical' AND (resolved_at IS NULL OR resolved_at = '')").fetchone()[0]
                    avg_risk = conn.execute("SELECT AVG(risk_level) FROM devices WHERE status = 'online'").fetchone()[0]
                    avg_risk = int(avg_risk) if avg_risk else 0
                    
                    conn.execute('''
                        INSERT INTO network_health_history 
                        (timestamp_minute, total_bytes_out, total_bytes_in, active_devices_count, critical_alerts_count, avg_risk_level)
                        VALUES (?, ?, ?, ?, ?, ?)
                    ''', (prev_minute_str, stats['out_bytes'], stats['in_bytes'], active_devices, critical_alerts, avg_risk))
                    conn.commit()
                conn.close()
                last_summarized_minute = now_minute
            time.sleep(10)
        except Exception as e:
            print(f"[HEALTH SUMMARIZER ERROR] {e}")
            time.sleep(10)

# Start background pipeline workers
threading.Thread(target=summarize_network_health, daemon=True, name="Health-Summarizer").start()
threading.Thread(target=flush_traffic_buffer, daemon=True, name="DB-Flusher").start()
sim_thread = threading.Thread(target=simulate_traffic, daemon=True, name="Traffic-Sim")
sim_thread.start()

@app.route('/')
@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')

@app.route('/topology')
def topology():
    return render_template('topology.html')

@app.route('/assets')
def assets():
    return render_template('assets.html')

@app.route('/traffic')
def traffic():
    return render_template('traffic.html')

@app.route('/securityAudit')
def securityAudit():
    return render_template('securityAudit.html')

@app.route('/accessControl')
def accessControl():
    return render_template('accessControl.html')

@app.route('/alerts')
def alerts():
    return render_template('alerts.html')

@app.route('/settings')
def settings():
    return render_template('settings.html')

# --- API Endpoints ---

@app.route('/api/devices', methods=['GET'])
def get_devices():
    try:
        conn = get_db_connection()
        # Ensure uptime_seconds is included (it's in the devices table)
        devices = conn.execute('SELECT * FROM devices').fetchall()
        conn.close()
        return jsonify([dict(row) for row in devices])
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/devices/approve/<string:device_id>', methods=['POST'])
@audit_logger('APPROVE', 'DEVICE')
def approve_device(device_id):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE devices SET status = 'online' WHERE id = ?",
            (device_id,)
        )
        if cursor.rowcount == 0:
            conn.close()
            return jsonify({"error": "Device not found"}), 404
        conn.commit()
        conn.close()
        return jsonify({"success": True, "message": f"Device {device_id} approved",
                        "new_status": "online"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/devices/isolate/<string:device_id>', methods=['POST'])
@audit_logger('ISOLATE', 'DEVICE')
def isolate_device(device_id):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Read current status before changing it
        row = cursor.execute(
            'SELECT status, risk_level FROM devices WHERE id = ?', (device_id,)
        ).fetchone()
        if not row:
            conn.close()
            return jsonify({"error": "Device not found"}), 404

        prev_status = row['status']
        prev_risk   = row['risk_level']

        cursor.execute(
            "UPDATE devices SET status = 'Isolated', risk_level = 100 WHERE id = ?",
            (device_id,)
        )

        # Uptime event
        cursor.execute('''
            INSERT INTO device_uptime_log (device_id, event, timestamp, triggered_by)
            VALUES (?, 'Isolated', datetime('now'), 'operator')
        ''', (device_id,))

        conn.commit()
        conn.close()

        return jsonify({
            "success": True,
            "message": f"Device {device_id} isolated from network. Action logged.",
            "new_status": "Isolated"
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/devices/scan/<string:device_id>', methods=['POST'])
@audit_logger('MANUAL_SCAN', 'DEVICE')
def manual_scan(device_id):
    """
    Starts a manual scan:
      1. Immediately sets status='Under Scan' and creates a scan row (status='running')
      2. Returns the scan_id so the UI can poll for completion if desired
      3. A background thread sleeps 3s, then completes the scan with mock CVE IDs
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Verify device exists
        row = cursor.execute('SELECT id FROM devices WHERE id = ?', (device_id,)).fetchone()
        if not row:
            conn.close()
            return jsonify({"error": "Device not found"}), 404

        # 1. Stamp device as 'Under Scan'
        scan_start = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        cursor.execute("UPDATE devices SET status = 'Under Scan' WHERE id = ?", (device_id,))

        # 2. Insert a scan row with status='running'
        cursor.execute('''
            INSERT INTO security_scans
                (device_id, scan_date, open_ports, vulnerabilities_found,
                 risk_level_detected, triggered_by, status)
            VALUES (?, ?, '', 'Scan in progress...', 0, 'manual', 'running')
        ''', (device_id, scan_start))
        scan_id = cursor.lastrowid

        conn.commit()
        conn.close()

        # 3. Background thread: complete the scan after 3 seconds
        def _complete_scan(sid, did):
            import time, json
            time.sleep(3)

            is_clear   = random.random() < 0.5
            open_ports = '22, 80, 443'
            scan_end   = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

            try:
                c = get_db_connection()
                
                if is_clear:
                    vulns    = 'Threat Neutralized: All patches applied'
                    cve_ids  = json.dumps([])
                else:
                    vulns    = 'Critical: Exploit payload detected in /tmp'
                    cve_ids  = json.dumps([
                        f'CVE-2024-{random.randint(1000, 9999)}',
                        f'CVE-2023-{random.randint(1000, 9999)}'
                    ])
                    # Physically insert into intelligence table
                    c.execute('''
                        INSERT INTO vulnerability_reports (device_id, finding_type, severity, description, timestamp)
                        VALUES (?, ?, ?, ?, ?)
                    ''', (did, 'Active Exploit', 'critical', vulns, scan_end))
                
                # Dynamic Risk Computation based on vulnerabilities
                vuln_rows = c.execute("SELECT severity FROM vulnerability_reports WHERE device_id = ?", (did,)).fetchall()
                extracted_risk = 0
                for vr in vuln_rows:
                    if vr['severity'] == 'critical': extracted_risk = max(extracted_risk, 95)
                    elif vr['severity'] == 'warning': extracted_risk = max(extracted_risk, 70)
                    elif vr['severity'] == 'info': extracted_risk = max(extracted_risk, 30)

                risk = extracted_risk if not is_clear and extracted_risk > 0 else 0

                duration_ms = 3000 + random.randint(0, 500)
                c.execute('''
                    UPDATE security_scans
                    SET open_ports=?, vulnerabilities_found=?, risk_level_detected=?,
                        cve_ids_found=?, status='complete', scan_duration_ms=?
                    WHERE id=?
                ''', (open_ports, vulns, risk, cve_ids, duration_ms, sid))
                
                c.execute(
                    'UPDATE devices SET risk_level=?, status=? WHERE id=?',
                    (risk, 'online' if is_clear else 'warning', did)
                )

                c.commit()
                c.close()
                log_user_action('scan_complete', 'device', did,
                                detail=json.dumps({'scan_id': sid, 'risk': risk,
                                                   'clear': is_clear}))
            except Exception as ex:
                print(f'[SCAN THREAD ERROR] {ex}')

        t = threading.Thread(target=_complete_scan, args=(scan_id, device_id), name=f"ScanThread-{device_id}", daemon=True)
        t.start()

        return jsonify({
            "success":  True,
            "message":  "Manual scan initiated. Results available in ~3 seconds.",
            "scan_id":  scan_id,
            "status":   "running"
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/devices/restore/<string:device_id>', methods=['POST'])
@audit_logger('RESTORE', 'DEVICE')
def restore_device(device_id):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # 1. Security gate: last scan must be clean
        last_scan = cursor.execute('''
            SELECT vulnerabilities_found, risk_level_detected
            FROM security_scans
            WHERE device_id = ? AND status = 'complete'
            ORDER BY id DESC LIMIT 1
        ''', (device_id,)).fetchone()

        if not last_scan or 'Threat Neutralized' not in last_scan['vulnerabilities_found']:
            conn.close()
            return jsonify({
                "error": "Restoration denied: Device still hazardous. "
                         "Run a successful manual scan first."
            }), 403

        safe_risk = last_scan['risk_level_detected'] or 10

        # 2. Restore status + reset risk from last clean scan
        cursor.execute(
            "UPDATE devices SET status = 'online', risk_level = ? WHERE id = ?",
            (safe_risk, device_id)
        )

        # 3. Uptime event
        cursor.execute('''
            INSERT INTO device_uptime_log (device_id, event, timestamp, triggered_by)
            VALUES (?, 'online', datetime('now'), 'operator')
        ''', (device_id,))

        conn.commit()
        conn.close()

        return jsonify({
            "success":    True,
            "message":    f"Device {device_id} restored to pool.",
            "new_status": "online",
            "risk_level": safe_risk
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/audit-logs', methods=['GET'])
def get_audit_logs():
    """Returns the last 50 operator actions for the Audit Trail UI panel."""
    try:
        conn = get_db_connection()
        rows = conn.execute('''
            SELECT id, operator, action, target_type, target_id, detail,
                   ip_address, timestamp
            FROM user_action_logs
            ORDER BY id DESC
            LIMIT 50
        ''').fetchall()
        conn.close()
        return jsonify([dict(r) for r in rows])
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/traffic', methods=['GET'])
def get_traffic():
    try:
        conn = get_db_connection()
        logs = conn.execute('''
            SELECT t.*, d.hostname 
            FROM traffic_logs t
            JOIN devices d ON t.device_id = d.id
            ORDER BY t.id DESC LIMIT 20
        ''').fetchall()
        conn.close()
        return jsonify([dict(row) for row in logs])
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/traffic/stats', methods=['GET'])
def get_traffic_stats():
    """Returns real-time aggregates for traffic KPIs."""
    try:
        conn = get_db_connection()
        # total_download_gbps (simulated from bytes_sent in last 5 mins)
        # total_upload_mbps (simulated from bytes_recv in last 5 mins)
        res = conn.execute('''
            SELECT 
                COALESCE(SUM(bytes_sent), 0) as total_sent,
                COALESCE(SUM(bytes_recv), 0) as total_recv,
                COUNT(id) as active_conns,
                MAX(bytes_sent + bytes_recv) as peak_val
            FROM traffic_logs 
            WHERE timestamp >= datetime('now', 'localtime', '-5 minutes')
        ''').fetchone()
        
        # Protocol distribution for Sankey/Donut
        proto = conn.execute('''
            SELECT protocol, COUNT(*) as count 
            FROM traffic_logs 
            WHERE timestamp >= datetime('now', 'localtime', '-30 minutes')
            GROUP BY protocol
        ''').fetchall()
        
        # Destination nodes for Sankey (top 3)
        nodes = conn.execute('''
            SELECT dest_ip, SUM(bytes_sent) as volume 
            FROM traffic_logs 
            WHERE timestamp >= datetime('now', 'localtime', '-30 minutes')
            GROUP BY dest_ip ORDER BY volume DESC LIMIT 3
        ''').fetchall()

        conn.close()

        # Convert to units
        dl_gbps = round((res['total_sent'] * 8) / (5 * 60 * 1e9), 2)
        ul_mbps = round((res['total_recv'] * 8) / (5 * 60 * 1e6), 1)

        return jsonify({
            "download_rate": f"{dl_gbps} Gbps",
            "upload_rate": f"{ul_mbps} Mbps",
            "active_connections_count": res['active_conns'],
            "peak_traffic_value": f"{round(res['peak_val'] / 1e6, 2)} Mbps" if res['peak_val'] else "0 Mbps",
            "protocol_dist": {row['protocol']: row['count'] for row in proto},
            "top_destinations": [dict(n) for n in nodes]
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/traffic/heatmap', methods=['GET'])
def get_traffic_heatmap():
    """Returns traffic density grouped by hour (00-23) for the heatmap."""
    try:
        conn = get_db_connection()
        # Query density by hour from the last 24 hours of traffic
        rows = conn.execute('''
            SELECT 
                strftime('%H', timestamp) as hour,
                COUNT(*) as count
            FROM traffic_logs
            WHERE timestamp >= datetime('now', '-24 hours')
            GROUP BY hour
        ''').fetchall()
        conn.close()
        
        # Max count for normalization in frontend
        data = [dict(r) for r in rows]
        max_count = max([d['count'] for d in data]) if data else 1
        for d in data:
            d['intensity'] = round(d['count'] / max_count, 2)

        return jsonify(data)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/rules', methods=['GET', 'POST'])
@audit_logger('MANAGE_RULES', 'FIREWALL')
def manage_rules():
    try:
        conn = get_db_connection()
        if request.method == 'POST':
            data = request.json
            conn.execute('''
                INSERT INTO access_rules (title, action, source_cidr, dest_cidr, dest_port, protocol, priority)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (data['title'], data['action'], data.get('source_cidr'), 
                  data.get('dest_cidr'), data.get('dest_port'), 
                  data.get('protocol', 'TCP'), data.get('priority', 99)))
            conn.commit()
            conn.close()
            return jsonify({"status": "success"})
        else:
            rules = conn.execute('SELECT * FROM access_rules ORDER BY priority ASC').fetchall()
            conn.close()
            return jsonify([dict(row) for row in rules])
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/rules/<int:rule_id>/toggle', methods=['PATCH'])
@audit_logger('TOGGLE_RULE', 'FIREWALL')
def toggle_rule(rule_id):
    try:
        conn = get_db_connection()
        conn.execute('UPDATE access_rules SET enabled = NOT enabled WHERE id = ?', (rule_id,))
        conn.commit()
        conn.close()
        return jsonify({"status": "success"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/rules/<int:rule_id>', methods=['DELETE'])
@audit_logger('DELETE_RULE', 'FIREWALL')
def delete_rule(rule_id):
    try:
        conn = get_db_connection()
        conn.execute('DELETE FROM access_rules WHERE id = ?', (rule_id,))
        conn.commit()
        conn.close()
        return jsonify({"status": "success"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/rules/<int:rule_id>/schedule', methods=['PATCH'])
def update_rule_schedule(rule_id):
    try:
        data = request.json
        conn = get_db_connection()
        conn.execute('UPDATE access_rules SET schedule = ? WHERE id = ?', (json.dumps(data.get('schedule', [])), rule_id))
        conn.commit()
        conn.close()
        return jsonify({"status": "success"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/settings', methods=['GET', 'POST'])
@audit_logger('UPDATE_SETTINGS', 'SYSTEM')
def handle_settings():
    try:
        conn = get_db_connection()
        if request.method == 'POST':
            data = request.json
            for key, value in data.items():
                conn.execute('INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)', (key, str(value)))
            conn.commit()
            conn.close()
            return jsonify({"status": "success"})
        else:
            rows = conn.execute('SELECT * FROM settings').fetchall()
            conn.close()
            return {row['key']: row['value'] for row in rows}
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/traffic/protocol-dist', methods=['GET'])
def get_protocol_dist():
    try:
        conn = get_db_connection()
        rows = conn.execute('''
            SELECT protocol, COUNT(*) as count 
            FROM traffic_logs 
            GROUP BY protocol
        ''').fetchall()
        conn.close()
        return jsonify({row['protocol']: row['count'] for row in rows})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/alerts', methods=['GET'])
def get_alerts():
    """Returns persistent DB alerts merged with session-based memory alerts."""
    try:
        conn = get_db_connection()
        alerts = conn.execute('''
            SELECT a.*, d.hostname, d.ip_address 
            FROM security_alerts a
            JOIN devices d ON a.device_id = d.id
            ORDER BY a.id DESC LIMIT 30
        ''').fetchall()
        conn.close()
        
        db_alerts = [dict(row) for row in alerts]
        # Merge with memory alerts (low-risk)
        all_alerts = db_alerts + MEMORY_ALERTS
        # Sort by timestamp descending
        all_alerts.sort(key=lambda x: x['timestamp'], reverse=True)
        
        return jsonify(all_alerts[:50])
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/safe-zones', methods=['GET'])
def get_safe_zones():
    try:
        conn = get_db_connection()
        zones = conn.execute('SELECT * FROM safe_zones').fetchall()
        conn.close()
        return jsonify([dict(row) for row in zones])
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/scans', methods=['GET'])
def get_scans():
    try:
        conn = get_db_connection()
        scans = conn.execute('''
            SELECT s.*, d.hostname, d.ip_address 
            FROM security_scans s
            JOIN devices d ON s.device_id = d.id
            ORDER BY s.id DESC LIMIT 30
        ''').fetchall()
        conn.close()
        return jsonify([dict(row) for row in scans])
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/risk-profile', methods=['GET'])
def get_risk_profile():
    try:
        conn = get_db_connection()
        # Rank devices by number of alerts
        profile = conn.execute('''
            SELECT d.hostname, d.ip_address, COUNT(a.id) as alert_count, MAX(a.timestamp) as last_incident
            FROM devices d
            LEFT JOIN security_alerts a ON d.id = a.device_id
            GROUP BY d.id
            ORDER BY alert_count DESC
        ''').fetchall()
        conn.close()
        return jsonify([dict(row) for row in profile])
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ─────────────────────────────────────────────────────────────────────────────
# Dashboard Analytics APIs (Phase 2)
# ─────────────────────────────────────────────────────────────────────────────

@app.route('/api/stats', methods=['GET'])
def get_stats():
    """
    Returns a single-row summary for the Dashboard KPI cards:
      - total_bytes_out / total_bytes_in  (last 60 minutes)
      - download_rate / upload_rate       (formatted Mbps strings)
      - critical_alerts_count             (unresolved critical alerts)
      - network_volatility                (% change vs previous 60-min window)
    """
    try:
        conn = get_db_connection()
        now_str = datetime.now().strftime('%H:%M:%S')

        # Current window: last 5 minutes of traffic
        cur = conn.execute('''
            SELECT
                COALESCE(SUM(bytes_sent), 0)  AS bytes_out,
                COALESCE(SUM(bytes_recv), 0)  AS bytes_in,
                COUNT(*)                       AS pkt_count
            FROM traffic_logs
            WHERE timestamp >= datetime('now', 'localtime', '-5 minutes')
        ''').fetchone()

        # Previous window: 5-10 minutes ago (for volatility and trends)
        prev = conn.execute('''
            SELECT 
                COALESCE(SUM(bytes_sent), 0) AS bytes_out,
                COALESCE(SUM(bytes_recv), 0) AS bytes_in
            FROM traffic_logs
            WHERE timestamp >= datetime('now', 'localtime', '-10 minutes')
              AND timestamp <  datetime('now', 'localtime', '-5 minutes')
        ''').fetchone()

        # Unresolved critical alerts
        critical_count = conn.execute('''
            SELECT COUNT(*) AS cnt FROM security_alerts
            WHERE severity = 'critical' AND (resolved_at IS NULL OR resolved_at = '')
        ''').fetchone()['cnt']

        conn.close()

        bytes_out  = cur['bytes_out']
        bytes_in   = cur['bytes_in']
        prev_bytes_out = prev['bytes_out'] if prev['bytes_out'] else 0
        prev_bytes_in  = prev['bytes_in'] if prev['bytes_in'] else 0

        dl_bps = (bytes_out * 8) / 300
        ul_bps = (bytes_in * 8) / 300
        
        prev_dl_bps = (prev_bytes_out * 8) / 300
        prev_ul_bps = (prev_bytes_in * 8) / 300

        dl_trend = round((dl_bps - prev_dl_bps), 2)
        ul_trend = round((ul_bps - prev_ul_bps), 2)

        # Volatility: percentage change in total traffic current vs previous window
        total_cur = bytes_out + bytes_in
        total_prev = prev_bytes_out + prev_bytes_in
        
        if total_prev > 0:
            volatility = round(((total_cur - total_prev) / total_prev) * 100, 1)
        elif total_cur > 0:
            volatility = 100.0
        else:
            volatility = 0.0

        return jsonify({
            "download_rate":          f"{round(dl_bps/1_000_000, 2)} Mbps",
            "upload_rate":            f"{round(ul_bps/1_000_000, 2)} Mbps",
            "download_bps":           dl_bps,
            "upload_bps":             ul_bps,
            "download_trend":         dl_trend,
            "upload_trend":           ul_trend,
            "total_bytes_out":        bytes_out,
            "total_bytes_in":         bytes_in,
            "critical_alerts_count":  critical_count,
            "network_volatility":     volatility,
            "volatility_label":       f"{'+' if volatility >= 0 else ''}{volatility}% VOLATILITY"
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/traffic-timeline', methods=['GET'])
def get_traffic_timeline():
    """
    Returns 24 hourly buckets for the area chart (last 24 hours).
    Uses strftime('%H:00', timestamp) to group traffic_logs by hour.
    Fills missing hours with zeros so the chart line is always complete.
    """
    try:
        conn = get_db_connection()

        rows = conn.execute('''
            SELECT
                strftime('%H:00', timestamp)   AS hour,
                COALESCE(SUM(bytes_sent), 0)   AS bytes_out,
                COALESCE(SUM(bytes_recv), 0)   AS bytes_in,
                COUNT(*)                        AS packet_count
            FROM traffic_logs
            WHERE timestamp >= time('now', '-24 hours')
            GROUP BY strftime('%H:00', timestamp)
            ORDER BY hour ASC
        ''').fetchall()
        conn.close()

        # Build a zero-filled 24-slot map keyed by "HH:00"
        timeline = {f"{h:02d}:00": {"hour": f"{h:02d}:00", "bytes_out": 0, "bytes_in": 0, "packet_count": 0}
                    for h in range(24)}
        for row in rows:
            if row['hour']:
                timeline[row['hour']] = dict(row)

        # Return as ordered list (00:00 → 23:00)
        return jsonify(list(timeline.values()))
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/top-talkers', methods=['GET'])
def get_top_talkers():
    """
    Returns the top 5 devices by total bytes_sent in the last 60 minutes.
    Includes percentage of total traffic for the progress bar in the UI.
    """
    try:
        conn = get_db_connection()

        rows = conn.execute('''
            SELECT
                d.id,
                d.hostname,
                d.ip_address,
                d.type,
                d.status,
                COALESCE(SUM(t.bytes_sent), 0) AS total_bytes,
                COUNT(t.id)                     AS packet_count
            FROM devices d
            LEFT JOIN traffic_logs t
                ON t.device_id = d.id
               AND t.timestamp >= time('now', '-60 minutes')
            GROUP BY d.id
            ORDER BY total_bytes DESC
            LIMIT 5
        ''').fetchall()

        # Compute percentages relative to max sender
        result = [dict(r) for r in rows]
        max_bytes = result[0]['total_bytes'] if result and result[0]['total_bytes'] > 0 else 1
        total_all = sum(r['total_bytes'] for r in result) or 1

        for r in result:
            r['pct_of_max']   = round(r['total_bytes'] / max_bytes * 100, 1)
            r['pct_of_total'] = round(r['total_bytes'] / total_all * 100, 1)
            # Human-readable bandwidth label
            mb = r['total_bytes'] / 1_000_000
            r['bandwidth_label'] = f"{mb:.1f} MB" if mb >= 1 else f"{r['total_bytes'] // 1000} KB"

        conn.close()
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/ai/context', methods=['GET'])
def get_ai_context():
    """Aggregates full network state for explicitly structured AI ingestion (Narrative JSON)."""
    try:
        conn = get_db_connection()
        
        # 1. Network State (Summary Narrative)
        health_snapshot = conn.execute("SELECT * FROM network_health_history ORDER BY id DESC LIMIT 1").fetchone()
        active_devices = conn.execute("SELECT COUNT(*) FROM devices WHERE status != 'offline'").fetchone()[0]
        isolated_devices = conn.execute("SELECT COUNT(*) FROM devices WHERE status = 'Isolated'").fetchone()[0]
        recent_scans = conn.execute("SELECT COUNT(*) FROM security_scans WHERE timestamp(scan_date) >= datetime('now', '-24 hours')").fetchone()[0]
        
        network_state_summary = {
            "current_time": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            "active_devices": active_devices,
            "isolated_devices": isolated_devices,
            "recent_scans_24h": recent_scans,
            "latest_minute_health": dict(health_snapshot) if health_snapshot else {}
        }
        
        # 2. Top Offenders (High Risk / Critical Alerts)
        offenders = conn.execute('''
            SELECT id, hostname, ip_address, type, risk_level, status
            FROM devices 
            WHERE risk_level > 50 OR status = 'Isolated' OR id IN (SELECT device_id FROM security_alerts WHERE severity = 'critical')
            ORDER BY risk_level DESC 
            LIMIT 5
        ''').fetchall()
        
        # 3. Unresolved Vulnerabilities
        vulns = conn.execute('''
            SELECT v.finding_type, v.severity, v.description, v.timestamp, d.hostname, d.ip_address
            FROM vulnerability_reports v
            JOIN devices d ON v.device_id = d.id
            ORDER BY v.id DESC LIMIT 20
        ''').fetchall()
        
        conn.close()
        
        return jsonify({
            "network_state": network_state_summary,
            "top_offenders": [dict(o) for o in offenders],
            "unresolved_vulnerabilities": [dict(v) for v in vulns]
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/analytics/risk-history', methods=['GET'])
def get_risk_history():
    """
    Returns aggregated Hourly Risk Counts for the last 24 hours.
    Categories: Critical, High (Warning), Medium (Info).
    """
    try:
        conn = get_db_connection()
        # We query security_alerts for specific severity levels over time
        rows = conn.execute('''
            SELECT 
                strftime('%H:00', timestamp) AS hour,
                SUM(CASE WHEN severity = 'critical' THEN 1 ELSE 0 END) AS critical_count,
                SUM(CASE WHEN severity = 'warning' THEN 1 ELSE 0 END) AS high_count,
                SUM(CASE WHEN severity = 'info' THEN 1 ELSE 0 END) AS medium_count
            FROM security_alerts
            WHERE timestamp >= datetime('now', '-24 hours')
            GROUP BY hour
            ORDER BY hour ASC
        ''').fetchall()
        conn.close()

        # Build zero-filled timeline
        # Since 'now' varies, we'll generate the last 24 slots relative to the current hour
        current_hour = datetime.now().hour
        history = []
        for i in range(24):
            h = (current_hour - 23 + i) % 24
            hour_str = f"{h:02d}:00"
            match = next((dict(r) for r in rows if r['hour'] == hour_str), None)
            if match:
                history.append(match)
            else:
                history.append({
                    "hour": hour_str,
                    "critical_count": 0,
                    "high_count": 0,
                    "medium_count": 0
                })

        return jsonify(history)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/topology', methods=['GET'])
def get_topology():
    """Returns the static topology links."""
    try:
        conn = get_db_connection()
        links = conn.execute('SELECT * FROM topology_links').fetchall()
        conn.close()
        return jsonify([dict(row) for row in links])
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Removed external sim_thread start as it's now handled inside the logger system initialization

# Initialize DB on startup
init_db()

if __name__ == '__main__':
    socketio.run(app, debug=True, port=5000)
