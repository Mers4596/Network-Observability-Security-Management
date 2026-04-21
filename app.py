import sqlite3
import os
import threading
import time
import random
import collections
import json
import shutil
from datetime import datetime
from flask import Flask, render_template, jsonify, request, session, redirect, url_for
from flask_socketio import SocketIO, emit
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash

# ── Database Configuration ───────────────────────────────────────────────────
app = Flask(__name__)
app.secret_key = 'nebulanet_secure_session_key_2026'
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
socketio = SocketIO(app, cors_allowed_origins="*")
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH   = os.path.join(BASE_DIR, 'observability_v2.db')

# ── Startup: clean stale WAL/SHM files that cause "readonly database" on Windows
def _clean_stale_wal():
    """Remove leftover WAL auxiliary files that Windows’ file system sometimes holds
    as read-only after an unclean shutdown or debug-reloader restart."""
    for suffix in ('-wal', '-shm'):
        aux = DB_PATH + suffix
        if os.path.exists(aux):
            try:
                # Try a proper WAL checkpoint first (collapses WAL into the main DB)
                tmp = sqlite3.connect(DB_PATH, timeout=5)
                tmp.execute('PRAGMA wal_checkpoint(TRUNCATE)')
                tmp.close()
                # If the WAL file is now empty, it’s safe to remove
                if os.path.getsize(aux) == 0:
                    os.remove(aux)
                    print(f"[DB] Removed stale {suffix} file.")
            except Exception as e:
                print(f"[DB] WAL cleanup warning ({suffix}): {e}")

    # Ensure the main DB file is writable
    if os.path.exists(DB_PATH) and not os.access(DB_PATH, os.W_OK):
        try:
            os.chmod(DB_PATH, 0o666)
            print(f"[DB] Fixed read-only permission on {DB_PATH}")
        except Exception as e:
            print(f"[DB] Permission fix failed: {e}")

_clean_stale_wal()


def _wal_checkpoint_recovery():
    """Emergency recovery: force a WAL checkpoint to clear any stale locks."""
    try:
        tmp = sqlite3.connect(DB_PATH, timeout=10, check_same_thread=False)
        tmp.execute('PRAGMA wal_checkpoint(RESTART)')
        tmp.close()
        print("[DB] WAL checkpoint RESTART completed (recovery).")
        return True
    except Exception as e:
        print(f"[DB] WAL checkpoint recovery failed: {e}")
        return False


def get_db_connection():
    """Return a connection with WAL mode and sensible concurrency settings.
    On the first 'readonly' error the caller should invoke _wal_checkpoint_recovery().
    """
    conn = sqlite3.connect(
        DB_PATH,
        timeout=60,                 # Give WAL writers up to 60 s to finish
        check_same_thread=False,    # Allow use from background threads
        isolation_level=None        # Autocommit at driver level; we call conn.commit() manually
    )
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    conn.execute("PRAGMA foreign_keys=ON;")
    conn.execute("PRAGMA busy_timeout=30000;")  # 30 s busy-wait instead of immediate error
    conn.isolation_level = ''        # Re-enable manual transactions after PRAGMA
    return conn

# Threading sync for DB Initialization
DB_READY = threading.Event()

def init_db():
    print(f"DB INIT: {DB_PATH}")
    conn   = get_db_connection()
    cursor = conn.cursor()

    mock_devices = [
        # ID, Hostname, IP, MAC, Status, Type, Risk, Department, OS/Kernel, Location, Last Seen, Discovery, ParentID, ShadowRisk
        ('dev-001', 'CORE-RT-100',  '10.0.0.1',   '00:11:22:33:44:55', 'Online',   'Network',     5,  'Infra',   'Cisco IOS-XE', 'DataCenter-A', '2024-03-12 10:00', '2024-01-01', None, 0),
        ('dev-002', 'DB-PROD-01',   '10.0.0.50',  'AA:BB:CC:DD:EE:11', 'Online',   'Server',      15, 'Infra',   'Linux 5.15',   'DataCenter-A', '2024-03-12 10:05', '2024-01-05', 'dev-001', 0),
        ('dev-003', 'WEB-FE-01',    '10.0.0.60',  '11:22:33:44:55:66', 'Online',   'Server',      30, 'Infra',   'Linux 6.1',    'DataCenter-B', '2024-03-12 10:06', '2024-01-05', 'dev-001', 0),
        ('dev-004', 'FIN-PC-012',   '192.168.1.12','CC:DD:EE:FF:00:11', 'Offline',  'Workstation', 85, 'Finance', 'Win 11',       'Office-4',     '2024-03-11 18:30', '2024-02-15', 'dev-001', 1),
        ('dev-005', 'FIN-PC-015',   '192.168.1.15','CC:DD:EE:FF:00:22', 'Online',   'Workstation', 10, 'Finance', 'Win 10',       'Office-4',     '2024-03-12 10:10', '2024-02-15', 'dev-001', 1),
        ('dev-006', 'CEO-LAPTOP',   '192.168.1.5', 'EE:FF:00:11:22:33', 'Pending',  'Workstation', 40, 'Mgmt',    'macOS 14',     'Exec-Suite',   '2024-03-12 09:15', '2024-03-12', 'dev-001', 0),
        ('dev-007', 'HR-KIOSK-1',   '192.168.2.10','00:AA:11:BB:22:CC', 'Online',   'Workstation', 25, 'HR',      'Win 10',       'Lobby',        '2024-03-12 08:30', '2024-02-28', 'dev-002', 0),
        ('dev-008', 'SEC-CAM-EXT',  '192.168.3.55','55:44:33:22:11:00', 'Isolated', 'IoT',         95, 'Infra',   'Embedded OS',  'Main Gate',    '2024-03-10 12:00', '2024-01-20', 'dev-003', 0),
        ('dev-009', 'CONF-ROOM-TV', '192.168.2.50','99:88:77:66:55:44', 'Online',   'IoT',         60, 'Mgmt',    'Tizen OS',     'Boardroom',    '2024-03-12 10:15', '2024-03-01', 'dev-003', 0),
        ('dev-010', 'DEV-MAC-XYZ',  '192.168.4.22','AA:11:BB:22:CC:33', 'Online',   'Workstation', 15, 'Infra',   'macOS 14',     'Office-2',     '2024-03-12 10:20', '2024-03-10', 'dev-002', 0),
        ('dev-011', 'HR-MAIN-SRV',  '10.0.3.50',  'BB:AA:33:44:55:66', 'Online',   'Server',      20, 'HR',      'Win Server',   'HR-Dept',      '2024-03-12 10:25', '2024-03-11', 'dev-002', 0)
    ]

    # ── 1. Phase 1 Core Tables (Identity & Assets) ───────────────────────────

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            username        TEXT    NOT NULL UNIQUE,
            email           TEXT    NOT NULL UNIQUE,
            role            TEXT    NOT NULL,
            password_hash   TEXT    NOT NULL,
            last_login      TEXT,
            avatar_initials TEXT,
            created_at      TEXT    DEFAULT (datetime('now'))
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS devices (
            id              TEXT    PRIMARY KEY,
            hostname        TEXT    NOT NULL,
            ip_address      TEXT,
            mac_address     TEXT    UNIQUE,
            status          TEXT    NOT NULL,
            type            TEXT    NOT NULL,
            risk_level      INTEGER DEFAULT 0,
            shadow_risk_flag INTEGER DEFAULT 0,
            department      TEXT,
            os_kernel       TEXT,
            location        TEXT,
            last_seen       TEXT,
            discovery_date  TEXT    DEFAULT (datetime('now')),
            parent_id       TEXT,
            FOREIGN KEY (parent_id) REFERENCES devices(id) ON DELETE SET NULL
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS traffic_logs (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id       TEXT    NOT NULL,
            dest_ip         TEXT,
            dest_port       INTEGER,
            protocol        TEXT    DEFAULT 'TCP',
            app_protocol    TEXT    DEFAULT 'Unknown',
            bytes_sent      INTEGER DEFAULT 0,
            bytes_received  INTEGER DEFAULT 0,
            latency_ms      INTEGER DEFAULT 0,
            packet_loss_pct FLOAT   DEFAULT 0.0,
            risk_score      INTEGER DEFAULT 0,
            anomaly_flag    INTEGER DEFAULT 0,
            timestamp       TEXT    DEFAULT (datetime('now', 'localtime')),
            FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE
        )
    ''')
    # Schema Migration for existing DBs
    cursor.execute("PRAGMA table_info(traffic_logs)")
    cols = [c[1] for c in cursor.fetchall()]
    new_cols = [
        ('app_protocol', 'TEXT DEFAULT "Unknown"'),
        ('latency_ms', 'INTEGER DEFAULT 0'),
        ('packet_loss_pct', 'FLOAT DEFAULT 0.0'),
        ('anomaly_flag', 'INTEGER DEFAULT 0')
    ]
    for col_name, col_def in new_cols:
        if col_name not in cols:
            print(f"MIGRATION: Adding {col_name} to traffic_logs")
            cursor.execute(f"ALTER TABLE traffic_logs ADD COLUMN {col_name} {col_def}")

    cursor.execute('CREATE INDEX IF NOT EXISTS idx_traffic_time ON traffic_logs(timestamp)')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS network_health_history (
            id                    INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp             TEXT    UNIQUE,
            total_bandwidth_usage REAL    DEFAULT 0.0,
            active_devices_count  INTEGER DEFAULT 0,
            avg_network_risk      INTEGER DEFAULT 0,
            critical_alert_count  INTEGER DEFAULT 0
        )
    ''')

    # --- URGENT STABILIZATION: Stub Tables for UI Modules ---
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS user_action_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            operator TEXT, action TEXT, target_type TEXT, target_id TEXT, detail TEXT, ip_address TEXT, 
            timestamp TEXT DEFAULT (datetime('now', 'localtime'))
        )
    ''')
    # ── 2. Phase 3 Policy & Rules ───────────────────────────────────────────

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS access_rules (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            rule_name   TEXT    NOT NULL,
            rule_type   TEXT    NOT NULL, -- 'Firewall' or 'Access'
            source      TEXT    DEFAULT 'Any',
            destination TEXT    DEFAULT 'Any',
            protocol    TEXT    DEFAULT 'All',
            action      TEXT    DEFAULT 'Monitor', -- 'Allow', 'Block', 'Monitor'
            status      TEXT    DEFAULT 'Enabled', -- 'Enabled', 'Disabled'
            priority    INTEGER DEFAULT 99,
            schedule    TEXT    DEFAULT '[]',
            created_at  TEXT    DEFAULT (datetime('now', 'localtime'))
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS system_settings (
            id                  INTEGER PRIMARY KEY AUTOINCREMENT,
            guest_wifi_enabled  INTEGER DEFAULT 0,
            auto_scan_enabled   INTEGER DEFAULT 1,
            scan_frequency      INTEGER DEFAULT 60, -- minutes
            retention_days      INTEGER DEFAULT 30,
            security_level      TEXT    DEFAULT 'Normal', -- 'Strict', 'Normal', 'Relaxed'
            system_name         TEXT    DEFAULT 'Nebula Net - Ana Merkez',
            default_lang        TEXT    DEFAULT 'Türkçe',
            timezone            TEXT    DEFAULT 'Europe/Istanbul (UTC+3)',
            access_schedule     TEXT    DEFAULT '[]'
        )
    ''')
    
    # Schema Migration for system_settings
    cursor.execute("PRAGMA table_info(system_settings)")
    sys_cols = [c[1] for c in cursor.fetchall()]
    new_sys_cols = [
        ('system_name', "TEXT DEFAULT 'Nebula Net - Ana Merkez'"),
        ('default_lang', "TEXT DEFAULT 'Türkçe'"),
        ('timezone', "TEXT DEFAULT 'Europe/Istanbul (UTC+3)'"),
        ('access_schedule', "TEXT DEFAULT '[]'")
    ]
    for col_name, col_def in new_sys_cols:
        if col_name not in sys_cols:
            print(f"MIGRATION: Adding {col_name} to system_settings")
            cursor.execute(f"ALTER TABLE system_settings ADD COLUMN {col_name} {col_def}")

    # Schema Migration for access_rules
    cursor.execute("PRAGMA table_info(access_rules)")
    rule_cols = [c[1] for c in cursor.fetchall()]
    if 'schedule' not in rule_cols:
        print("MIGRATION: Adding schedule to access_rules")
        cursor.execute("ALTER TABLE access_rules ADD COLUMN schedule TEXT DEFAULT '[]'")

    # Phase 3 Integations
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS api_keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            provider TEXT NOT NULL UNIQUE,
            api_key TEXT NOT NULL,
            status TEXT DEFAULT 'active'
        )
    ''')

    conn.commit()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS security_scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT, 
            device_id TEXT, 
            hostname TEXT,
            ip_address TEXT,
            scan_date TEXT, 
            open_ports TEXT, 
            vulnerabilities_found TEXT, 
            risk_level_detected INTEGER, 
            status TEXT DEFAULT 'completed', 
            triggered_by TEXT, 
            cve_ids_found TEXT, 
            scan_duration_ms INTEGER
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS security_alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT, device_id TEXT, type TEXT, severity TEXT, message TEXT, 
            timestamp TEXT, resolved_at TEXT
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS vulnerability_reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT, device_id TEXT, finding_type TEXT, severity TEXT, 
            description TEXT, timestamp TEXT
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS safe_zones (
            id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, ip_range TEXT
        )
    ''')

    # Schema Migration for security_alerts: status + hostname columns
    cursor.execute("PRAGMA table_info(security_alerts)")
    alert_cols = [c[1] for c in cursor.fetchall()]
    if 'status' not in alert_cols:
        print("MIGRATION: Adding status to security_alerts")
        cursor.execute("ALTER TABLE security_alerts ADD COLUMN status TEXT DEFAULT 'active'")
    if 'hostname' not in alert_cols:
        print("MIGRATION: Adding hostname to security_alerts")
        cursor.execute("ALTER TABLE security_alerts ADD COLUMN hostname TEXT DEFAULT ''")
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS topology_links (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source_id TEXT NOT NULL,
            target_id TEXT NOT NULL,
            link_type TEXT DEFAULT 'physical',
            status TEXT DEFAULT 'up',
            FOREIGN KEY (source_id) REFERENCES devices(id) ON DELETE CASCADE,
            FOREIGN KEY (target_id) REFERENCES devices(id) ON DELETE CASCADE
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS device_uptime_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id TEXT NOT NULL,
            event TEXT,
            timestamp TEXT DEFAULT (datetime('now', 'localtime')),
            triggered_by TEXT,
            FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE
        )
    ''')

    # ── 2. Data Seeding (only if tables are empty) ───────────────────────────

    cursor.execute('SELECT COUNT(*) FROM access_rules')
    if cursor.fetchone()[0] == 0:
        print("Seeding default Firewall rules...")
        default_rules = [
            ('Block SSH External', 'Firewall', 'External', 'Any',    'TCP/22', 'Block',   'Enabled', 10),
            ('Allow HTTPS Web',    'Firewall', 'Any',      '10.0.0.60','TCP/443','Allow',   'Enabled', 20),
            ('Isolate IoT Net',    'Access',   '192.168.3.0/24', 'Any', 'All',    'Monitor', 'Enabled', 30),
            ('Guest Isolation',    'Access',   'Guest-WiFi', 'Internal', 'All',   'Block',   'Enabled', 40)
        ]
        cursor.executemany('''
            INSERT INTO access_rules (rule_name, rule_type, source, destination, protocol, action, status, priority)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', default_rules)

    cursor.execute('SELECT COUNT(*) FROM system_settings')
    if cursor.fetchone()[0] == 0:
        print("Seeding default system settings...")
        cursor.execute('''
            INSERT INTO system_settings (guest_wifi_enabled, auto_scan_enabled, scan_frequency, retention_days, security_level)
            VALUES (?, ?, ?, ?, ?)
        ''', (0, 1, 60, 30, 'Normal'))

    cursor.execute('SELECT COUNT(*) FROM users')
    if cursor.fetchone()[0] == 0:
        print("Seeding database with Admin user...")
        # Since this is a mock setup, we'll store a mock hash
        cursor.execute('''
            INSERT INTO users (username, email, role, password_hash, avatar_initials)
            VALUES (?, ?, ?, ?, ?)
        ''', ('Mehmet Ersolak', 'mehmet@nebulanets.local', 'Admin', generate_password_hash('admin123'), 'ME'))

    cursor.execute('SELECT COUNT(*) FROM devices')
    if cursor.fetchone()[0] == 0:
        print("Seeding database with 10 diverse mock devices and hierarchy...")
        cursor.executemany('''
            INSERT INTO devices
                (id, hostname, ip_address, mac_address, status, type, risk_level,
                 department, os_kernel, location, last_seen, discovery_date, parent_id, shadow_risk_flag)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        ''', mock_devices)

    cursor.execute('SELECT COUNT(*) FROM topology_links')
    if cursor.fetchone()[0] == 0:
        print("Seeding topology links based on device hierarchy...")
        links = []
        for d in mock_devices:
            if d[12]: # if parent_id exists
                links.append((d[12], d[0], 'physical'))
        
        cursor.executemany('''
            INSERT INTO topology_links (source_id, target_id, link_type)
            VALUES (?, ?, ?)
        ''', links)

    cursor.execute('SELECT COUNT(*) FROM vulnerability_reports')
    if cursor.fetchone()[0] == 0:
        print("Seeding mock vulnerability findings...")
        findings = [
            ('dev-001', 'Broken Authentication', 'Critical', 'Plaintext credentials found in config files.', '2024-03-12 10:00'),
            ('dev-001', 'Outdated Firmware', 'Medium', 'Device running version 2.4.1. Latest is 2.5.0.', '2024-03-11 15:30'),
            ('dev-008', 'Ransomware Artifact', 'Critical', 'Suspicious encrypted file patterns detected.', '2024-03-10 11:45'),
            ('dev-005', 'Open Telnet Port', 'High', 'Unencrypted remote access service (Telnet) is active.', '2024-03-12 09:20'),
            ('dev-010', 'Missing OS Patches', 'Medium', 'KB5031354 update missing from the kernel.', '2024-03-12 08:45')
        ]
        cursor.executemany('''
            INSERT INTO vulnerability_reports (device_id, finding_type, severity, description, timestamp)
            VALUES (?, ?, ?, ?, ?)
        ''', findings)

    cursor.execute('SELECT COUNT(*) FROM safe_zones')
    if cursor.fetchone()[0] == 0:
        print("Seeding default safe zones...")
        default_zones = [
            ('Corporate LAN',     '10.0.0.0/8'),
            ('Office Network',    '192.168.0.0/16'),
            ('Management VLAN',   '172.16.0.0/12'),
            ('Server Zone',       '10.0.0.0/24'),
            ('IoT Segment',       '192.168.3.0/24'),
        ]
        cursor.executemany(
            'INSERT INTO safe_zones (name, ip_range) VALUES (?, ?)',
            default_zones
        )

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
            
            try:
                response = f(*args, **kwargs)
            except Exception as e:
                return jsonify({"error": "Internal Server Error", "details": str(e)}), 500
            
            # Log only if successful
            status_code = response[1] if isinstance(response, tuple) else (getattr(response, 'status_code', 200))
            if 200 <= status_code < 300:
                t_id = 'global'
                if kwargs:
                    t_id = next(iter(kwargs.values()))
                elif action_type == 'CREATE_USER':
                    try:
                        res_data = response[0].get_json() if isinstance(response, tuple) else response.get_json()
                        if res_data and 'id' in res_data:
                            t_id = res_data['id']
                    except:
                        pass
                
                detail = None
                if request.is_json and request.method != 'GET':
                    try:
                        detail = json.dumps(request.json)
                    except:
                        pass
                        
                try:
                    log_user_action(
                        action=action_type,
                        target_type=target_type,
                        target_id=str(t_id),
                        detail=detail,
                        operator='Admin'
                    )
                except Exception as e:
                    print(f"Audit Log Guard caught exception: {e}")
            return response
        return decorated_function
    return decorator

from flask import has_request_context

def log_user_action(action, target_type, target_id, detail=None, operator='system'):
    """Write every operator write-action to the audit trail."""
    remote_ip = request.remote_addr if has_request_context() else 'internal'

    max_retries = 5
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
        except sqlite3.OperationalError as e:
            err = str(e).lower()
            if 'readonly' in err:
                # WAL got stuck — attempt checkpoint recovery once, then retry
                print(f"[AUDIT] Readonly detected (attempt {attempt+1}), running WAL recovery...")
                recovered = _wal_checkpoint_recovery()
                if recovered:
                    time.sleep(0.3)
                    continue
                else:
                    time.sleep(1.0)
            elif 'locked' in err:
                # Transient lock — exponential backoff
                time.sleep(0.2 * (2 ** attempt))
            else:
                print(f"[AUDIT LOG ERROR] Failed after retries: {e}")
                break
        except Exception as e:
            if attempt < max_retries - 1:
                time.sleep(0.5)
            else:
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
    """Background worker to perform batch inserts for traffic logs."""
    DB_READY.wait()
    last_flush = time.time()
    while True:
        try:
            batch = []
            now = time.time()
            with TRAFFIC_LOCK:
                if len(TRAFFIC_BUFFER) >= 20 or (len(TRAFFIC_BUFFER) > 0 and (now - last_flush) >= 2):
                    while TRAFFIC_BUFFER and len(batch) < 100:
                        batch.append(TRAFFIC_BUFFER.popleft())
                    last_flush = now
            
            if batch:
                max_retries = 3
                for attempt in range(max_retries):
                    try:
                        conn = get_db_connection()
                        # 1. Insert Traffic Logs
                        conn.executemany('''
                            INSERT INTO traffic_logs 
                            (device_id, dest_ip, dest_port, protocol, app_protocol,
                             bytes_sent, bytes_received, latency_ms, packet_loss_pct,
                             risk_score, anomaly_flag, timestamp)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        ''', [item[:12] for item in batch])

                        # 2. Autonomous Alerting for Anomalies
                        for item in batch:
                            if item[10] == 1: # anomaly_flag
                                # More professional distribution of severity based on risk_score and size
                                risk = item[9]
                                size_mb = item[5] / 1_000_000
                                
                                if risk >= 90:
                                    severity = 'critical'
                                    msg = f"Critical Data Exfiltration: {item[4]} flow ({size_mb:.1f} MB) detected from {item[12]} to {item[1]}."
                                elif risk >= 60:
                                    severity = 'warning'
                                    msg = f"Suspicious Activity: High-volume {item[4]} transfer ({size_mb:.1f} MB) from {item[12]}."
                                else:
                                    severity = 'info'
                                    msg = f"Unusual Traffic Pattern: Elevated {item[4]} usage from {item[12]}."

                                conn.execute('''
                                    INSERT INTO security_alerts (device_id, type, severity, message, timestamp)
                                    VALUES (?, ?, ?, ?, ?)
                                ''', (item[0], 'Traffic Anomaly', severity, msg, item[11]))
                                
                                if severity == 'critical':
                                    socketio.emit('new_critical_alert', {
                                        'device_id': item[0],
                                        'type': 'Traffic Anomaly',
                                        'severity': 'critical',
                                        'message': msg,
                                        'timestamp': item[11],
                                        'hostname': item[12]
                                    })

                        # 3. Retention Policy Check & Cleanup
                        ret_settings = conn.execute("SELECT retention_days FROM system_settings WHERE id = 1").fetchone()
                        ret_days = ret_settings['retention_days'] if ret_settings else 30
                        
                        conn.execute(f"DELETE FROM traffic_logs WHERE timestamp < datetime('now', 'localtime', '-{ret_days} days')")
                        conn.execute(f"DELETE FROM device_uptime_log WHERE timestamp < datetime('now', 'localtime', '-{ret_days} days')")

                        conn.commit()
                        conn.close()
                        
                        # 4. Emit LIVE TRAFFIC payload to WebSockets for connected clients
                        live_packets = []
                        total_bytes = 0
                        for item in batch:
                            hostname = item[12] if len(item) > 12 else 'Unknown'
                            # source_id, dest_ip, dest_port, protocol, app_p, bytes_sent, bytes_received, latency, loss, risk_score, a_flag, now_str = item[:12]
                            total_bytes += (item[5] + item[6])
                            live_packets.append({
                                'hostname': hostname,
                                'dest_ip': item[1],
                                'dest_port': item[2],
                                'protocol': item[3],
                                'app_protocol': item[4],
                                'bytes_sent': item[5],
                                'bytes_received': item[6],
                                'latency': item[7],
                                'risk_score': item[9]
                            })
                            
                        # calculate rough bps based on last_flush diff or just abstract it
                        elapsed_secs = max(now - last_flush, 0.1)
                        live_bps = int((total_bytes * 8) / elapsed_secs)
                        
                        socketio.emit('live_traffic_feed', {
                            'packets': live_packets,
                            'live_bps': live_bps
                        })
                        
                        break
                    except sqlite3.OperationalError as e:
                        err_msg = str(e).lower()
                        if 'readonly' in err_msg:
                            print(f"[FLUSHER] Readonly DB detected, attempting WAL recovery...")
                            try:
                                conn.close()
                            except Exception:
                                pass
                            _wal_checkpoint_recovery()
                            time.sleep(1.0)
                        elif 'locked' in err_msg and attempt < max_retries - 1:
                            try:
                                conn.close()
                            except Exception:
                                pass
                            time.sleep(0.5 * (2 ** attempt))  # Exponential backoff
                        else:
                            print(f"[FLUSHER ERROR] {e}")
                            try:
                                conn.close()
                            except Exception:
                                pass
                            break  # Only continue loop for readonly/locked
                    except Exception as e:
                        print(f"[FLUSHER Error] {e}")
                        try:
                            conn.close()
                        except Exception:
                            pass
                        break
            time.sleep(1)
        except Exception as e:
            print(f"[FLUSHER Outer Error] {e}")
            time.sleep(2)

def simulate_traffic():
    """Refactored Simulator: Fetches real devices, inserts robust traffic mapping."""
    DB_READY.wait()
    print("Traffic Simulator Engine started (Phase 2)...")
    while True:
        try:
            conn = get_db_connection()
            # Fetch valid devices with hostname for alerting context
            devices = conn.execute("SELECT id, hostname, status, risk_level FROM devices").fetchall()
            conn.close()
            
            if devices:
                active_devices = [d for d in devices if d['status'] not in ('Offline', 'Isolated', 'Pending')]
                # Randomly pick 1 to 4 devices to simulate traffic for in this tick
                selected_devices = random.sample(active_devices, min(len(active_devices), random.randint(1, 4))) if active_devices else []
                
                now_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                with TRAFFIC_LOCK:
                    for device in selected_devices:
                        source_id = device['id']
                        dest_ip = f"192.168.{random.randint(1, 255)}.{random.randint(1, 255)}"
                        
                        roll = random.random()
                        protocol = random.choice(['TCP', 'UDP', 'ICMP'])
                        
                        if roll < 0.02: # 2% chance for Severe High Risk
                            dest_port = 445
                            bytes_sent = random.randint(5_000_000, 15_000_000)
                            bytes_received = random.randint(100, 500)
                            risk_score = 95
                            a_flag = 1
                        elif roll < 0.10: # 8% chance for Medium Risk Suspicious Behavior
                            dest_port = 443
                            bytes_sent = random.randint(1_000_000, 5_000_000)
                            bytes_received = random.randint(1000, 5000)
                            risk_score = 65
                            a_flag = 1
                        elif roll < 0.20: # 10% chance for Info level anomaly (Unusual but expected)
                            dest_port = random.choice([80, 8080])
                            bytes_sent = random.randint(500_000, 2_000_000)
                            bytes_received = random.randint(5000, 15000)
                            risk_score = device['risk_level'] if device['risk_level'] else 25
                            a_flag = 1
                        else: # 80% Normal baseline traffic
                            dest_port = random.choice([443, 22, 53, 3000])
                            bytes_sent = random.randint(5000, 500_000)
                            bytes_received = random.randint(50000, 500_000)
                            risk_score = device['risk_level'] if device['risk_level'] else 5
                            a_flag = 0

                        # L7 Application Discovery
                        app_protocols = ['HTTPS', 'SSH', 'DNS', 'SMTP', 'SMB', 'FTP']
                        app_p = random.choice(app_protocols)
                        
                        # Performance metrics
                        latency = random.randint(10, 80)
                        loss = round(random.uniform(0.0, 0.5), 2)
                        
                        TRAFFIC_BUFFER.append((
                            source_id, dest_ip, dest_port, protocol, app_p,
                            bytes_sent, bytes_received, latency, loss,
                            risk_score, a_flag, now_str, device['hostname']
                        ))
        except Exception as e:
            print(f"Simulator Error: {e}")
            
        time.sleep(1)

from datetime import timedelta

def summarize_network_health():
    """Background worker to aggregate traffic & alerts into minute-by-minute AI timeline."""
    DB_READY.wait()
    # Align roughly to the start of the next minute
    time.sleep(60 - datetime.now().second)
    
    while True:
        try:
            conn = get_db_connection()
            end_time = datetime.now()
            start_time = end_time - timedelta(seconds=60)
            start_str = start_time.strftime('%Y-%m-%d %H:%M:%S')
            end_str = end_time.strftime('%Y-%m-%d %H:%M:%S')
            snapshot_time = end_str

            stats = conn.execute('''
                SELECT 
                    COALESCE(SUM(bytes_sent + bytes_received), 0) as total_bytes
                FROM traffic_logs 
                WHERE timestamp >= ? AND timestamp < ?
            ''', (start_str, end_str)).fetchone()
            
            # Convert to Mbps (Megabits per second over 60 seconds)
            total_mbps = round((stats['total_bytes'] * 8) / (60 * 1_000_000), 2)
            
            active_devices = conn.execute("SELECT COUNT(*) FROM devices WHERE status NOT IN ('Offline', 'Isolated')").fetchone()[0]
            avg_risk = conn.execute("SELECT AVG(risk_level) FROM devices WHERE status NOT IN ('Offline', 'Isolated')").fetchone()[0]
            avg_risk = int(avg_risk) if avg_risk else 0
            
            try:
                alerts_cnt = conn.execute("SELECT COUNT(*) FROM security_alerts WHERE severity = 'critical'").fetchone()[0]
            except sqlite3.OperationalError:
                alerts_cnt = 0
            
            conn.execute('''
                INSERT OR REPLACE INTO network_health_history 
                (timestamp, total_bandwidth_usage, active_devices_count, avg_network_risk, critical_alert_count)
                VALUES (?, ?, ?, ?, ?)
            ''', (snapshot_time, total_mbps, active_devices, avg_risk, alerts_cnt))
            conn.commit()
            conn.close()
            
            # Re-align to next minute perfectly
            sleep_time = 60 - datetime.now().second
            if sleep_time < 0: sleep_time = 60
            time.sleep(sleep_time)
            
        except sqlite3.OperationalError as e:
            err_msg = str(e).lower()
            if 'readonly' in err_msg:
                print(f"[HEALTH SUMMARIZER] Readonly DB, running WAL recovery...")
                try:
                    conn.close()
                except Exception:
                    pass
                _wal_checkpoint_recovery()
                time.sleep(5)
            else:
                print(f"[HEALTH SUMMARIZER ERROR] {e}")
                time.sleep(10)
        except Exception as e:
            print(f"[HEALTH SUMMARIZER ERROR] {e}")
            time.sleep(10)

# Start background pipeline workers
# Only run inside the main Werkzeug worker process to prevent DB locked/readonly conflicts
if os.environ.get('WERKZEUG_RUN_MAIN') == 'true' or not os.environ.get('FLASK_DEBUG'):
    threading.Thread(target=summarize_network_health, daemon=True, name="Health-Summarizer").start()
    threading.Thread(target=flush_traffic_buffer, daemon=True, name="DB-Flusher").start()
    sim_thread = threading.Thread(target=simulate_traffic, daemon=True, name="Traffic-Sim")
    sim_thread.start()

# ── Authentication Middleware ─────────────────────────────────────────────
@app.before_request
def require_login():
    # Allow static assets and public routes
    allowed_routes = ['login', 'api_login', 'api_register', 'static']
    if request.endpoint in allowed_routes:
        return
    
    # Require session ID for dashboard logic
    if 'user_id' not in session:
        return redirect(url_for('login'))

@app.route('/login')
def login():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('login.html')

@app.route('/api/login', methods=['POST'])
def api_login():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    if not username or not password:
        return jsonify({"error": "Missing credentials"}), 400
        
    try:
        conn = get_db_connection()
        # Allow login using either username or email (Case-Insensitive)
        user = conn.execute("SELECT * FROM users WHERE LOWER(username) = LOWER(?) OR LOWER(email) = LOWER(?)", (username, username)).fetchone()
        conn.close()
        
        if user and check_password_hash(user['password_hash'], password):
            # Login successful
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']
            return jsonify({"status": "success", "message": "Logged in"})
        else:
            return jsonify({"error": "Invalid username or password"}), 401
    except Exception as e:
        return jsonify({"error": "Internal server error"}), 500

@app.route('/api/logout', methods=['POST'])
def api_logout():
    session.clear()
    return jsonify({"status": "success"})

@app.route('/api/register', methods=['POST'])
def api_register():
    data = request.json
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')
    
    if not username or not email or not password:
        return jsonify({"error": "Missing required fields (username, email, password)"}), 400
        
    try:
        conn = get_db_connection()
        existing = conn.execute("SELECT id FROM users WHERE username = ? OR email = ?", (username, email)).fetchone()
        if existing:
            conn.close()
            return jsonify({"error": "Username or email already exists"}), 409
            
        hashed_pw = generate_password_hash(password)
        avatar = username[:2].upper()
        # Default role assigned is "Operator"
        conn.execute('''
            INSERT INTO users (username, email, role, password_hash, avatar_initials)
            VALUES (?, ?, ?, ?, ?)
        ''', (username, email, 'Operator', hashed_pw, avatar))
        conn.commit()
        conn.close()
        
        return jsonify({"status": "success", "message": "Account created successfully"}), 201
    except Exception as e:
        return jsonify({"error": "Internal server error during registration", "details": str(e)}), 500


# ── Integrations & Backup (Phase 3) ───────────────────────────────────────
@app.route('/api/system/backup', methods=['POST'])
def system_backup():
    try:
        backup_dir = os.path.join(BASE_DIR, 'backups')
        os.makedirs(backup_dir, exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_file = os.path.join(backup_dir, f"observability_backup_{timestamp}.db")
        
        # Synchronize and copy the main DB
        conn = get_db_connection()
        # Force a checkpoint for WAL mode before copy
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        conn.close()
        
        shutil.copy2(DB_PATH, backup_file)
        return jsonify({"success": True, "file": f"observability_backup_{timestamp}.db"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/integrations', methods=['GET', 'POST'])
def manage_integrations():
    try:
        conn = get_db_connection()
        if request.method == 'POST':
            data = request.json
            provider = data.get('provider')
            api_key = data.get('api_key')
            if not provider or not api_key:
                 return jsonify({"error": "Provider and API Key required"}), 400
             
            # Upsert logic (Insert or Replace)
            conn.execute('''
                INSERT INTO api_keys (provider, api_key, status)
                VALUES (?, ?, 'active')
                ON CONFLICT(provider) DO UPDATE SET api_key=excluded.api_key, status='active'
            ''', (provider, api_key))
            conn.commit()
            conn.close()
            return jsonify({"success": True, "message": f"{provider} key saved"})
            
        else: # GET
            keys = conn.execute("SELECT id, provider, status FROM api_keys").fetchall()
            conn.close()
            # Deliberately exclude the actual api_key value in GET for security
            return jsonify([dict(k) for k in keys])
            
    except Exception as e:
        return jsonify({"error": str(e)}), 500
        
@app.route('/api/integrations/<provider>', methods=['DELETE'])
def delete_integration(provider):
    try:
        conn = get_db_connection()
        conn.execute("DELETE FROM api_keys WHERE provider = ?", (provider,))
        conn.commit()
        conn.close()
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


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

@app.route('/api/devices/paged', methods=['GET'])
def get_devices_paged():
    try:
        page = int(request.args.get('page', 1))
        limit = int(request.args.get('limit', 10))
        offset = (page - 1) * limit
        
        type_filter = request.args.get('type', 'all').lower()
        status_filter = request.args.get('status', 'all').lower()
        search_filter = request.args.get('search', '').lower()
        
        conn = get_db_connection()
        
        query = "SELECT * FROM devices WHERE 1=1"
        params = []
        
        if type_filter != 'all':
            query += " AND LOWER(type) = ?"
            params.append(type_filter)
        if status_filter != 'all':
            query += " AND LOWER(status) = ?"
            params.append(status_filter)
        if search_filter:
            query += " AND (LOWER(hostname) LIKE ? OR LOWER(ip_address) LIKE ? OR LOWER(mac_address) LIKE ? OR LOWER(department) LIKE ?)"
            search_pattern = f"%{search_filter}%"
            params.extend([search_pattern, search_pattern, search_pattern, search_pattern])
            
        count_query = query.replace("SELECT *", "SELECT COUNT(*)")
        total = conn.execute(count_query, params).fetchone()[0]
        
        query += " LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        
        devices = conn.execute(query, params).fetchall()
        conn.close()
        
        return jsonify({
            "data": [dict(row) for row in devices],
            "total": total,
            "page": page,
            "limit": limit
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/security-audit/export/csv', methods=['GET'])
def export_security_audit_csv():
    import io
    import csv
    from flask import Response
    try:
        conn = get_db_connection()
        logs = conn.execute('SELECT * FROM user_action_logs ORDER BY timestamp DESC LIMIT 1000').fetchall()
        conn.close()

        si = io.StringIO()
        cw = csv.writer(si)
        cw.writerow(['ID', 'Operator', 'Action', 'Target Type', 'Target ID', 'Details', 'IP Address', 'Timestamp'])
        
        for log in logs:
            cw.writerow([
                log['id'], log['operator'], log['action'], log['target_type'],
                log['target_id'], log['detail'], log['ip_address'], log['timestamp']
            ])

        output = si.getvalue()
        return Response(
            output,
            mimetype="text/csv",
            headers={"Content-disposition": "attachment; filename=security_audit_export.csv"}
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 500

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

        cursor.execute(
            "UPDATE devices SET status = 'Isolated', risk_level = 100 WHERE id = ?",
            (device_id,)
        )

        # Uptime event
        cursor.execute('''
            INSERT INTO device_uptime_log (device_id, event, timestamp, triggered_by)
            VALUES (?, 'Isolated', datetime('now', 'localtime'), 'operator')
        ''', (device_id,))

        conn.commit()
        conn.close()

        return jsonify({
            "success": True,
            "message": f"Device {device_id} isolated from network. Action logged.",
            "new_status": "Isolated"
        })
    except Exception as e:
        print(f"Isolate Error: {e}")
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

        # Fetch device info for audit persistence
        dev_info = cursor.execute('SELECT hostname, ip_address FROM devices WHERE id = ?', (device_id,)).fetchone()
        dev_name = dev_info['hostname'] if dev_info else 'Unknown'
        dev_ip = dev_info['ip_address'] if dev_info else 'Unknown'

        # 1. Stamp device as 'Under Scan'
        scan_start = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        cursor.execute("UPDATE devices SET status = 'Under Scan' WHERE id = ?", (device_id,))

        # 2. Insert a scan row with status='running'
        cursor.execute('''
            INSERT INTO security_scans
                (device_id, hostname, ip_address, scan_date, open_ports, vulnerabilities_found,
                 risk_level_detected, triggered_by, status)
            VALUES (?, ?, ?, ?, '', 'Scan in progress...', 0, 'manual', 'running')
        ''', (device_id, dev_name, dev_ip, scan_start))
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
                        cve_ids_found=?, status='completed', scan_duration_ms=?
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
            WHERE device_id = ? AND status = 'completed'
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
        hours = int(request.args.get('hours', 1))
        # Cap to sane limits
        hours = max(1, min(hours, 720))
        conn = get_db_connection()
        logs = conn.execute('''
            SELECT t.*, d.hostname 
            FROM traffic_logs t
            JOIN devices d ON t.device_id = d.id
            WHERE t.timestamp >= datetime('now', 'localtime', ? || ' hours')
            ORDER BY t.id DESC LIMIT 100
        ''', (f'-{hours}',)).fetchall()
        conn.close()
        return jsonify([dict(row) for row in logs])
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/traffic/stats', methods=['GET'])
def get_traffic_stats():
    """Returns real-time aggregates for traffic KPIs. Supports ?hours=N time window."""
    try:
        hours = int(request.args.get('hours', 1))
        hours = max(1, min(hours, 720))
        window_minutes = hours * 60
        conn = get_db_connection()
        res = conn.execute(f'''
            SELECT 
                COALESCE(SUM(bytes_sent), 0) as total_sent,
                COALESCE(SUM(bytes_received), 0) as total_recv,
                COUNT(id) as active_conns,
                MAX(bytes_sent + bytes_received) as peak_val
            FROM traffic_logs 
            WHERE timestamp >= datetime('now', 'localtime', '-{window_minutes} minutes')
        ''').fetchone()
        
        # Protocol distribution for Sankey/Donut
        proto = conn.execute(f'''
            SELECT protocol, COUNT(*) as cnt, SUM(bytes_sent) as total_bytes
            FROM traffic_logs 
            WHERE timestamp >= datetime('now', 'localtime', '-{window_minutes} minutes')
            GROUP BY protocol
        ''').fetchall()
        
        # L7 app protocol distribution
        app_proto = conn.execute(f'''
            SELECT app_protocol, COUNT(*) as cnt, SUM(bytes_sent) as total_bytes
            FROM traffic_logs 
            WHERE timestamp >= datetime('now', 'localtime', '-{window_minutes} minutes')
            GROUP BY app_protocol
        ''').fetchall()
        
        # Destination nodes for Sankey (top 3 by volume)
        nodes = conn.execute(f'''
            SELECT dest_ip, SUM(bytes_sent) as volume 
            FROM traffic_logs 
            WHERE timestamp >= datetime('now', 'localtime', '-{window_minutes} minutes')
            GROUP BY dest_ip ORDER BY volume DESC LIMIT 3
        ''').fetchall()

        conn.close()

        dl_bps = int(res['total_recv'] * 8 / max(window_minutes * 60, 1))
        ul_bps = int(res['total_sent'] * 8 / max(window_minutes * 60, 1))
        
        dl_gbps = round(dl_bps / 1e9, 2)
        ul_mbps = round(ul_bps / 1e6, 2)

        return jsonify({
            "download_rate": f"{dl_gbps} Gbps",
            "upload_rate": f"{ul_mbps} Mbps",
            "download_bps": dl_bps,
            "upload_bps": ul_bps,
            "active_connections_count": res['active_conns'],
            "peak_traffic_value": f"{round(res['peak_val'] / 1e6, 2)} Mbps" if res['peak_val'] else "0 Mbps",
            "protocol_dist": {row['protocol']: row['cnt'] for row in proto},
            "app_protocol_dist": {row['app_protocol']: {"count": row['cnt'], "bytes": row['total_bytes']} for row in app_proto},
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
                INSERT INTO access_rules (rule_name, rule_type, source, destination, protocol, action, status, priority)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (data.get('rule_name'), data.get('rule_type', 'Firewall'), 
                  data.get('source', 'Any'), data.get('destination', 'Any'), 
                  data.get('protocol', 'All'), data.get('action', 'Monitor'),
                  data.get('status', 'Enabled'), data.get('priority', 99)))
            conn.commit()
            conn.close()
            return jsonify({"status": "success", "message": "Rule added successfully"})
        else:
            rules = conn.execute('SELECT * FROM access_rules ORDER BY priority ASC').fetchall()
            conn.close()
            return jsonify([dict(row) for row in rules])
    except Exception as e:
        print(f"API Error at /api/rules: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/rules/<int:rule_id>/toggle', methods=['PATCH'])
@audit_logger('TOGGLE_RULE', 'FIREWALL')
def toggle_rule(rule_id):
    try:
        conn = get_db_connection()
        conn.execute("UPDATE access_rules SET status = CASE WHEN status = 'Enabled' THEN 'Disabled' ELSE 'Enabled' END WHERE id = ?", (rule_id,))
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

@app.route('/api/rules/<int:rule_id>', methods=['PUT'])
@audit_logger('UPDATE_RULE', 'FIREWALL')
def update_rule(rule_id):
    """Full update of an access rule (edit modal)."""
    try:
        data = request.json
        if not data or not data.get('rule_name'):
            return jsonify({"error": "rule_name is required"}), 400
        conn = get_db_connection()
        conn.execute('''
            UPDATE access_rules
            SET rule_name = ?, rule_type = ?, source = ?, destination = ?,
                protocol = ?, action = ?, status = ?, priority = ?
            WHERE id = ?
        ''', (
            data.get('rule_name'),
            data.get('rule_type', 'Firewall'),
            data.get('source', 'Any'),
            data.get('destination', 'Any'),
            data.get('protocol', 'All'),
            data.get('action', 'Monitor'),
            data.get('status', 'Enabled'),
            int(data.get('priority', 99)),
            rule_id
        ))
        conn.commit()
        conn.close()
        return jsonify({"status": "success", "message": "Rule updated successfully"})
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

@app.route('/api/settings', methods=['GET', 'PATCH'])
@audit_logger('MANAGE_SETTINGS', 'SYSTEM')
def handle_settings():
    try:
        conn = get_db_connection()
        if request.method == 'PATCH':
            data = request.json
            if 'system_name' not in data or not data['system_name']:
                # The explicit strict validation requirement
                return jsonify({"error": "system_name is fundamentally required and cannot be empty"}), 400
                
            # Update Governance Settings - Explicit Type Casting
            guest_wifi = 1 if data.get('guest_wifi_enabled', 0) in [1, True, '1', 'true', 'True'] else 0
            auto_scan = 1 if data.get('auto_scan_enabled', 1) in [1, True, '1', 'true', 'True'] else 0
            scan_freq = int(data.get('scan_frequency', 60))
            ret_days = int(data.get('retention_days', 30))
            sec_level = str(data.get('security_level', 'Normal'))
            system_name = str(data['system_name'])
            default_lang = str(data.get('default_lang', 'Türkçe'))
            timezone = str(data.get('timezone', 'Europe/Istanbul (UTC+3)'))
            
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE system_settings SET 
                    guest_wifi_enabled = ?, 
                    auto_scan_enabled = ?, 
                    scan_frequency = ?, 
                    retention_days = ?, 
                    security_level = ?,
                    system_name = ?,
                    default_lang = ?,
                    timezone = ?
                WHERE id = 1
            ''', (guest_wifi, auto_scan, scan_freq, ret_days, sec_level, system_name, default_lang, timezone))
            
            if cursor.rowcount == 0:
                conn.close()
                return jsonify({"error": "No settings record found to update"}), 404
                
            conn.commit()
            conn.close()
            return jsonify({"status": "success", "message": "Settings updated successfully"}), 200
        else:
            # Return Users + Governance Settings
            users_rows = conn.execute('SELECT * FROM users').fetchall()
            settings_row = conn.execute('SELECT * FROM system_settings WHERE id = 1').fetchone()
            
            users = [dict(row) for row in users_rows]
            governance = dict(settings_row) if settings_row else {}
            
            conn.close()
            return jsonify({
                "users": users,
                "governance": governance
            })
    except Exception as e:
        print(f"API Error at /api/settings: {e}")
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

@app.route('/api/attack-map', methods=['GET'])
def get_attack_map():
    # Returns last 50 external/anomalous traffic paths dynamically
    try:
        conn = get_db_connection()
        logs = conn.execute('''
            SELECT dest_ip, anomaly_flag, risk_score
            FROM traffic_logs
            ORDER BY id DESC LIMIT 40
        ''').fetchall()
        conn.close()
        
        # Attach pseudo coordinates (top: %, left: %) based on IP hash to keep it consistent
        results = []
        for l in logs:
            ip = l['dest_ip'] or '0.0.0.0'
            ip_hash = hash(ip)
            
            # Map hash to 10-90% for visual dot placement
            top = 10 + (abs(ip_hash) % 80)
            left = 10 + (abs(ip_hash >> 4) % 80)
            
            results.append({
                "ip": ip,
                "anomalous": bool(l['anomaly_flag']),
                "risk": l['risk_score'],
                "top": top,
                "left": left
            })
            
        return jsonify(results)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/alerts', methods=['GET'])
def get_alerts():
    """Returns persistent DB alerts. Supports ?today=true and ?status=active filters."""
    try:
        conn = get_db_connection()
        today_only = request.args.get('today', 'false').lower() == 'true'
        status_filter = request.args.get('status', None)

        where_clauses = []
        params = []

        if today_only:
            where_clauses.append("date(a.timestamp) = date('now', 'localtime')")

        if status_filter:
            where_clauses.append("(a.status = ? OR (a.status IS NULL AND ? = 'active'))")
            params.extend([status_filter, status_filter])

        where_sql = ("WHERE " + " AND ".join(where_clauses)) if where_clauses else ""

        alerts = conn.execute(f'''
            SELECT a.*, d.hostname, d.ip_address 
            FROM security_alerts a
            JOIN devices d ON a.device_id = d.id
            {where_sql}
            ORDER BY a.id DESC LIMIT 50
        ''', params).fetchall()
        conn.close()
        
        db_alerts = [dict(row) for row in alerts]
        all_alerts = db_alerts + MEMORY_ALERTS
        all_alerts.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
        
        return jsonify(all_alerts[:50])
    except Exception as e:
        print(f"API Error at /api/alerts: {e}")
        return jsonify(MEMORY_ALERTS[:50])


@app.route('/api/alerts/<int:alert_id>/resolve', methods=['PATCH'])
@audit_logger('RESOLVE_ALERT', 'ALERT')
def resolve_alert(alert_id):
    """Marks an alert as resolved with a timestamp."""
    try:
        conn = get_db_connection()
        result = conn.execute(
            "UPDATE security_alerts SET status = 'resolved', resolved_at = datetime('now', 'localtime') WHERE id = ?",
            (alert_id,)
        )
        if result.rowcount == 0:
            conn.close()
            return jsonify({"error": "Alert not found"}), 404
        conn.commit()
        conn.close()
        return jsonify({"success": True, "message": f"Alert {alert_id} marked as resolved"})
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
        print(f"API Error at /api/safe-zones: {e}")
        return jsonify([])

@app.route('/api/safe-zones', methods=['POST'])
@audit_logger('ADD_ZONE', 'NETWORK')
def add_safe_zone():
    """Add a new trusted network segment."""
    try:
        data = request.json
        name     = data.get('name', '').strip()
        ip_range = data.get('ip_range', '').strip()
        if not name or not ip_range:
            return jsonify({"error": "Both name and ip_range are required"}), 400
        conn = get_db_connection()
        conn.execute('INSERT INTO safe_zones (name, ip_range) VALUES (?, ?)', (name, ip_range))
        conn.commit()
        conn.close()
        return jsonify({"status": "success", "message": f"Zone '{name}' created"}), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/safe-zones/<int:zone_id>', methods=['DELETE'])
@audit_logger('DELETE_ZONE', 'NETWORK')
def delete_safe_zone(zone_id):
    """Remove a trusted network zone."""
    try:
        conn = get_db_connection()
        conn.execute('DELETE FROM safe_zones WHERE id = ?', (zone_id,))
        conn.commit()
        conn.close()
        return jsonify({"status": "success"})
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
        print(f"API Error at /api/scans: {e}")
        return jsonify([])

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
    try:
        conn = get_db_connection()
        # Fetch last two minute snapshots from AI Timeline
        history = conn.execute('''
            SELECT * FROM network_health_history
            ORDER BY id DESC LIMIT 2
        ''').fetchall()
        
        # Current active metrics
        active_devices = conn.execute("SELECT COUNT(*) FROM devices WHERE status NOT IN ('Offline', 'Isolated')").fetchone()[0]
        
        # Compute real-time upload/download bps from last 60 seconds
        traffic = conn.execute('''
            SELECT COALESCE(SUM(bytes_sent), 0) as up_bytes, COALESCE(SUM(bytes_received), 0) as down_bytes
            FROM traffic_logs WHERE timestamp >= datetime('now', 'localtime', '-1 minute')
        ''').fetchone()
        conn.close()

        down_mbps = (traffic['down_bytes'] * 8) / (60 * 1_000_000)
        up_mbps = (traffic['up_bytes'] * 8) / (60 * 1_000_000)

        total_mbps = 0.0
        prev_mbps = 0.0
        critical_count = 0
        if history:
            total_mbps = history[0]['total_bandwidth_usage']
            critical_count = history[0]['critical_alert_count']
            if len(history) > 1:
                prev_mbps = history[1]['total_bandwidth_usage']

        volatility = 0.0
        if prev_mbps > 0:
            volatility = round(((total_mbps - prev_mbps) / prev_mbps) * 100, 1)
        elif total_mbps > 0:
            volatility = 100.0

        return jsonify({
            "download_rate":          f"{round(down_mbps, 2)} Mbps",
            "upload_rate":            f"{round(up_mbps, 2)} Mbps",
            "download_bps":           (traffic['down_bytes'] * 8) / 60,
            "upload_bps":             (traffic['up_bytes'] * 8) / 60,
            "total_bandwidth_usage":  total_mbps,
            "active_devices_count":   active_devices,
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
                COALESCE(SUM(bytes_received), 0)   AS bytes_in,
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
        active_devices = conn.execute("SELECT COUNT(*) FROM devices WHERE status NOT IN ('Offline', 'Isolated')").fetchone()[0]
        isolated_devices = conn.execute("SELECT COUNT(*) FROM devices WHERE status = 'Isolated'").fetchone()[0]
        try:
            recent_scans = conn.execute("SELECT COUNT(*) FROM security_scans WHERE scan_date >= datetime('now', '-24 hours')").fetchone()[0]
        except sqlite3.OperationalError:
            recent_scans = 0
            
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
        try:
            vulns = conn.execute('''
                SELECT v.finding_type, v.severity, v.description, v.timestamp, d.hostname, d.ip_address
                FROM vulnerability_reports v
                JOIN devices d ON v.device_id = d.id
                ORDER BY v.id DESC LIMIT 20
            ''').fetchall()
        except sqlite3.OperationalError:
            vulns = []
        
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
    Returns aggregated Minute Risk Counts for the last 60 minutes.
    Categories: Critical, High (Warning), Medium (Info).
    """
    try:
        conn = get_db_connection()
        rows = conn.execute('''
            SELECT 
                strftime('%H:%M', timestamp) AS time_slot,
                SUM(CASE WHEN severity = 'critical' THEN 1 ELSE 0 END) AS critical_count,
                SUM(CASE WHEN severity = 'warning' THEN 1 ELSE 0 END) AS high_count,
                SUM(CASE WHEN severity = 'info' THEN 1 ELSE 0 END) AS medium_count
            FROM security_alerts
            WHERE timestamp >= datetime('now', '-60 minutes')
            GROUP BY time_slot
            ORDER BY time_slot ASC
        ''').fetchall()
        conn.close()

        # Build zero-filled timeline for the last 60 minutes
        history = []
        now = datetime.now()
        for i in range(59, -1, -1):
            target_time = now - timedelta(minutes=i)
            time_str = target_time.strftime('%H:%M')
            match = next((dict(r) for r in rows if r['time_slot'] == time_str), None)
            
            if match:
                history.append({
                    "hour": time_str, # keep key as 'hour' for frontend compatibility
                    "critical_count": match['critical_count'],
                    "high_count": match['high_count'],
                    "medium_count": match['medium_count']
                })
            else:
                history.append({
                    "hour": time_str,
                    "critical_count": 0,
                    "high_count": 0,
                    "medium_count": 0
                })

        return jsonify(history)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/scans/<device_id>', methods=['GET'])
def get_device_scans(device_id):
    """
    Returns the latest vulnerability scan reports for a specific device.
    Used by the Assets Side Drawer.
    """
    try:
        conn = get_db_connection()
        scans = conn.execute('''
            SELECT finding_type as vulnerabilities_found, severity as risk_level_detected, 
                   description, timestamp as scan_date, 'N/A' as open_ports, 'Unknown' as hostname
            FROM vulnerability_reports 
            WHERE device_id = ?
            ORDER BY id DESC LIMIT 5
        ''', (device_id,)).fetchall()
        conn.close()
        return jsonify([dict(s) for s in scans])
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/devices/risk-history/<string:device_id>', methods=['GET'])
def get_device_risk_history(device_id):
    """
    Returns the last 7 risk levels for a specific device for the sparkline chart.
    """
    try:
        conn = get_db_connection()
        # Try to get from security_scans first
        rows = conn.execute('''
            SELECT risk_level_detected 
            FROM security_scans 
            WHERE device_id = ? AND status = 'completed'
            ORDER BY id DESC LIMIT 7
        ''', (device_id,)).fetchall()
        
        # Fallback to current risk_level if no history
        if not rows:
            device = conn.execute('SELECT risk_level FROM devices WHERE id = ?', (device_id,)).fetchone()
            conn.close()
            current_risk = device['risk_level'] if device else 0
            return jsonify([current_risk] * 7)
            
        conn.close()
        # Return in chronological order (oldest to newest)
        history = [r['risk_level_detected'] for r in rows][::-1]
        
        # Pad with the earliest value if less than 7 points
        while len(history) < 7:
            history.insert(0, history[0])
            
        return jsonify(history)
    except Exception as e:
        return jsonify([0] * 7), 500

@app.route('/api/topology', methods=['GET'])
def get_topology():
    """Returns the static topology links and nodes."""
    try:
        conn = get_db_connection()
        nodes = conn.execute('SELECT * FROM devices').fetchall()
        links = conn.execute('SELECT * FROM topology_links').fetchall()
        conn.close()
        return jsonify({
            "nodes": [dict(row) for row in nodes],
            "links": [dict(row) for row in links]
        })
    except Exception as e:
        print(f"API Error at /api/topology: {e}")
        return jsonify({"nodes": [], "links": []})

@app.route('/api/users', methods=['POST'])
@audit_logger('CREATE_USER', 'USER')
def create_user():
    try:
        data = request.json
        if not data:
            return jsonify({"error": "JSON payload required"}), 400
            
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO users (username, email, role, password_hash, avatar_initials)
            VALUES (?, ?, ?, ?, ?)
        ''', (data.get('username'), data.get('email'), data.get('role', 'Viewer'), 'hashed_pwd_stub', ''.join(word[0] for word in str(data.get('username', 'U')).split()[:2]).upper()))
        
        new_id = cursor.lastrowid
        
        conn.commit()
        conn.close()
        return jsonify({"status": "success", "id": new_id}), 201
    except sqlite3.IntegrityError:
        return jsonify({"error": "Username or email already exists"}), 400
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500

@app.route('/api/users/<int:user_id>', methods=['PATCH'])
@audit_logger('UPDATE_USER', 'USER')
def update_user(user_id):
    try:
        data = request.json
        if not data:
            return jsonify({"error": "JSON payload required"}), 400
            
        conn = get_db_connection()
        updates = []
        params = []
        if 'role' in data:
            updates.append("role = ?")
            params.append(data['role'])
        if 'email' in data:
            updates.append("email = ?")
            params.append(data['email'])
        if 'username' in data:
            updates.append("username = ?")
            params.append(data['username'])
            updates.append("avatar_initials = ?")
            params.append(''.join(word[0] for word in str(data['username']).split()[:2]).upper())
            
        if not updates:
            conn.close()
            return jsonify({"error": "No valid fields to update"}), 400
            
        params.append(user_id)
        
        query = f"UPDATE users SET {', '.join(updates)} WHERE id = ?"
        conn.execute(query, tuple(params))
        conn.commit()
        conn.close()
        return jsonify({"status": "success"}), 200
    except sqlite3.IntegrityError:
        return jsonify({"error": "Username or email already exists"}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/users/<int:user_id>', methods=['DELETE'])
@audit_logger('DELETE_USER', 'USER')
def delete_user(user_id):
    try:
        conn = get_db_connection()
        if user_id == 1:
            conn.close()
            return jsonify({"error": "Cannot delete primary admin user"}), 403
            
        conn.execute('DELETE FROM users WHERE id = ?', (user_id,))
        conn.commit()
        conn.close()
        return jsonify({"status": "success"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Removed external sim_thread start as it's now handled inside the logger system initialization

# Initialize DB on startup
init_db()

if __name__ == '__main__':
    socketio.run(app, debug=True, port=5000, allow_unsafe_werkzeug=True)
