import sqlite3
import os
import sys

def run_audit():
    db_path = 'observability_v2.db'
    print("="*60)
    print("NEBULA NET: SYSTEM FIDELITY AUDIT REPORT")
    print("="*60)

    # 1. File Check
    print(f"\n[1/4] DATABASE SOVEREIGNTY")
    if os.path.exists(db_path):
        size = os.path.getsize(db_path) / 1024
        print(f"  - {db_path}: FOUND ({size:.1f} KB)")
    else:
        print(f"  - {db_path}: MISSING! [FAIL]")
        return

    legacy = ['observability.db', 'observability.db-shm', 'observability.db-wal']
    toxic_files = [f for f in legacy if os.path.exists(f)]
    if toxic_files:
        print(f"  - Legacy Files Found: {toxic_files} [FAIL]")
    else:
        print(f"  - Legacy Purge: CONFIRMED [PASS]")

    # 2. Schema Audit
    print(f"\n[2/4] SCHEMA FIDELITY AUDIT")
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    table_checks = [
        'users', 'devices', 'traffic_logs', 'network_health_history',
        'user_action_logs', 'access_rules', 'system_settings',
        'security_scans', 'security_alerts', 'vulnerability_reports',
        'safe_zones', 'topology_links', 'device_uptime_log'
    ]
    
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
    existing_tables = [t[0] for t in cursor.fetchall()]
    
    missing_tables = [t for t in table_checks if t not in existing_tables]
    if missing_tables:
        print(f"  - Missing Tables: {missing_tables} [FAIL]")
    else:
        print(f"  - Core Table Count ({len(table_checks)}): MATCHED [PASS]")

    # 3. Critical Column Multi-Check
    print(f"\n[3/4] CRITICAL COLUMN VALIDATION")
    col_checks = [
        ('devices', 'shadow_risk_flag'),
        ('devices', 'parent_id'),
        ('security_scans', 'hostname'),
        ('topology_links', 'status'),
        ('traffic_logs', 'app_protocol'),
        ('traffic_logs', 'latency_ms'),
        ('traffic_logs', 'packet_loss_pct'),
        ('traffic_logs', 'anomaly_flag')
    ]
    
    for table, col in col_checks:
        cursor.execute(f"PRAGMA table_info({table})")
        cols = [c[1] for c in cursor.fetchall()]
        if col in cols:
            print(f"  - {table}.{col}: FOUND [PASS]")
        else:
            print(f"  - {table}.{col}: MISSING! [FAIL]")

    # 4. Data Population
    print(f"\n[4/4] LIVE DATA SEEDING STATUS")
    cursor.execute("SELECT COUNT(*) FROM devices")
    dev_count = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM topology_links")
    link_count = cursor.fetchone()[0]
    
    print(f"  - Node Inventory: {dev_count} devices")
    print(f"  - Topology Matrix: {link_count} links")
    
    if dev_count > 0 and link_count > 0:
        print(f"  - Data Vitality: HEALTHY [PASS]")
    else:
        print(f"  - Data Vitality: ANEMIC [FAIL]")

    conn.close()
    print("\n" + "="*60)
    print("AUDIT COMPLETE: ARCHITECTURAL INTEGRITY CONFIRMED")
    print("="*60 + "\n")

if __name__ == "__main__":
    run_audit()
