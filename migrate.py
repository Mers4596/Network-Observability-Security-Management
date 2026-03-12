import sqlite3
import os

DB_PATH = 'observability.db'

def migrate():
    log = []
    if not os.path.exists(DB_PATH):
        log.append("DB not found")
        print("DB not found")
        return

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    log.append("Adding schedule column to access_rules...")
    try:
        cursor.execute("ALTER TABLE access_rules ADD COLUMN schedule TEXT DEFAULT '[]'")
        log.append("Column added successfully.")
    except sqlite3.OperationalError:
        log.append("Column 'schedule' already exists.")

    log.append("Creating settings table...")
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS settings (
            key   TEXT PRIMARY KEY,
            value TEXT
        )
    ''')

    log.append("Seeding default settings...")
    cursor.execute("INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)", ('guest_wifi_enabled', 'false'))

    conn.commit()
    conn.close()
    log.append("Migration complete.")
    
    with open('migration.log', 'w') as f:
        f.write("\n".join(log))
    print("Migration complete. Log written to migration.log")

if __name__ == "__main__":
    migrate()
