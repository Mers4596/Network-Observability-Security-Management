import os
import time
import sqlite3
from app import init_db, DB_PATH

def purge_sidecars(path):
    for suffix in ["-wal", "-shm"]:
        sidecar = path + suffix
        if os.path.exists(sidecar):
            try:
                os.remove(sidecar)
                print(f"Purged: {sidecar}")
            except Exception as e:
                print(f"Failed to purge {sidecar}: {e}")

if __name__ == "__main__":
    print("\n" + "="*60)
    print("NEBULA NET: ARCHITECTURAL RESET PROTOCOL (v2)")
    print("="*60)
    
    print(f"Target DB: {DB_PATH}")

    if os.path.exists(DB_PATH):
        print(f"Attempting to delete active database...")
        max_retries = 5
        for attempt in range(max_retries):
            try:
                purge_sidecars(DB_PATH)
                os.remove(DB_PATH)
                print(f"DELETED: {DB_PATH} successfully.")
                break
            except Exception as e:
                print(f"Attempt {attempt+1}/{max_retries} failed: {e}")
                time.sleep(1)
        else:
            print("\n" + "!"*60)
            print("CRITICAL: Failed to delete database due to file locks.")
            print("Please close ALL running instances of app.py or VS Code's SQLite viewer.")
            print("!"*60 + "\n")
            exit(1)

    print("\nInitializing fresh v2 schema...")
    init_db()
    
    print("\n" + "="*60)
    print("RESET COMPLETE: Environment is now 100% Phase 4 Ready.")
    print("="*60 + "\n")

