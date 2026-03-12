import os
from app import init_db, DB_PATH

if __name__ == "__main__":
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
        print(f"Deleted old database at {DB_PATH}")

    print("Initializing fresh database...")
    init_db()
    print("Database reset complete. You can now start app.py")
