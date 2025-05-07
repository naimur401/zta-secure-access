import os

def find_sqlite_files(start_path='.'):
    """Find all SQLite database files in the given directory and subdirectories"""
    sqlite_files = []
    
    for root, dirs, files in os.walk(start_path):
        for file in files:
            if file.endswith('.db') or file.endswith('.sqlite') or file.endswith('.sqlite3'):
                full_path = os.path.join(root, file)
                sqlite_files.append(full_path)
    
    return sqlite_files

if __name__ == "__main__":
    print("Searching for SQLite database files...")
    db_files = find_sqlite_files()
    
    if db_files:
        print(f"Found {len(db_files)} potential database files:")
        for file in db_files:
            print(f"  - {file}")
    else:
        print("No SQLite database files found.")
        print("It seems the database hasn't been created yet.")