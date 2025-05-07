from flask import Flask
import sqlite3
import os

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///zero_trust.db'

def migrate_database():
    # Check if database file exists
    db_path = 'zero_trust.db'
    db_exists = os.path.exists(db_path)
    
    if db_exists:
        print("Existing database found. Adding MFA columns...")
        # Connect to the database
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Check if mfa_secret column already exists
        cursor.execute("PRAGMA table_info(user)")
        columns = cursor.fetchall()
        column_names = [column[1] for column in columns]
        
        # Add mfa_secret column if it doesn't exist
        if 'mfa_secret' not in column_names:
            cursor.execute("ALTER TABLE user ADD COLUMN mfa_secret VARCHAR(32)")
            print("Added mfa_secret column")
        
        # Add mfa_enabled column if it doesn't exist
        if 'mfa_enabled' not in column_names:
            cursor.execute("ALTER TABLE user ADD COLUMN mfa_enabled BOOLEAN DEFAULT 0")
            print("Added mfa_enabled column")
        
        conn.commit()
        conn.close()
        print("Database migration completed successfully!")
    else:
        print("Database doesn't exist yet. It will be created with the correct schema when you run app.py")

if __name__ == "__main__":
    migrate_database()