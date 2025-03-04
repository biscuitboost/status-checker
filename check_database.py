#!/usr/bin/env python3
"""
Script to check the contents of the URL checker database.
"""

import sqlite3
import os
import sys

def get_db_connection(db_path='config/url_checker.db'):
    """Connect to the SQLite database."""
    if not os.path.exists(db_path):
        print(f"Database file not found: {db_path}")
        sys.exit(1)
    
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn

def check_database():
    """Check the contents of the database tables."""
    db_path = 'config/url_checker.db'
    
    if not os.path.exists(db_path):
        print(f"Database file not found at expected location: {db_path}")
        if os.path.exists('url_checker.db'):
            db_path = 'url_checker.db'
            print(f"Using database at alternate location: {db_path}")
        else:
            print("Database file not found. Please specify the path to the database.")
            sys.exit(1)
    
    print(f"Using database: {db_path}")
    
    conn = get_db_connection(db_path)
    
    try:
        # Get list of tables
        tables = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%';"
        ).fetchall()
        
        # Check row count for each table
        for table in tables:
            table_name = table['name']
            count = conn.execute(f"SELECT COUNT(*) as count FROM {table_name}").fetchone()['count']
            print(f"Table {table_name}: {count} rows")
        
    except Exception as e:
        print(f"Error checking database: {e}")
    finally:
        conn.close()

if __name__ == "__main__":
    check_database()
