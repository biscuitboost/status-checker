#!/usr/bin/env python3
"""
Script to clear all test data from the URL checker database
while preserving the table structure.
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

def clear_database():
    """Clear all data from the database tables while preserving structure."""
    conn = get_db_connection()
    
    try:
        # Get list of tables
        tables = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%';"
        ).fetchall()
        
        # Begin transaction
        conn.execute("BEGIN TRANSACTION;")
        
        # Delete from each table
        for table in tables:
            table_name = table['name']
            print(f"Clearing data from table: {table_name}")
            conn.execute(f"DELETE FROM {table_name};")
        
        # Commit changes
        conn.execute("COMMIT;")
        print("All test data has been cleared successfully.")
        
    except Exception as e:
        # Rollback in case of error
        conn.execute("ROLLBACK;")
        print(f"Error clearing data: {e}")
    finally:
        conn.close()

if __name__ == "__main__":
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
    
    # Ask for confirmation
    confirm = input("This will delete ALL data from the database. Continue? (y/n): ")
    if confirm.lower() != 'y':
        print("Operation cancelled.")
        sys.exit(0)
    
    # Connect and clear
    conn = get_db_connection(db_path)
    
    try:
        # Get list of tables
        tables = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%';"
        ).fetchall()
        
        # Begin transaction
        conn.execute("BEGIN TRANSACTION;")
        
        # Delete from each table
        for table in tables:
            table_name = table['name']
            print(f"Clearing data from table: {table_name}")
            conn.execute(f"DELETE FROM {table_name};")
        
        # Commit changes
        conn.execute("COMMIT;")
        print("All test data has been cleared successfully.")
        
    except Exception as e:
        # Rollback in case of error
        conn.execute("ROLLBACK;")
        print(f"Error clearing data: {e}")
    finally:
        conn.close()
