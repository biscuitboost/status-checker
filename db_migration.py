#!/usr/bin/env python3
"""
Database Migration Script for Status Checker

This script updates the database schema to include error tracking fields in the domains table.
"""

import sqlite3
import os
import logging
from datetime import datetime

def get_db_connection():
    """Connect to the SQLite database"""
    db_path = 'config/url_checker.db'
    if not os.path.exists(os.path.dirname(db_path)):
        os.makedirs(os.path.dirname(db_path))
    
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn

def check_if_columns_exist(conn, table, columns):
    """Check if the specified columns exist in the table"""
    cursor = conn.cursor()
    cursor.execute(f"PRAGMA table_info({table})")
    table_info = cursor.fetchall()
    existing_columns = [column_info['name'] for column_info in table_info]
    
    return all(column in existing_columns for column in columns)

def migrate_database():
    """Apply database migrations"""
    conn = get_db_connection()
    
    try:
        # Check if error tracking columns exist in domains table
        error_tracking_columns = ['last_error', 'error_count', 'last_error_time']
        columns_exist = check_if_columns_exist(conn, 'domains', error_tracking_columns)
        
        if not columns_exist:
            print("Migrating database: Adding error tracking columns to domains table")
            
            # Add the new columns to the table
            conn.execute("ALTER TABLE domains ADD COLUMN last_error TEXT;")
            conn.execute("ALTER TABLE domains ADD COLUMN error_count INTEGER DEFAULT 0;")
            conn.execute("ALTER TABLE domains ADD COLUMN last_error_time TIMESTAMP;")
            
            # Initialize error_count based on existing errors
            conn.execute("""
                UPDATE domains
                SET error_count = (
                    SELECT COUNT(*)
                    FROM url_history
                    WHERE domain_url = domains.url
                    AND error IS NOT NULL
                    AND check_time >= datetime('now', '-1 day')
                )
            """)
            
            # Set the last error and last error time
            conn.execute("""
                UPDATE domains
                SET last_error = (
                    SELECT error
                    FROM url_history
                    WHERE domain_url = domains.url
                    AND error IS NOT NULL
                    ORDER BY check_time DESC
                    LIMIT 1
                ),
                last_error_time = (
                    SELECT check_time
                    FROM url_history
                    WHERE domain_url = domains.url
                    AND error IS NOT NULL
                    ORDER BY check_time DESC
                    LIMIT 1
                )
            """)
            
            conn.commit()
            print("Migration completed successfully!")
        else:
            print("No migration needed: Error tracking columns already exist")
    
    except Exception as e:
        conn.rollback()
        print(f"Migration failed: {e}")
        logging.error(f"Database migration error: {e}")
    
    finally:
        conn.close()

if __name__ == "__main__":
    migrate_database()
