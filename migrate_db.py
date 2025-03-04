import sqlite3
import logging

def migrate_database():
    logging.basicConfig(level=logging.INFO)
    conn = sqlite3.connect('config/url_checker.db')
    
    try:
        # Add ssl_expiry column
        conn.execute('ALTER TABLE url_history ADD COLUMN ssl_expiry TIMESTAMP')
        logging.info("Added ssl_expiry column")
        
        # Add ssl_valid column
        conn.execute('ALTER TABLE url_history ADD COLUMN ssl_valid INTEGER')
        logging.info("Added ssl_valid column")
        
        conn.commit()
        logging.info("Database migration completed successfully")
    except sqlite3.OperationalError as e:
        if "duplicate column name" in str(e).lower():
            logging.info("Columns already exist, skipping migration")
        else:
            logging.error(f"Error during migration: {e}")
            raise
    finally:
        conn.close()

if __name__ == '__main__':
    migrate_database()
