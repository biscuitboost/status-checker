from flask import Flask, render_template, jsonify, redirect, url_for, request, flash
import sqlite3
from datetime import datetime, timedelta
import threading
import time
import requests
import logging
import os
from dotenv import load_dotenv
from notifications import (
    send_alert, send_sla_report, is_in_maintenance, get_custom_thresholds,
    calculate_sla
)
from auth import get_auth_headers

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY', 'your-secret-key-here')

def init_db():
    conn = get_db_connection()
    c = conn.cursor()
    
    c.execute('''
        CREATE TABLE IF NOT EXISTS domains (
            url TEXT PRIMARY KEY,
            application TEXT,
            region TEXT,
            environment TEXT,
            active INTEGER DEFAULT 1,
            last_error TEXT,
            error_count INTEGER DEFAULT 0,
            last_error_time TIMESTAMP
        )
    ''')
    
    c.execute('''
        CREATE TABLE IF NOT EXISTS url_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain_url TEXT,
            check_time TIMESTAMP,
            status_code INTEGER,
            response_time REAL,
            error TEXT,
            ssl_expiry TIMESTAMP,
            ssl_valid INTEGER,
            FOREIGN KEY (domain_url) REFERENCES domains (url)
        )
    ''')
    
    c.execute('''
        CREATE TABLE IF NOT EXISTS alert_config (
            id INTEGER PRIMARY KEY,
            response_time_warning INTEGER,
            response_time_critical INTEGER,
            ssl_expiry_warning INTEGER,
            ssl_expiry_critical INTEGER,
            updated_at TIMESTAMP
        )
    ''')
    
    c.execute('''
        CREATE TABLE IF NOT EXISTS alert_contacts (
            id INTEGER PRIMARY KEY,
            name TEXT,
            email TEXT UNIQUE
        )
    ''')
    
    c.execute('''
        CREATE TABLE IF NOT EXISTS group_alert_contacts (
            id INTEGER PRIMARY KEY,
            contact_id INTEGER,
            application TEXT,
            region TEXT,
            environment TEXT,
            notify_on_warning INTEGER,
            notify_on_critical INTEGER,
            FOREIGN KEY (contact_id) REFERENCES alert_contacts (id)
        )
    ''')
    
    c.execute('''
        CREATE TABLE IF NOT EXISTS maintenance_windows (
            id INTEGER PRIMARY KEY,
            url TEXT,
            application TEXT,
            region TEXT,
            environment TEXT,
            start_time TIMESTAMP,
            end_time TIMESTAMP,
            description TEXT,
            created_by TEXT
        )
    ''')
    
    c.execute('''
        CREATE TABLE IF NOT EXISTS custom_alert_thresholds (
            id INTEGER PRIMARY KEY,
            url TEXT,
            application TEXT,
            region TEXT,
            environment TEXT,
            response_time_warning INTEGER,
            response_time_critical INTEGER,
            ssl_expiry_warning INTEGER,
            ssl_expiry_critical INTEGER
        )
    ''')
    
    c.execute('''
        CREATE TABLE IF NOT EXISTS custom_headers (
            id INTEGER PRIMARY KEY,
            url TEXT,
            header_name TEXT,
            header_value TEXT,
            is_auth_header INTEGER
        )
    ''')
    
    c.execute('''
        CREATE TABLE IF NOT EXISTS group_auth_config (
            id INTEGER PRIMARY KEY,
            application TEXT,
            region TEXT,
            environment TEXT,
            auth_url TEXT,
            auth_username TEXT,
            auth_password TEXT
        )
    ''')
    
    try:
        c.execute('''
            INSERT OR IGNORE INTO alert_config (
                id, response_time_warning, response_time_critical,
                ssl_expiry_warning, ssl_expiry_critical
            ) VALUES (
                1, 1000, 2000, 30, 7
            )
        ''')
        conn.commit()
    except Exception as e:
        logging.error(f"Error initializing database: {e}")
        raise
    finally:
        conn.close()

def get_db_connection():
    conn = sqlite3.connect('config/url_checker.db')
    conn.row_factory = sqlite3.Row
    return conn

# Get or create alert configuration
def get_alert_config():
    conn = get_db_connection()
    try:
        cursor = conn.execute('SELECT * FROM alert_config ORDER BY id DESC LIMIT 1')
        config = cursor.fetchone()
        
        if not config:
            # Create default config if none exists
            cursor.execute('''
                INSERT INTO alert_config (
                    response_time_warning, response_time_critical,
                    ssl_expiry_warning, ssl_expiry_critical
                ) VALUES (?, ?, ?, ?)
            ''', (1000, 2000, 30, 7))
            conn.commit()
            
            cursor = conn.execute('SELECT * FROM alert_config ORDER BY id DESC LIMIT 1')
            config = cursor.fetchone()
        
        return dict(config)
    finally:
        conn.close()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/group/<application>/<region>/<environment>')
def group_view(application, region, environment):
    return render_template('group.html', 
                         application=application, 
                         region=region, 
                         environment=environment)

@app.route('/api/groups')
def get_groups():
    conn = get_db_connection()
    try:
        groups = conn.execute('''
            SELECT DISTINCT application, region, environment,
                   COUNT(*) as url_count,
                   SUM(CASE WHEN h.error IS NULL AND h.status_code < 400 THEN 1 ELSE 0 END) as healthy_count
            FROM domains d
            LEFT JOIN url_history h ON d.url = h.domain_url
            AND h.check_time = (
                SELECT MAX(check_time)
                FROM url_history
                WHERE domain_url = d.url
            )
            WHERE d.active = 1
            GROUP BY application, region, environment
        ''').fetchall()
        
        result = []
        for group in groups:
            result.append({
                'application': group['application'],
                'region': group['region'],
                'environment': group['environment'],
                'url_count': group['url_count'],
                'healthy_count': group['healthy_count']
            })
        
        return jsonify(result)
    finally:
        conn.close()

@app.route('/api/urls')
def get_urls():
    conn = get_db_connection()
    try:
        urls = conn.execute('''
            SELECT d.url, d.application, d.region, d.environment, d.active,
                   h.status_code, h.response_time, h.check_time, h.error,
                   h.ssl_expiry, h.ssl_valid,
                   (SELECT AVG(response_time)
                    FROM url_history h2
                    WHERE h2.domain_url = d.url
                    AND h2.check_time >= datetime('now', '-1 hour')
                   ) as avg_response_time,
                   d.error_count, d.last_error_time
            FROM domains d
            LEFT JOIN url_history h ON d.url = h.domain_url
            AND h.check_time = (
                SELECT MAX(check_time)
                FROM url_history
                WHERE domain_url = d.url
            )
            ORDER BY d.application, d.region, d.environment
        ''').fetchall()
        
        result = []
        for url in urls:
            result.append({
                'url': url['url'],
                'application': url['application'],
                'region': url['region'],
                'environment': url['environment'],
                'active': bool(url['active']),
                'status_code': url['status_code'],
                'response_time': url['response_time'],
                'avg_response_time': url['avg_response_time'],
                'last_check': url['check_time'],
                'error': url['error'],
                'error_count': url['error_count'],
                'last_error_time': url['last_error_time'],
                'ssl_expiry': url['ssl_expiry'],
                'ssl_valid': bool(url['ssl_valid']) if url['ssl_valid'] is not None else None
            })
        
        return jsonify(result)
    except Exception as e:
        logging.error(f"Error getting URLs: {e}")
        return jsonify({'error': str(e)}), 500
    finally:
        conn.close()

@app.route('/api/urls/<application>/<region>/<environment>')
def get_group_urls(application, region, environment):
    conn = get_db_connection()
    try:
        urls_data = []
        
        # Get all domains for this group
        domains = conn.execute('''
            SELECT url, application, region, environment, active,
                   last_error, error_count, last_error_time
            FROM domains
            WHERE application = ? AND region = ? AND environment = ?
            ORDER BY url
        ''', (application, region, environment)).fetchall()
        
        for domain in domains:
            # Get the latest status for each domain
            latest_status = conn.execute('''
                SELECT status_code, response_time, check_time, error,
                       ssl_expiry, ssl_valid
                FROM url_history
                WHERE domain_url = ?
                ORDER BY check_time DESC
                LIMIT 1
            ''', (domain['url'],)).fetchone()
            
            # Get average response time for the last hour
            avg_response = conn.execute('''
                SELECT AVG(response_time) as avg_response_time
                FROM url_history
                WHERE domain_url = ?
                AND check_time >= datetime('now', '-1 hour')
                AND response_time IS NOT NULL
            ''', (domain['url'],)).fetchone()
            
            url_entry = {
                'url': domain['url'],
                'application': domain['application'],
                'region': domain['region'],
                'environment': domain['environment'],
                'active': bool(domain['active']),
                'error_count': domain['error_count'] if 'error_count' in domain.keys() else 0,
                'last_error_time': domain['last_error_time'] if 'last_error_time' in domain.keys() else None
            }
            
            if latest_status:
                url_entry.update({
                    'status_code': latest_status['status_code'],
                    'response_time': latest_status['response_time'],
                    'last_check': latest_status['check_time'],
                    'error': latest_status['error'] or (domain['last_error'] if 'last_error' in domain.keys() else None),
                    'ssl_expiry': latest_status['ssl_expiry'],
                    'ssl_valid': bool(latest_status['ssl_valid']) if latest_status['ssl_valid'] is not None else None
                })
                
            if avg_response:
                url_entry['avg_response_time'] = avg_response['avg_response_time']
            
            urls_data.append(url_entry)
        
        # Log the data for debugging
        print(f"URLs data: {urls_data}")
        
        # Make sure we always return a list, even if empty
        return jsonify(urls_data if urls_data else [])
    except Exception as e:
        logging.error(f"Error getting URLs: {e}")
        print(f"Error in get_group_urls: {e}")
        return jsonify([]), 500
    finally:
        conn.close()

@app.route('/api/response-time-history/<application>/<region>/<environment>')
def get_response_time_history(application, region, environment):
    conn = get_db_connection()
    try:
        # Get all URLs in the group
        urls = conn.execute('''
            SELECT url FROM domains
            WHERE application = ? AND region = ? AND environment = ?
        ''', (application, region, environment)).fetchall()
        
        url_list = [url['url'] for url in urls]
        
        # Create result template
        result = {}
        for url in url_list:
            result[url] = []
        
        # Get response time history for the last hour for all URLs in the group
        history = conn.execute('''
            SELECT h.domain_url, h.check_time, h.response_time
            FROM url_history h
            JOIN domains d ON h.domain_url = d.url
            WHERE d.application = ? AND d.region = ? AND d.environment = ?
            AND h.check_time >= datetime('now', '-1 hour')
            AND h.response_time IS NOT NULL
            ORDER BY h.check_time
        ''', (application, region, environment)).fetchall()
        
        # Organize data by URL
        for entry in history:
            if entry['domain_url'] in result:
                result[entry['domain_url']].append({
                    'timestamp': entry['check_time'],
                    'response_time': entry['response_time']
                })
        
        return jsonify(result)
    except Exception as e:
        logging.error(f"Error getting response time history: {e}")
        return jsonify({'error': str(e)}), 500
    finally:
        conn.close()

@app.route('/api/stats')
def get_stats():
    conn = get_db_connection()
    try:
        # Get all URLs and their latest check
        cursor = conn.execute('''
            WITH LatestChecks AS (
                SELECT domain_url, MAX(check_time) as max_check_time
                FROM url_history
                GROUP BY domain_url
            )
            SELECT 
                d.url,
                h.status_code,
                h.response_time,
                h.ssl_expiry,
                h.ssl_valid
            FROM domains d
            LEFT JOIN LatestChecks lc ON d.url = lc.domain_url
            LEFT JOIN url_history h ON lc.domain_url = h.domain_url 
                AND lc.max_check_time = h.check_time
            WHERE d.active = 1
        ''')
        urls = cursor.fetchall()

        # Calculate total and active URLs
        total_urls = len(urls)
        active_urls = sum(1 for url in urls if url['status_code'] == 200)

        # Calculate status breakdown
        status_breakdown = {
            'green': sum(1 for url in urls if url['status_code'] == 200),
            'amber': sum(1 for url in urls if url['status_code'] and url['status_code'] != 200),
            'red': sum(1 for url in urls if not url['status_code'])
        }

        # Calculate SSL breakdown
        now = datetime.now()
        ssl_breakdown = {
            'green': 0,  # Valid and expires in > 30 days
            'amber': 0,  # Valid but expires in <= 30 days
            'red': 0     # Invalid or expired
        }
        
        for url in urls:
            if not url['ssl_expiry']:
                ssl_breakdown['red'] += 1
            else:
                expiry = datetime.strptime(url['ssl_expiry'], '%Y-%m-%d %H:%M:%S')
                days_until_expiry = (expiry - now).days
                if days_until_expiry <= 0:
                    ssl_breakdown['red'] += 1
                elif days_until_expiry <= 30:
                    ssl_breakdown['amber'] += 1
                else:
                    ssl_breakdown['green'] += 1

        # Get error count in last 24h
        cursor = conn.execute('''
            SELECT COUNT(*) as count
            FROM url_history
            WHERE check_time >= datetime('now', '-1 day')
            AND (status_code >= 400 OR status_code IS NULL)
        ''')
        error_count = cursor.fetchone()['count']

        # Calculate average response times per group
        cursor = conn.execute('''
            WITH LatestChecks AS (
                SELECT domain_url, MAX(check_time) as max_check_time
                FROM url_history
                GROUP BY domain_url
            )
            SELECT 
                d.application || ' - ' || d.region || ' - ' || d.environment as group_name,
                AVG(h.response_time) as avg_response_time,
                MIN(h.response_time) as min_response_time,
                MAX(h.response_time) as max_response_time
            FROM domains d
            LEFT JOIN LatestChecks lc ON d.url = lc.domain_url
            LEFT JOIN url_history h ON lc.domain_url = h.domain_url 
                AND lc.max_check_time = h.check_time
            WHERE d.active = 1
            GROUP BY d.application, d.region, d.environment
        ''')
        response_times = {row['group_name']: {
            'avg': row['avg_response_time'],
            'min': row['min_response_time'],
            'max': row['max_response_time']
        } for row in cursor.fetchall()}

        return jsonify({
            'total_urls': total_urls,
            'active_urls': active_urls,
            'error_count_24h': error_count,
            'avg_response_times': response_times,
            'status_breakdown': status_breakdown,
            'ssl_breakdown': ssl_breakdown
        })
    except Exception as e:
        logging.error(f"Error getting stats: {e}")
        return jsonify({'error': str(e)}), 500
    finally:
        conn.close()

@app.route('/api/stats/<application>/<region>/<environment>')
def get_group_stats(application, region, environment):
    conn = get_db_connection()
    try:
        # Get total URLs and active URLs for the group
        url_stats = conn.execute('''
            SELECT COUNT(*) as total,
                   SUM(CASE WHEN active = 1 THEN 1 ELSE 0 END) as active
            FROM domains
            WHERE application = ? AND region = ? AND environment = ?
        ''', (application, region, environment)).fetchone()
        
        # Get error count in last 24 hours for the group
        error_count = conn.execute('''
            SELECT COUNT(*) as count
            FROM url_history h
            JOIN domains d ON h.domain_url = d.url
            WHERE d.application = ? AND d.region = ? AND d.environment = ?
            AND h.error IS NOT NULL
            AND h.check_time >= datetime('now', '-1 day')
        ''', (application, region, environment)).fetchone()
        
        # Get average response time for the group in the last hour
        perf_stats = conn.execute('''
            SELECT AVG(h.response_time) as avg_time,
                   MIN(h.response_time) as min_time,
                   MAX(h.response_time) as max_time
            FROM domains d
            JOIN url_history h ON d.url = h.domain_url
            WHERE d.application = ? AND d.region = ? AND d.environment = ?
            AND h.check_time >= datetime('now', '-1 hour')
            AND h.response_time IS NOT NULL
        ''', (application, region, environment)).fetchone()
        
        # Get SSL stats
        ssl_stats = conn.execute('''
            SELECT COUNT(*) as total,
                   SUM(CASE WHEN h.ssl_valid = 1 THEN 1 ELSE 0 END) as valid
            FROM (
                SELECT domain_url, MAX(check_time) as latest_check
                FROM url_history
                GROUP BY domain_url
            ) latest
            JOIN url_history h ON h.domain_url = latest.domain_url 
                AND h.check_time = latest.latest_check
            JOIN domains d ON d.url = h.domain_url
            WHERE d.application = ? AND d.region = ? AND d.environment = ?
        ''', (application, region, environment)).fetchone()
        
        return jsonify({
            'urls': {
                'total': url_stats['total'],
                'active': url_stats['active']
            },
            'errors': {
                'last_24h': error_count['count']
            },
            'performance': {
                'avg_response_time': perf_stats['avg_time'],
                'min_response_time': perf_stats['min_time'],
                'max_response_time': perf_stats['max_time']
            },
            'ssl': {
                'total': ssl_stats['total'],
                'valid': ssl_stats['valid']
            }
        })
    except Exception as e:
        logging.error(f"Error getting group stats: {e}")
        return jsonify({'error': str(e)}), 500
    finally:
        conn.close()

@app.route('/api/errors/<application>/<region>/<environment>')
def get_error_history(application, region, environment):
    conn = get_db_connection()
    try:
        # Get errors from the last 24 hours with counts
        errors = []
        
        # First, get the unique errors with their latest occurrence
        unique_errors = conn.execute('''
            SELECT domain_url, error, MAX(check_time) as latest_check_time
            FROM url_history
            WHERE domain_url IN (
                SELECT url FROM domains 
                WHERE application = ? AND region = ? AND environment = ?
            )
            AND error IS NOT NULL
            AND check_time >= datetime('now', '-1 day')
            GROUP BY domain_url, error
            ORDER BY latest_check_time DESC
        ''', (application, region, environment)).fetchall()
        
        # For each unique error, get the latest record details
        for unique_error in unique_errors:
            latest_record = conn.execute('''
                SELECT h.domain_url, h.check_time, h.error,
                       h.status_code, h.response_time,
                       d.error_count
                FROM url_history h
                JOIN domains d ON h.domain_url = d.url
                WHERE h.domain_url = ? 
                AND h.error = ?
                AND h.check_time = ?
                LIMIT 1
            ''', (unique_error['domain_url'], unique_error['error'], unique_error['latest_check_time'])).fetchone()
            
            if latest_record:
                errors.append({
                    'url': latest_record['domain_url'],
                    'timestamp': latest_record['check_time'],
                    'error': latest_record['error'],
                    'status_code': latest_record['status_code'],
                    'response_time': latest_record['response_time'],
                    'error_count': latest_record['error_count'] if 'error_count' in latest_record.keys() else 1
                })
        
        # Log the data for debugging
        print(f"Error history data: {errors}")
        
        # Make sure we always return a list, even if empty
        return jsonify(errors if errors else [])
    except Exception as e:
        logging.error(f"Error getting error history: {e}")
        print(f"Error in get_error_history: {e}")
        return jsonify([]), 500
    finally:
        conn.close()

@app.route('/admin')
def admin():
    conn = get_db_connection()
    try:
        # Get existing URLs
        cursor = conn.execute('SELECT * FROM domains ORDER BY application, region, environment')
        urls = cursor.fetchall()
        
        # Get alert configuration
        cursor = conn.execute('SELECT * FROM alert_config LIMIT 1')
        alert_config = cursor.fetchone()
        
        # Get group authentication configurations
        cursor = conn.execute('''
            SELECT id, application, region, environment, auth_url, auth_username 
            FROM group_auth_config 
            ORDER BY application, region, environment
        ''')
        group_auth_configs = cursor.fetchall()
        
        # Get unique groups (application, region, environment combinations)
        cursor = conn.execute('''
            SELECT DISTINCT application, region, environment 
            FROM domains 
            ORDER BY application, region, environment
        ''')
        groups = cursor.fetchall()
        
        # Get alert contacts
        cursor = conn.execute('SELECT * FROM alert_contacts ORDER BY name')
        contacts = cursor.fetchall()
        
        return render_template('admin.html', 
                             urls=urls, 
                             alert_config=alert_config,
                             group_auth_configs=group_auth_configs,
                             groups=groups,
                             contacts=contacts)
    finally:
        conn.close()

@app.route('/admin/urls/add', methods=['POST'])
def add_url():
    url = request.form.get('url')
    application = request.form.get('application')
    region = request.form.get('region')
    environment = request.form.get('environment')
    
    if not all([url, application, region, environment]):
        flash('All fields are required', 'error')
        return redirect('/admin')
    
    conn = get_db_connection()
    try:
        # Check if URL already exists
        cursor = conn.execute('SELECT url FROM domains WHERE url = ?', (url,))
        if cursor.fetchone():
            flash('URL already exists', 'error')
            return redirect('/admin')
        
        # Add new URL
        conn.execute('''
            INSERT INTO domains (url, application, region, environment, active)
            VALUES (?, ?, ?, ?, 1)
        ''', (url, application, region, environment))
        conn.commit()
        flash('URL added successfully')
    except Exception as e:
        flash(f'Error adding URL: {str(e)}', 'error')
    finally:
        conn.close()
    
    return redirect('/admin')

@app.route('/admin/urls/toggle', methods=['POST'])
def toggle_url():
    url = request.form.get('url')
    if not url:
        flash('URL is required', 'error')
        return redirect('/admin')
    
    conn = get_db_connection()
    try:
        # Toggle active status
        conn.execute('''
            UPDATE domains 
            SET active = CASE WHEN active = 1 THEN 0 ELSE 1 END 
            WHERE url = ?
        ''', (url,))
        conn.commit()
        flash('URL status updated successfully')
    except Exception as e:
        flash(f'Error updating URL: {str(e)}', 'error')
    finally:
        conn.close()
    
    return redirect('/admin')

@app.route('/admin/urls/delete', methods=['POST'])
def delete_url():
    url = request.form.get('url')
    if not url:
        flash('URL is required', 'error')
        return redirect('/admin')
    
    conn = get_db_connection()
    try:
        # Delete URL and its history
        conn.execute('DELETE FROM url_history WHERE domain_url = ?', (url,))
        conn.execute('DELETE FROM domains WHERE url = ?', (url,))
        conn.commit()
        flash('URL deleted successfully')
    except Exception as e:
        flash(f'Error deleting URL: {str(e)}', 'error')
    finally:
        conn.close()
    
    return redirect('/admin')

@app.route('/admin/alerts/update', methods=['POST'])
def update_alerts():
    try:
        response_time_warning = int(request.form.get('response_time_warning', 1000))
        response_time_critical = int(request.form.get('response_time_critical', 2000))
        ssl_expiry_warning = int(request.form.get('ssl_expiry_warning', 30))
        ssl_expiry_critical = int(request.form.get('ssl_expiry_critical', 7))
        
        conn = get_db_connection()
        try:
            conn.execute('''
                INSERT OR REPLACE INTO alert_config (
                    id, response_time_warning, response_time_critical,
                    ssl_expiry_warning, ssl_expiry_critical,
                    updated_at
                ) VALUES (
                    1, ?, ?, ?, ?,
                    CURRENT_TIMESTAMP
                )
            ''', (response_time_warning, response_time_critical, 
                  ssl_expiry_warning, ssl_expiry_critical))
            conn.commit()
            flash('Alert configuration updated successfully')
        finally:
            conn.close()
    except ValueError:
        flash('Invalid values provided. Please enter numbers only.', 'error')
    except Exception as e:
        flash(f'Error updating alert configuration: {str(e)}', 'error')
    
    return redirect('/admin')

@app.route('/admin/contacts/add', methods=['POST'])
def add_contact():
    name = request.form.get('name')
    email = request.form.get('email')
    
    if not all([name, email]):
        flash('Name and email are required', 'error')
        return redirect('/admin')
    
    conn = get_db_connection()
    try:
        # Check if email already exists
        cursor = conn.execute('SELECT email FROM alert_contacts WHERE email = ?', (email,))
        if cursor.fetchone():
            flash('Email already exists', 'error')
            return redirect('/admin')
        
        # Add new contact
        conn.execute('''
            INSERT INTO alert_contacts (name, email)
            VALUES (?, ?)
        ''', (name, email))
        conn.commit()
        flash('Contact added successfully')
    except Exception as e:
        flash(f'Error adding contact: {str(e)}', 'error')
    finally:
        conn.close()
    
    return redirect('/admin')

@app.route('/admin/contacts/delete', methods=['POST'])
def delete_contact():
    contact_id = request.form.get('contact_id')
    if not contact_id:
        flash('Contact ID is required', 'error')
        return redirect('/admin')
    
    conn = get_db_connection()
    try:
        # Delete contact and their group assignments
        conn.execute('DELETE FROM group_alert_contacts WHERE contact_id = ?', (contact_id,))
        conn.execute('DELETE FROM alert_contacts WHERE id = ?', (contact_id,))
        conn.commit()
        flash('Contact deleted successfully')
    except Exception as e:
        flash(f'Error deleting contact: {str(e)}', 'error')
    finally:
        conn.close()
    
    return redirect('/admin')

@app.route('/admin/contacts/<int:contact_id>/groups')
def get_contact_groups(contact_id):
    conn = get_db_connection()
    try:
        cursor = conn.execute('''
            SELECT 
                d.application || '_' || d.region || '_' || d.environment as group_id,
                gac.notify_on_warning,
                gac.notify_on_critical
            FROM domains d
            LEFT JOIN group_alert_contacts gac ON 
                gac.application = d.application AND
                gac.region = d.region AND
                gac.environment = d.environment AND
                gac.contact_id = ?
            GROUP BY d.application, d.region, d.environment
        ''', (contact_id,))
        assignments = []
        for row in cursor.fetchall():
            assignments.append({
                'group_id': row[0],
                'notify_on_warning': bool(row[1]) if row[1] is not None else False,
                'notify_on_critical': bool(row[2]) if row[2] is not None else False
            })
        return jsonify(assignments)
    finally:
        conn.close()

@app.route('/admin/contacts/assign-groups', methods=['POST'])
def assign_groups():
    contact_id = request.form.get('contact_id')
    if not contact_id:
        flash('Contact ID is required', 'error')
        return redirect('/admin')
    
    conn = get_db_connection()
    try:
        # Get all groups
        cursor = conn.execute('''
            SELECT DISTINCT application, region, environment 
            FROM domains
        ''')
        groups = cursor.fetchall()
        
        # Delete existing assignments for this contact
        conn.execute('DELETE FROM group_alert_contacts WHERE contact_id = ?', (contact_id,))
        
        # Add new assignments
        for group in groups:
            group_id = f"{group['application']}_{group['region']}_{group['environment']}"
            notify_warning = request.form.get(f'group_{group_id}_warning') == 'on'
            notify_critical = request.form.get(f'group_{group_id}_critical') == 'on'
            
            if notify_warning or notify_critical:
                conn.execute('''
                    INSERT INTO group_alert_contacts (
                        contact_id, application, region, environment,
                        notify_on_warning, notify_on_critical
                    ) VALUES (?, ?, ?, ?, ?, ?)
                ''', (contact_id, group['application'], group['region'], 
                      group['environment'], notify_warning, notify_critical))
        
        conn.commit()
        flash('Group assignments updated successfully')
    except Exception as e:
        flash(f'Error updating group assignments: {str(e)}', 'error')
    finally:
        conn.close()
    
    return redirect('/admin')

@app.route('/admin/auth/add', methods=['POST'])
def add_group_auth():
    application = request.form.get('application')
    region = request.form.get('region')
    environment = request.form.get('environment')
    auth_url = request.form.get('auth_url')
    auth_username = request.form.get('auth_username')
    auth_password = request.form.get('auth_password')
    
    if not all([application, region, environment, auth_url, auth_username, auth_password]):
        flash('All fields are required', 'error')
        return redirect('/admin')
    
    conn = get_db_connection()
    try:
        # Check if configuration already exists
        cursor = conn.execute('''
            SELECT id FROM group_auth_config 
            WHERE application = ? AND region = ? AND environment = ?
        ''', (application, region, environment))
        existing = cursor.fetchone()
        
        if existing:
            # Update existing configuration
            conn.execute('''
                UPDATE group_auth_config 
                SET auth_url = ?, auth_username = ?, auth_password = ?
                WHERE application = ? AND region = ? AND environment = ?
            ''', (auth_url, auth_username, auth_password, 
                  application, region, environment))
            flash('Group authentication configuration updated successfully')
        else:
            # Insert new configuration
            conn.execute('''
                INSERT INTO group_auth_config (
                    application, region, environment,
                    auth_url, auth_username, auth_password
                ) VALUES (?, ?, ?, ?, ?, ?)
            ''', (application, region, environment,
                  auth_url, auth_username, auth_password))
            flash('Group authentication configuration added successfully')
        
        conn.commit()
    except Exception as e:
        flash(f'Error saving group authentication: {str(e)}', 'error')
    finally:
        conn.close()
    
    return redirect('/admin')

@app.route('/admin/auth/delete', methods=['POST'])
def delete_group_auth():
    auth_id = request.form.get('id')
    if not auth_id:
        flash('Authentication ID is required', 'error')
        return redirect('/admin')
    
    conn = get_db_connection()
    try:
        conn.execute('DELETE FROM group_auth_config WHERE id = ?', (auth_id,))
        conn.commit()
        flash('Group authentication configuration deleted successfully')
    except Exception as e:
        flash(f'Error deleting group authentication: {str(e)}', 'error')
    finally:
        conn.close()
    
    return redirect('/admin')

def get_alert_contacts(application, region, environment, is_critical=False):
    """Get alert contacts for a specific group and alert level"""
    conn = get_db_connection()
    try:
        cursor = conn.execute('''
            SELECT ac.name, ac.email
            FROM alert_contacts ac
            JOIN group_alert_contacts gac ON ac.id = gac.contact_id
            WHERE gac.application = ? AND gac.region = ? AND gac.environment = ?
            AND (? = 1 AND gac.notify_on_critical = 1 OR ? = 0 AND gac.notify_on_warning = 1)
        ''', (application, region, environment, is_critical, is_critical))
        return cursor.fetchall()
    finally:
        conn.close()

@app.route('/admin/maintenance/add', methods=['POST'])
def add_maintenance():
    url = request.form.get('url')
    application = request.form.get('application')
    region = request.form.get('region')
    environment = request.form.get('environment')
    start_time = request.form.get('start_time')
    end_time = request.form.get('end_time')
    description = request.form.get('description')
    created_by = request.form.get('created_by', 'admin')
    
    if not all([start_time, end_time]):
        flash('Start time and end time are required', 'error')
        return redirect('/admin')
    
    try:
        start = datetime.fromisoformat(start_time)
        end = datetime.fromisoformat(end_time)
        
        if end <= start:
            flash('End time must be after start time', 'error')
            return redirect('/admin')
        
        conn = get_db_connection()
        try:
            conn.execute('''
                INSERT INTO maintenance_windows (
                    url, application, region, environment,
                    start_time, end_time, description, created_by
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (url, application, region, environment, start, end, description, created_by))
            conn.commit()
            flash('Maintenance window added successfully')
        finally:
            conn.close()
    except ValueError as e:
        flash(f'Invalid date format: {str(e)}', 'error')
    except Exception as e:
        flash(f'Error adding maintenance window: {str(e)}', 'error')
    
    return redirect('/admin')

@app.route('/admin/maintenance/delete', methods=['POST'])
def delete_maintenance():
    maintenance_id = request.form.get('maintenance_id')
    if not maintenance_id:
        flash('Maintenance ID is required', 'error')
        return redirect('/admin')
    
    conn = get_db_connection()
    try:
        conn.execute('DELETE FROM maintenance_windows WHERE id = ?', (maintenance_id,))
        conn.commit()
        flash('Maintenance window deleted successfully')
    except Exception as e:
        flash(f'Error deleting maintenance window: {str(e)}', 'error')
    finally:
        conn.close()
    
    return redirect('/admin')

@app.route('/admin/thresholds/add', methods=['POST'])
def add_threshold():
    url = request.form.get('url')
    application = request.form.get('application')
    region = request.form.get('region')
    environment = request.form.get('environment')
    response_time_warning = request.form.get('response_time_warning')
    response_time_critical = request.form.get('response_time_critical')
    ssl_expiry_warning = request.form.get('ssl_expiry_warning')
    ssl_expiry_critical = request.form.get('ssl_expiry_critical')
    
    try:
        conn = get_db_connection()
        try:
            conn.execute('''
                INSERT OR REPLACE INTO custom_alert_thresholds (
                    url, application, region, environment,
                    response_time_warning, response_time_critical,
                    ssl_expiry_warning, ssl_expiry_critical
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (url, application, region, environment,
                  response_time_warning, response_time_critical,
                  ssl_expiry_warning, ssl_expiry_critical))
            conn.commit()
            flash('Alert thresholds updated successfully')
        finally:
            conn.close()
    except Exception as e:
        flash(f'Error updating alert thresholds: {str(e)}', 'error')
    
    return redirect('/admin')

@app.route('/admin/headers/add', methods=['POST'])
def add_header():
    url = request.form.get('url')
    header_name = request.form.get('header_name')
    header_value = request.form.get('header_value')
    is_auth_header = request.form.get('is_auth_header') == 'on'
    
    if not all([url, header_name, header_value]):
        flash('URL, header name, and value are required', 'error')
        return redirect('/admin')
    
    conn = get_db_connection()
    try:
        conn.execute('''
            INSERT INTO custom_headers (url, header_name, header_value, is_auth_header)
            VALUES (?, ?, ?, ?)
        ''', (url, header_name, header_value, is_auth_header))
        conn.commit()
        flash('Custom header added successfully')
    except Exception as e:
        flash(f'Error adding custom header: {str(e)}', 'error')
    finally:
        conn.close()
    
    return redirect('/admin')

@app.route('/admin/headers/delete', methods=['POST'])
def delete_header():
    header_id = request.form.get('header_id')
    if not header_id:
        flash('Header ID is required', 'error')
        return redirect('/admin')
    
    conn = get_db_connection()
    try:
        conn.execute('DELETE FROM custom_headers WHERE id = ?', (header_id,))
        conn.commit()
        flash('Custom header deleted successfully')
    except Exception as e:
        flash(f'Error deleting custom header: {str(e)}', 'error')
    finally:
        conn.close()
    
    return redirect('/admin')

@app.route('/sla/<application>')
def view_sla(application):
    period = request.args.get('period', 'monthly')
    end_date = datetime.now()
    
    if period == 'daily':
        start_date = end_date - timedelta(days=1)
    elif period == 'weekly':
        start_date = end_date - timedelta(weeks=1)
    elif period == 'monthly':
        start_date = end_date - timedelta(days=30)
    elif period == 'quarterly':
        start_date = end_date - timedelta(days=90)
    else:
        start_date = end_date - timedelta(days=365)
    
    conn = get_db_connection()
    try:
        # Get all URLs for this application
        cursor = conn.execute('''
            SELECT DISTINCT url, region, environment
            FROM domains
            WHERE application = ?
            AND active = 1
        ''', (application,))
        urls = cursor.fetchall()
        
        sla_data = []
        for url_info in urls:
            sla = calculate_sla(
                url_info['url'],
                application,
                url_info['region'],
                url_info['environment'],
                start_date,
                end_date
            )
            sla_data.append({
                'url': url_info['url'],
                'region': url_info['region'],
                'environment': url_info['environment'],
                **sla
            })
        
        return render_template('sla.html',
                             application=application,
                             period=period,
                             sla_data=sla_data,
                             start_date=start_date,
                             end_date=end_date)
    finally:
        conn.close()

def check_url_with_custom_config(url, application, region, environment, custom_thresholds=None):
    """Check URL with group-specific authentication and thresholds"""
    # Get authentication headers for this specific group
    headers = get_auth_headers(application, region, environment)
    
    try:
        start_time = time.time()
        response = requests.get(url, headers=headers, timeout=30, verify=True)
        response_time = (time.time() - start_time) * 1000  # Convert to milliseconds
        
        return {
            'status_code': response.status_code,
            'response_time': response_time,
            'ssl_expiry': None  # You'll need to implement SSL checking here
        }
    except requests.exceptions.RequestException as e:
        logging.error(f"Error checking URL {url}: {str(e)}")
        return {
            'status_code': None,
            'response_time': None,
            'ssl_expiry': None,
            'error': str(e)
        }

def check_urls():
    """Background task to check URLs"""
    while True:
        conn = get_db_connection()
        try:
            cursor = conn.execute('SELECT * FROM domains WHERE active = 1')
            domains = cursor.fetchall()
            
            for domain in domains:
                url = domain['url']
                application = domain['application']
                region = domain['region']
                environment = domain['environment']
                
                # Skip if in maintenance
                if is_in_maintenance(url, application, region, environment):
                    continue
                
                # Get custom thresholds
                custom_thresholds = get_custom_thresholds(url, application, region, environment)
                
                # Check URL with group-specific auth
                result = check_url_with_custom_config(
                    url, application, region, environment, custom_thresholds
                )
                
                # Use custom thresholds if available, otherwise use global thresholds
                thresholds = custom_thresholds or get_alert_config()
                
                # Store result
                conn.execute('''
                    INSERT INTO url_history (
                        domain_url, status_code, response_time, ssl_expiry, error
                    ) VALUES (?, ?, ?, ?, ?)
                ''', (url, result['status_code'], result['response_time'],
                      result['ssl_expiry'], result.get('error')))
                
                # Update error count and last error time
                if result.get('error'):
                    conn.execute('''
                        UPDATE domains
                        SET error_count = error_count + 1,
                            last_error_time = CURRENT_TIMESTAMP
                        WHERE url = ?
                    ''', (url,))
                
                # Check for alerts
                if result['response_time']:
                    if result['response_time'] >= thresholds['response_time_critical']:
                        contacts = get_alert_contacts(application, region, environment, is_critical=True)
                        send_alert('critical', url, application, region, environment,
                                 'High Response Time', f"{result['response_time']:.2f}ms",
                                 f"{thresholds['response_time_critical']}ms", contacts)
                    elif result['response_time'] >= thresholds['response_time_warning']:
                        contacts = get_alert_contacts(application, region, environment, is_critical=False)
                        send_alert('warning', url, application, region, environment,
                                 'High Response Time', f"{result['response_time']:.2f}ms",
                                 f"{thresholds['response_time_warning']}ms", contacts)
                
                conn.commit()
            
        except Exception as e:
            logging.error(f"Error in check_urls: {e}")
        finally:
            conn.close()
        
        time.sleep(60)  # Check every minute

def run_dashboard(host='localhost', port=5001):
    # Set up logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    
    # Initialize the database
    init_db()
    
    # Start the Flask app
    app.run(host=host, port=port, debug=False)

if __name__ == '__main__':
    run_dashboard()
