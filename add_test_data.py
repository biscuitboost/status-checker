import sqlite3
import random
from datetime import datetime, timedelta

# Sample data
applications = ['WebApp', 'MobileAPI', 'AdminPortal', 'PaymentService', 'Analytics']
regions = ['EU', 'US', 'APAC']
environments = ['prod', 'staging', 'dev']

# Common website domains and paths
domains = [
    'api.{}.com', 'www.{}.com', '{}.com', 'admin.{}.com', 'dashboard.{}.com',
    'auth.{}.com', 'cdn.{}.com', 'static.{}.com', 'docs.{}.com', 'blog.{}.com'
]

companies = [
    'acme', 'globex', 'initech', 'umbrella', 'cyberdyne',
    'hooli', 'piedpiper', 'dunder', 'wayne', 'stark',
    'oscorp', 'aperture', 'tyrell', 'weyland', 'massive'
]

def generate_unique_urls(count):
    urls = set()
    while len(urls) < count:
        company = random.choice(companies)
        domain_template = random.choice(domains)
        url = 'https://' + domain_template.format(company)
        urls.add(url)
    return list(urls)

def generate_random_data():
    # 80% chance of being a working URL
    is_working = random.random() < 0.8
    
    now = datetime.now()
    check_time = now - timedelta(minutes=random.randint(1, 60))
    
    if is_working:
        status_code = 200
        response_time = random.uniform(0.1, 2.0)
        error = None
    else:
        status_code = random.choice([404, 500, 502, 503, None])
        response_time = None
        error = "Connection failed" if status_code is None else f"HTTP {status_code}"
    
    # SSL expiry between 1 month ago and 1 year from now
    days_offset = random.randint(-30, 365)
    ssl_expiry = now + timedelta(days=days_offset)
    ssl_valid = days_offset > 0
    
    return {
        'status_code': status_code,
        'response_time': response_time,
        'error': error,
        'check_time': check_time,
        'ssl_expiry': ssl_expiry,
        'ssl_valid': ssl_valid
    }

def add_test_data():
    conn = sqlite3.connect('config/url_checker.db')
    cursor = conn.cursor()
    
    # Clear existing data
    cursor.execute('DELETE FROM url_history')
    cursor.execute('DELETE FROM domains')
    conn.commit()
    
    # Generate 50 unique URLs
    urls = generate_unique_urls(50)
    
    # Add each URL with random data
    for url in urls:
        application = random.choice(applications)
        region = random.choice(regions)
        environment = random.choice(environments)
        
        # Add domain
        cursor.execute('''
            INSERT INTO domains (url, application, region, environment, active)
            VALUES (?, ?, ?, ?, 1)
        ''', (url, application, region, environment))
        
        # Add history entry
        data = generate_random_data()
        cursor.execute('''
            INSERT INTO url_history (
                domain_url, check_time, status_code, response_time, 
                error, ssl_expiry, ssl_valid
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            url,
            data['check_time'].strftime('%Y-%m-%d %H:%M:%S'),
            data['status_code'],
            data['response_time'],
            data['error'],
            data['ssl_expiry'].strftime('%Y-%m-%d %H:%M:%S'),
            data['ssl_valid']
        ))
    
    conn.commit()
    conn.close()
    print(f"Added {len(urls)} test URLs to the database.")

if __name__ == '__main__':
    add_test_data()
