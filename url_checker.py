import requests
import logging
from datetime import datetime
from typing import Dict, List, Optional
import socket
import ssl
from urllib.parse import urlparse
import time
import sqlite3
from dataclasses import dataclass
import argparse
import sys
import json
import os
import subprocess
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

@dataclass
class URLStatus:
    url: str
    status_code: Optional[int] = None
    response_time: Optional[float] = None
    error: Optional[str] = None
    check_time: Optional[datetime] = None
    ssl_expiry: Optional[datetime] = None
    ssl_valid: Optional[bool] = None
    metadata: Optional[Dict] = None

    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}

class DatabaseManager:
    def __init__(self, db_path: str = 'config/url_checker.db'):
        self.db_path = db_path
        self.conn = None
        self.connect()
        self._init_db()

    def connect(self):
        if not self.conn:
            self.conn = sqlite3.connect(self.db_path)
            self.conn.row_factory = sqlite3.Row

    def close(self):
        if self.conn:
            self.conn.close()
            self.conn = None

    def _init_db(self):
        self.connect()
        self.conn.execute('''
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
        
        self.conn.execute('''
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

        # Add example URLs if the table is empty
        if self.conn.execute('SELECT COUNT(*) FROM domains').fetchone()[0] == 0:
            example_urls = [
                ('https://api.example.com/users', 'UserService', 'US', 'production'),
                ('https://api.example.com/orders', 'OrderService', 'US', 'production'),
                ('https://api.example.com/payments', 'PaymentService', 'US', 'production'),
                ('https://api.example.com/inventory', 'InventoryService', 'US', 'production'),
                ('https://api.example.com/shipping', 'ShippingService', 'US', 'production'),
                ('https://staging-api.example.com/users', 'UserService', 'US', 'staging'),
                ('https://staging-api.example.com/orders', 'OrderService', 'US', 'staging'),
                ('https://staging-api.example.com/payments', 'PaymentService', 'US', 'staging'),
                ('https://eu-api.example.com/users', 'UserService', 'EU', 'production'),
                ('https://eu-api.example.com/orders', 'OrderService', 'EU', 'production'),
                ('https://eu-api.example.com/payments', 'PaymentService', 'EU', 'production'),
                ('https://eu-staging-api.example.com/users', 'UserService', 'EU', 'staging'),
                ('https://eu-staging-api.example.com/orders', 'OrderService', 'EU', 'staging'),
                ('https://monitoring.example.com', 'Monitoring', 'US', 'production'),
                ('https://logging.example.com', 'Logging', 'US', 'production'),
                ('https://metrics.example.com', 'Metrics', 'US', 'production'),
                ('https://auth.example.com', 'Auth', 'US', 'production'),
                ('https://cdn.example.com', 'CDN', 'US', 'production'),
                ('https://search.example.com', 'Search', 'US', 'production'),
                ('https://analytics.example.com', 'Analytics', 'US', 'production')
            ]
            
            for url, app, region, env in example_urls:
                self.conn.execute('''
                    INSERT OR REPLACE INTO domains (url, application, region, environment, active)
                    VALUES (?, ?, ?, ?, 1)
                ''', (url, app, region, env))
            
            self.conn.commit()
            logging.info(f"Added {len(example_urls)} example URLs to the database")

    def add_domain(self, url: str, metadata: Dict) -> bool:
        try:
            self.connect()
            self.conn.execute('''
                INSERT OR REPLACE INTO domains (url, application, region, environment, active)
                VALUES (?, ?, ?, ?, 1)
            ''', (url, metadata.get('application'), metadata.get('region'), metadata.get('environment')))
            self.conn.commit()
            return True
        except sqlite3.Error as e:
            logging.error(f"Error adding domain {url}: {e}")
            return False

    def remove_domain(self, url: str) -> bool:
        try:
            self.connect()
            self.conn.execute('UPDATE domains SET active = 0 WHERE url = ?', (url,))
            self.conn.commit()
            return True
        except sqlite3.Error as e:
            logging.error(f"Error removing domain {url}: {e}")
            return False

    def get_active_domains(self, filters: Dict = None) -> List[Dict]:
        try:
            self.connect()
            query = 'SELECT url, application, region, environment FROM domains WHERE active = 1'
            params = []

            if filters:
                for key, value in filters.items():
                    if value:
                        query += f' AND {key} = ?'
                        params.append(value)

            cursor = self.conn.execute(query, params)
            return [{'url': row[0], 'metadata': {
                'application': row[1],
                'region': row[2],
                'environment': row[3]
            }} for row in cursor.fetchall()]
        except sqlite3.Error as e:
            logging.error(f"Error getting active domains: {e}")
            return []

    def save_url_status(self, status: URLStatus) -> None:
        """Save URL status to the database"""
        try:
            self.connect()
            
            # Check if this is a new error or the same as the last error
            if status.error is not None:
                # Get the last error for this URL
                last_error_record = self.conn.execute('''
                    SELECT last_error, error_count 
                    FROM domains 
                    WHERE url = ?
                ''', (status.url,)).fetchone()
                
                if last_error_record and last_error_record['last_error'] == status.error:
                    # Same error as before, increment counter
                    self.conn.execute('''
                        UPDATE domains 
                        SET error_count = error_count + 1,
                            last_error_time = ?
                        WHERE url = ?
                    ''', (status.check_time, status.url))
                else:
                    # New error or first error, save it and reset counter to 1
                    self.conn.execute('''
                        UPDATE domains 
                        SET last_error = ?,
                            error_count = 1,
                            last_error_time = ?
                        WHERE url = ?
                    ''', (status.error, status.check_time, status.url))
                    
                    # Insert into history because it's a new error
                    self.conn.execute('''
                        INSERT INTO url_history 
                        (domain_url, check_time, status_code, response_time, error, ssl_expiry, ssl_valid)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        status.url,
                        status.check_time,
                        status.status_code,
                        status.response_time,
                        status.error,
                        status.ssl_expiry,
                        status.ssl_valid
                    ))
            else:
                # No error, reset error count and last error
                self.conn.execute('''
                    UPDATE domains 
                    SET last_error = NULL,
                        error_count = 0,
                        last_error_time = NULL
                    WHERE url = ?
                ''', (status.url,))
                
                # Always insert successful checks into history
                self.conn.execute('''
                    INSERT INTO url_history 
                    (domain_url, check_time, status_code, response_time, error, ssl_expiry, ssl_valid)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (
                    status.url,
                    status.check_time,
                    status.status_code,
                    status.response_time,
                    status.error,
                    status.ssl_expiry,
                    status.ssl_valid
                ))
            
            self.conn.commit()
        except Exception as e:
            logging.error(f"Error saving URL status: {e}")
            raise

    def get_domain_history(self, url: str, limit: int = 10) -> List[Dict]:
        try:
            self.connect()
            cursor = self.conn.execute('''
                SELECT check_time, status_code, response_time, error, ssl_expiry, ssl_valid 
                FROM url_history 
                WHERE domain_url = ? 
                ORDER BY check_time DESC 
                LIMIT ?
            ''', (url, limit))
            return [{'check_time': row[0], 'status_code': row[1], 
                    'response_time': row[2], 'error': row[3], 
                    'ssl_expiry': row[4], 'ssl_valid': bool(row[5])} 
                    for row in cursor.fetchall()]
        except sqlite3.Error as e:
            logging.error(f"Error getting history for domain {url}: {e}")
            return []

    def list_domains(self, show_inactive: bool = False) -> List[Dict]:
        try:
            self.connect()
            query = 'SELECT url, application, region, environment, active FROM domains'
            if not show_inactive:
                query += ' WHERE active = 1'
            cursor = self.conn.execute(query)
            return [{'url': row[0], 'metadata': {
                'application': row[1],
                'region': row[2],
                'environment': row[3]
            }, 'active': bool(row[4])} for row in cursor.fetchall()]
        except sqlite3.Error as e:
            logging.error(f"Error listing domains: {e}")
            return []

class URLChecker:
    def __init__(self, ca_cert_path=None, verify_ssl=True):
        self.db = DatabaseManager()
        self.ca_cert_path = ca_cert_path
        self.verify_ssl = verify_ssl
        
        logging.basicConfig(
            filename='logs/url_checker.log',
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )

    def check_ssl_certificate(self, url: str) -> tuple[Optional[datetime], bool]:
        """
        Check SSL certificate expiry and validity for a given URL.
        Handles custom CA certificates and various SSL errors.
        """
        parsed_url = urlparse(url)
        hostname = parsed_url.hostname
        port = parsed_url.port or 443
        
        if not hostname:
            return None, False
        
        # Try multiple methods to get certificate information
        methods = [
            self._check_ssl_with_socket,
            self._check_ssl_with_openssl,
            self._check_ssl_with_requests
        ]
        
        for method in methods:
            try:
                result = method(hostname, port, url)
                if result[0] is not None:  # If we got a valid expiry date
                    return result
            except Exception as e:
                logging.warning(f"SSL check method failed for {url}: {str(e)}")
                continue
        
        logging.error(f"All SSL certificate check methods failed for {url}")
        return None, False
    
    def _check_ssl_with_socket(self, hostname, port, url) -> tuple[Optional[datetime], bool]:
        """Use socket and SSL to check certificate"""
        try:
            # Create a custom context that can handle weaker DH keys
            context = ssl.create_default_context()
            
            # If we have a custom CA cert path, load it
            if self.ca_cert_path and os.path.exists(self.ca_cert_path):
                context.load_verify_locations(cafile=self.ca_cert_path)
            
            # Set to most permissive options if verify_ssl is False
            if not self.verify_ssl:
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
            
            # For DH_KEY_TOO_SMALL errors, set minimum key size to 512
            context.set_ciphers('DEFAULT@SECLEVEL=1')
            
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Get expiry date
                    expiry_str = cert.get('notAfter')
                    if expiry_str:
                        # Convert ASN1 time format to datetime
                        expiry_date = datetime.strptime(expiry_str, '%b %d %H:%M:%S %Y %Z')
                        
                        # Check if certificate is valid (not expired)
                        is_valid = datetime.utcnow() < expiry_date
                        
                        return expiry_date, is_valid
        except Exception as e:
            logging.debug(f"Socket SSL check failed for {url}: {str(e)}")
            raise
        
        return None, False
    
    def _check_ssl_with_openssl(self, hostname, port, url) -> tuple[Optional[datetime], bool]:
        """Use OpenSSL command line to check certificate when other methods fail"""
        try:
            # Build the OpenSSL command
            cmd = ['openssl', 's_client', '-connect', f'{hostname}:{port}', '-servername', hostname, '-showcerts']
            
            # Add custom CA if provided
            if self.ca_cert_path and os.path.exists(self.ca_cert_path):
                cmd.extend(['-CAfile', self.ca_cert_path])
                
            if not self.verify_ssl:
                cmd.append('-no-verify-hostname')
                
            # Pipe the command to another openssl command to parse the certificate
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.PIPE
            )
            
            # Send QUIT to close the connection
            stdout, stderr = process.communicate(input=b'QUIT\n', timeout=10)
            
            if process.returncode != 0:
                logging.debug(f"OpenSSL command failed: {stderr.decode()}")
                raise Exception(f"OpenSSL command failed: {stderr.decode()}")
            
            # Pipe the certificate to openssl x509 to get the dates
            cert_process = subprocess.Popen(
                ['openssl', 'x509', '-noout', '-dates'],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.PIPE
            )
            
            cert_stdout, cert_stderr = cert_process.communicate(input=stdout)
            
            if cert_process.returncode != 0:
                logging.debug(f"OpenSSL x509 command failed: {cert_stderr.decode()}")
                raise Exception(f"OpenSSL x509 command failed: {cert_stderr.decode()}")
            
            # Parse the output to get the expiry date
            cert_output = cert_stdout.decode()
            for line in cert_output.splitlines():
                if line.startswith('notAfter='):
                    expiry_str = line.split('=', 1)[1]
                    # Format: notAfter=May 17 10:23:42 2023 GMT
                    expiry_date = datetime.strptime(expiry_str, '%b %d %H:%M:%S %Y %Z')
                    is_valid = datetime.utcnow() < expiry_date
                    return expiry_date, is_valid
        except Exception as e:
            logging.debug(f"OpenSSL check failed for {url}: {str(e)}")
            raise
        
        return None, False
    
    def _check_ssl_with_requests(self, hostname, port, url) -> tuple[Optional[datetime], bool]:
        """Use requests library to check certificate"""
        try:
            session = requests.Session()
            
            # Configure session for SSL
            verify = self.ca_cert_path if self.ca_cert_path and os.path.exists(self.ca_cert_path) else self.verify_ssl
            
            response = session.get(url, verify=verify, timeout=10)
            
            # Get the certificate from the response
            cert = response.raw.connection.sock.getpeercert()
            
            # Get expiry date
            expiry_str = cert.get('notAfter')
            if expiry_str:
                # Convert ASN1 time format to datetime
                expiry_date = datetime.strptime(expiry_str, '%b %d %H:%M:%S %Y %Z')
                
                # Check if certificate is valid (not expired)
                is_valid = datetime.utcnow() < expiry_date
                
                return expiry_date, is_valid
        except Exception as e:
            logging.debug(f"Requests SSL check failed for {url}: {str(e)}")
            raise
        
        return None, False

    def check_url(self, url: str, metadata: Dict = None) -> URLStatus:
        """Check a single URL and return its status"""
        try:
            start_time = time.time()
            
            # Create a session with custom SSL settings
            session = requests.Session()
            verify = self.ca_cert_path if self.ca_cert_path and os.path.exists(self.ca_cert_path) else self.verify_ssl
            
            response = session.get(url, timeout=10, verify=verify)
            response_time = time.time() - start_time
            
            # Check SSL certificate
            ssl_expiry, ssl_valid = self.check_ssl_certificate(url)
            
            status = URLStatus(
                url=url,
                status_code=response.status_code,
                response_time=response_time,
                error=None,
                check_time=datetime.utcnow(),
                ssl_expiry=ssl_expiry,
                ssl_valid=ssl_valid,
                metadata=metadata
            )
            
            self.db.save_url_status(status)
            return status
            
        except requests.RequestException as e:
            # Even if the request fails, try to get SSL info
            ssl_expiry, ssl_valid = self.check_ssl_certificate(url)
            
            status = URLStatus(
                url=url,
                status_code=None,
                response_time=None,
                error=str(e),
                check_time=datetime.utcnow(),
                ssl_expiry=ssl_expiry,
                ssl_valid=ssl_valid,
                metadata=metadata
            )
            self.db.save_url_status(status)
            return status

    def check_urls(self, urls: List[Dict]) -> List[URLStatus]:
        results = []
        for url_data in urls:
            url = url_data['url']
            metadata = url_data.get('metadata', {})
            
            # Add or update domain in the database
            self.db.connect()
            self.db.conn.execute('''
                INSERT OR REPLACE INTO domains (url, application, region, environment, active, last_error, error_count, last_error_time)
                VALUES (?, ?, ?, ?, 1, (SELECT last_error FROM domains WHERE url = ?), (SELECT error_count FROM domains WHERE url = ?), (SELECT last_error_time FROM domains WHERE url = ?))
            ''', (url, metadata.get('application'), metadata.get('region'), metadata.get('environment'), url, url, url))
            self.db.conn.commit()
            
            # Check the URL
            result = self.check_url(url, metadata)
            results.append(result)
        
        return results

    def add_url(self, url: str, metadata: Dict) -> bool:
        return self.db.add_domain(url, metadata)

    def remove_url(self, url: str) -> bool:
        return self.db.remove_domain(url)

    def get_url_history(self, url: str, limit: int = 10) -> List[Dict]:
        return self.db.get_domain_history(url, limit)

    def list_urls(self, show_inactive: bool = False) -> List[Dict]:
        return self.db.list_domains(show_inactive)

    def generate_report(self, results: List[URLStatus]) -> str:
        report = "URL Status Report\n" + "=" * 50 + "\n"
        
        for result in results:
            report += f"\nURL: {result.url}\n"
            if result.metadata:
                report += "Metadata:\n"
                for key, value in result.metadata.items():
                    if value:
                        report += f"  {key}: {value}\n"
            
            report += f"Status: {'OK' if result.status_code == 200 else 'ERROR'}\n"
            
            if result.error:
                report += f"Error: {result.error}\n"
            else:
                report += f"Status Code: {result.status_code}\n"
                report += f"Response Time: {result.response_time:.2f}ms\n"
                
                if result.ssl_valid is not None:
                    report += f"SSL Valid: {result.ssl_valid}\n"
                    report += f"SSL Expiry: {result.ssl_expiry}\n"
            
            report += "-" * 50 + "\n"
        
        return report

    def alert(self, status: URLStatus, threshold_ms: float = 1000):
        if status.error:
            logging.error(f"Alert: {status.url} is unreachable: {status.error}")
            return
        
        if status.response_time and status.response_time > threshold_ms:
            logging.warning(f"Alert: {status.url} response time ({status.response_time:.2f}ms) exceeds threshold")
        
        if status.status_code and status.status_code >= 400:
            logging.error(f"Alert: {status.url} returned status code {status.status_code}")

class RetryableSession(requests.Session):
    def __init__(self, retries=3, backoff_factor=0.3, status_forcelist=(500, 502, 504), session=None):
        session = session or requests.Session()
        adapter = HTTPAdapter(max_retries=Retry(total=retries, read=retries, connect=retries,
                                                backoff_factor=backoff_factor, status_forcelist=status_forcelist))
        session.mount('http://', adapter)
        session.mount('https://', adapter)
        self.session = session

    def get(self, url, *args, **kwargs):
        return self.session.get(url, *args, **kwargs)

def parse_args():
    parser = argparse.ArgumentParser(description='URL Checker - Monitor websites and APIs')
    subparsers = parser.add_subparsers(dest='command', help='Commands')

    # Global arguments for SSL
    parser.add_argument('--ca-cert', help='Path to custom CA certificate file')
    parser.add_argument('--no-verify-ssl', action='store_true', help='Disable SSL verification')

    # Add URL command
    add_parser = subparsers.add_parser('add', help='Add a URL to monitor')
    add_parser.add_argument('url', help='URL to monitor')
    add_parser.add_argument('--app', help='Application name')
    add_parser.add_argument('--region', help='Region')
    add_parser.add_argument('--env', help='Environment')

    # Remove URL command
    remove_parser = subparsers.add_parser('remove', help='Remove a URL from monitoring')
    remove_parser.add_argument('url', help='URL to remove')

    # List URLs command
    list_parser = subparsers.add_parser('list', help='List monitored URLs')
    list_parser.add_argument('--all', action='store_true', help='Show inactive URLs as well')

    # Check URLs command
    check_parser = subparsers.add_parser('check', help='Check URLs')
    check_parser.add_argument('--app', help='Filter by application')
    check_parser.add_argument('--region', help='Filter by region')
    check_parser.add_argument('--env', help='Filter by environment')

    # History command
    history_parser = subparsers.add_parser('history', help='Show URL check history')
    history_parser.add_argument('url', help='URL to show history for')
    history_parser.add_argument('--limit', type=int, default=5, help='Number of entries to show')

    return parser.parse_args()

def main():
    args = parse_args()
    
    # Initialize checker with SSL options
    checker = URLChecker(
        ca_cert_path=args.ca_cert,
        verify_ssl=not args.no_verify_ssl
    )

    if args.command == 'add':
        metadata = {
            'application': args.app,
            'region': args.region,
            'environment': args.env
        }
        if checker.add_url(args.url, metadata):
            print(f"Added {args.url} to monitoring")
        else:
            print(f"Failed to add {args.url}")

    elif args.command == 'remove':
        if checker.remove_url(args.url):
            print(f"Removed {args.url} from monitoring")
        else:
            print(f"Failed to remove {args.url}")

    elif args.command == 'list':
        domains = checker.list_urls(args.all)
        print("\nMonitored URLs:")
        for domain in domains:
            status = "Active" if domain['active'] else "Inactive"
            print(f"\n{domain['url']} ({status})")
            if domain['metadata']:
                for key, value in domain['metadata'].items():
                    if value:
                        print(f"  {key}: {value}")

    elif args.command == 'check':
        filters = {
            'application': args.app,
            'region': args.region,
            'environment': args.env
        }
        domains = checker.db.get_active_domains(filters)
        results = checker.check_urls(domains)
        print(checker.generate_report(results))

    elif args.command == 'history':
        history = checker.get_url_history(args.url, args.limit)
        print(f"\nHistory for {args.url}:")
        for entry in history:
            print(f"\nTime: {entry['check_time']}")
            print(f"Status: {entry['status_code']}")
            print(f"Response Time: {entry['response_time']}s")
            if entry['error']:
                print(f"Error: {entry['error']}")
            if entry['ssl_expiry']:
                print(f"SSL Expiry: {entry['ssl_expiry']}")
            print(f"SSL Valid: {entry['ssl_valid']}")
            print("-" * 30)

    else:
        print("Please specify a command. Use --help for usage information.")

if __name__ == '__main__':
    main()
