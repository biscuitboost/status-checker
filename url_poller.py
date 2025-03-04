import json
import logging
import schedule
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
import threading
from queue import Queue
import signal
import sys
import requests
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
import jsonpath_ng
from prometheus_client import start_http_server, Counter, Gauge, Histogram
import aiohttp
from aiohttp import web
import backoff
from functools import partial
import asyncio
from url_checker import URLChecker

# Prometheus metrics
REQUEST_TIME = Histogram('url_check_duration_seconds', 'Time spent checking URL', ['url', 'application', 'region', 'environment'])
REQUEST_FAILURES = Counter('url_check_failures_total', 'Number of failed checks', ['url', 'application', 'region', 'environment'])
SSL_EXPIRY_TIME = Gauge('ssl_expiry_days', 'Days until SSL certificate expires', ['url'])
RESPONSE_SIZE = Histogram('response_size_bytes', 'Size of response in bytes', ['url'])

class HealthCheck:
    def __init__(self, port: int = 8080):
        self.port = port
        self.app = web.Application()
        self.app.router.add_get('/health', self.health_check)
        self.runner = None
        self._running = False
        self._thread = None
        self._loop = None

    async def health_check(self, request):
        return web.Response(text='healthy')

    async def _run_app(self):
        self.runner = web.AppRunner(self.app)
        await self.runner.setup()
        site = web.TCPSite(self.runner, 'localhost', self.port)
        await site.start()
        self._running = True
        
        # Keep the server running
        while self._running:
            await asyncio.sleep(1)

    def start(self):
        def run_server():
            self._loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self._loop)
            self._loop.run_until_complete(self._run_app())
            self._loop.close()

        self._thread = threading.Thread(target=run_server, daemon=True)
        self._thread.start()
        # Give it a moment to start
        time.sleep(1)
        logging.info(f"Health check server started on port {self.port}")

    def stop(self):
        self._running = False
        if self._loop:
            async def cleanup():
                if self.runner:
                    await self.runner.cleanup()
            
            if self._loop.is_running():
                self._loop.create_task(cleanup())
            else:
                self._loop.run_until_complete(cleanup())

class RetryableSession:
    def __init__(self, retries: int = 3, backoff_factor: float = 0.3):
        self.session = requests.Session()
        retry = Retry(
            total=retries,
            read=retries,
            connect=retries,
            backoff_factor=backoff_factor,
            status_forcelist=[500, 502, 503, 504],
        )
        adapter = HTTPAdapter(max_retries=retry)
        self.session.mount('http://', adapter)
        self.session.mount('https://', adapter)

    def __enter__(self):
        return self.session

    def __exit__(self, *args):
        self.session.close()

class AlertConfig:
    def __init__(self, config_file: str = 'config/alert_config.json'):
        with open(config_file, 'r') as f:
            self.config = json.load(f)
        
        self.alert_rules = self.config['alert_rules']
        self.default_rule = self.config['default_rule']
        self.smtp_config = self.config['smtp_config']
        self.metrics_config = self.config.get('metrics', {})
        self.health_check_config = self.config.get('health_check', {})

    def get_rule_for_url(self, metadata: Dict) -> Dict:
        for rule in self.alert_rules:
            if (rule['application'] == metadata.get('application') and
                rule['region'] == metadata.get('region') and
                rule['environment'] == metadata.get('environment')):
                return rule
        return self.default_rule

class EmailAlerter:
    def __init__(self, smtp_config: Dict):
        self.config = smtp_config
        self.email_queue = Queue()
        self.worker_thread = threading.Thread(target=self._process_email_queue, daemon=True)
        self.worker_thread.start()

    def _process_email_queue(self):
        while True:
            try:
                email_data = self.email_queue.get()
                if email_data is None:
                    break

                to_email, subject, body = email_data
                self._send_email(to_email, subject, body)
                self.email_queue.task_done()
            except Exception as e:
                logging.error(f"Error processing email: {e}")

    def _send_email(self, to_email: str, subject: str, body: str):
        try:
            msg = MIMEMultipart()
            msg['From'] = self.config['username']
            msg['To'] = to_email
            msg['Subject'] = subject

            msg.attach(MIMEText(body, 'plain'))

            with smtplib.SMTP(self.config['server'], self.config['port']) as server:
                if self.config['use_tls']:
                    server.starttls()
                server.login(self.config['username'], self.config['password'])
                server.send_message(msg)

            logging.info(f"Alert email sent to {to_email}")
        except Exception as e:
            logging.error(f"Failed to send email to {to_email}: {e}")

    def queue_alert(self, to_email: str, subject: str, body: str):
        self.email_queue.put((to_email, subject, body))

class URLPoller:
    def __init__(self, config_file: str = 'config/alert_config.json'):
        self.checker = URLChecker()
        self.alert_config = AlertConfig(config_file)
        self.email_alerter = EmailAlerter(self.alert_config.smtp_config)
        self.running = False
        self.max_workers = 20
        self.health_check = None

        # Initialize Prometheus metrics if enabled
        if self.alert_config.metrics_config.get('prometheus', {}).get('enabled'):
            prometheus_port = self.alert_config.metrics_config['prometheus']['port']
            start_http_server(prometheus_port)

    def check_content(self, response: requests.Response, content_check: Dict) -> bool:
        try:
            if content_check['type'] == 'json':
                data = response.json()
                jsonpath_expr = jsonpath_ng.parse(content_check['path'])
                matches = [match.value for match in jsonpath_expr.find(data)]
                return any(match == content_check['expected_value'] for match in matches)
            return True
        except Exception as e:
            logging.error(f"Content check failed: {e}")
            return False

    def check_url_with_rule(self, url: str, metadata: Dict, rule: Dict):
        """Check a URL using the specified rule"""
        try:
            status = self.checker.check_url(url, metadata)
            
            # Check if we need to alert
            if status.error:
                logging.error(f"Error checking {url}: {status.error}")
                self.email_alerter.queue_alert(rule['email'], f"Error: {status.error}", f"Problem detected with URL: {url}\nTime: {datetime.now().isoformat()}\nApplication: {metadata.get('application')}\nRegion: {metadata.get('region')}\nEnvironment: {metadata.get('environment')}\nError: {status.error}")
            elif status.response_time > rule.get('alert_threshold_ms', 5000) / 1000:  # Convert ms to seconds
                logging.warning(f"Slow response from {url}: {status.response_time:.2f}s")
                self.email_alerter.queue_alert(rule['email'], f"Slow response: {status.response_time:.2f}s", f"Problem detected with URL: {url}\nTime: {datetime.now().isoformat()}\nApplication: {metadata.get('application')}\nRegion: {metadata.get('region')}\nEnvironment: {metadata.get('environment')}\nError: Slow response")
            elif status.status_code and status.status_code >= 400:
                logging.error(f"Bad status from {url}: {status.status_code}")
                self.email_alerter.queue_alert(rule['email'], f"Bad status: {status.status_code}", f"Problem detected with URL: {url}\nTime: {datetime.now().isoformat()}\nApplication: {metadata.get('application')}\nRegion: {metadata.get('region')}\nEnvironment: {metadata.get('environment')}\nError: Bad status")
            else:
                logging.info(f"Successfully checked {url}: {status.status_code}")
        except Exception as e:
            logging.error(f"Error in check_url_with_rule for {url}: {e}")
            self.email_alerter.queue_alert(rule['email'], f"Error: {str(e)}", f"Problem detected with URL: {url}\nTime: {datetime.now().isoformat()}\nApplication: {metadata.get('application')}\nRegion: {metadata.get('region')}\nEnvironment: {metadata.get('environment')}\nError: {str(e)}")

    async def start_health_check(self):
        if self.alert_config.health_check_config.get('enabled'):
            self.health_check = HealthCheck(self.alert_config.health_check_config['port'])
            self.health_check.start()

    async def stop_health_check(self):
        if self.health_check:
            self.health_check.stop()

    def start(self):
        self.running = True
        
        # Start health check server
        if self.alert_config.health_check_config.get('enabled'):
            self.health_check = HealthCheck(self.alert_config.health_check_config['port'])
            self.health_check.start()
        
        # Schedule checks based on rules
        domains = self.checker.list_urls()
        for domain in domains:
            url = domain['url']
            metadata = domain['metadata']
            rule = self.alert_config.get_rule_for_url(metadata)
            interval = rule.get('check_interval_seconds', 60)
            
            # Do an initial check immediately
            self.check_url_with_rule(url, metadata, rule)
            
            # Schedule periodic checks
            schedule.every(interval).seconds.do(
                self.check_url_with_rule,
                url,
                metadata,
                rule
            )
            logging.info(f"Scheduled checks for {url} every {interval} seconds")

        def signal_handler(signum, frame):
            self.stop()

        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)

        # Run the scheduler in the main thread
        logging.info("Starting URL check scheduler...")
        while self.running:
            schedule.run_pending()
            time.sleep(1)

    def stop(self):
        self.running = False
        schedule.clear()
        if self.health_check:
            self.health_check.stop()

def main():
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('logs/url_poller.log'),
            logging.StreamHandler()
        ]
    )

    # Start the dashboard in a separate thread
    from dashboard import run_dashboard
    dashboard_thread = threading.Thread(target=run_dashboard, daemon=True)
    dashboard_thread.start()
    logging.info("Dashboard started on http://localhost:5000")

    poller = URLPoller()
    logging.info("Starting URL Poller...")
    poller.start()

if __name__ == '__main__':
    main()
