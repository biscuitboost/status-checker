import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import sqlite3
from datetime import datetime, timedelta
import os
from typing import Dict, List, Optional, Tuple

# Email configuration - these should be set in environment variables
SMTP_HOST = os.getenv('SMTP_HOST', 'smtp.gmail.com')
SMTP_PORT = int(os.getenv('SMTP_PORT', '587'))
SMTP_USER = os.getenv('SMTP_USER', '')
SMTP_PASSWORD = os.getenv('SMTP_PASSWORD', '')
FROM_EMAIL = os.getenv('FROM_EMAIL', SMTP_USER)
DASHBOARD_URL = os.getenv('DASHBOARD_URL', 'http://localhost:5001')

def get_db_connection():
    conn = sqlite3.connect('config/url_checker.db')
    conn.row_factory = sqlite3.Row
    return conn

def get_email_template(template_name: str) -> Tuple[str, str, str]:
    """Get email template by name"""
    conn = get_db_connection()
    try:
        cursor = conn.execute(
            'SELECT subject_template, html_template, text_template FROM email_templates WHERE name = ?',
            (template_name,)
        )
        template = cursor.fetchone()
        if template:
            return template['subject_template'], template['html_template'], template['text_template']
        raise ValueError(f"Template {template_name} not found")
    finally:
        conn.close()

def format_template(template: str, context: Dict[str, str]) -> str:
    """Format template with context"""
    return template.format(**context)

def send_email(to_addresses: List[str], subject: str, html_content: str, text_content: str):
    """Send email using SMTP"""
    if not SMTP_USER or not SMTP_PASSWORD:
        raise ValueError("SMTP credentials not configured")

    msg = MIMEMultipart('alternative')
    msg['Subject'] = subject
    msg['From'] = FROM_EMAIL
    msg['To'] = ', '.join(to_addresses)

    msg.attach(MIMEText(text_content, 'plain'))
    msg.attach(MIMEText(html_content, 'html'))

    with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
        server.starttls()
        server.login(SMTP_USER, SMTP_PASSWORD)
        server.send_message(msg)

def send_alert(
    alert_type: str,
    url: str,
    application: str,
    region: str,
    environment: str,
    issue: str,
    value: str,
    threshold: str,
    contacts: List[Dict[str, str]]
):
    """Send alert email to contacts"""
    template_name = 'critical_alert' if alert_type == 'critical' else 'warning_alert'
    subject_template, html_template, text_template = get_email_template(template_name)

    context = {
        'url': url,
        'application': application,
        'region': region,
        'environment': environment,
        'issue': issue,
        'value': value,
        'threshold': threshold,
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'dashboard_url': f"{DASHBOARD_URL}/group/{application}/{region}/{environment}"
    }

    subject = format_template(subject_template, context)
    html_content = format_template(html_template, context)
    text_content = format_template(text_template, context)

    to_addresses = [contact['email'] for contact in contacts]
    if to_addresses:
        send_email(to_addresses, subject, html_content, text_content)

def send_sla_report(
    application: str,
    period: str,
    start_date: datetime,
    end_date: datetime,
    target_sla: float,
    achieved_sla: float,
    total_downtime: str,
    maintenance_time: str,
    incident_count: int,
    contacts: List[Dict[str, str]]
):
    """Send SLA report email"""
    subject_template, html_template, text_template = get_email_template('sla_report')

    sla_status = 'met' if achieved_sla >= target_sla else 'missed'
    context = {
        'application': application,
        'period': period,
        'start_date': start_date.strftime('%Y-%m-%d'),
        'end_date': end_date.strftime('%Y-%m-%d'),
        'target_sla': f"{target_sla:.2f}",
        'achieved_sla': f"{achieved_sla:.2f}",
        'sla_status': sla_status,
        'total_downtime': total_downtime,
        'maintenance_time': maintenance_time,
        'incident_count': incident_count,
        'dashboard_url': f"{DASHBOARD_URL}/sla/{application}"
    }

    subject = format_template(subject_template, context)
    html_content = format_template(html_template, context)
    text_content = format_template(text_template, context)

    to_addresses = [contact['email'] for contact in contacts]
    if to_addresses:
        send_email(to_addresses, subject, html_content, text_content)

def is_in_maintenance(url: str, application: str, region: str, environment: str) -> bool:
    """Check if a URL is currently in maintenance window"""
    conn = get_db_connection()
    try:
        now = datetime.now()
        cursor = conn.execute('''
            SELECT COUNT(*) as count
            FROM maintenance_windows
            WHERE (url = ? OR (
                    application = ? AND
                    region = ? AND
                    environment = ?
                  ))
            AND start_time <= ?
            AND end_time >= ?
        ''', (url, application, region, environment, now, now))
        result = cursor.fetchone()
        return result['count'] > 0
    finally:
        conn.close()

def get_custom_thresholds(url: str, application: str, region: str, environment: str) -> Optional[Dict]:
    """Get custom alert thresholds for a URL or group"""
    conn = get_db_connection()
    try:
        # First try URL-specific thresholds
        cursor = conn.execute('''
            SELECT * FROM custom_alert_thresholds
            WHERE url = ?
        ''', (url,))
        thresholds = cursor.fetchone()
        
        if not thresholds:
            # Try group-level thresholds
            cursor = conn.execute('''
                SELECT * FROM custom_alert_thresholds
                WHERE application = ?
                AND region = ?
                AND environment = ?
                AND url IS NULL
            ''', (application, region, environment))
            thresholds = cursor.fetchone()
        
        return dict(thresholds) if thresholds else None
    finally:
        conn.close()

def get_custom_headers(url: str) -> List[Dict]:
    """Get custom headers for a URL"""
    conn = get_db_connection()
    try:
        cursor = conn.execute('''
            SELECT header_name, header_value, is_auth_header
            FROM custom_headers
            WHERE url = ?
        ''', (url,))
        return [dict(row) for row in cursor.fetchall()]
    finally:
        conn.close()

def calculate_sla(
    url: str,
    application: str,
    region: str,
    environment: str,
    start_date: datetime,
    end_date: datetime
) -> Dict:
    """Calculate SLA metrics for a URL or group"""
    conn = get_db_connection()
    try:
        # Get total checks and successful checks
        cursor = conn.execute('''
            SELECT 
                COUNT(*) as total_checks,
                SUM(CASE WHEN status_code = 200 THEN 1 ELSE 0 END) as successful_checks,
                SUM(CASE WHEN status_code != 200 THEN 1 ELSE 0 END) as failed_checks
            FROM url_history
            WHERE domain_url = ?
            AND timestamp BETWEEN ? AND ?
        ''', (url, start_date, end_date))
        result = cursor.fetchone()
        
        # Get maintenance windows during this period
        cursor = conn.execute('''
            SELECT SUM(
                CASE 
                    WHEN end_time > ? THEN 
                        (strftime('%s', ?) - strftime('%s', start_time))
                    ELSE 
                        (strftime('%s', end_time) - strftime('%s', start_time))
                END
            ) as maintenance_seconds
            FROM maintenance_windows
            WHERE (url = ? OR (
                    application = ? AND
                    region = ? AND
                    environment = ?
                  ))
            AND start_time < ?
            AND end_time > ?
        ''', (end_date, end_date, url, application, region, environment, end_date, start_date))
        maintenance = cursor.fetchone()
        
        total_checks = result['total_checks']
        successful_checks = result['successful_checks']
        failed_checks = result['failed_checks']
        maintenance_minutes = (maintenance['maintenance_seconds'] or 0) / 60
        
        if total_checks > 0:
            sla = (successful_checks / total_checks) * 100
        else:
            sla = 0
        
        return {
            'sla_percentage': sla,
            'total_checks': total_checks,
            'successful_checks': successful_checks,
            'failed_checks': failed_checks,
            'maintenance_minutes': maintenance_minutes,
            'start_date': start_date,
            'end_date': end_date
        }
    finally:
        conn.close()
