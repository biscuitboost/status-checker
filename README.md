# URL Checker

A comprehensive URL monitoring tool that checks the status and health of websites and APIs, with SQLite database storage for persistent monitoring and configurable email alerts.

## Features

- **URL Management**:
  - Add/remove URLs to monitor via command line
  - Track active/inactive status
  - Support for metadata (Application, Region, Environment)
  - Persistent storage in SQLite database

- **Detailed URL Analysis**:
  - HTTP status codes
  - Response times
  - Content type and size
  - SSL certificate validation
  - Redirect chains
  - Response headers

- **Automated Polling**:
  - Configurable check intervals per rule
  - Concurrent URL checking
  - Graceful shutdown handling
  - Scalable to hundreds of URLs

- **Smart Alerting**:
  - Configure alerts based on metadata (Application/Region/Environment)
  - Different email recipients per configuration
  - Customizable alert thresholds
  - Asynchronous email processing
  - SMTP support with TLS

- **History Tracking**:
  - SQLite database storage
  - Historical data for each URL
  - Timestamp-based queries
  - Configurable history limits

- **Filtering and Organization**:
  - Filter URLs by application
  - Filter by region
  - Filter by environment
  - View active/inactive URLs

## Installation

```bash
pip install -r requirements.txt
```

## Configuration

### Alert Configuration
Create an `alert_config.json` file:

```json
{
    "alert_rules": [
        {
            "application": "application1",
            "region": "uk",
            "environment": "dev",
            "email": "uktestalerts@application1.com",
            "alert_threshold_ms": 2000,
            "check_interval_seconds": 60
        }
    ],
    "default_rule": {
        "email": "alerts@default.com",
        "alert_threshold_ms": 5000,
        "check_interval_seconds": 300
    },
    "smtp_config": {
        "server": "smtp.company.com",
        "port": 587,
        "use_tls": true,
        "username": "alerts@company.com",
        "password": "YOUR_PASSWORD"
    }
}
```

## Command-Line Usage

### Adding a URL
```bash
# Add a URL with metadata
python url_checker.py add https://example.com --app MyApp --region US --env prod

# Add a URL without metadata
python url_checker.py add https://example.com
```

### Removing a URL
```bash
python url_checker.py remove https://example.com
```

### Listing URLs
```bash
# List all active URLs
python url_checker.py list

# List all URLs including inactive
python url_checker.py list --all
```

### Checking URLs
```bash
# Check all active URLs
python url_checker.py check

# Check URLs filtered by application
python url_checker.py check --app MyApp

# Check URLs filtered by region and environment
python url_checker.py check --region US --env prod
```

### SSL Certificate Handling Options

The URL Checker now supports custom SSL certificate handling for environments with internal CA certificates or older SSL configurations:

```bash
# Use a custom CA certificate file
python url_checker.py check --ca-cert /path/to/custom/ca.crt

# Disable SSL verification (use with caution, only in trusted environments)
python url_checker.py check --no-verify-ssl

# Combine with other filters
python url_checker.py check --app InternalApp --env test --ca-cert /path/to/custom/ca.crt
```

These SSL options help address:
1. Internal servers using custom root CA certificates
2. Servers with DH_KEY_TOO_SMALL issues or other SSL configuration challenges

The tool will attempt multiple methods to retrieve SSL certificate information:
- Standard socket-based SSL verification
- OpenSSL command-line fallback
- Requests library connection inspection

### Viewing URL History
```bash
# View last 5 checks
python url_checker.py history https://example.com

# View last N checks
python url_checker.py history https://example.com --limit 10
```

## Running the Poller

Start the automated URL checker:

```bash
python url_poller.py
```

The poller will:
1. Load alert configurations from `alert_config.json`
2. Start checking URLs based on their configured intervals
3. Send alerts when issues are detected
4. Use concurrent processing for efficient checking
5. Handle graceful shutdown on CTRL+C

## Alert Rules

Alert rules are matched based on the combination of:
- Application name
- Region
- Environment

Each rule can specify:
- Email recipient
- Response time threshold
- Check interval

If no specific rule matches, the default rule is used.

## Logging

- URL checks are logged to `logs/url_checker.log`
- Poller activities are logged to `logs/url_poller.log`
- Results are stored in `config/url_checker.db` (SQLite database)

## Performance

The poller uses:
- ThreadPoolExecutor for concurrent URL checking
- Asynchronous email processing
- Connection pooling for database operations
- Configurable number of worker threads

## Alert Thresholds

Configurable per rule:
- Response time threshold (milliseconds)
- Check interval (seconds)
- Different thresholds for different environments
