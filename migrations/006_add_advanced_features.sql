-- Custom alert thresholds per URL/group
CREATE TABLE IF NOT EXISTS custom_alert_thresholds (
    id INTEGER PRIMARY KEY,
    url TEXT,
    application TEXT,
    region TEXT,
    environment TEXT,
    response_time_warning INTEGER,
    response_time_critical INTEGER,
    ssl_expiry_warning INTEGER,
    ssl_expiry_critical INTEGER,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (url) REFERENCES domains(url) ON DELETE CASCADE,
    UNIQUE(url, application, region, environment)
);

-- Maintenance windows
CREATE TABLE IF NOT EXISTS maintenance_windows (
    id INTEGER PRIMARY KEY,
    url TEXT,
    application TEXT,
    region TEXT,
    environment TEXT,
    start_time TIMESTAMP NOT NULL,
    end_time TIMESTAMP NOT NULL,
    description TEXT,
    created_by TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (url) REFERENCES domains(url) ON DELETE CASCADE
);

-- Custom HTTP headers
CREATE TABLE IF NOT EXISTS custom_headers (
    id INTEGER PRIMARY KEY,
    url TEXT NOT NULL,
    header_name TEXT NOT NULL,
    header_value TEXT NOT NULL,
    is_auth_header BOOLEAN DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (url) REFERENCES domains(url) ON DELETE CASCADE
);

-- SLA tracking
CREATE TABLE IF NOT EXISTS sla_definitions (
    id INTEGER PRIMARY KEY,
    url TEXT,
    application TEXT,
    region TEXT,
    environment TEXT,
    target_percentage REAL NOT NULL,
    measurement_period TEXT NOT NULL, -- 'daily', 'weekly', 'monthly', 'quarterly', 'yearly'
    exclude_maintenance BOOLEAN DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (url) REFERENCES domains(url) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS sla_history (
    id INTEGER PRIMARY KEY,
    sla_definition_id INTEGER NOT NULL,
    period_start TIMESTAMP NOT NULL,
    period_end TIMESTAMP NOT NULL,
    uptime_percentage REAL NOT NULL,
    total_downtime_minutes INTEGER NOT NULL,
    maintenance_minutes INTEGER NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (sla_definition_id) REFERENCES sla_definitions(id) ON DELETE CASCADE
);

-- Email templates
CREATE TABLE IF NOT EXISTS email_templates (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    subject_template TEXT NOT NULL,
    html_template TEXT NOT NULL,
    text_template TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Insert default email templates
INSERT OR IGNORE INTO email_templates (name, subject_template, html_template, text_template) VALUES
('warning_alert', 
 '[Warning] {application} - {url} Response Time Alert',
 '<!DOCTYPE html>
<html>
<head>
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
        .warning { color: #856404; background-color: #fff3cd; padding: 10px; border-radius: 4px; }
        .details { margin: 20px 0; }
        .button { background-color: #007bff; color: white; padding: 10px 20px; text-decoration: none; border-radius: 4px; }
    </style>
</head>
<body>
    <h2>⚠️ Warning Alert</h2>
    <div class="warning">
        <p>A warning threshold has been exceeded for {url}</p>
    </div>
    <div class="details">
        <p><strong>Application:</strong> {application}</p>
        <p><strong>Environment:</strong> {environment}</p>
        <p><strong>Region:</strong> {region}</p>
        <p><strong>Issue:</strong> {issue}</p>
        <p><strong>Value:</strong> {value}</p>
        <p><strong>Threshold:</strong> {threshold}</p>
        <p><strong>Time:</strong> {timestamp}</p>
    </div>
    <a href="{dashboard_url}" class="button">View in Dashboard</a>
</body>
</html>',
'Warning Alert: {application} - {url}

A warning threshold has been exceeded:
- Application: {application}
- Environment: {environment}
- Region: {region}
- Issue: {issue}
- Value: {value}
- Threshold: {threshold}
- Time: {timestamp}

View in Dashboard: {dashboard_url}'),

('critical_alert',
 '[CRITICAL] {application} - {url} Critical Alert',
 '<!DOCTYPE html>
<html>
<head>
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
        .critical { color: #721c24; background-color: #f8d7da; padding: 10px; border-radius: 4px; }
        .details { margin: 20px 0; }
        .button { background-color: #dc3545; color: white; padding: 10px 20px; text-decoration: none; border-radius: 4px; }
    </style>
</head>
<body>
    <h2>🚨 Critical Alert</h2>
    <div class="critical">
        <p>A critical threshold has been exceeded for {url}</p>
    </div>
    <div class="details">
        <p><strong>Application:</strong> {application}</p>
        <p><strong>Environment:</strong> {environment}</p>
        <p><strong>Region:</strong> {region}</p>
        <p><strong>Issue:</strong> {issue}</p>
        <p><strong>Value:</strong> {value}</p>
        <p><strong>Threshold:</strong> {threshold}</p>
        <p><strong>Time:</strong> {timestamp}</p>
    </div>
    <a href="{dashboard_url}" class="button">View in Dashboard</a>
</body>
</html>',
'CRITICAL Alert: {application} - {url}

A critical threshold has been exceeded:
- Application: {application}
- Environment: {environment}
- Region: {region}
- Issue: {issue}
- Value: {value}
- Threshold: {threshold}
- Time: {timestamp}

View in Dashboard: {dashboard_url}'),

('sla_report',
 'SLA Report: {application} - {period}',
 '<!DOCTYPE html>
<html>
<head>
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
        .header { margin-bottom: 20px; }
        .summary { background-color: #f8f9fa; padding: 15px; border-radius: 4px; }
        .details { margin: 20px 0; }
        .met { color: #155724; background-color: #d4edda; padding: 5px 10px; border-radius: 4px; }
        .missed { color: #721c24; background-color: #f8d7da; padding: 5px 10px; border-radius: 4px; }
        .button { background-color: #007bff; color: white; padding: 10px 20px; text-decoration: none; border-radius: 4px; }
    </style>
</head>
<body>
    <div class="header">
        <h2>SLA Report: {period}</h2>
        <p>Application: {application}</p>
    </div>
    <div class="summary">
        <h3>Summary</h3>
        <p>Period: {start_date} to {end_date}</p>
        <p>Target SLA: {target_sla}%</p>
        <p>Achieved SLA: {achieved_sla}% <span class="{sla_status}">{sla_status}</span></p>
    </div>
    <div class="details">
        <h3>Details</h3>
        <p>Total Downtime: {total_downtime}</p>
        <p>Maintenance Time: {maintenance_time}</p>
        <p>Incidents: {incident_count}</p>
    </div>
    <a href="{dashboard_url}" class="button">View Full Report</a>
</body>
</html>',
'SLA Report: {application} - {period}

Period: {start_date} to {end_date}
Target SLA: {target_sla}%
Achieved SLA: {achieved_sla}% ({sla_status})

Details:
- Total Downtime: {total_downtime}
- Maintenance Time: {maintenance_time}
- Incidents: {incident_count}

View Full Report: {dashboard_url}');
