# Duo Authentication Logs Collector

A specialized Python script for collecting and analyzing authentication logs from Duo Security's Admin API. This tool focuses specifically on authentication logs as documented in the [Duo Admin API documentation](https://duo.com/docs/adminapi#authentication-logs).

## Overview

Authentication logs contain detailed information about user authentication attempts, including:
- **Authentication results**: SUCCESS, FAILURE, ERROR, FRAUD
- **User information**: Username, user ID
- **Device details**: Device name, platform, browser information
- **Location data**: IP address, city, state, country
- **Application context**: Application name, integration details
- **Authentication factors**: Push, SMS, phone call, hardware token, etc.
- **Timing information**: Timestamp of authentication attempts
- **Additional metadata**: Reason codes, risk scores, and more

## Features

- **Focused Collection**: Specialized for authentication logs only
- **Pagination Support**: Handles large log volumes with automatic pagination
- **Comprehensive Analysis**: Detailed analysis of authentication patterns
- **Security Insights**: Identifies potential security issues and anomalies
- **Multiple Output Formats**: JSON logs and CSV export options
- **Flexible Time Ranges**: Custom date ranges or days back
- **Real-time Monitoring**: Continuous log collection capabilities

## Prerequisites

- Python 3.6 or higher
- Duo Admin API credentials (integration key, secret key, API hostname)
- Admin API application with "Grant read log" permission
- Network access to Duo's API endpoints (HTTPS on port 443)

## Setup

### 1. Duo Admin API Configuration

Before using this script, set up an Admin API application in your Duo account:

1. Log in to the Duo Admin Panel
2. Navigate to Applications -> Application Catalog
3. Find "Admin API" and click "Add"
4. Configure the application with **"Grant read log"** permission
5. Note your integration key, secret key, and API hostname

### 2. Environment Variables

Set the following environment variables with your Duo API credentials:

```bash
export DUO_INTEGRATION_KEY="your_integration_key_here"
export DUO_SECRET_KEY="your_secret_key_here"  
export DUO_API_HOSTNAME="api-xxxxx.duosecurity.com"
```

**Security Note**: Never hardcode credentials in the script. Use environment variables or a secure credential management system.

### 3. Installation

Clone or download this repository:

```bash
git clone <repository-url>
cd duo
```

No additional packages are required - the script uses only Python standard library modules.

## Usage

### Basic Usage

Collect authentication logs for the last 7 days:

```bash
python duo_auth_logs_only.py
```

### Advanced Usage

```bash
# Collect authentication logs for the last 30 days
python duo_auth_logs_only.py --days 30

# Collect with a maximum limit of 10,000 logs
python duo_auth_logs_only.py --days 14 --max-logs 10000

# Enable verbose logging for debugging
python duo_auth_logs_only.py --verbose

# Specify custom output directory
python duo_auth_logs_only.py --output-dir /path/to/logs
```

### Command Line Options

- `--days`: Number of days back to collect logs (default: 7)
- `--max-logs`: Maximum number of logs to retrieve (default: all)
- `--output-dir`: Output directory for log files (default: duo_auth_logs)
- `--verbose`: Enable verbose logging for debugging

## Output

The script creates the following outputs:

### Log Files

1. **Raw Authentication Logs**: `auth_logs_YYYYMMDD_HHMMSS.json`
   - Complete authentication log entries in JSON format
   - Includes all fields returned by the Duo API
   - Suitable for SIEM integration or further analysis

2. **Analysis Report**: `auth_analysis_YYYYMMDD_HHMMSS.json`
   - Summary statistics and analysis results
   - Authentication result breakdowns
   - Factor usage analysis
   - Top users and applications

### Console Output

Summary report showing:
- Total authentication attempts
- Unique users and devices
- Authentication result breakdown
- Factor usage statistics
- Top applications and users

## Authentication Log Fields

Based on the Duo Admin API documentation, authentication logs include:

| Field | Description |
|-------|-------------|
| `timestamp` | Unix timestamp of the authentication attempt |
| `username` | Username of the authenticating user |
| `user_id` | Unique user identifier |
| `result` | Authentication result (SUCCESS, FAILURE, ERROR, FRAUD) |
| `factor` | Authentication factor used (push, sms, phone, etc.) |
| `device` | Device name or identifier |
| `platform` | Device platform (iOS, Android, Windows, etc.) |
| `browser` | Browser information (for web-based authentication) |
| `location` | Geographic location information |
| `ip` | IP address of the authentication attempt |
| `application` | Application being accessed |
| `reason` | Reason code for the result |
| `risk_score` | Risk score (if available) |

## Analysis Features

### Authentication Results Analysis
- Success/failure rate calculations
- Error pattern identification
- Fraud detection analysis

### User Behavior Analysis
- Authentication patterns per user
- Device usage patterns
- Location-based analysis
- Time-based activity patterns

### Security Insights
- High failure rate users
- Multiple device usage
- Unusual location patterns
- Rapid authentication attempts
- Fraud indicators

## Advanced Usage Examples

### Continuous Monitoring

```bash
# Collect logs every hour (run via cron)
0 * * * * /usr/bin/python3 /path/to/duo_auth_logs_only.py --days 1 --output-dir /var/log/duo
```

### SIEM Integration

```bash
# Export to CSV for SIEM ingestion
python duo_auth_logs_only.py --days 7 --export-csv
```

### Custom Time Range

```python
from duo_auth_logs_only import DuoAuthLogCollector
from datetime import datetime, timedelta

# Custom time range (last 2 hours)
end_time = int(datetime.now().timestamp())
start_time = int((datetime.now() - timedelta(hours=2)).timestamp())

collector = DuoAuthLogCollector(integration_key, secret_key, api_hostname)
logs = collector.get_all_authentication_logs(mintime=start_time, maxtime=end_time)
```

## Security Considerations

### Credential Security
- Store API credentials securely using environment variables
- Never commit credentials to version control
- Rotate credentials regularly
- Use least-privilege access (only grant necessary permissions)

### Data Handling
- Authentication logs contain sensitive information
- Implement proper access controls on log storage
- Consider encryption for log files at rest
- Follow data retention policies

### Network Security
- Ensure outbound HTTPS access to Duo's API endpoints
- Consider IP restrictions in Duo Admin Panel if needed
- Monitor for unusual API usage patterns

## Troubleshooting

### Common Issues

**No Logs Retrieved**
- Verify the time range contains authentication activity
- Check that users have been authenticating during the specified period
- Ensure the account has the appropriate Duo edition

**Permission Errors**
- Confirm "Grant read log" permission is enabled
- Verify the Admin API application is active
- Check for IP restrictions in Duo Admin Panel

**Rate Limiting**
- The script includes automatic delays between requests
- Reduce the time range if experiencing rate limits
- Contact Duo support for rate limit increases

### Testing Connection

Use the test script to verify your setup:

```bash
python test_auth_logs.py
```

This will:
- Verify credentials are working
- Test authentication log access
- Show sample log structure
- Validate API permissions

## API Documentation

For complete API documentation, refer to:
- [Duo Admin API Authentication Logs](https://duo.com/docs/adminapi#authentication-logs)
- [Duo Admin API Overview](https://duo.com/docs/adminapi)
- [Authentication Methods](https://duo.com/docs/adminapi#authentication)

## Contributing

When contributing to this project:

1. Follow security best practices
2. Add appropriate error handling
3. Include logging for audit trails
4. Test with various time ranges and log volumes
5. Update documentation for new features

## License

This project is provided as-is for educational and operational purposes. Please review and comply with Duo's terms of service and your organization's security policies.

## Support

For issues related to:
- **Duo API**: Contact [Duo Support](https://duo.com/support)
- **This Script**: Create an issue in the project repository
- **Security Concerns**: Follow your organization's security incident procedures
