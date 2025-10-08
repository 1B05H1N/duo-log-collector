# Duo Log Collector

A comprehensive Python toolkit for collecting and analyzing logs from Duo Security's Admin API. This repository provides secure, production-ready scripts for gathering authentication logs, administrator logs, telephony logs, and offline access logs from your Duo Security environment.

## Features

- **Multiple Log Types**: Collect authentication, administrator, telephony, and offline access logs
- **Advanced Analysis**: Deep security analysis with anomaly detection and threat identification
- **Secure Design**: Uses only Python standard library, no external dependencies
- **Flexible Collection**: Configurable time ranges, pagination support, and batch processing
- **Export Options**: JSON and CSV export for SIEM integration
- **Comprehensive Documentation**: Detailed guides and examples

## Prerequisites

- Python 3.6 or higher
- Duo Admin API credentials (integration key, secret key, API hostname)
- Admin API application with "Grant read log" permission
- Network access to Duo's API endpoints (HTTPS on port 443)

## Quick Start

### 1. Clone the Repository

```bash
git clone https://github.com/1B05H1N/duo-log-collector.git
cd duo-log-collector
```

### 2. Set Up Credentials

Copy the environment template and configure your credentials:

```bash
cp docs/.env.example .env
```

Edit `.env` with your Duo API credentials:

```bash
DUO_INTEGRATION_KEY=your_integration_key_here
DUO_SECRET_KEY=your_secret_key_here
DUO_API_HOSTNAME=api-xxxxx.duosecurity.com
```

**Security Note**: Never commit the `.env` file to version control.

### 3. Test Your Connection

```bash
python tests/test_duo_connection.py
```

### 4. Collect Logs

#### Basic Usage - All Log Types
```bash
python src/duo_log_collector.py
```

#### Authentication Logs Only
```bash
python src/duo_auth_logs_only.py --days 7
```

#### Advanced Analysis
```bash
python src/duo_auth_log_analyzer.py --days 30 --export-csv
```

## Repository Structure

```
duo-log-collector/
├── src/                          # Main scripts
│   ├── duo_log_collector.py      # General log collector
│   ├── duo_auth_logs_only.py     # Authentication logs only
│   └── duo_auth_log_analyzer.py  # Advanced analysis tool
├── tests/                        # Test scripts
│   ├── test_duo_connection.py    # General connection test
│   └── test_auth_logs.py         # Authentication logs test
├── examples/                     # Usage examples
│   └── example_usage.py          # Programmatic usage examples
├── docs/                         # Documentation
│   ├── README_AUTH_LOGS.md       # Authentication logs guide
│   └── .env.example              # Environment template
├── .gitignore                    # Git ignore rules
├── requirements.txt              # Dependencies (none required)
└── README.md                     # This file
```

## Scripts Overview

### Main Scripts

| Script | Purpose | Best For |
|--------|---------|----------|
| `duo_log_collector.py` | General log collection (all types) | Comprehensive monitoring |
| `duo_auth_logs_only.py` | Authentication logs only | Security analysis |
| `duo_auth_log_analyzer.py` | Advanced analysis with threat detection | Security teams |

### Test Scripts

| Script | Purpose |
|--------|---------|
| `test_duo_connection.py` | Test general API connectivity |
| `test_auth_logs.py` | Test authentication log access |

## Log Types

### Authentication Logs
- User authentication attempts and results
- Device and platform information
- Location and IP address data
- Authentication factors used
- Application context

### Administrator Logs
- Admin panel actions and changes
- User management activities
- Application configuration changes
- Policy modifications

### Telephony Logs
- Phone call authentication attempts
- SMS delivery and results
- Telephony credit usage
- Call duration and outcomes

### Offline Access Logs
- Offline code generation and usage
- Emergency access scenarios
- Offline authentication patterns

## Security Features

- **No External Dependencies**: Uses only Python standard library
- **Secure Authentication**: HMAC-SHA1 signatures as required by Duo API
- **Credential Protection**: Environment variable-based configuration
- **Audit Logging**: Comprehensive logging for all operations
- **Error Handling**: Graceful error handling without credential exposure

## Analysis Capabilities

### Authentication Analysis
- Success/failure rate analysis
- User behavior patterns
- Device usage tracking
- Location-based insights
- Time-based activity analysis

### Security Insights
- High failure rate user identification
- Multiple device/location usage detection
- Fraud indicator analysis
- Unusual activity pattern detection
- Risk assessment and recommendations

## Usage Examples

### Command Line Usage

```bash
# Collect all log types for last 7 days
python src/duo_log_collector.py

# Collect authentication logs for last 30 days
python src/duo_auth_logs_only.py --days 30

# Advanced analysis with CSV export
python src/duo_auth_log_analyzer.py --days 14 --export-csv --verbose

# Custom output directory
python src/duo_log_collector.py --output-dir /var/log/duo --days 1
```

### Programmatic Usage

```python
from src.duo_auth_logs_only import DuoAuthLogCollector
from datetime import datetime, timedelta

# Initialize collector
collector = DuoAuthLogCollector(integration_key, secret_key, api_hostname)

# Collect logs for last 24 hours
end_time = int(datetime.now().timestamp())
start_time = int((datetime.now() - timedelta(hours=24)).timestamp())

logs = collector.get_all_authentication_logs(
    mintime=start_time,
    maxtime=end_time
)

# Analyze logs
analysis = collector.analyze_authentication_logs(logs)
print(f"Total authentication attempts: {analysis['summary']['total_logs']}")
```

## Documentation

- **[Authentication Logs Guide](docs/README_AUTH_LOGS.md)**: Detailed guide for authentication log collection
- **[Duo Admin API Documentation](https://duo.com/docs/adminapi)**: Official Duo API documentation
- **[Examples](examples/example_usage.py)**: Programmatic usage examples

## Configuration

### Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `DUO_INTEGRATION_KEY` | Duo Admin API integration key | Yes |
| `DUO_SECRET_KEY` | Duo Admin API secret key | Yes |
| `DUO_API_HOSTNAME` | Duo API hostname | Yes |

### Command Line Options

All scripts support common options:

- `--days`: Number of days back to collect logs
- `--max-logs`: Maximum number of logs to retrieve
- `--output-dir`: Output directory for log files
- `--verbose`: Enable verbose logging

## Security Considerations

### Credential Security
- Store API credentials securely using environment variables
- Never commit credentials to version control
- Rotate credentials regularly
- Use least-privilege access principles

### Data Handling
- Log files contain sensitive information - protect accordingly
- Implement proper access controls on log storage
- Consider encryption for log files at rest
- Follow data retention policies

### Network Security
- Ensure outbound HTTPS access to Duo's API endpoints
- Consider IP restrictions in Duo Admin Panel
- Monitor for unusual API usage patterns

## Troubleshooting

### Common Issues

**Authentication Errors**
- Verify integration key, secret key, and API hostname
- Check that the Admin API application has proper permissions
- Ensure network connectivity to Duo's API endpoints

**Permission Errors**
- Confirm "Grant read log" permission is enabled
- Verify the Admin API application is active
- Check for IP restrictions in Duo Admin Panel

**No Logs Retrieved**
- Verify the time range contains log data
- Check that the account has the appropriate Duo edition
- Confirm log retention period for your account

### Getting Help

1. Run the test scripts to verify your setup
2. Check the logs for detailed error messages
3. Review the [Duo Admin API documentation](https://duo.com/docs/adminapi)
4. Contact [Duo Support](https://duo.com/support) for API-related issues

## Author

**Ibrahim** - [@1B05H1N](https://github.com/1B05H1N)

- Website: [1b05h1n.com](https://1b05h1N.com/)
- LinkedIn: [in/ibrahim-](https://linkedin.com/in/ibrahim-)
- Location: Los Angeles, CA

## Disclaimer

This software is provided as-is for educational and operational purposes. Please review and comply with Duo's terms of service and your organization's security policies. The author is not responsible for any misuse or security issues arising from the use of this software.

## Links

- [Duo Security](https://duo.com/)
- [Duo Admin API Documentation](https://duo.com/docs/adminapi)
- [Duo Support](https://duo.com/support)