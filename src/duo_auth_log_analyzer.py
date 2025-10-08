#!/usr/bin/env python3
"""
Duo Authentication Log Analyzer

This script specializes in collecting and analyzing authentication logs from Duo Security's Admin API.
Based on the official Duo Admin API documentation for authentication logs.

Features:
- Detailed authentication log collection
- Advanced analysis of authentication patterns
- Security threat detection
- User behavior analysis
- Device and location tracking
- Export capabilities for SIEM integration

Requirements:
- Duo Admin API credentials (integration key, secret key, API hostname)
- "Grant read log" API permission
- Python 3.6+

Security Notes:
- Store credentials securely (environment variables recommended)
- Use HTTPS for all API communications
- Implement proper error handling and logging
"""

import os
import sys
import json
import time
import hmac
import hashlib
import base64
import urllib.parse
import urllib.request
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from collections import defaultdict, Counter
import argparse
import logging
import csv

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('duo_auth_analyzer.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)


class DuoAPIClient:
    """Client for interacting with Duo Admin API"""
    
    def __init__(self, integration_key: str, secret_key: str, api_hostname: str):
        """
        Initialize Duo API client
        
        Args:
            integration_key: Duo Admin API integration key
            secret_key: Duo Admin API secret key  
            api_hostname: Duo API hostname (e.g., api-xxxxx.duosecurity.com)
        """
        self.integration_key = integration_key
        self.secret_key = secret_key
        self.api_hostname = api_hostname
        self.base_url = f"https://{api_hostname}/admin/v1"
        
    def _generate_signature(self, method: str, host: str, path: str, params: Dict[str, str]) -> str:
        """
        Generate HMAC signature for API authentication
        
        Args:
            method: HTTP method (GET, POST, etc.)
            host: API hostname
            path: API endpoint path
            params: Query parameters
            
        Returns:
            Base64 encoded signature
        """
        # Create canonical string
        canonical = [method, host, path]
        
        # Add sorted parameters
        if params:
            sorted_params = sorted(params.items())
            param_string = urllib.parse.urlencode(sorted_params)
            canonical.append(param_string)
        else:
            canonical.append("")
            
        canonical_string = "\n".join(canonical)
        
        # Generate HMAC signature
        signature = hmac.new(
            self.secret_key.encode('utf-8'),
            canonical_string.encode('utf-8'),
            hashlib.sha1
        ).hexdigest()
        
        return base64.b64encode(signature.encode('utf-8')).decode('utf-8')
    
    def _make_request(self, method: str, endpoint: str, params: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        """
        Make authenticated request to Duo API
        
        Args:
            method: HTTP method
            endpoint: API endpoint path
            params: Query parameters
            
        Returns:
            JSON response as dictionary
            
        Raises:
            Exception: If API request fails
        """
        if params is None:
            params = {}
            
        # Add authentication parameters
        params['ikey'] = self.integration_key
        
        # Generate signature
        signature = self._generate_signature(method, self.api_hostname, endpoint, params)
        params['sig'] = signature
        
        # Build URL
        url = f"{self.base_url}{endpoint}"
        if params:
            query_string = urllib.parse.urlencode(params)
            url = f"{url}?{query_string}"
            
        logger.debug(f"Making {method} request to: {url}")
        
        try:
            # Create request
            request = urllib.request.Request(url, method=method)
            request.add_header('User-Agent', 'Duo-Auth-Analyzer/1.0')
            
            # Make request
            with urllib.request.urlopen(request, timeout=30) as response:
                response_data = response.read().decode('utf-8')
                return json.loads(response_data)
                
        except urllib.error.HTTPError as e:
            error_msg = f"HTTP Error {e.code}: {e.reason}"
            try:
                error_body = e.read().decode('utf-8')
                error_data = json.loads(error_body)
                error_msg += f" - {error_data.get('message', 'Unknown error')}"
            except:
                pass
            raise Exception(error_msg)
        except Exception as e:
            raise Exception(f"Request failed: {str(e)}")
    
    def get_authentication_logs(self, mintime: Optional[int] = None, maxtime: Optional[int] = None, 
                              limit: int = 1000, next_offset: Optional[str] = None) -> Tuple[List[Dict[str, Any]], Optional[str]]:
        """
        Retrieve authentication logs with pagination support
        
        Args:
            mintime: Unix timestamp for start of time range
            maxtime: Unix timestamp for end of time range  
            limit: Maximum number of logs to retrieve per request
            next_offset: Pagination offset for next request
            
        Returns:
            Tuple of (list of authentication log entries, next_offset for pagination)
        """
        params = {'limit': str(limit)}
        
        if mintime:
            params['mintime'] = str(mintime)
        if maxtime:
            params['maxtime'] = str(maxtime)
        if next_offset:
            params['next_offset'] = next_offset
            
        logger.info(f"Retrieving authentication logs (limit: {limit})")
        response = self._make_request('GET', '/admin/v1/logs/authentication', params)
        
        if response.get('stat') != 'OK':
            raise Exception(f"API error: {response.get('message', 'Unknown error')}")
            
        # Extract pagination info
        metadata = response.get('metadata', {})
        next_offset = metadata.get('next_offset')
        
        return response.get('response', []), next_offset
    
    def get_all_authentication_logs(self, mintime: Optional[int] = None, maxtime: Optional[int] = None,
                                   max_logs: Optional[int] = None) -> List[Dict[str, Any]]:
        """
        Retrieve all authentication logs with automatic pagination
        
        Args:
            mintime: Unix timestamp for start of time range
            maxtime: Unix timestamp for end of time range
            max_logs: Maximum total number of logs to retrieve (None for all)
            
        Returns:
            List of all authentication log entries
        """
        all_logs = []
        next_offset = None
        batch_size = 1000
        
        while True:
            if max_logs and len(all_logs) >= max_logs:
                break
                
            # Adjust batch size if we're near the limit
            current_batch_size = batch_size
            if max_logs and len(all_logs) + batch_size > max_logs:
                current_batch_size = max_logs - len(all_logs)
            
            try:
                logs, next_offset = self.get_authentication_logs(
                    mintime=mintime,
                    maxtime=maxtime,
                    limit=current_batch_size,
                    next_offset=next_offset
                )
                
                all_logs.extend(logs)
                logger.info(f"Retrieved {len(logs)} logs (total: {len(all_logs)})")
                
                if not next_offset or not logs:
                    break
                    
            except Exception as e:
                logger.error(f"Error retrieving logs: {str(e)}")
                break
                
        return all_logs


class AuthenticationLogAnalyzer:
    """Advanced analyzer for Duo authentication logs"""
    
    def __init__(self, logs: List[Dict[str, Any]]):
        """
        Initialize analyzer with authentication logs
        
        Args:
            logs: List of authentication log entries
        """
        self.logs = logs
        self.analysis_results = {}
        
    def analyze_authentication_results(self) -> Dict[str, Any]:
        """
        Analyze authentication results and success/failure patterns
        
        Returns:
            Analysis of authentication results
        """
        results = Counter()
        result_details = defaultdict(list)
        
        for log in self.logs:
            result = log.get('result', 'UNKNOWN')
            results[result] += 1
            result_details[result].append(log)
        
        analysis = {
            'total_attempts': len(self.logs),
            'result_counts': dict(results),
            'result_percentages': {
                result: (count / len(self.logs)) * 100 
                for result, count in results.items()
            },
            'result_details': dict(result_details)
        }
        
        self.analysis_results['authentication_results'] = analysis
        return analysis
    
    def analyze_user_patterns(self) -> Dict[str, Any]:
        """
        Analyze user authentication patterns
        
        Returns:
            Analysis of user behavior patterns
        """
        user_stats = defaultdict(lambda: {
            'total_attempts': 0,
            'successful_attempts': 0,
            'failed_attempts': 0,
            'unique_devices': set(),
            'unique_locations': set(),
            'unique_applications': set(),
            'first_seen': None,
            'last_seen': None,
            'authentication_methods': Counter()
        })
        
        for log in self.logs:
            username = log.get('username', 'unknown')
            user_data = user_stats[username]
            
            # Update counters
            user_data['total_attempts'] += 1
            if log.get('result') == 'SUCCESS':
                user_data['successful_attempts'] += 1
            else:
                user_data['failed_attempts'] += 1
            
            # Track unique values
            if log.get('device'):
                user_data['unique_devices'].add(log['device'])
            if log.get('location'):
                user_data['unique_locations'].add(log['location'])
            if log.get('application'):
                user_data['unique_applications'].add(log['application'])
            
            # Track authentication methods
            if log.get('factor'):
                user_data['authentication_methods'][log['factor']] += 1
            
            # Track time range
            timestamp = log.get('timestamp')
            if timestamp:
                if not user_data['first_seen'] or timestamp < user_data['first_seen']:
                    user_data['first_seen'] = timestamp
                if not user_data['last_seen'] or timestamp > user_data['last_seen']:
                    user_data['last_seen'] = timestamp
        
        # Convert sets to counts and clean up data
        for username, data in user_stats.items():
            data['unique_device_count'] = len(data['unique_devices'])
            data['unique_location_count'] = len(data['unique_locations'])
            data['unique_application_count'] = len(data['unique_applications'])
            data['success_rate'] = (data['successful_attempts'] / data['total_attempts']) * 100 if data['total_attempts'] > 0 else 0
            data['authentication_methods'] = dict(data['authentication_methods'])
            
            # Remove sets to make JSON serializable
            del data['unique_devices']
            del data['unique_locations']
            del data['unique_applications']
        
        analysis = {
            'total_users': len(user_stats),
            'user_statistics': dict(user_stats),
            'top_users_by_attempts': sorted(
                user_stats.items(), 
                key=lambda x: x[1]['total_attempts'], 
                reverse=True
            )[:10]
        }
        
        self.analysis_results['user_patterns'] = analysis
        return analysis
    
    def detect_anomalies(self) -> Dict[str, Any]:
        """
        Detect potential security anomalies in authentication patterns
        
        Returns:
            Analysis of potential security issues
        """
        anomalies = {
            'high_failure_rate_users': [],
            'multiple_locations_users': [],
            'multiple_devices_users': [],
            'rapid_authentication_attempts': [],
            'unusual_hours_activity': [],
            'fraud_indicators': []
        }
        
        user_stats = self.analysis_results.get('user_patterns', {}).get('user_statistics', {})
        
        for username, stats in user_stats.items():
            # High failure rate users (>50% failure rate with >5 attempts)
            if stats['total_attempts'] > 5 and stats['success_rate'] < 50:
                anomalies['high_failure_rate_users'].append({
                    'username': username,
                    'failure_rate': 100 - stats['success_rate'],
                    'total_attempts': stats['total_attempts']
                })
            
            # Users with multiple locations (>3 unique locations)
            if stats['unique_location_count'] > 3:
                anomalies['multiple_locations_users'].append({
                    'username': username,
                    'location_count': stats['unique_location_count']
                })
            
            # Users with multiple devices (>3 unique devices)
            if stats['unique_device_count'] > 3:
                anomalies['multiple_devices_users'].append({
                    'username': username,
                    'device_count': stats['unique_device_count']
                })
        
        # Analyze time patterns
        hourly_attempts = defaultdict(int)
        for log in self.logs:
            timestamp = log.get('timestamp')
            if timestamp:
                hour = datetime.fromtimestamp(timestamp).hour
                hourly_attempts[hour] += 1
        
        # Detect unusual hours (outside 6 AM - 10 PM)
        for hour, count in hourly_attempts.items():
            if hour < 6 or hour > 22:
                anomalies['unusual_hours_activity'].append({
                    'hour': hour,
                    'attempt_count': count
                })
        
        # Detect fraud indicators
        fraud_logs = [log for log in self.logs if log.get('result') == 'FRAUD']
        for log in fraud_logs:
            anomalies['fraud_indicators'].append({
                'username': log.get('username'),
                'timestamp': log.get('timestamp'),
                'device': log.get('device'),
                'location': log.get('location'),
                'reason': log.get('reason', 'Unknown')
            })
        
        self.analysis_results['anomalies'] = anomalies
        return anomalies
    
    def analyze_device_patterns(self) -> Dict[str, Any]:
        """
        Analyze device usage patterns
        
        Returns:
            Analysis of device authentication patterns
        """
        device_stats = defaultdict(lambda: {
            'total_attempts': 0,
            'successful_attempts': 0,
            'unique_users': set(),
            'platforms': Counter(),
            'first_seen': None,
            'last_seen': None
        })
        
        for log in self.logs:
            device = log.get('device', 'unknown')
            device_data = device_stats[device]
            
            device_data['total_attempts'] += 1
            if log.get('result') == 'SUCCESS':
                device_data['successful_attempts'] += 1
            
            if log.get('username'):
                device_data['unique_users'].add(log['username'])
            
            if log.get('platform'):
                device_data['platforms'][log['platform']] += 1
            
            timestamp = log.get('timestamp')
            if timestamp:
                if not device_data['first_seen'] or timestamp < device_data['first_seen']:
                    device_data['first_seen'] = timestamp
                if not device_data['last_seen'] or timestamp > device_data['last_seen']:
                    device_data['last_seen'] = timestamp
        
        # Clean up data for JSON serialization
        for device, data in device_stats.items():
            data['unique_user_count'] = len(data['unique_users'])
            data['success_rate'] = (data['successful_attempts'] / data['total_attempts']) * 100 if data['total_attempts'] > 0 else 0
            data['platforms'] = dict(data['platforms'])
            del data['unique_users']
        
        analysis = {
            'total_devices': len(device_stats),
            'device_statistics': dict(device_stats),
            'top_devices_by_attempts': sorted(
                device_stats.items(),
                key=lambda x: x[1]['total_attempts'],
                reverse=True
            )[:10]
        }
        
        self.analysis_results['device_patterns'] = analysis
        return analysis
    
    def generate_security_report(self) -> Dict[str, Any]:
        """
        Generate comprehensive security report
        
        Returns:
            Complete security analysis report
        """
        if not self.analysis_results:
            # Run all analyses if not already done
            self.analyze_authentication_results()
            self.analyze_user_patterns()
            self.detect_anomalies()
            self.analyze_device_patterns()
        
        report = {
            'report_generated': datetime.now().isoformat(),
            'analysis_period': {
                'start': min(log.get('timestamp', 0) for log in self.logs) if self.logs else 0,
                'end': max(log.get('timestamp', 0) for log in self.logs) if self.logs else 0,
                'total_logs': len(self.logs)
            },
            'summary': {
                'total_authentication_attempts': len(self.logs),
                'unique_users': len(set(log.get('username') for log in self.logs if log.get('username'))),
                'unique_devices': len(set(log.get('device') for log in self.logs if log.get('device'))),
                'unique_applications': len(set(log.get('application') for log in self.logs if log.get('application')))
            },
            'detailed_analysis': self.analysis_results,
            'security_recommendations': self._generate_recommendations()
        }
        
        return report
    
    def _generate_recommendations(self) -> List[str]:
        """
        Generate security recommendations based on analysis
        
        Returns:
            List of security recommendations
        """
        recommendations = []
        
        anomalies = self.analysis_results.get('anomalies', {})
        
        if anomalies.get('high_failure_rate_users'):
            recommendations.append(
                f"Review {len(anomalies['high_failure_rate_users'])} users with high failure rates - "
                "consider additional authentication factors or account review"
            )
        
        if anomalies.get('multiple_locations_users'):
            recommendations.append(
                f"Investigate {len(anomalies['multiple_locations_users'])} users authenticating from "
                "multiple locations - verify legitimate access patterns"
            )
        
        if anomalies.get('multiple_devices_users'):
            recommendations.append(
                f"Review {len(anomalies['multiple_devices_users'])} users with multiple devices - "
                "ensure device registration is properly managed"
            )
        
        if anomalies.get('fraud_indicators'):
            recommendations.append(
                f"URGENT: {len(anomalies['fraud_indicators'])} fraud indicators detected - "
                "immediate investigation required"
            )
        
        if anomalies.get('unusual_hours_activity'):
            recommendations.append(
                "Monitor authentication attempts during unusual hours - "
                "consider implementing time-based access controls"
            )
        
        if not recommendations:
            recommendations.append("No significant security anomalies detected in current analysis")
        
        return recommendations
    
    def export_to_csv(self, filename: str) -> None:
        """
        Export authentication logs to CSV format
        
        Args:
            filename: Output CSV filename
        """
        if not self.logs:
            logger.warning("No logs to export")
            return
        
        # Get all possible field names
        fieldnames = set()
        for log in self.logs:
            fieldnames.update(log.keys())
        fieldnames = sorted(list(fieldnames))
        
        with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            
            for log in self.logs:
                # Convert timestamp to readable format
                if 'timestamp' in log and log['timestamp']:
                    log_copy = log.copy()
                    log_copy['timestamp_readable'] = datetime.fromtimestamp(log['timestamp']).isoformat()
                    writer.writerow(log_copy)
                else:
                    writer.writerow(log)
        
        logger.info(f"Exported {len(self.logs)} logs to {filename}")


def load_credentials() -> tuple:
    """
    Load Duo API credentials from environment variables
    
    Returns:
        Tuple of (integration_key, secret_key, api_hostname)
        
    Raises:
        Exception: If required credentials are missing
    """
    integration_key = os.getenv('DUO_INTEGRATION_KEY')
    secret_key = os.getenv('DUO_SECRET_KEY')
    api_hostname = os.getenv('DUO_API_HOSTNAME')
    
    if not all([integration_key, secret_key, api_hostname]):
        missing = []
        if not integration_key:
            missing.append('DUO_INTEGRATION_KEY')
        if not secret_key:
            missing.append('DUO_SECRET_KEY')
        if not api_hostname:
            missing.append('DUO_API_HOSTNAME')
            
        raise Exception(f"Missing required environment variables: {', '.join(missing)}")
        
    return integration_key, secret_key, api_hostname


def main():
    """Main function"""
    parser = argparse.ArgumentParser(description='Analyze Duo authentication logs')
    parser.add_argument('--days', type=int, default=7,
                       help='Number of days back to analyze (default: 7)')
    parser.add_argument('--max-logs', type=int,
                       help='Maximum number of logs to retrieve (default: all)')
    parser.add_argument('--output-dir', default='auth_analysis',
                       help='Output directory for analysis files (default: auth_analysis)')
    parser.add_argument('--export-csv', action='store_true',
                       help='Export raw logs to CSV format')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Enable verbose logging')
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    try:
        # Load credentials
        logger.info("Loading Duo API credentials...")
        integration_key, secret_key, api_hostname = load_credentials()
        
        # Initialize client
        logger.info("Initializing Duo API client...")
        client = DuoAPIClient(integration_key, secret_key, api_hostname)
        
        # Calculate time range
        end_time = int(time.time())
        start_time = end_time - (args.days * 24 * 60 * 60)
        
        logger.info(f"Collecting authentication logs from {datetime.fromtimestamp(start_time)} to {datetime.fromtimestamp(end_time)}")
        
        # Collect authentication logs
        logs = client.get_all_authentication_logs(
            mintime=start_time,
            maxtime=end_time,
            max_logs=args.max_logs
        )
        
        if not logs:
            logger.warning("No authentication logs found for the specified time range")
            return
        
        logger.info(f"Collected {len(logs)} authentication log entries")
        
        # Create output directory
        os.makedirs(args.output_dir, exist_ok=True)
        
        # Initialize analyzer
        analyzer = AuthenticationLogAnalyzer(logs)
        
        # Perform analysis
        logger.info("Performing authentication log analysis...")
        report = analyzer.generate_security_report()
        
        # Save analysis report
        report_filename = f"{args.output_dir}/auth_analysis_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(report_filename, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        
        # Export to CSV if requested
        if args.export_csv:
            csv_filename = f"{args.output_dir}/auth_logs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
            analyzer.export_to_csv(csv_filename)
            logger.info(f"Raw logs exported to {csv_filename}")
        
        # Print summary
        print("\n" + "="*60)
        print("DUO AUTHENTICATION LOG ANALYSIS SUMMARY")
        print("="*60)
        
        summary = report['summary']
        print(f"\nAnalysis Period: {args.days} days")
        print(f"Total Authentication Attempts: {summary['total_authentication_attempts']}")
        print(f"Unique Users: {summary['unique_users']}")
        print(f"Unique Devices: {summary['unique_devices']}")
        print(f"Unique Applications: {summary['unique_applications']}")
        
        # Authentication results
        auth_results = report['detailed_analysis']['authentication_results']
        print(f"\nAuthentication Results:")
        for result, count in auth_results['result_counts'].items():
            percentage = auth_results['result_percentages'][result]
            print(f"  {result}: {count} ({percentage:.1f}%)")
        
        # Security recommendations
        recommendations = report['security_recommendations']
        print(f"\nSecurity Recommendations:")
        for i, rec in enumerate(recommendations, 1):
            print(f"  {i}. {rec}")
        
        print(f"\nDetailed analysis saved to: {report_filename}")
        if args.export_csv:
            print(f"Raw logs exported to: {csv_filename}")
        
        logger.info("Authentication log analysis completed successfully")
        
    except Exception as e:
        logger.error(f"Analysis failed: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main()
