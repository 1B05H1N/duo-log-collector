#!/usr/bin/env python3
"""
Duo Authentication Logs Collector

This script specifically collects authentication logs from Duo Security's Admin API
based on the official documentation at https://duo.com/docs/adminapi#authentication-logs

Authentication logs contain information about:
- User authentication attempts
- Authentication results (SUCCESS, FAILURE, ERROR, FRAUD)
- Device information and platform details
- Location data
- Application context
- Timestamp information
- Factor used for authentication

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
import argparse
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('duo_auth_logs.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)


class DuoAuthLogCollector:
    """Specialized collector for Duo authentication logs"""
    
    def __init__(self, integration_key: str, secret_key: str, api_hostname: str):
        """
        Initialize Duo authentication log collector
        
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
            request.add_header('User-Agent', 'Duo-Auth-Log-Collector/1.0')
            
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
        Retrieve authentication logs from Duo Admin API
        
        This method calls the /admin/v1/logs/authentication endpoint as documented
        in the Duo Admin API documentation.
        
        Args:
            mintime: Unix timestamp for start of time range
            maxtime: Unix timestamp for end of time range  
            limit: Maximum number of logs to retrieve per request (max 1000)
            next_offset: Pagination offset for next request
            
        Returns:
            Tuple of (list of authentication log entries, next_offset for pagination)
            
        Raises:
            Exception: If API request fails
        """
        params = {'limit': str(min(limit, 1000))}  # API max is 1000
        
        if mintime:
            params['mintime'] = str(mintime)
        if maxtime:
            params['maxtime'] = str(maxtime)
        if next_offset:
            params['next_offset'] = next_offset
            
        logger.info(f"Retrieving authentication logs (limit: {params['limit']})")
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
                    
                # Small delay to be respectful to the API
                time.sleep(0.1)
                    
            except Exception as e:
                logger.error(f"Error retrieving logs: {str(e)}")
                break
                
        return all_logs
    
    def analyze_authentication_logs(self, logs: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Perform basic analysis on authentication logs
        
        Args:
            logs: List of authentication log entries
            
        Returns:
            Analysis results
        """
        if not logs:
            return {'error': 'No logs to analyze'}
        
        # Basic statistics
        total_logs = len(logs)
        results = {}
        factors = {}
        applications = {}
        users = set()
        devices = set()
        
        # Time range
        timestamps = [log.get('timestamp', 0) for log in logs if log.get('timestamp')]
        time_range = {
            'earliest': min(timestamps) if timestamps else 0,
            'latest': max(timestamps) if timestamps else 0
        }
        
        # Analyze each log entry
        for log in logs:
            # Count results
            result = log.get('result', 'UNKNOWN')
            results[result] = results.get(result, 0) + 1
            
            # Count factors
            factor = log.get('factor', 'UNKNOWN')
            factors[factor] = factors.get(factor, 0) + 1
            
            # Count applications
            app = log.get('application', {}).get('name', 'UNKNOWN') if isinstance(log.get('application'), dict) else 'UNKNOWN'
            applications[app] = applications.get(app, 0) + 1
            
            # Track unique users and devices
            if log.get('username'):
                users.add(log['username'])
            if log.get('device'):
                devices.add(log['device'])
        
        # Calculate percentages
        result_percentages = {result: (count / total_logs) * 100 for result, count in results.items()}
        factor_percentages = {factor: (count / total_logs) * 100 for factor, count in factors.items()}
        
        analysis = {
            'summary': {
                'total_logs': total_logs,
                'unique_users': len(users),
                'unique_devices': len(devices),
                'time_range': time_range
            },
            'authentication_results': {
                'counts': results,
                'percentages': result_percentages
            },
            'authentication_factors': {
                'counts': factors,
                'percentages': factor_percentages
            },
            'applications': {
                'counts': applications
            },
            'top_users': sorted(
                [(user, sum(1 for log in logs if log.get('username') == user)) for user in users],
                key=lambda x: x[1],
                reverse=True
            )[:10]
        }
        
        return analysis
    
    def save_logs_to_file(self, logs: List[Dict[str, Any]], filename: str) -> None:
        """
        Save authentication logs to JSON file
        
        Args:
            logs: List of authentication log entries
            filename: Output filename
        """
        with open(filename, 'w') as f:
            json.dump(logs, f, indent=2, default=str)
        logger.info(f"Saved {len(logs)} authentication logs to {filename}")
    
    def save_analysis_to_file(self, analysis: Dict[str, Any], filename: str) -> None:
        """
        Save analysis results to JSON file
        
        Args:
            analysis: Analysis results
            filename: Output filename
        """
        with open(filename, 'w') as f:
            json.dump(analysis, f, indent=2, default=str)
        logger.info(f"Saved analysis results to {filename}")


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
    parser = argparse.ArgumentParser(description='Collect Duo authentication logs')
    parser.add_argument('--days', type=int, default=7,
                       help='Number of days back to collect logs (default: 7)')
    parser.add_argument('--max-logs', type=int,
                       help='Maximum number of logs to retrieve (default: all)')
    parser.add_argument('--output-dir', default='duo_auth_logs',
                       help='Output directory for log files (default: duo_auth_logs)')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Enable verbose logging')
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    try:
        # Load credentials
        logger.info("Loading Duo API credentials...")
        integration_key, secret_key, api_hostname = load_credentials()
        
        # Initialize collector
        logger.info("Initializing Duo authentication log collector...")
        collector = DuoAuthLogCollector(integration_key, secret_key, api_hostname)
        
        # Calculate time range
        end_time = int(time.time())
        start_time = end_time - (args.days * 24 * 60 * 60)
        
        logger.info(f"Collecting authentication logs from {datetime.fromtimestamp(start_time)} to {datetime.fromtimestamp(end_time)}")
        
        # Collect authentication logs
        logs = collector.get_all_authentication_logs(
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
        
        # Save raw logs
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        logs_filename = f"{args.output_dir}/auth_logs_{timestamp}.json"
        collector.save_logs_to_file(logs, logs_filename)
        
        # Perform analysis
        logger.info("Analyzing authentication logs...")
        analysis = collector.analyze_authentication_logs(logs)
        
        # Save analysis
        analysis_filename = f"{args.output_dir}/auth_analysis_{timestamp}.json"
        collector.save_analysis_to_file(analysis, analysis_filename)
        
        # Print summary
        print("\n" + "="*50)
        print("DUO AUTHENTICATION LOGS SUMMARY")
        print("="*50)
        
        summary = analysis['summary']
        print(f"\nCollection Period: {args.days} days")
        print(f"Total Authentication Attempts: {summary['total_logs']}")
        print(f"Unique Users: {summary['unique_users']}")
        print(f"Unique Devices: {summary['unique_devices']}")
        
        if summary['time_range']['earliest']:
            earliest = datetime.fromtimestamp(summary['time_range']['earliest'])
            latest = datetime.fromtimestamp(summary['time_range']['latest'])
            print(f"Time Range: {earliest} to {latest}")
        
        # Authentication results
        print(f"\nAuthentication Results:")
        for result, count in analysis['authentication_results']['counts'].items():
            percentage = analysis['authentication_results']['percentages'][result]
            print(f"  {result}: {count} ({percentage:.1f}%)")
        
        # Authentication factors
        print(f"\nAuthentication Factors:")
        for factor, count in analysis['authentication_factors']['counts'].items():
            percentage = analysis['authentication_factors']['percentages'][factor]
            print(f"  {factor}: {count} ({percentage:.1f}%)")
        
        # Top applications
        print(f"\nTop Applications:")
        for app, count in list(analysis['applications']['counts'].items())[:5]:
            print(f"  {app}: {count}")
        
        # Top users
        print(f"\nTop Users by Authentication Attempts:")
        for user, count in analysis['top_users'][:5]:
            print(f"  {user}: {count}")
        
        print(f"\nFiles saved to: {args.output_dir}/")
        print(f"  Raw logs: {logs_filename}")
        print(f"  Analysis: {analysis_filename}")
        
        logger.info("Authentication log collection completed successfully")
        
    except Exception as e:
        logger.error(f"Collection failed: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main()
