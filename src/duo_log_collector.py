#!/usr/bin/env python3
"""
Duo Admin API Log Collector

This script collects various types of logs from Duo Security's Admin API:
- Authentication logs
- Administrator action logs  
- Telephony logs

Requirements:
- Duo Admin API credentials (integration key, secret key, API hostname)
- Appropriate API permissions (Grant read log)
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
from typing import Dict, List, Optional, Any
import argparse
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('duo_log_collector.log'),
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
            request.add_header('User-Agent', 'Duo-Log-Collector/1.0')
            
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
                              limit: int = 1000) -> List[Dict[str, Any]]:
        """
        Retrieve authentication logs
        
        Args:
            mintime: Unix timestamp for start of time range
            maxtime: Unix timestamp for end of time range  
            limit: Maximum number of logs to retrieve
            
        Returns:
            List of authentication log entries
        """
        params = {'limit': str(limit)}
        
        if mintime:
            params['mintime'] = str(mintime)
        if maxtime:
            params['maxtime'] = str(maxtime)
            
        logger.info(f"Retrieving authentication logs (limit: {limit})")
        response = self._make_request('GET', '/admin/v1/logs/authentication', params)
        
        if response.get('stat') != 'OK':
            raise Exception(f"API error: {response.get('message', 'Unknown error')}")
            
        return response.get('response', [])
    
    def get_administrator_logs(self, mintime: Optional[int] = None, maxtime: Optional[int] = None,
                              limit: int = 1000) -> List[Dict[str, Any]]:
        """
        Retrieve administrator action logs
        
        Args:
            mintime: Unix timestamp for start of time range
            maxtime: Unix timestamp for end of time range
            limit: Maximum number of logs to retrieve
            
        Returns:
            List of administrator log entries
        """
        params = {'limit': str(limit)}
        
        if mintime:
            params['mintime'] = str(mintime)
        if maxtime:
            params['maxtime'] = str(maxtime)
            
        logger.info(f"Retrieving administrator logs (limit: {limit})")
        response = self._make_request('GET', '/admin/v1/logs/administrator', params)
        
        if response.get('stat') != 'OK':
            raise Exception(f"API error: {response.get('message', 'Unknown error')}")
            
        return response.get('response', [])
    
    def get_telephony_logs(self, mintime: Optional[int] = None, maxtime: Optional[int] = None,
                          limit: int = 1000) -> List[Dict[str, Any]]:
        """
        Retrieve telephony logs
        
        Args:
            mintime: Unix timestamp for start of time range
            maxtime: Unix timestamp for end of time range
            limit: Maximum number of logs to retrieve
            
        Returns:
            List of telephony log entries
        """
        params = {'limit': str(limit)}
        
        if mintime:
            params['mintime'] = str(mintime)
        if maxtime:
            params['maxtime'] = str(maxtime)
            
        logger.info(f"Retrieving telephony logs (limit: {limit})")
        response = self._make_request('GET', '/admin/v1/logs/telephony', params)
        
        if response.get('stat') != 'OK':
            raise Exception(f"API error: {response.get('message', 'Unknown error')}")
            
        return response.get('response', [])
    
    def get_offline_access_logs(self, mintime: Optional[int] = None, maxtime: Optional[int] = None,
                               limit: int = 1000) -> List[Dict[str, Any]]:
        """
        Retrieve offline access logs
        
        Args:
            mintime: Unix timestamp for start of time range
            maxtime: Unix timestamp for end of time range
            limit: Maximum number of logs to retrieve
            
        Returns:
            List of offline access log entries
        """
        params = {'limit': str(limit)}
        
        if mintime:
            params['mintime'] = str(mintime)
        if maxtime:
            params['maxtime'] = str(maxtime)
            
        logger.info(f"Retrieving offline access logs (limit: {limit})")
        response = self._make_request('GET', '/admin/v1/logs/offline_access', params)
        
        if response.get('stat') != 'OK':
            raise Exception(f"API error: {response.get('message', 'Unknown error')}")
            
        return response.get('response', [])


class DuoLogCollector:
    """Main class for collecting and processing Duo logs"""
    
    def __init__(self, client: DuoAPIClient):
        """
        Initialize log collector
        
        Args:
            client: Authenticated Duo API client
        """
        self.client = client
        
    def collect_logs(self, log_types: List[str], days_back: int = 7, 
                    output_dir: str = "duo_logs") -> Dict[str, List[Dict[str, Any]]]:
        """
        Collect specified types of logs
        
        Args:
            log_types: List of log types to collect ('auth', 'admin', 'telephony', 'offline')
            days_back: Number of days back to collect logs
            output_dir: Directory to save log files
            
        Returns:
            Dictionary mapping log types to their data
        """
        # Create output directory
        os.makedirs(output_dir, exist_ok=True)
        
        # Calculate time range
        end_time = int(time.time())
        start_time = end_time - (days_back * 24 * 60 * 60)
        
        logger.info(f"Collecting logs from {datetime.fromtimestamp(start_time)} to {datetime.fromtimestamp(end_time)}")
        
        collected_logs = {}
        
        for log_type in log_types:
            try:
                if log_type == 'auth':
                    logs = self.client.get_authentication_logs(start_time, end_time)
                elif log_type == 'admin':
                    logs = self.client.get_administrator_logs(start_time, end_time)
                elif log_type == 'telephony':
                    logs = self.client.get_telephony_logs(start_time, end_time)
                elif log_type == 'offline':
                    logs = self.client.get_offline_access_logs(start_time, end_time)
                else:
                    logger.warning(f"Unknown log type: {log_type}")
                    continue
                    
                collected_logs[log_type] = logs
                logger.info(f"Collected {len(logs)} {log_type} log entries")
                
                # Save to file
                filename = f"{output_dir}/{log_type}_logs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
                with open(filename, 'w') as f:
                    json.dump(logs, f, indent=2)
                logger.info(f"Saved {log_type} logs to {filename}")
                
            except Exception as e:
                logger.error(f"Failed to collect {log_type} logs: {str(e)}")
                collected_logs[log_type] = []
                
        return collected_logs
    
    def analyze_logs(self, logs: Dict[str, List[Dict[str, Any]]]) -> Dict[str, Any]:
        """
        Perform basic analysis on collected logs
        
        Args:
            logs: Dictionary of log data by type
            
        Returns:
            Analysis results
        """
        analysis = {}
        
        for log_type, log_data in logs.items():
            if not log_data:
                continue
                
            analysis[log_type] = {
                'total_entries': len(log_data),
                'time_range': {
                    'earliest': min(entry.get('timestamp', 0) for entry in log_data) if log_data else 0,
                    'latest': max(entry.get('timestamp', 0) for entry in log_data) if log_data else 0
                }
            }
            
            # Type-specific analysis
            if log_type == 'auth':
                # Analyze authentication results
                results = {}
                for entry in log_data:
                    result = entry.get('result', 'UNKNOWN')
                    results[result] = results.get(result, 0) + 1
                analysis[log_type]['results'] = results
                
            elif log_type == 'admin':
                # Analyze admin actions
                actions = {}
                for entry in log_data:
                    action = entry.get('action', 'UNKNOWN')
                    actions[action] = actions.get(action, 0) + 1
                analysis[log_type]['actions'] = actions
                
        return analysis


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
    parser = argparse.ArgumentParser(description='Collect logs from Duo Admin API')
    parser.add_argument('--log-types', nargs='+', 
                       choices=['auth', 'admin', 'telephony', 'offline'],
                       default=['auth', 'admin'],
                       help='Types of logs to collect (default: auth, admin)')
    parser.add_argument('--days', type=int, default=7,
                       help='Number of days back to collect logs (default: 7)')
    parser.add_argument('--output-dir', default='duo_logs',
                       help='Output directory for log files (default: duo_logs)')
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
        
        # Initialize collector
        collector = DuoLogCollector(client)
        
        # Collect logs
        logger.info(f"Starting log collection for types: {', '.join(args.log_types)}")
        logs = collector.collect_logs(args.log_types, args.days, args.output_dir)
        
        # Analyze logs
        logger.info("Analyzing collected logs...")
        analysis = collector.analyze_logs(logs)
        
        # Print summary
        print("\n" + "="*50)
        print("DUO LOG COLLECTION SUMMARY")
        print("="*50)
        
        for log_type, data in analysis.items():
            print(f"\n{log_type.upper()} LOGS:")
            print(f"  Total entries: {data['total_entries']}")
            if data['time_range']['earliest']:
                earliest = datetime.fromtimestamp(data['time_range']['earliest'])
                latest = datetime.fromtimestamp(data['time_range']['latest'])
                print(f"  Time range: {earliest} to {latest}")
                
            # Print type-specific analysis
            if 'results' in data:
                print("  Authentication results:")
                for result, count in data['results'].items():
                    print(f"    {result}: {count}")
            elif 'actions' in data:
                print("  Admin actions:")
                for action, count in data['actions'].items():
                    print(f"    {action}: {count}")
        
        print(f"\nLog files saved to: {args.output_dir}/")
        logger.info("Log collection completed successfully")
        
    except Exception as e:
        logger.error(f"Log collection failed: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main()
