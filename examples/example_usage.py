#!/usr/bin/env python3
"""
Example Usage of Duo Log Collector

This script demonstrates how to use the DuoLogCollector class
programmatically for custom log collection scenarios.
"""

import os
import json
from datetime import datetime, timedelta
import sys
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'src'))

from duo_log_collector import DuoAPIClient, DuoLogCollector, load_credentials


def example_basic_collection():
    """Example: Basic log collection"""
    print("Example 1: Basic Log Collection")
    print("-" * 40)
    
    try:
        # Load credentials
        integration_key, secret_key, api_hostname = load_credentials()
        
        # Initialize client and collector
        client = DuoAPIClient(integration_key, secret_key, api_hostname)
        collector = DuoLogCollector(client)
        
        # Collect authentication logs for last 3 days
        logs = collector.collect_logs(
            log_types=['auth'],
            days_back=3,
            output_dir='example_logs'
        )
        
        print(f"Collected {len(logs.get('auth', []))} authentication log entries")
        
    except Exception as e:
        print(f"Error: {str(e)}")


def example_custom_time_range():
    """Example: Custom time range collection"""
    print("\nExample 2: Custom Time Range Collection")
    print("-" * 40)
    
    try:
        # Load credentials
        integration_key, secret_key, api_hostname = load_credentials()
        client = DuoAPIClient(integration_key, secret_key, api_hostname)
        
        # Define custom time range (last 24 hours)
        end_time = int(datetime.now().timestamp())
        start_time = int((datetime.now() - timedelta(hours=24)).timestamp())
        
        # Collect logs for custom time range
        auth_logs = client.get_authentication_logs(
            mintime=start_time,
            maxtime=end_time,
            limit=100
        )
        
        print(f"Collected {len(auth_logs)} authentication logs from last 24 hours")
        
        # Analyze the logs
        if auth_logs:
            results = {}
            for log in auth_logs:
                result = log.get('result', 'UNKNOWN')
                results[result] = results.get(result, 0) + 1
            
            print("Authentication results:")
            for result, count in results.items():
                print(f"  {result}: {count}")
        
    except Exception as e:
        print(f"Error: {str(e)}")


def example_log_analysis():
    """Example: Advanced log analysis"""
    print("\nExample 3: Advanced Log Analysis")
    print("-" * 40)
    
    try:
        # Load credentials
        integration_key, secret_key, api_hostname = load_credentials()
        client = DuoAPIClient(integration_key, secret_key, api_hostname)
        collector = DuoLogCollector(client)
        
        # Collect multiple log types
        logs = collector.collect_logs(
            log_types=['auth', 'admin'],
            days_back=7,
            output_dir='analysis_logs'
        )
        
        # Perform analysis
        analysis = collector.analyze_logs(logs)
        
        # Display detailed analysis
        for log_type, data in analysis.items():
            print(f"\n{log_type.upper()} Analysis:")
            print(f"  Total entries: {data['total_entries']}")
            
            if 'results' in data:
                print("  Authentication results:")
                for result, count in data['results'].items():
                    percentage = (count / data['total_entries']) * 100
                    print(f"    {result}: {count} ({percentage:.1f}%)")
            
            if 'actions' in data:
                print("  Admin actions:")
                for action, count in data['actions'].items():
                    percentage = (count / data['total_entries']) * 100
                    print(f"    {action}: {count} ({percentage:.1f}%)")
        
    except Exception as e:
        print(f"Error: {str(e)}")


def example_specific_user_analysis():
    """Example: Analyze logs for a specific user"""
    print("\nExample 4: Specific User Analysis")
    print("-" * 40)
    
    try:
        # Load credentials
        integration_key, secret_key, api_hostname = load_credentials()
        client = DuoAPIClient(integration_key, secret_key, api_hostname)
        
        # Collect authentication logs
        auth_logs = client.get_authentication_logs(days_back=30)
        
        # Filter for specific user (replace with actual username)
        target_user = "example.user@company.com"
        user_logs = [log for log in auth_logs if log.get('username') == target_user]
        
        if user_logs:
            print(f"Found {len(user_logs)} authentication attempts for {target_user}")
            
            # Analyze user's authentication patterns
            results = {}
            devices = set()
            locations = set()
            
            for log in user_logs:
                result = log.get('result', 'UNKNOWN')
                results[result] = results.get(result, 0) + 1
                
                if log.get('device'):
                    devices.add(log['device'])
                if log.get('location'):
                    locations.add(log['location'])
            
            print(f"  Authentication results: {results}")
            print(f"  Unique devices used: {len(devices)}")
            print(f"  Unique locations: {len(locations)}")
            
            if devices:
                print(f"  Devices: {', '.join(list(devices)[:5])}")  # Show first 5
            if locations:
                print(f"  Locations: {', '.join(list(locations)[:5])}")  # Show first 5
        else:
            print(f"No authentication logs found for {target_user}")
        
    except Exception as e:
        print(f"Error: {str(e)}")


def main():
    """Run all examples"""
    print("Duo Log Collector - Usage Examples")
    print("=" * 50)
    
    # Check if credentials are available
    try:
        load_credentials()
    except Exception as e:
        print(f"Credential error: {str(e)}")
        print("Please set up your Duo API credentials first.")
        return
    
    # Run examples
    example_basic_collection()
    example_custom_time_range()
    example_log_analysis()
    example_specific_user_analysis()
    
    print("\n" + "=" * 50)
    print("Examples completed!")


if __name__ == "__main__":
    main()
